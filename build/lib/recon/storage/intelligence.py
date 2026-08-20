"""Persistent intelligence adapters for Night Scout.

This module connects storage-agnostic intelligence protocols to the workspace
SQLite database without moving intelligence policy into the storage layer.

Durable state that cannot be reconstructed losslessly is persisted explicitly:

    SQLiteYieldStore
        Raw yield observations with exact token/pattern credit.

    SQLiteConvergenceStateStore
        Latest branch/lane convergence controller state.

    SQLiteTargetGenomeStore
        Versioned semantic Target Genome snapshots.

State that *can* be reconstructed remains derived from the existing source of
truth instead of being duplicated:

    SQLiteTargetEventProvider
        Event history for vocabulary/pattern/genome builders.

    SQLiteConfidenceEvidenceProvider
        ConfidenceEvidence projected from event observations + lineage.

    SQLiteNoveltyHistoryProvider
        NoveltyHistory projected from event observations + snapshot changes.

The workspace database is intentionally documented as one target workspace, so
target event enumeration does not try to infer ownership from DNS/IP/cert data.
Scope and authorization remain policy-layer responsibilities.

Raw credentials are never persisted by this module. Sensitive evidence remains
in the separate protected evidence store used by mobile/export workflows.
"""

from __future__ import annotations

from collections.abc import Sequence
from sqlalchemy import Select, select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.budgets import BudgetLane
from recon.core.events import Event, EventType, ScopeState
from recon.intelligence.confidence import (
    ConfidenceEvidence,
    confidence_source_family,
    confidence_subject_key,
    event_is_historical,
    event_to_confidence_evidence,
)
from recon.intelligence.convergence import ConvergenceState
from recon.intelligence.genome import TargetGenome
from recon.intelligence.novelty import NoveltyHistory, novelty_subject_key
from recon.intelligence.yield_model import (
    PatternYieldCredit,
    TokenYieldCredit,
    YieldAggregate,
    YieldObservation,
    YieldQuery,
    aggregate_observations_for_query,
    observation_matches_query,
)
from recon.storage.database import Database
from recon.storage.models import (
    AssetRecord,
    ConvergenceStateRecord,
    EventObservationRecord,
    SnapshotChangeRecord,
    TargetGenomeSnapshotRecord,
    YieldObservationRecord,
)


class SQLiteYieldStore:
    """Durable implementation of intelligence.yield_model.YieldStore."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def append(self, observation: YieldObservation) -> bool:
        """Insert one immutable yield observation.

        The operation is idempotent by observation_id. Reusing an existing id
        for different content is rejected instead of silently overwriting
        scheduler history.
        """

        async with self._database.transaction(immediate=True) as session:
            existing = await session.get(
                YieldObservationRecord,
                observation.observation_id,
            )

            if existing is not None:
                restored = _yield_from_record(existing)
                if restored != observation:
                    raise ValueError(
                        "yield observation_id already refers to different "
                        f"content: {observation.observation_id}"
                    )
                return False

            session.add(_yield_to_record(observation))
            return True

    async def query(self, query: YieldQuery) -> Sequence[YieldObservation]:
        """Return observations matching scalar and nested credit filters."""

        statement = _yield_statement(query)

        async with self._database.session() as session:
            rows = list((await session.scalars(statement)).all())

        observations = [
            _yield_from_record(row)
            for row in rows
        ]

        # source_id/token/pattern filters live in JSON payloads. Keeping the
        # final domain-level predicate here guarantees exact parity with the
        # in-memory store even when future credit fields are added.
        matches = [
            observation
            for observation in observations
            if observation_matches_query(observation, query)
        ]

        matches.sort(
            key=lambda observation: (
                observation.observed_at,
                observation.observation_id,
            ),
            reverse=query.newest_first,
        )

        if query.limit is not None:
            matches = matches[: query.limit]

        return tuple(matches)

    async def aggregate(self, query: YieldQuery) -> YieldAggregate:
        observations = await self.query(
            query.model_copy(update={"limit": None})
        )
        return aggregate_observations_for_query(
            observations,
            query=query,
        )


class SQLiteConvergenceStateStore:
    """Durable implementation of convergence.ConvergenceStateStore."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def get(
        self,
        *,
        target_key: str | None,
        branch_id: str,
        lane: BudgetLane,
    ) -> ConvergenceState | None:
        key = _database_target_key(target_key)

        async with self._database.session() as session:
            record = await session.scalar(
                select(ConvergenceStateRecord).where(
                    ConvergenceStateRecord.target_key == key,
                    ConvergenceStateRecord.branch_id == branch_id,
                    ConvergenceStateRecord.lane == lane.value,
                )
            )

        if record is None:
            return None

        state = ConvergenceState.model_validate(record.state_json)

        expected_target = target_key.lower() if target_key is not None else None
        if (
            state.target_key != expected_target
            or state.branch_id != branch_id
            or state.lane is not lane
        ):
            raise RuntimeError("convergence state row identity/payload mismatch")

        return state

    async def put(self, state: ConvergenceState) -> None:
        key = _database_target_key(state.target_key)
        payload = state.model_dump(mode="json")

        async with self._database.transaction(immediate=True) as session:
            record = await session.scalar(
                select(ConvergenceStateRecord).where(
                    ConvergenceStateRecord.target_key == key,
                    ConvergenceStateRecord.branch_id == state.branch_id,
                    ConvergenceStateRecord.lane == state.lane.value,
                )
            )

            if record is None:
                record = ConvergenceStateRecord(
                    target_key=key,
                    branch_id=state.branch_id,
                    lane=state.lane.value,
                    tier=state.tier.value,
                    closed=state.closed,
                    cooldown_until=state.cooldown_until,
                    updated_at=state.updated_at,
                    state_json=payload,
                )
                session.add(record)
                return

            # Last-write wins only for a state that is at least as new as the
            # persisted state. This prevents a delayed coroutine from rolling
            # branch convergence backwards after a newer evaluation.
            if state.updated_at < record.updated_at:
                return

            record.tier = state.tier.value
            record.closed = state.closed
            record.cooldown_until = state.cooldown_until
            record.updated_at = state.updated_at
            record.state_json = payload


class SQLiteTargetGenomeStore:
    """Durable semantic Target Genome snapshot store."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def save(self, genome: TargetGenome) -> None:
        target_key = genome.target_key.strip().lower()
        payload = genome.model_dump(mode="json")

        async with self._database.transaction(immediate=True) as session:
            existing = await session.scalar(
                select(TargetGenomeSnapshotRecord).where(
                    TargetGenomeSnapshotRecord.target_key == target_key,
                    TargetGenomeSnapshotRecord.fingerprint == genome.fingerprint,
                )
            )

            if existing is None:
                session.add(
                    TargetGenomeSnapshotRecord(
                        target_key=target_key,
                        genome_version=genome.genome_version,
                        generated_at=genome.generated_at,
                        fingerprint=genome.fingerprint,
                        genome_json=payload,
                    )
                )
                return

            # Same semantic fingerprint: coalesce unchanged snapshots while
            # keeping the most recent generated_at/payload for explainability.
            if genome.generated_at >= existing.generated_at:
                existing.genome_version = genome.genome_version
                existing.generated_at = genome.generated_at
                existing.genome_json = payload

    async def latest(self, target_key: str) -> TargetGenome | None:
        normalized = target_key.strip().lower()
        if not normalized:
            raise ValueError("target_key must not be blank")

        async with self._database.session() as session:
            record = await session.scalar(
                select(TargetGenomeSnapshotRecord)
                .where(TargetGenomeSnapshotRecord.target_key == normalized)
                .order_by(
                    TargetGenomeSnapshotRecord.generated_at.desc(),
                    TargetGenomeSnapshotRecord.genome_id.desc(),
                )
                .limit(1)
            )

        if record is None:
            return None

        genome = TargetGenome.model_validate(record.genome_json)
        if genome.target_key.strip().lower() != normalized:
            raise RuntimeError("target genome row identity/payload mismatch")
        return genome

    async def history(
        self,
        target_key: str,
        *,
        limit: int = 20,
    ) -> tuple[TargetGenome, ...]:
        """Return recent distinct semantic snapshots for explain/diff workflows."""

        if limit <= 0:
            return ()

        normalized = target_key.strip().lower()
        if not normalized:
            raise ValueError("target_key must not be blank")

        async with self._database.session() as session:
            records = list(
                (
                    await session.scalars(
                        select(TargetGenomeSnapshotRecord)
                        .where(
                            TargetGenomeSnapshotRecord.target_key == normalized
                        )
                        .order_by(
                            TargetGenomeSnapshotRecord.generated_at.desc(),
                            TargetGenomeSnapshotRecord.genome_id.desc(),
                        )
                        .limit(limit)
                    )
                ).all()
            )

        return tuple(
            TargetGenome.model_validate(record.genome_json)
            for record in records
        )


class SQLiteTargetEventProvider:
    """Persistent Event provider for vocabulary/pattern/genome builders.

    Night Scout's Database is one target workspace, so this provider enumerates
    observations from that workspace rather than inferring target ownership
    from DNS/IP/certificate relationships.
    """

    def __init__(
        self,
        database: Database,
        *,
        max_events: int = 250_000,
    ) -> None:
        if max_events <= 0:
            raise ValueError("max_events must be positive")
        self._database = database
        self._max_events = max_events

    async def events_for(self, seed_event: Event) -> Sequence[Event]:
        async with self._database.session() as session:
            records = list(
                (
                    await session.scalars(
                        select(EventObservationRecord)
                        .where(EventObservationRecord.event_id != seed_event.event_id)
                        .order_by(
                            EventObservationRecord.last_seen.desc(),
                            EventObservationRecord.event_id.desc(),
                        )
                        .limit(self._max_events)
                    )
                ).all()
            )

        # The bound must never starve recent observations when a long-running
        # workspace exceeds max_events. Builders still receive deterministic
        # chronological order inside the selected recent window.
        records.sort(key=lambda record: (record.first_seen, record.event_id))
        return tuple(_event_from_record(record) for record in records)

    async def get_event(self, event_id: str) -> Event | None:
        """Also satisfies yield_model.YieldEventProvider."""

        async with self._database.session() as session:
            record = await session.get(EventObservationRecord, event_id)
        return _event_from_record(record) if record is not None else None


class SQLiteConfidenceEvidenceProvider:
    """Reconstruct confidence evidence from observations + primary lineage."""

    def __init__(
        self,
        database: Database,
        *,
        max_candidate_events: int = 20_000,
        max_evidence: int = 4_096,
        max_lineage_depth: int = 64,
    ) -> None:
        if min(max_candidate_events, max_evidence, max_lineage_depth) <= 0:
            raise ValueError("confidence provider limits must be positive")
        self._database = database
        self._max_candidate_events = max_candidate_events
        self._max_evidence = max_evidence
        self._max_lineage_depth = max_lineage_depth

    async def evidence_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> Sequence[ConfidenceEvidence]:
        expected = confidence_subject_key(event)
        if subject_key != expected:
            raise ValueError(
                "subject_key does not match supplied Event confidence subject"
            )

        async with self._database.session() as session:
            statement = _confidence_candidate_statement(
                subject_key,
                max_candidates=self._max_candidate_events,
            )
            records = list((await session.scalars(statement)).all())

            evidence: list[ConfidenceEvidence] = []

            for record in records:
                candidate = _event_from_record(record)
                if confidence_subject_key(candidate) != subject_key:
                    continue

                causal_root = await _causal_root_id(
                    session,
                    record,
                    max_depth=self._max_lineage_depth,
                )

                item = event_to_confidence_evidence(
                    candidate,
                    subject_key=subject_key,
                    causal_root_id=causal_root,
                )

                if item is not None:
                    evidence.append(item)

                if len(evidence) >= self._max_evidence:
                    break

        return tuple(evidence)


class SQLiteNoveltyHistoryProvider:
    """Reconstruct novelty history from observations and snapshot changes."""

    def __init__(
        self,
        database: Database,
        *,
        max_candidate_events: int = 20_000,
        max_changes: int = 4_096,
    ) -> None:
        if min(max_candidate_events, max_changes) <= 0:
            raise ValueError("novelty provider limits must be positive")
        self._database = database
        self._max_candidate_events = max_candidate_events
        self._max_changes = max_changes

    async def history_for(
        self,
        event: Event,
        *,
        subject_key: str,
    ) -> NoveltyHistory:
        expected = novelty_subject_key(event)
        if subject_key != expected:
            raise ValueError(
                "subject_key does not match supplied Event novelty subject"
            )

        async with self._database.session() as session:
            records = list(
                (
                    await session.scalars(
                        select(EventObservationRecord)
                        .where(
                            EventObservationRecord.event_type == event.type.value,
                            EventObservationRecord.event_id != event.event_id,
                        )
                        .order_by(
                            EventObservationRecord.last_seen.desc(),
                            EventObservationRecord.event_id.desc(),
                        )
                        .limit(self._max_candidate_events)
                    )
                ).all()
            )

            matching = [
                record
                for record in records
                if novelty_subject_key(_event_from_record(record)) == subject_key
            ]

            matching_events = [_event_from_record(record) for record in matching]
            source_families = {
                confidence_source_family(item.source)
                for item in matching_events
            }

            historical_count = sum(
                1 for item in matching_events if event_is_historical(item)
            )
            live_count = len(matching_events) - historical_count

            timestamps = sorted(
                (item.last_seen for item in matching_events),
            )

            asset_ids = {record.asset_id for record in matching}

            # Snapshot changes belong to the canonical asset, not to an
            # individual observation. Include the current persisted event's
            # asset id for change lookup while still excluding the current
            # observation from repetition counts.
            current_record = await session.get(
                EventObservationRecord,
                event.event_id,
            )
            if current_record is not None:
                asset_ids.add(current_record.asset_id)

            changes: list[SnapshotChangeRecord] = []

            if asset_ids:
                changes = list(
                    (
                        await session.scalars(
                            select(SnapshotChangeRecord)
                            .where(SnapshotChangeRecord.asset_id.in_(sorted(asset_ids)))
                            .order_by(
                                SnapshotChangeRecord.detected_at.desc(),
                                SnapshotChangeRecord.change_id.desc(),
                            )
                            .limit(self._max_changes)
                        )
                    ).all()
                )

            peer_count, peer_known = await _exact_peer_count(
                session,
                event,
            )

        return NoveltyHistory(
            subject_key=subject_key,
            observation_count=len(matching_events),
            live_observation_count=live_count,
            historical_observation_count=historical_count,
            distinct_source_families=len(source_families),
            first_seen_at=(
                min(item.first_seen for item in matching_events)
                if matching_events
                else None
            ),
            previous_seen_at=(timestamps[-2] if len(timestamps) >= 2 else None),
            last_seen_at=(timestamps[-1] if timestamps else None),
            change_types=tuple(sorted({change.change_type for change in changes})),
            change_fingerprints=tuple(
                sorted({change.change_key for change in changes})
            ),
            fingerprint_peer_count=(
                peer_count if event.type is EventType.FINGERPRINT else 0
            ),
            fingerprint_peer_count_known=(
                peer_known and event.type is EventType.FINGERPRINT
            ),
            technology_peer_count=(
                peer_count if event.type is EventType.TECHNOLOGY else 0
            ),
            technology_peer_count_known=(
                peer_known and event.type is EventType.TECHNOLOGY
            ),
            naming_frequency=None,
            historical_only=(historical_count > 0 and live_count == 0),
            live_after_historical=(historical_count > 0 and live_count > 0),
            metadata={
                "storage_backend": "sqlite",
                "history_excludes_current_event_id": event.event_id,
                "snapshot_change_count": len(changes),
                "naming_frequency_source": None,
            },
        )


class SQLiteIntelligenceStores:
    """Convenience bundle for orchestrator bootstrap wiring."""

    def __init__(
        self,
        database: Database,
        *,
        max_target_events: int = 250_000,
    ) -> None:
        self.yield_store = SQLiteYieldStore(database)
        self.convergence_store = SQLiteConvergenceStateStore(database)
        self.genome_store = SQLiteTargetGenomeStore(database)
        self.events = SQLiteTargetEventProvider(
            database,
            max_events=max_target_events,
        )
        self.confidence = SQLiteConfidenceEvidenceProvider(database)
        self.novelty = SQLiteNoveltyHistoryProvider(database)


def _yield_to_record(observation: YieldObservation) -> YieldObservationRecord:
    return YieldObservationRecord(
        observation_id=observation.observation_id,
        observed_at=observation.observed_at,
        run_id=observation.run_id,
        task_id=observation.task_id,
        input_event_id=observation.input_event_id,
        target_key=observation.target_key,
        branch_id=observation.branch_id,
        worker=observation.worker,
        action=observation.action,
        route_rule_id=observation.route_rule_id,
        input_source=observation.input_source,
        execution_outcome=observation.execution_outcome.value,
        attempted_units=observation.attempted_units,
        successful_hits=observation.successful_hits,
        new_assets=observation.new_assets,
        novel_assets=observation.novel_assets,
        new_domains=observation.new_domains,
        new_urls=observation.new_urls,
        new_endpoints=observation.new_endpoints,
        new_vocabulary_tokens=observation.new_vocabulary_tokens,
        new_patterns=observation.new_patterns,
        request_count=observation.request_count,
        runtime_seconds=observation.runtime_seconds,
        cost_units=observation.cost_units,
        source_ids_json=sorted(observation.source_ids),
        token_credits_json=[
            credit.model_dump(mode="json")
            for credit in observation.token_credits
        ],
        pattern_credits_json=[
            credit.model_dump(mode="json")
            for credit in observation.pattern_credits
        ],
        metadata_json=dict(observation.metadata),
    )


def _yield_from_record(record: YieldObservationRecord) -> YieldObservation:
    return YieldObservation(
        observation_id=record.observation_id,
        observed_at=record.observed_at,
        run_id=record.run_id,
        task_id=record.task_id,
        input_event_id=record.input_event_id,
        target_key=record.target_key,
        branch_id=record.branch_id,
        worker=record.worker,
        action=record.action,
        route_rule_id=record.route_rule_id,
        input_source=record.input_source,
        source_ids=frozenset(record.source_ids_json),
        execution_outcome=record.execution_outcome,
        attempted_units=record.attempted_units,
        successful_hits=record.successful_hits,
        new_assets=record.new_assets,
        novel_assets=record.novel_assets,
        new_domains=record.new_domains,
        new_urls=record.new_urls,
        new_endpoints=record.new_endpoints,
        new_vocabulary_tokens=record.new_vocabulary_tokens,
        new_patterns=record.new_patterns,
        request_count=record.request_count,
        runtime_seconds=record.runtime_seconds,
        cost_units=record.cost_units,
        token_credits=tuple(
            TokenYieldCredit.model_validate(payload)
            for payload in record.token_credits_json
        ),
        pattern_credits=tuple(
            PatternYieldCredit.model_validate(payload)
            for payload in record.pattern_credits_json
        ),
        metadata=dict(record.metadata_json),
    )


def _yield_statement(query: YieldQuery) -> Select[tuple[YieldObservationRecord]]:
    statement = select(YieldObservationRecord)

    if query.target_key is not None:
        statement = statement.where(
            YieldObservationRecord.target_key == query.target_key
        )
    if query.branch_id is not None:
        statement = statement.where(
            YieldObservationRecord.branch_id == query.branch_id
        )
    if query.worker is not None:
        statement = statement.where(YieldObservationRecord.worker == query.worker)
    if query.action is not None:
        statement = statement.where(YieldObservationRecord.action == query.action)
    if query.route_rule_id is not None:
        statement = statement.where(
            YieldObservationRecord.route_rule_id == query.route_rule_id
        )
    if query.input_source is not None:
        statement = statement.where(
            YieldObservationRecord.input_source == query.input_source
        )
    if query.since is not None:
        statement = statement.where(
            YieldObservationRecord.observed_at >= query.since
        )
    if query.until is not None:
        statement = statement.where(
            YieldObservationRecord.observed_at <= query.until
        )

    ordering = (
        YieldObservationRecord.observed_at.desc()
        if query.newest_first
        else YieldObservationRecord.observed_at.asc()
    )
    id_ordering = (
        YieldObservationRecord.observation_id.desc()
        if query.newest_first
        else YieldObservationRecord.observation_id.asc()
    )
    return statement.order_by(ordering, id_ordering)


def _database_target_key(target_key: str | None) -> str:
    if target_key is None:
        return ""
    return target_key.strip().lower()


def _event_from_record(record: EventObservationRecord) -> Event:
    return Event(
        event_id=record.event_id,
        type=EventType(record.event_type),
        value=record.value,
        source=record.source,
        parent_event_id=record.parent_event_id,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        scope_state=ScopeState(record.scope_state),
        confidence=record.confidence,
        novelty=record.novelty,
        depth=record.depth,
        tags=set(record.tags_json),
        metadata=dict(record.metadata_json),
    )


def _confidence_candidate_statement(
    subject_key: str,
    *,
    max_candidates: int,
) -> Select[tuple[EventObservationRecord]]:
    """Narrow candidate event types without changing domain subject semantics."""

    if subject_key.startswith("dns:"):
        types = (
            EventType.DNS_NAME.value,
            EventType.CERT_SAN.value,
            EventType.DNS_RECORD.value,
        )
    elif subject_key.startswith("ip:"):
        types = (EventType.IP_ADDRESS.value,)
    elif subject_key.startswith("url:"):
        types = (
            EventType.URL.value,
            EventType.API_ENDPOINT.value,
            EventType.JAVASCRIPT.value,
        )
    elif subject_key.startswith("http-service:"):
        types = (EventType.HTTP_SERVICE.value,)
    elif subject_key.startswith("http-response:"):
        types = (EventType.HTTP_RESPONSE.value,)
    elif subject_key.startswith("certificate:"):
        types = (EventType.CERTIFICATE.value,)
    else:
        prefix = subject_key.split(":", 1)[0].upper()
        types = (
            (prefix,)
            if prefix in {event_type.value for event_type in EventType}
            else tuple(event_type.value for event_type in EventType)
        )

    return (
        select(EventObservationRecord)
        .where(EventObservationRecord.event_type.in_(types))
        .order_by(
            EventObservationRecord.last_seen.desc(),
            EventObservationRecord.event_id.desc(),
        )
        .limit(max_candidates)
    )


async def _causal_root_id(
    session: AsyncSession,
    record: EventObservationRecord,
    *,
    max_depth: int,
) -> str | None:
    """Follow primary-parent lineage to a bounded causal root.

    Explicit multi-parent provenance remains available to the full provenance
    repository; this adapter uses the Event compatibility parent chain because
    confidence.py already applies same-provider dependency discounts.
    """

    parent_id = record.parent_event_id
    if parent_id is None:
        return None

    seen = {record.event_id}
    root = parent_id

    for _ in range(max_depth):
        if root in seen:
            break
        seen.add(root)

        parent = await session.get(EventObservationRecord, root)
        if parent is None or parent.parent_event_id is None:
            break
        root = parent.parent_event_id

    return root


async def _exact_peer_count(
    session: AsyncSession,
    event: Event,
) -> tuple[int, bool]:
    """Return exact peer count only for directly canonical comparable types."""

    if event.type not in {
        EventType.FINGERPRINT,
        EventType.TECHNOLOGY,
    }:
        return 0, False

    rows = list(
        (
            await session.scalars(
                select(AssetRecord.asset_id).where(
                    AssetRecord.event_type == event.type.value,
                    AssetRecord.value == event.value,
                )
            )
        ).all()
    )
    return len(set(rows)), True
