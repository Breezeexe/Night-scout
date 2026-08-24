"""Provenance graph storage and lineage tracing for Night Scout.

Provenance answers:

    "Why does Night Scout know this?"

A canonical Asset is intentionally not enough. The same asset can be observed
through multiple independent paths, and later intelligence modules need those
paths for confidence, target vocabulary, pattern learning, and explainability.

Example lineage:

    JAVASCRIPT bundle
        -> EXTRACTED_FROM -> API_ENDPOINT /internal-api/v3/orders
        -> EXTRACTED_FROM -> VOCAB_TOKEN "internal"
        -> GENERATED_FROM -> NAMING_PATTERN "{token}-api-{env}"
        -> GENERATED_FROM -> DNS_NAME internal-api-stage.example.com
        -> CONFIRMED_FROM -> DNS_NAME internal-api-stage.example.com (dns worker)

The final two observations may point at the same canonical AssetRecord while
remaining separate EventObservationRecord rows. This preserves the distinction
between a hypothesis and an independently confirmed observation.

`parent_event_id` on Event remains the convenient primary-parent field.
`provenance_edges` supplements it with any number of additional parents.

Raw sensitive values should never be stored in provenance summaries. Evidence
pointers should contain redacted summaries, hashes, and safe locators.
"""

from __future__ import annotations

from collections import deque
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import and_, select
from sqlalchemy.ext.asyncio import AsyncSession

from recon.core.events import EventType
from recon.storage.database import Database
from recon.storage.models import (
    AssetRecord,
    EvidenceRecord,
    EventObservationRecord,
    ProvenanceEdgeRecord,
    RelationshipRecord,
)


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


class ProvenanceRelation(StrEnum):
    """How a child observation was informed by a parent observation.

    Edges are always stored:
        parent_event_id -> child_event_id

    The enum value describes the child relative to that parent.
    """

    DISCOVERED_FROM = "DISCOVERED_FROM"
    EXTRACTED_FROM = "EXTRACTED_FROM"
    DERIVED_FROM = "DERIVED_FROM"
    GENERATED_FROM = "GENERATED_FROM"
    RESOLVED_FROM = "RESOLVED_FROM"
    CONFIRMED_FROM = "CONFIRMED_FROM"
    HISTORICAL_FROM = "HISTORICAL_FROM"

    # Correlation is informational rather than causal; unlike derivation edges,
    # it is not used for DAG cycle prevention.
    CORRELATED_FROM = "CORRELATED_FROM"

    @property
    def is_causal(self) -> bool:
        """Return whether this relation participates in causal lineage."""
        return self is not ProvenanceRelation.CORRELATED_FROM


class AssetRelationType(StrEnum):
    """Baseline relationship vocabulary for the canonical asset graph."""

    RESOLVES_TO = "RESOLVES_TO"
    HAS_DNS_RECORD = "HAS_DNS_RECORD"
    HAS_SUBDOMAIN = "HAS_SUBDOMAIN"
    ALIASES_TO = "ALIASES_TO"
    BELONGS_TO_CIDR = "BELONGS_TO_CIDR"
    ANNOUNCED_BY_ASN = "ANNOUNCED_BY_ASN"
    EXPOSES_SERVICE = "EXPOSES_SERVICE"
    SERVED_BY = "SERVED_BY"
    PRESENTS_CERTIFICATE = "PRESENTS_CERTIFICATE"
    CERTIFICATE_NAMES = "CERTIFICATE_NAMES"
    LINKS_TO = "LINKS_TO"
    REDIRECTS_TO = "REDIRECTS_TO"
    REFERENCES = "REFERENCES"
    USES_TECHNOLOGY = "USES_TECHNOLOGY"
    HAS_ENDPOINT = "HAS_ENDPOINT"
    HAS_CHILD_PATH = "HAS_CHILD_PATH"
    HAS_PARAMETER = "HAS_PARAMETER"
    HAS_ARTIFACT = "HAS_ARTIFACT"
    HISTORICAL_VERSION_OF = "HISTORICAL_VERSION_OF"
    FINGERPRINT_MATCH = "FINGERPRINT_MATCH"
    POTENTIALLY_AFFECTED_BY = "POTENTIALLY_AFFECTED_BY"
    CONFIRMED_AFFECTED_BY = "CONFIRMED_AFFECTED_BY"
    RELATED_TO = "RELATED_TO"


class EvidenceKind(StrEnum):
    """Safe evidence-pointer categories."""

    USER_SEED = "USER_SEED"
    TOOL_OUTPUT = "TOOL_OUTPUT"
    DNS_RESPONSE = "DNS_RESPONSE"
    HTTP_RESPONSE = "HTTP_RESPONSE"
    TLS_CERTIFICATE = "TLS_CERTIFICATE"
    ARCHIVE_RECORD = "ARCHIVE_RECORD"
    JAVASCRIPT_SOURCE = "JAVASCRIPT_SOURCE"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    FILE_ARTIFACT = "FILE_ARTIFACT"
    FINGERPRINT = "FINGERPRINT"
    POLICY_DECISION = "POLICY_DECISION"
    OTHER = "OTHER"


class ProvenanceEdge(BaseModel):
    """Storage-independent representation of one provenance edge."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    edge_id: str
    parent_event_id: str
    child_event_id: str

    relation: ProvenanceRelation
    source: str

    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    created_at: datetime

    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator(
        "edge_id",
        "parent_event_id",
        "child_event_id",
        "source",
    )
    @classmethod
    def required_text(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("must not be blank")
        return normalized

    @field_validator("created_at")
    @classmethod
    def aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("created_at must be timezone-aware")
        return value

    @model_validator(mode="after")
    def no_self_edge(self) -> ProvenanceEdge:
        if self.parent_event_id == self.child_event_id:
            raise ValueError("provenance self-edges are not allowed")
        return self


class AssetRelationship(BaseModel):
    """Storage-independent canonical asset relationship."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    relationship_id: str

    source_asset_id: str
    target_asset_id: str
    relation_type: str

    first_source_event_id: str | None = None

    confidence: float = Field(default=0.0, ge=0.0, le=1.0)

    first_seen: datetime
    last_seen: datetime

    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidencePointer(BaseModel):
    """Safe evidence reference without embedding raw sensitive content."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_id: str

    asset_id: str | None = None
    event_id: str | None = None
    relationship_id: str | None = None

    kind: EvidenceKind
    source: str

    locator: str | None = None
    content_hash: str | None = None
    summary: str | None = None

    created_at: datetime

    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def require_subject(self) -> EvidencePointer:
        if not any(
            (
                self.asset_id,
                self.event_id,
                self.relationship_id,
            )
        ):
            raise ValueError(
                "evidence pointer requires asset_id, event_id, "
                "or relationship_id"
            )
        return self


class LineageNode(BaseModel):
    """One observation represented in an explainable lineage graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    asset_id: str

    event_type: EventType
    value: str
    source: str

    primary_parent_event_id: str | None = None

    depth_from_focus: int = Field(ge=0)

    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime

    tags: tuple[str, ...] = ()


class LineageEdge(BaseModel):
    """Edge included in a returned lineage graph."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    edge_id: str

    parent_event_id: str
    child_event_id: str

    relation: ProvenanceRelation
    source: str

    confidence: float = Field(ge=0.0, le=1.0)

    # True for the compatibility edge synthesized from parent_event_id when no
    # explicit ProvenanceEdgeRecord exists for the same event pair.
    implicit_primary_parent: bool = False


class ProvenanceTrace(BaseModel):
    """Explainable bounded lineage graph around one focus event."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    focus_event_id: str

    direction: str
    max_depth: int = Field(ge=0)

    nodes: tuple[LineageNode, ...]
    edges: tuple[LineageEdge, ...]


class ProvenancePath(BaseModel):
    """One shortest causal path between two observations."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    start_event_id: str
    end_event_id: str

    nodes: tuple[LineageNode, ...]
    edges: tuple[LineageEdge, ...]


class ProvenanceRepository:
    """Persist/query observation lineage, asset relationships, and evidence."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def add_edge(
        self,
        *,
        parent_event_id: str,
        child_event_id: str,
        relation: ProvenanceRelation,
        source: str,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
        set_primary_parent_if_empty: bool = True,
    ) -> ProvenanceEdge:
        """Create or merge one provenance edge.

        Causal relations are maintained as a DAG. CORRELATED_FROM is allowed to
        participate in non-causal cycles because it expresses association, not
        derivation.
        """
        parent = parent_event_id.strip()
        child = child_event_id.strip()
        normalized_source = source.strip()

        if not parent or not child:
            raise ValueError("parent_event_id and child_event_id are required")
        if parent == child:
            raise ValueError("provenance self-edges are not allowed")
        if not normalized_source:
            raise ValueError("source must not be blank")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

        async with self._database.transaction(immediate=True) as session:
            parent_record = await session.get(
                EventObservationRecord,
                parent,
            )
            child_record = await session.get(
                EventObservationRecord,
                child,
            )

            if parent_record is None:
                raise KeyError(f"unknown parent event: {parent}")
            if child_record is None:
                raise KeyError(f"unknown child event: {child}")

            if relation.is_causal and await self._would_create_cycle(
                session,
                parent_event_id=parent,
                child_event_id=child,
            ):
                raise ValueError(
                    "causal provenance edge would create a lineage cycle: "
                    f"{parent} -> {child}"
                )

            existing = await session.scalar(
                select(ProvenanceEdgeRecord).where(
                    ProvenanceEdgeRecord.parent_event_id == parent,
                    ProvenanceEdgeRecord.child_event_id == child,
                    ProvenanceEdgeRecord.relation_type == relation.value,
                    ProvenanceEdgeRecord.source == normalized_source,
                )
            )

            if existing is None:
                record = ProvenanceEdgeRecord(
                    parent_event_id=parent,
                    child_event_id=child,
                    relation_type=relation.value,
                    source=normalized_source,
                    confidence=confidence,
                    metadata_json=dict(metadata or {}),
                )
                session.add(record)
                await session.flush()
            else:
                record = existing
                record.confidence = max(
                    record.confidence,
                    confidence,
                )
                merged = dict(record.metadata_json)
                merged.update(metadata or {})
                record.metadata_json = merged

            if (
                set_primary_parent_if_empty
                and child_record.parent_event_id is None
            ):
                child_record.parent_event_id = parent

            return _provenance_edge_from_record(record)

    async def capture_primary_parent(
        self,
        child_event_id: str,
        *,
        relation: ProvenanceRelation = ProvenanceRelation.DISCOVERED_FROM,
        source: str = "event.parent_event_id",
    ) -> ProvenanceEdge | None:
        """Materialize an Event.parent_event_id as an explicit edge."""
        async with self._database.session() as session:
            child = await session.get(
                EventObservationRecord,
                child_event_id,
            )
            if child is None:
                raise KeyError(f"unknown child event: {child_event_id}")
            parent_event_id = child.parent_event_id

        if parent_event_id is None:
            return None

        return await self.add_edge(
            parent_event_id=parent_event_id,
            child_event_id=child_event_id,
            relation=relation,
            source=source,
            set_primary_parent_if_empty=False,
        )

    async def add_asset_relationship(
        self,
        *,
        source_event_id: str,
        target_event_id: str,
        relation_type: AssetRelationType | str,
        confidence: float = 0.5,
        metadata: dict[str, Any] | None = None,
        seen_at: datetime | None = None,
    ) -> AssetRelationship:
        """Create/merge a canonical asset relationship from two observations."""
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")

        relation_value = (
            relation_type.value
            if isinstance(relation_type, AssetRelationType)
            else relation_type.strip()
        )
        if not relation_value:
            raise ValueError("relation_type must not be blank")

        timestamp = seen_at or utc_now()
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("seen_at must be timezone-aware")

        async with self._database.transaction(immediate=True) as session:
            source_event = await session.get(
                EventObservationRecord,
                source_event_id,
            )
            target_event = await session.get(
                EventObservationRecord,
                target_event_id,
            )

            if source_event is None:
                raise KeyError(f"unknown source event: {source_event_id}")
            if target_event is None:
                raise KeyError(f"unknown target event: {target_event_id}")

            if source_event.asset_id == target_event.asset_id:
                raise ValueError(
                    "asset relationship requires two distinct canonical assets; "
                    "use a provenance edge for observations of the same asset"
                )

            record = await session.scalar(
                select(RelationshipRecord).where(
                    RelationshipRecord.source_asset_id
                    == source_event.asset_id,
                    RelationshipRecord.target_asset_id
                    == target_event.asset_id,
                    RelationshipRecord.relation_type
                    == relation_value,
                )
            )

            if record is None:
                record = RelationshipRecord(
                    source_asset_id=source_event.asset_id,
                    target_asset_id=target_event.asset_id,
                    relation_type=relation_value,
                    first_source_event_id=source_event_id,
                    confidence=confidence,
                    first_seen=timestamp,
                    last_seen=timestamp,
                    metadata_json=dict(metadata or {}),
                )
                session.add(record)
                await session.flush()
            else:
                record.confidence = max(
                    record.confidence,
                    confidence,
                )
                record.first_seen = min(
                    record.first_seen,
                    timestamp,
                )
                record.last_seen = max(
                    record.last_seen,
                    timestamp,
                )

                merged = dict(record.metadata_json)
                merged.update(metadata or {})
                record.metadata_json = merged

            return _asset_relationship_from_record(record)

    async def add_evidence(
        self,
        *,
        kind: EvidenceKind,
        source: str,
        asset_id: str | None = None,
        event_id: str | None = None,
        relationship_id: str | None = None,
        locator: str | None = None,
        content_hash: str | None = None,
        summary: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> EvidencePointer:
        """Attach an idempotent safe evidence pointer to graph entities."""
        normalized_source = source.strip()
        if not normalized_source:
            raise ValueError("source must not be blank")

        if not any((asset_id, event_id, relationship_id)):
            raise ValueError(
                "evidence requires asset_id, event_id, or relationship_id"
            )

        normalized_locator = (
            locator.strip() if locator is not None else None
        ) or None
        normalized_hash = (
            content_hash.strip() if content_hash is not None else None
        ) or None
        normalized_summary = (
            summary.strip() if summary is not None else None
        ) or None

        async with self._database.transaction(immediate=True) as session:
            await self._validate_evidence_subjects(
                session,
                asset_id=asset_id,
                event_id=event_id,
                relationship_id=relationship_id,
            )

            conditions = [
                EvidenceRecord.kind == kind.value,
                EvidenceRecord.source == normalized_source,
            ]

            conditions.extend(
                (
                    EvidenceRecord.asset_id.is_(None)
                    if asset_id is None
                    else EvidenceRecord.asset_id == asset_id,
                    EvidenceRecord.event_id.is_(None)
                    if event_id is None
                    else EvidenceRecord.event_id == event_id,
                    EvidenceRecord.relationship_id.is_(None)
                    if relationship_id is None
                    else EvidenceRecord.relationship_id == relationship_id,
                    EvidenceRecord.locator.is_(None)
                    if normalized_locator is None
                    else EvidenceRecord.locator == normalized_locator,
                    EvidenceRecord.content_hash.is_(None)
                    if normalized_hash is None
                    else EvidenceRecord.content_hash == normalized_hash,
                )
            )

            existing = await session.scalar(
                select(EvidenceRecord).where(and_(*conditions))
            )

            if existing is None:
                record = EvidenceRecord(
                    asset_id=asset_id,
                    event_id=event_id,
                    relationship_id=relationship_id,
                    kind=kind.value,
                    source=normalized_source,
                    locator=normalized_locator,
                    content_hash=normalized_hash,
                    summary=normalized_summary,
                    metadata_json=dict(metadata or {}),
                )
                session.add(record)
                await session.flush()
            else:
                record = existing
                if normalized_summary is not None:
                    record.summary = normalized_summary
                merged = dict(record.metadata_json)
                merged.update(metadata or {})
                record.metadata_json = merged

            return _evidence_pointer_from_record(record)

    async def ancestors(
        self,
        event_id: str,
        *,
        max_depth: int = 8,
    ) -> ProvenanceTrace:
        """Return a bounded backward lineage graph."""
        return await self._trace(
            event_id,
            direction="ANCESTORS",
            max_depth=max_depth,
        )

    async def descendants(
        self,
        event_id: str,
        *,
        max_depth: int = 8,
    ) -> ProvenanceTrace:
        """Return a bounded forward lineage graph."""
        return await self._trace(
            event_id,
            direction="DESCENDANTS",
            max_depth=max_depth,
        )

    async def shortest_path(
        self,
        *,
        start_event_id: str,
        end_event_id: str,
        max_depth: int = 16,
    ) -> ProvenancePath | None:
        """Return the shortest forward provenance path between observations."""
        if max_depth < 0:
            raise ValueError("max_depth cannot be negative")

        if start_event_id == end_event_id:
            async with self._database.session() as session:
                node = await self._load_node(
                    session,
                    start_event_id,
                    depth=0,
                )
                if node is None:
                    raise KeyError(
                        f"unknown event: {start_event_id}"
                    )
                return ProvenancePath(
                    start_event_id=start_event_id,
                    end_event_id=end_event_id,
                    nodes=(node,),
                    edges=(),
                )

        async with self._database.session() as session:
            if await session.get(
                EventObservationRecord,
                start_event_id,
            ) is None:
                raise KeyError(
                    f"unknown start event: {start_event_id}"
                )
            if await session.get(
                EventObservationRecord,
                end_event_id,
            ) is None:
                raise KeyError(
                    f"unknown end event: {end_event_id}"
                )

            queue: deque[tuple[str, int]] = deque(
                [(start_event_id, 0)]
            )
            visited = {start_event_id}
            previous: dict[
                str,
                tuple[str, LineageEdge],
            ] = {}

            found = False

            while queue and not found:
                current, depth = queue.popleft()
                if depth >= max_depth:
                    continue

                outgoing = await self._outgoing_edges(
                    session,
                    {current},
                )

                for edge in outgoing:
                    child = edge.child_event_id
                    if child in visited:
                        continue

                    visited.add(child)
                    previous[child] = (current, edge)

                    if child == end_event_id:
                        found = True
                        break

                    queue.append((child, depth + 1))

            if not found:
                return None

            event_ids = [end_event_id]
            edges_reversed: list[LineageEdge] = []

            cursor = end_event_id
            while cursor != start_event_id:
                parent, edge = previous[cursor]
                edges_reversed.append(edge)
                event_ids.append(parent)
                cursor = parent

            event_ids.reverse()
            edges = tuple(reversed(edges_reversed))

            nodes: list[LineageNode] = []
            for depth, current_event_id in enumerate(event_ids):
                node = await self._load_node(
                    session,
                    current_event_id,
                    depth=depth,
                )
                if node is None:
                    raise RuntimeError(
                        "provenance path references missing observation"
                    )
                nodes.append(node)

            return ProvenancePath(
                start_event_id=start_event_id,
                end_event_id=end_event_id,
                nodes=tuple(nodes),
                edges=edges,
            )

    async def direct_parent_sources(
        self,
        event_id: str,
    ) -> frozenset[str]:
        """Return independent direct parent observation sources.

        This is intentionally simple but useful for future confidence and
        vocabulary models: a token independently extracted from JavaScript,
        archives, and an APK has stronger evidence diversity than 100 repeats
        from one bundle.
        """
        async with self._database.session() as session:
            if await session.get(
                EventObservationRecord,
                event_id,
            ) is None:
                raise KeyError(f"unknown event: {event_id}")

            incoming = await self._incoming_edges(
                session,
                {event_id},
            )
            parent_ids = {
                edge.parent_event_id
                for edge in incoming
            }

            if not parent_ids:
                return frozenset()

            rows = list(
                (
                    await session.scalars(
                        select(EventObservationRecord).where(
                            EventObservationRecord.event_id.in_(
                                parent_ids
                            )
                        )
                    )
                ).all()
            )
            return frozenset(row.source for row in rows)

    async def _trace(
        self,
        event_id: str,
        *,
        direction: str,
        max_depth: int,
    ) -> ProvenanceTrace:
        if max_depth < 0:
            raise ValueError("max_depth cannot be negative")

        async with self._database.session() as session:
            focus = await self._load_node(
                session,
                event_id,
                depth=0,
            )
            if focus is None:
                raise KeyError(f"unknown event: {event_id}")

            nodes: dict[str, LineageNode] = {
                event_id: focus,
            }
            edges: dict[str, LineageEdge] = {}

            frontier = {event_id}
            visited = {event_id}

            for depth in range(1, max_depth + 1):
                if not frontier:
                    break

                if direction == "ANCESTORS":
                    level_edges = await self._incoming_edges(
                        session,
                        frontier,
                    )
                    next_ids = {
                        edge.parent_event_id
                        for edge in level_edges
                        if edge.parent_event_id not in visited
                    }
                elif direction == "DESCENDANTS":
                    level_edges = await self._outgoing_edges(
                        session,
                        frontier,
                    )
                    next_ids = {
                        edge.child_event_id
                        for edge in level_edges
                        if edge.child_event_id not in visited
                    }
                else:
                    raise ValueError(
                        f"unsupported trace direction: {direction}"
                    )

                for edge in level_edges:
                    edges[_lineage_edge_identity(edge)] = edge

                if not next_ids:
                    break

                records = list(
                    (
                        await session.scalars(
                            select(EventObservationRecord).where(
                                EventObservationRecord.event_id.in_(
                                    next_ids
                                )
                            )
                        )
                    ).all()
                )

                for record in records:
                    nodes[record.event_id] = _lineage_node_from_record(
                        record,
                        depth=depth,
                    )

                visited.update(next_ids)
                frontier = next_ids

            ordered_nodes = tuple(
                sorted(
                    nodes.values(),
                    key=lambda node: (
                        node.depth_from_focus,
                        node.first_seen,
                        node.event_id,
                    ),
                )
            )
            ordered_edges = tuple(
                sorted(
                    edges.values(),
                    key=lambda edge: (
                        edge.parent_event_id,
                        edge.child_event_id,
                        edge.relation.value,
                        edge.source,
                    ),
                )
            )

            return ProvenanceTrace(
                focus_event_id=event_id,
                direction=direction,
                max_depth=max_depth,
                nodes=ordered_nodes,
                edges=ordered_edges,
            )

    async def _incoming_edges(
        self,
        session: AsyncSession,
        child_ids: set[str],
    ) -> tuple[LineageEdge, ...]:
        explicit = list(
            (
                await session.scalars(
                    select(ProvenanceEdgeRecord).where(
                        ProvenanceEdgeRecord.child_event_id.in_(
                            child_ids
                        )
                    )
                )
            ).all()
        )

        result = {
            (
                row.parent_event_id,
                row.child_event_id,
                row.relation_type,
                row.source,
            ): _lineage_edge_from_record(row)
            for row in explicit
        }

        explicit_pairs = {
            (row.parent_event_id, row.child_event_id)
            for row in explicit
        }

        children = list(
            (
                await session.scalars(
                    select(EventObservationRecord).where(
                        EventObservationRecord.event_id.in_(child_ids),
                        EventObservationRecord.parent_event_id.is_not(
                            None
                        ),
                    )
                )
            ).all()
        )

        for child in children:
            parent = child.parent_event_id
            if parent is None:
                continue
            if (parent, child.event_id) in explicit_pairs:
                continue

            edge = _implicit_primary_edge(
                parent_event_id=parent,
                child_event_id=child.event_id,
            )
            result[
                (
                    edge.parent_event_id,
                    edge.child_event_id,
                    edge.relation.value,
                    edge.source,
                )
            ] = edge

        return tuple(result.values())

    async def _outgoing_edges(
        self,
        session: AsyncSession,
        parent_ids: set[str],
    ) -> tuple[LineageEdge, ...]:
        explicit = list(
            (
                await session.scalars(
                    select(ProvenanceEdgeRecord).where(
                        ProvenanceEdgeRecord.parent_event_id.in_(
                            parent_ids
                        )
                    )
                )
            ).all()
        )

        result = {
            (
                row.parent_event_id,
                row.child_event_id,
                row.relation_type,
                row.source,
            ): _lineage_edge_from_record(row)
            for row in explicit
        }

        explicit_pairs = {
            (row.parent_event_id, row.child_event_id)
            for row in explicit
        }

        children = list(
            (
                await session.scalars(
                    select(EventObservationRecord).where(
                        EventObservationRecord.parent_event_id.in_(
                            parent_ids
                        )
                    )
                )
            ).all()
        )

        for child in children:
            parent = child.parent_event_id
            if parent is None:
                continue
            if (parent, child.event_id) in explicit_pairs:
                continue

            edge = _implicit_primary_edge(
                parent_event_id=parent,
                child_event_id=child.event_id,
            )
            result[
                (
                    edge.parent_event_id,
                    edge.child_event_id,
                    edge.relation.value,
                    edge.source,
                )
            ] = edge

        return tuple(result.values())

    async def _would_create_cycle(
        self,
        session: AsyncSession,
        *,
        parent_event_id: str,
        child_event_id: str,
    ) -> bool:
        """Return whether parent->child would close a causal cycle."""
        # If child can already causally reach parent, adding parent->child
        # closes a cycle.
        frontier = {child_event_id}
        visited = {child_event_id}

        while frontier:
            rows = list(
                (
                    await session.scalars(
                        select(ProvenanceEdgeRecord).where(
                            ProvenanceEdgeRecord.parent_event_id.in_(
                                frontier
                            ),
                            ProvenanceEdgeRecord.relation_type.in_(
                                tuple(
                                    relation.value
                                    for relation in ProvenanceRelation
                                    if relation.is_causal
                                )
                            ),
                        )
                    )
                ).all()
            )

            next_ids = {
                row.child_event_id
                for row in rows
                if row.child_event_id not in visited
            }

            # Include primary-parent compatibility edges.
            implicit_children = list(
                (
                    await session.scalars(
                        select(EventObservationRecord).where(
                            EventObservationRecord.parent_event_id.in_(
                                frontier
                            )
                        )
                    )
                ).all()
            )
            next_ids.update(
                row.event_id
                for row in implicit_children
                if row.event_id not in visited
            )

            if parent_event_id in next_ids:
                return True

            visited.update(next_ids)
            frontier = next_ids

        return False

    @staticmethod
    async def _load_node(
        session: AsyncSession,
        event_id: str,
        *,
        depth: int,
    ) -> LineageNode | None:
        record = await session.get(
            EventObservationRecord,
            event_id,
        )
        if record is None:
            return None
        return _lineage_node_from_record(record, depth=depth)

    @staticmethod
    async def _validate_evidence_subjects(
        session: AsyncSession,
        *,
        asset_id: str | None,
        event_id: str | None,
        relationship_id: str | None,
    ) -> None:
        if (
            asset_id is not None
            and await session.get(AssetRecord, asset_id) is None
        ):
            raise KeyError(f"unknown asset: {asset_id}")

        if (
            event_id is not None
            and await session.get(
                EventObservationRecord,
                event_id,
            )
            is None
        ):
            raise KeyError(f"unknown event: {event_id}")

        if (
            relationship_id is not None
            and await session.get(
                RelationshipRecord,
                relationship_id,
            )
            is None
        ):
            raise KeyError(
                f"unknown relationship: {relationship_id}"
            )


def _provenance_edge_from_record(
    record: ProvenanceEdgeRecord,
) -> ProvenanceEdge:
    return ProvenanceEdge(
        edge_id=record.edge_id,
        parent_event_id=record.parent_event_id,
        child_event_id=record.child_event_id,
        relation=ProvenanceRelation(record.relation_type),
        source=record.source,
        confidence=record.confidence,
        created_at=record.created_at,
        metadata=dict(record.metadata_json),
    )


def _lineage_edge_from_record(
    record: ProvenanceEdgeRecord,
) -> LineageEdge:
    return LineageEdge(
        edge_id=record.edge_id,
        parent_event_id=record.parent_event_id,
        child_event_id=record.child_event_id,
        relation=ProvenanceRelation(record.relation_type),
        source=record.source,
        confidence=record.confidence,
        implicit_primary_parent=False,
    )


def _implicit_primary_edge(
    *,
    parent_event_id: str,
    child_event_id: str,
) -> LineageEdge:
    return LineageEdge(
        edge_id=f"primary:{parent_event_id}:{child_event_id}",
        parent_event_id=parent_event_id,
        child_event_id=child_event_id,
        relation=ProvenanceRelation.DISCOVERED_FROM,
        source="event.parent_event_id",
        confidence=1.0,
        implicit_primary_parent=True,
    )


def _lineage_node_from_record(
    record: EventObservationRecord,
    *,
    depth: int,
) -> LineageNode:
    return LineageNode(
        event_id=record.event_id,
        asset_id=record.asset_id,
        event_type=EventType(record.event_type),
        value=record.value,
        source=record.source,
        primary_parent_event_id=record.parent_event_id,
        depth_from_focus=depth,
        confidence=record.confidence,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        tags=tuple(sorted(record.tags_json)),
    )


def _asset_relationship_from_record(
    record: RelationshipRecord,
) -> AssetRelationship:
    return AssetRelationship(
        relationship_id=record.relationship_id,
        source_asset_id=record.source_asset_id,
        target_asset_id=record.target_asset_id,
        relation_type=record.relation_type,
        first_source_event_id=record.first_source_event_id,
        confidence=record.confidence,
        first_seen=record.first_seen,
        last_seen=record.last_seen,
        metadata=dict(record.metadata_json),
    )


def _evidence_pointer_from_record(
    record: EvidenceRecord,
) -> EvidencePointer:
    return EvidencePointer(
        evidence_id=record.evidence_id,
        asset_id=record.asset_id,
        event_id=record.event_id,
        relationship_id=record.relationship_id,
        kind=EvidenceKind(record.kind),
        source=record.source,
        locator=record.locator,
        content_hash=record.content_hash,
        summary=record.summary,
        created_at=record.created_at,
        metadata=dict(record.metadata_json),
    )


def _lineage_edge_identity(edge: LineageEdge) -> str:
    return "|".join(
        (
            edge.parent_event_id,
            edge.child_event_id,
            edge.relation.value,
            edge.source,
        )
    )
