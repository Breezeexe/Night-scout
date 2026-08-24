"""Offline, idempotent semantic relationship backfill for existing workspaces."""

from __future__ import annotations

import math

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from recon.core.events import Event, EventType, ScopeState
from recon.storage.database import Database, EventRepository
from recon.storage.models import EventObservationRecord, RelationshipRecord
from recon.storage.provenance import ProvenanceRepository
from recon.surface.projector import (
    SurfaceRelationshipProjector,
    dns_owner_candidates,
    relationship_candidates,
)


class SurfaceRebuildReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    dry_run: bool
    observations: int = Field(ge=0)
    candidates: int = Field(ge=0)
    edges_created: int = Field(ge=0)
    edges_merged: int = Field(ge=0)
    skipped: int = Field(ge=0)
    batch_size: int = Field(ge=1)
    batches: int = Field(ge=0)
    warnings: tuple[str, ...] = ()


class SurfaceGraphRebuilder:
    def __init__(self, database: Database) -> None:
        self._database = database
        self._events = EventRepository(database)
        self._projector = SurfaceRelationshipProjector(
            events=self._events,
            provenance=ProvenanceRepository(database),
        )

    async def rebuild(
        self,
        *,
        dry_run: bool = False,
        batch_size: int = 500,
    ) -> SurfaceRebuildReport:
        if batch_size < 1 or batch_size > 10_000:
            raise ValueError("batch_size must be between 1 and 10000")
        async with self._database.session() as session:
            records = list(
                (
                    await session.scalars(
                        select(EventObservationRecord).order_by(
                            EventObservationRecord.first_seen,
                            EventObservationRecord.event_id,
                        )
                    )
                ).all()
            )
            existing_ids = set(
                (await session.scalars(select(RelationshipRecord.relationship_id))).all()
            )
        events = {record.event_id: _event_from_record(record) for record in records}
        candidates = 0
        skipped = 0
        warnings: list[str] = []
        created = 0
        merged = 0

        ordered_events = list(events.values())
        for offset in range(0, len(ordered_events), batch_size):
            batch = ordered_events[offset : offset + batch_size]
            for event in batch:
                parent = events.get(event.parent_event_id or "")
                if parent is not None:
                    candidates += len(relationship_candidates(parent, event))
                    if parent.type is EventType.DNS_RECORD:
                        grandparent = events.get(parent.parent_event_id or "")
                        if grandparent is not None:
                            candidates += len(dns_owner_candidates(grandparent, parent, event))
                if dry_run:
                    if parent is None:
                        skipped += 1
                    continue
                report = await self._projector.project(event)
                skipped += report.skipped
                warnings.extend(report.warnings)
                for relationship_id in report.relationship_ids:
                    if relationship_id in existing_ids:
                        merged += 1
                    else:
                        existing_ids.add(relationship_id)
                        created += 1

        return SurfaceRebuildReport(
            dry_run=dry_run,
            observations=len(records),
            candidates=candidates,
            edges_created=created,
            edges_merged=merged,
            skipped=skipped,
            batch_size=batch_size,
            batches=math.ceil(len(records) / batch_size),
            warnings=tuple(warnings),
        )


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
