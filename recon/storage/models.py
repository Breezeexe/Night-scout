"""SQLAlchemy persistence models for Night Scout.

The SQLite database is the durable source of truth for a single target
workspace. Core/policy modules remain storage-agnostic; conversion between
Pydantic domain objects and these ORM records belongs in storage/database.py.

A deliberate distinction is made between:

    AssetRecord
        One canonical deduplicated asset in the target knowledge graph.

    EventObservationRecord
        One observation of an asset, preserving source/provenance.

For example, if the same hostname is discovered independently by passive DNS,
a certificate SAN, JavaScript, and an archive, Night Scout keeps one AssetRecord
but four EventObservationRecord rows.

This prevents deduplication from destroying evidence diversity.

The schema also persists:
    - graph relationships and evidence,
    - recon runs and branches,
    - task queue state,
    - scheduler/policy decisions for explainability,
    - human-review cases,
    - surface snapshots and differential changes,
    - raw yield observations,
    - branch convergence state,
    - Target Genome snapshots,
    - budget reservations,
    - shared rate-limit state.

Vocabulary/confidence/novelty remain derivable from durable Events, provenance
and snapshots; raw credentials stay outside this general-purpose schema.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.ext.mutable import MutableDict, MutableList
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy.types import TypeDecorator


def utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware datetime."""
    return datetime.now(timezone.utc)


def _new_id(prefix: str) -> str:
    """Create a compact prefixed identifier for persistence-only entities."""
    return f"{prefix}_{uuid4().hex}"


NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class UTCDateTime(TypeDecorator[datetime]):
    """Store timezone-aware datetimes as canonical UTC ISO-8601 strings.

    SQLite's native DateTime handling does not reliably preserve timezone
    information. Night Scout's domain models require aware timestamps, so this
    type performs an explicit round-trip instead of relying on SQLite affinity.
    """

    impl = String(40)
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime | None,
        dialect: Dialect,
    ) -> str | None:
        del dialect

        if value is None:
            return None

        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Night Scout timestamps must be timezone-aware")

        return value.astimezone(timezone.utc).isoformat(timespec="microseconds")

    def process_result_value(
        self,
        value: str | None,
        dialect: Dialect,
    ) -> datetime | None:
        del dialect

        if value is None:
            return None

        parsed = datetime.fromisoformat(value)

        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError(
                "database contained a timezone-naive Night Scout timestamp"
            )

        return parsed.astimezone(timezone.utc)


class Base(DeclarativeBase):
    """Declarative base shared by all Night Scout ORM models."""

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


class ReconRunRecord(Base):
    """One reconnaissance execution/session inside a target workspace."""

    __tablename__ = "recon_runs"

    run_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("run"),
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="RUNNING",
        index=True,
    )

    started_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )

    config_hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        CheckConstraint(
            "finished_at IS NULL OR status != 'RUNNING'",
            name="finished_run_not_running",
        ),
    )


class AssetRecord(Base):
    """Canonical deduplicated asset in the target knowledge graph."""

    __tablename__ = "assets"

    asset_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("ast"),
    )

    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    # Produced from the normalized domain identity, normally:
    #     f"{event_type}:{canonical_value}"
    identity_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    last_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    scope_state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="UNKNOWN",
        index=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    novelty: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    min_depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    tags_json: Mapped[list[str]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "identity_key",
            name="asset_identity",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="asset_confidence_range",
        ),
        CheckConstraint(
            "novelty >= 0.0 AND novelty <= 1.0",
            name="asset_novelty_range",
        ),
        CheckConstraint(
            "min_depth >= 0",
            name="asset_min_depth_nonnegative",
        ),
        Index(
            "ix_assets_type_value",
            "event_type",
            "value",
        ),
        Index(
            "ix_assets_last_seen",
            "last_seen",
        ),
    )


class EventObservationRecord(Base):
    """One provenance-preserving observation of a canonical asset."""

    __tablename__ = "event_observations"

    event_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
    )

    asset_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    run_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("recon_runs.run_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    event_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    value: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    source: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    parent_event_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey(
            "event_observations.event_id",
            ondelete="SET NULL",
        ),
        nullable=True,
        index=True,
    )

    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    last_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    scope_state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="UNKNOWN",
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    novelty: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    tags_json: Mapped[list[str]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="event_confidence_range",
        ),
        CheckConstraint(
            "novelty >= 0.0 AND novelty <= 1.0",
            name="event_novelty_range",
        ),
        CheckConstraint(
            "depth >= 0",
            name="event_depth_nonnegative",
        ),
        Index(
            "ix_event_observations_asset_source",
            "asset_id",
            "source",
        ),
        Index(
            "ix_event_observations_run_type",
            "run_id",
            "event_type",
        ),
    )


class ProvenanceEdgeRecord(Base):
    """Directed observation-to-observation provenance edge."""

    __tablename__ = "provenance_edges"

    edge_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("prv"),
    )
    parent_event_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("event_observations.event_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    child_event_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("event_observations.event_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    relation_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=1.0,
    )
    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "parent_event_id",
            "child_event_id",
            "relation_type",
            "source",
            name="provenance_edge_identity",
        ),
        CheckConstraint(
            "parent_event_id != child_event_id",
            name="provenance_no_self_edge",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="provenance_confidence_range",
        ),
        Index(
            "ix_provenance_parent_created",
            "parent_event_id",
            "created_at",
        ),
        Index(
            "ix_provenance_child_created",
            "child_event_id",
            "created_at",
        ),
    )


class RelationshipRecord(Base):
    """Canonical directed edge between two assets."""

    __tablename__ = "asset_relationships"

    relationship_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("rel"),
    )

    source_asset_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    target_asset_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    relation_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )

    first_source_event_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey(
            "event_observations.event_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    first_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    last_seen: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "source_asset_id",
            "target_asset_id",
            "relation_type",
            name="asset_relationship_identity",
        ),
        CheckConstraint(
            "source_asset_id != target_asset_id",
            name="relationship_no_self_edge",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="relationship_confidence_range",
        ),
    )


class EvidenceRecord(Base):
    """One safe provenance/evidence pointer.

    Raw credential/private-data values should not be stored in `summary`.
    Sensitive bytes belong in a future evidence store with stricter handling;
    this table keeps fingerprints, locators, and redacted explanations.
    """

    __tablename__ = "evidence"

    evidence_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("evd"),
    )

    asset_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    event_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey(
            "event_observations.event_id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )
    relationship_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey(
            "asset_relationships.relationship_id",
            ondelete="CASCADE",
        ),
        nullable=True,
        index=True,
    )

    kind: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    source: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )

    locator: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )
    content_hash: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )
    summary: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        CheckConstraint(
            """
            asset_id IS NOT NULL
            OR event_id IS NOT NULL
            OR relationship_id IS NOT NULL
            """,
            name="evidence_has_subject",
        ),
    )


class BranchRecord(Base):
    """Persistent recursive-recon branch used by budgets/convergence."""

    __tablename__ = "branches"

    branch_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("brn"),
    )

    # Origin run only. A persistent branch may be resumed by later runs.
    run_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("recon_runs.run_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    parent_branch_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("branches.branch_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    root_event_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey(
            "event_observations.event_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="OPEN",
        index=True,
    )
    depth: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    soft_budget_multiplier: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=1.0,
    )

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )

    stats_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        CheckConstraint(
            "depth >= 0",
            name="branch_depth_nonnegative",
        ),
        CheckConstraint(
            "soft_budget_multiplier >= 1.0",
            name="branch_budget_multiplier_minimum",
        ),
    )


class TaskRecord(Base):
    """Durable task queue row compatible with core.queue.Task."""

    __tablename__ = "tasks"

    task_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
    )

    # Run that originally created this frontier item.
    run_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("recon_runs.run_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Most recent run that actually dispatched/claimed the item. Keeping this
    # separate prevents persistent-frontier resume from rewriting provenance.
    execution_run_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("recon_runs.run_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    worker: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    input_event_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey(
            "event_observations.event_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    branch_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("branches.branch_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    route_rule_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
    )
    routing_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    status: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="PENDING",
        index=True,
    )
    priority: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )

    attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )
    max_attempts: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=3,
    )

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    available_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    started_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    lease_expires_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )
    claim_token: Mapped[str | None] = mapped_column(
        String(64),
        nullable=True,
    )

    last_error: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    dedupe_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            "attempts >= 0",
            name="task_attempts_nonnegative",
        ),
        CheckConstraint(
            "max_attempts >= 1",
            name="task_max_attempts_positive",
        ),
        CheckConstraint(
            "attempts <= max_attempts",
            name="task_attempts_within_budget",
        ),
        CheckConstraint(
            "(status = 'RUNNING' AND claim_token IS NOT NULL) OR "
            "(status != 'RUNNING' AND claim_token IS NULL)",
            name="task_claim_token_matches_status",
        ),
        Index(
            "ix_tasks_ready",
            "status",
            "available_at",
            "priority",
        ),
        # Database-level protection against two active copies of the same
        # logical task. Terminal history does not block later re-scheduling.
        Index(
            "uq_tasks_active_dedupe",
            "dedupe_key",
            unique=True,
            sqlite_where=text(
                "status IN ('PENDING', 'RUNNING', 'DEFERRED', 'REVIEW')"
            ),
        ),
    )


class SchedulerDecisionRecord(Base):
    """Persisted scheduler scoring decision for explainability."""

    __tablename__ = "scheduler_decisions"

    decision_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("sch"),
    )

    task_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    evaluated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )

    score: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    selected: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
    )

    breakdown_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )
    signals_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )


class PolicyDecisionRecord(Base):
    """Generic append-only policy/scope/review decision log."""

    __tablename__ = "policy_decisions"

    decision_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("pol"),
    )

    task_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    gate: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )

    details_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        Index(
            "ix_policy_decisions_task_gate",
            "task_id",
            "gate",
            "created_at",
        ),
    )


class ReviewCaseRecord(Base):
    """Durable human-review queue case."""

    __tablename__ = "review_cases"

    case_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
    )

    task_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    worker: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    input_event_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey(
            "event_observations.event_id",
            ondelete="RESTRICT",
        ),
        nullable=False,
        index=True,
    )

    state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        default="OPEN",
        index=True,
    )

    # Hash of task + sorted signal fingerprints.
    dedupe_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    opened_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    resolved_at: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
    )

    resolution_reason: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
    )

    __table_args__ = (
        Index(
            "uq_review_cases_open_dedupe",
            "dedupe_key",
            unique=True,
            sqlite_where=text("state = 'OPEN'"),
        ),
    )


class ReviewSignalRecord(Base):
    """Redacted signal attached to one review case."""

    __tablename__ = "review_signals"

    signal_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("rsg"),
    )

    case_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("review_cases.case_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    category: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    severity: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    confidence: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    summary: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    source_event_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey(
            "event_observations.event_id",
            ondelete="SET NULL",
        ),
        nullable=True,
    )

    evidence_fingerprint: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )

    tags_json: Mapped[list[str]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )

    __table_args__ = (
        UniqueConstraint(
            "case_id",
            "evidence_fingerprint",
            name="review_case_signal_fingerprint",
        ),
        CheckConstraint(
            "confidence >= 0.0 AND confidence <= 1.0",
            name="review_signal_confidence_range",
        ),
    )


class SurfaceSnapshotRecord(Base):
    """One normalized surface-state observation for an asset in a recon run."""

    __tablename__ = "surface_snapshots"

    snapshot_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("snp"),
    )
    run_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("recon_runs.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    snapshot_kind: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    observed_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )
    present: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=True,
    )
    state_hash: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    state_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "asset_id",
            "snapshot_kind",
            name="surface_snapshot_run_asset_kind",
        ),
        Index(
            "ix_surface_snapshots_asset_kind_time",
            "asset_id",
            "snapshot_kind",
            "observed_at",
        ),
    )


class SnapshotChangeRecord(Base):
    """One persisted differential-recon change."""

    __tablename__ = "snapshot_changes"

    change_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("chg"),
    )
    run_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("recon_runs.run_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    asset_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    previous_snapshot_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("surface_snapshots.snapshot_id", ondelete="SET NULL"),
        nullable=True,
    )
    current_snapshot_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("surface_snapshots.snapshot_id", ondelete="SET NULL"),
        nullable=True,
    )
    change_type: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
        index=True,
    )
    change_key: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    detected_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )
    before_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )
    after_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )
    details_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "run_id",
            "change_key",
            name="snapshot_change_run_key",
        ),
        Index(
            "ix_snapshot_changes_asset_time",
            "asset_id",
            "detected_at",
        ),
    )


class YieldObservationRecord(Base):
    """Durable raw discovery-yield observation.

    The indexed scalar columns support scheduler/convergence queries while the
    JSON credit payloads preserve exact per-token and per-pattern attribution.
    Raw credentials must never be stored here.
    """

    __tablename__ = "yield_observations"

    observation_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
    )
    observed_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )

    run_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("recon_runs.run_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    task_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("tasks.task_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    input_event_id: Mapped[str | None] = mapped_column(
        String(40),
        ForeignKey("event_observations.event_id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    target_key: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        index=True,
    )
    branch_id: Mapped[str | None] = mapped_column(
        String(128),
        nullable=True,
        index=True,
    )

    worker: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    action: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    route_rule_id: Mapped[str | None] = mapped_column(
        String(160),
        nullable=True,
        index=True,
    )
    input_source: Mapped[str | None] = mapped_column(
        String(160),
        nullable=True,
        index=True,
    )

    execution_outcome: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    attempted_units: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    successful_hits: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    new_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    novel_assets: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_domains: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_urls: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_endpoints: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_vocabulary_tokens: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    new_patterns: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    request_count: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    runtime_seconds: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    cost_units: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    source_ids_json: Mapped[list[str]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )
    token_credits_json: Mapped[list[dict[str, Any]]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )
    pattern_credits_json: Mapped[list[dict[str, Any]]] = mapped_column(
        MutableList.as_mutable(JSON),
        nullable=False,
        default=list,
    )
    metadata_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        CheckConstraint("attempted_units >= 0", name="yield_attempted_nonnegative"),
        CheckConstraint("successful_hits >= 0", name="yield_hits_nonnegative"),
        CheckConstraint(
            "successful_hits <= attempted_units",
            name="yield_hits_not_over_attempts",
        ),
        CheckConstraint("new_assets >= 0", name="yield_assets_nonnegative"),
        CheckConstraint("novel_assets >= 0", name="yield_novel_assets_nonnegative"),
        CheckConstraint(
            "novel_assets <= new_assets",
            name="yield_novel_not_over_new",
        ),
        CheckConstraint("request_count >= 0.0", name="yield_requests_nonnegative"),
        CheckConstraint("runtime_seconds >= 0.0", name="yield_runtime_nonnegative"),
        CheckConstraint("cost_units > 0.0", name="yield_cost_positive"),
        Index(
            "ix_yield_target_worker_action_time",
            "target_key",
            "worker",
            "action",
            "observed_at",
        ),
        Index(
            "ix_yield_target_branch_time",
            "target_key",
            "branch_id",
            "observed_at",
        ),
    )


class ConvergenceStateRecord(Base):
    """Latest persistent convergence controller state per branch/lane."""

    __tablename__ = "convergence_states"

    state_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("cvg"),
    )

    # Empty string represents domain-model target_key=None so the SQL UNIQUE
    # constraint remains effective (SQLite permits multiple NULL values).
    target_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="",
    )
    branch_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    lane: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    tier: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )
    closed: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        default=False,
        index=True,
    )
    cooldown_until: Mapped[datetime | None] = mapped_column(
        UTCDateTime(),
        nullable=True,
        index=True,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
        index=True,
    )

    state_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "target_key",
            "branch_id",
            "lane",
            name="convergence_state_identity",
        ),
        Index(
            "ix_convergence_target_closed_updated",
            "target_key",
            "closed",
            "updated_at",
        ),
    )


class TargetGenomeSnapshotRecord(Base):
    """Versioned semantic Target Genome snapshot.

    Identical semantic fingerprints for one target are coalesced by the store;
    a changed fingerprint creates a new durable snapshot.
    """

    __tablename__ = "target_genome_snapshots"

    genome_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("gnm"),
    )
    target_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        index=True,
    )
    genome_version: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
    )
    generated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        index=True,
    )
    fingerprint: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
        index=True,
    )
    genome_json: Mapped[dict[str, Any]] = mapped_column(
        MutableDict.as_mutable(JSON),
        nullable=False,
        default=dict,
    )

    __table_args__ = (
        UniqueConstraint(
            "target_key",
            "fingerprint",
            name="target_genome_target_fingerprint",
        ),
        CheckConstraint(
            "genome_version >= 1",
            name="target_genome_version_positive",
        ),
        Index(
            "ix_target_genome_latest",
            "target_key",
            "generated_at",
        ),
    )


class BudgetReservationRecord(Base):
    """Durable budget reservation lease."""

    __tablename__ = "budget_reservations"

    reservation_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
    )

    task_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        index=True,
    )


class BudgetReservationItemRecord(Base):
    """One bucket/metric amount held by a budget reservation."""

    __tablename__ = "budget_reservation_items"

    item_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("bgi"),
    )

    reservation_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey(
            "budget_reservations.reservation_id",
            ondelete="CASCADE",
        ),
        nullable=False,
        index=True,
    )

    bucket_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    metric: Mapped[str] = mapped_column(
        String(64),
        nullable=False,
    )

    # Nullable for compatibility with early schema/domain versions; new code
    # should persist SOFT/HARD explicitly.
    budget_class: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
    )

    amount: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )

    __table_args__ = (
        CheckConstraint(
            "amount > 0.0",
            name="budget_item_amount_positive",
        ),
        UniqueConstraint(
            "reservation_id",
            "bucket_key",
            "metric",
            "budget_class",
            name="budget_reservation_bucket_metric",
        ),
    )


class BudgetUsageRecord(Base):
    """Persistent committed/reserved usage for one budget bucket."""

    __tablename__ = "budget_usage"

    bucket_key: Mapped[str] = mapped_column(
        Text,
        primary_key=True,
    )
    budget_class: Mapped[str] = mapped_column(
        String(16),
        primary_key=True,
    )
    metric: Mapped[str] = mapped_column(
        String(64),
        primary_key=True,
    )
    committed: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    reserved: Mapped[float] = mapped_column(
        Float,
        nullable=False,
        default=0.0,
    )
    updated_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )

    __table_args__ = (
        CheckConstraint(
            "committed >= 0.0",
            name="budget_usage_committed_nonnegative",
        ),
        CheckConstraint(
            "reserved >= 0.0",
            name="budget_usage_reserved_nonnegative",
        ),
    )


class RateBucketRecord(Base):
    """Shared token-bucket/concurrency state."""

    __tablename__ = "rate_buckets"

    rule_id: Mapped[str] = mapped_column(
        String(128),
        primary_key=True,
    )
    bucket_key: Mapped[str] = mapped_column(
        Text,
        primary_key=True,
    )

    tokens: Mapped[float] = mapped_column(
        Float,
        nullable=False,
    )
    last_refill_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
    )
    active_concurrency: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    __table_args__ = (
        CheckConstraint(
            "tokens >= 0.0",
            name="rate_bucket_tokens_nonnegative",
        ),
        CheckConstraint(
            "active_concurrency >= 0",
            name="rate_bucket_concurrency_nonnegative",
        ),
    )


class RateLeaseRecord(Base):
    """Durable active-rate/concurrency lease."""

    __tablename__ = "rate_leases"

    lease_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
    )

    task_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("tasks.task_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    state: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
        index=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        default=utc_now,
    )
    expires_at: Mapped[datetime] = mapped_column(
        UTCDateTime(),
        nullable=False,
        index=True,
    )


class RateLeaseItemRecord(Base):
    """Concurrency amount held by a rate-limit lease in one bucket."""

    __tablename__ = "rate_lease_items"

    item_id: Mapped[str] = mapped_column(
        String(40),
        primary_key=True,
        default=lambda: _new_id("rli"),
    )

    lease_id: Mapped[str] = mapped_column(
        String(40),
        ForeignKey("rate_leases.lease_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    rule_id: Mapped[str] = mapped_column(
        String(128),
        nullable=False,
    )
    bucket_key: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )

    concurrency: Mapped[int] = mapped_column(
        Integer,
        nullable=False,
        default=0,
    )

    __table_args__ = (
        CheckConstraint(
            "concurrency >= 0",
            name="rate_lease_concurrency_nonnegative",
        ),
        UniqueConstraint(
            "lease_id",
            "rule_id",
            "bucket_key",
            name="rate_lease_bucket",
        ),
    )
