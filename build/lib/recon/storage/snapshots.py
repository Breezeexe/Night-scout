"""Differential attack-surface snapshots for Night Scout.

Snapshots answer:

    "What changed since the last confirmed observation?"

The design is deliberately conservative:

    missing snapshot row
        != disappeared asset

A disappearance is emitted only when a worker explicitly captures
`SurfaceState(present=False)`. This prevents partial coverage, worker failures,
or disabled modules from being interpreted as infrastructure removal.

Typical flow:

    run N
        -> capture normalized states

    run N+1
        -> capture normalized states
        -> compare each state with the previous confirmed state
        -> persist meaningful SurfaceChange objects

Examples:
    NEW_HOST
    NEW_URL
    NEW_ENDPOINT
    NEW_CERT_SAN
    IP_CHANGED
    STATUS_CHANGED
    TITLE_CHANGED
    BODY_HASH_CHANGED
    NEW_JAVASCRIPT
    RESURRECTED_HOST
    DISAPPEARED_HOST
    SCOPE_CHANGED

The snapshot layer does not assign vulnerability severity. It records changes;
future novelty/scheduler modules decide how interesting each change is.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator
from sqlalchemy import select

from recon.core.events import EventType, ScopeState
from recon.storage.database import Database
from recon.storage.models import (
    AssetRecord,
    ReconRunRecord,
    SnapshotChangeRecord,
    SurfaceSnapshotRecord,
)


def utc_now() -> datetime:
    """Return current UTC time."""
    return datetime.now(timezone.utc)


class SnapshotKind(StrEnum):
    """Logical normalized state families."""

    DNS = "DNS"
    HTTP = "HTTP"
    TLS = "TLS"
    JAVASCRIPT = "JAVASCRIPT"
    API = "API"
    ASSET = "ASSET"


class ChangeType(StrEnum):
    """Persisted differential-recon change vocabulary."""

    NEW_HOST = "NEW_HOST"
    NEW_URL = "NEW_URL"
    NEW_ENDPOINT = "NEW_ENDPOINT"
    NEW_CERT_SAN = "NEW_CERT_SAN"
    NEW_JAVASCRIPT = "NEW_JAVASCRIPT"
    NEW_ASSET = "NEW_ASSET"

    RESURRECTED_HOST = "RESURRECTED_HOST"
    REAPPEARED_ASSET = "REAPPEARED_ASSET"

    DISAPPEARED_HOST = "DISAPPEARED_HOST"
    DISAPPEARED_ASSET = "DISAPPEARED_ASSET"

    IP_CHANGED = "IP_CHANGED"
    STATUS_CHANGED = "STATUS_CHANGED"
    TITLE_CHANGED = "TITLE_CHANGED"
    BODY_HASH_CHANGED = "BODY_HASH_CHANGED"
    CERTIFICATE_CHANGED = "CERTIFICATE_CHANGED"
    SCOPE_CHANGED = "SCOPE_CHANGED"

    STATE_CHANGED = "STATE_CHANGED"


class SurfaceState(BaseModel):
    """Normalized cross-worker snapshot state.

    Workers populate only fields they can authoritatively observe. `extra`
    keeps tool-specific normalized facts without expanding the core schema for
    every technology.

    Collection-valued fields are canonicalized to sorted unique tuples so
    state hashes are deterministic.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    present: bool = True

    ips: tuple[str, ...] = ()

    status_code: int | None = Field(default=None, ge=100, le=599)
    title: str | None = None
    body_hash: str | None = None

    certificate_fingerprints: tuple[str, ...] = ()
    certificate_sans: tuple[str, ...] = ()

    javascript_hashes: tuple[str, ...] = ()
    endpoint_keys: tuple[str, ...] = ()

    scope_state: ScopeState | None = None

    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ips")
    @classmethod
    def normalize_ips(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        canonical = {
            str(ipaddress.ip_address(value.strip()))
            for value in values
            if value.strip()
        }
        return tuple(
            sorted(
                canonical,
                key=lambda value: (
                    ipaddress.ip_address(value).version,
                    int(ipaddress.ip_address(value)),
                ),
            )
        )

    @field_validator(
        "certificate_fingerprints",
        "javascript_hashes",
        "endpoint_keys",
    )
    @classmethod
    def normalize_string_sets(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    value.strip()
                    for value in values
                    if value.strip()
                }
            )
        )

    @field_validator("certificate_sans")
    @classmethod
    def normalize_sans(
        cls,
        values: tuple[str, ...],
    ) -> tuple[str, ...]:
        return tuple(
            sorted(
                {
                    value.strip().lower().rstrip(".")
                    for value in values
                    if value.strip()
                }
            )
        )

    @field_validator("title", "body_hash")
    @classmethod
    def normalize_optional_text(
        cls,
        value: str | None,
    ) -> str | None:
        if value is None:
            return None
        return value.strip() or None

    @model_validator(mode="after")
    def absence_has_no_live_state(self) -> SurfaceState:
        """Make explicit absence semantically unambiguous.

        We do not allow a snapshot to say both "not present" and "HTTP 200".
        """
        if self.present:
            return self

        live_fields = (
            self.ips,
            self.status_code,
            self.title,
            self.body_hash,
            self.certificate_fingerprints,
            self.certificate_sans,
            self.javascript_hashes,
            self.endpoint_keys,
        )

        if any(
            value not in (None, (), "")
            for value in live_fields
        ):
            raise ValueError(
                "present=False snapshots cannot contain live surface state"
            )

        return self

    @property
    def state_hash(self) -> str:
        """Stable hash of normalized state."""
        payload = self.model_dump(
            mode="json",
            exclude_none=False,
        )
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class SurfaceSnapshot(BaseModel):
    """Storage-independent snapshot representation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot_id: str
    run_id: str
    asset_id: str

    asset_event_type: EventType

    kind: SnapshotKind
    observed_at: datetime

    state: SurfaceState

    @field_validator("observed_at")
    @classmethod
    def observed_at_aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")
        return value


class SurfaceChange(BaseModel):
    """One meaningful change produced by the pure diff engine."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    change_type: ChangeType

    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable content fingerprint used for run-level deduplication."""
        payload = {
            "change_type": self.change_type.value,
            "before": self.before,
            "after": self.after,
            "details": self.details,
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()


class PersistedSurfaceChange(BaseModel):
    """Database-backed change record."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    change_id: str
    run_id: str
    asset_id: str

    previous_snapshot_id: str | None = None
    current_snapshot_id: str | None = None

    change_type: ChangeType
    detected_at: datetime

    before: dict[str, Any] = Field(default_factory=dict)
    after: dict[str, Any] = Field(default_factory=dict)
    details: dict[str, Any] = Field(default_factory=dict)


class CaptureResult(BaseModel):
    """Result of one capture/upsert."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    snapshot: SurfaceSnapshot
    created: bool
    changed_within_run: bool


class SnapshotRepository:
    """Persist normalized states and differential changes."""

    def __init__(self, database: Database) -> None:
        self._database = database

    async def capture(
        self,
        *,
        run_id: str,
        asset_id: str,
        kind: SnapshotKind,
        state: SurfaceState,
        observed_at: datetime | None = None,
    ) -> CaptureResult:
        """Create/update one asset state inside a run.

        The unique key `(run_id, asset_id, kind)` means repeated observations
        inside the same run converge to the latest normalized state instead of
        producing fake cross-run history.
        """
        timestamp = observed_at or utc_now()
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("observed_at must be timezone-aware")

        async with self._database.transaction(immediate=True) as session:
            if await session.get(ReconRunRecord, run_id) is None:
                raise KeyError(f"unknown run_id: {run_id}")

            asset = await session.get(AssetRecord, asset_id)
            if asset is None:
                raise KeyError(f"unknown asset_id: {asset_id}")

            existing = await session.scalar(
                select(SurfaceSnapshotRecord).where(
                    SurfaceSnapshotRecord.run_id == run_id,
                    SurfaceSnapshotRecord.asset_id == asset_id,
                    SurfaceSnapshotRecord.snapshot_kind == kind.value,
                )
            )

            state_json = state.model_dump(
                mode="json",
                exclude_none=False,
            )

            if existing is None:
                record = SurfaceSnapshotRecord(
                    run_id=run_id,
                    asset_id=asset_id,
                    snapshot_kind=kind.value,
                    observed_at=timestamp,
                    present=state.present,
                    state_hash=state.state_hash,
                    state_json=state_json,
                )
                session.add(record)
                await session.flush()
                created = True
                changed_within_run = False
            else:
                record = existing
                changed_within_run = record.state_hash != state.state_hash

                if timestamp >= record.observed_at:
                    record.observed_at = timestamp
                    record.present = state.present
                    record.state_hash = state.state_hash
                    record.state_json = state_json

                created = False

            snapshot = _snapshot_from_record(
                record,
                asset_event_type=EventType(asset.event_type),
            )
            return CaptureResult(
                snapshot=snapshot,
                created=created,
                changed_within_run=changed_within_run,
            )

    async def get(
        self,
        snapshot_id: str,
    ) -> SurfaceSnapshot | None:
        """Return one persisted snapshot."""
        async with self._database.session() as session:
            record = await session.get(
                SurfaceSnapshotRecord,
                snapshot_id,
            )
            if record is None:
                return None

            asset = await session.get(AssetRecord, record.asset_id)
            if asset is None:
                raise RuntimeError(
                    "surface snapshot references missing asset"
                )

            return _snapshot_from_record(
                record,
                asset_event_type=EventType(asset.event_type),
            )

    async def previous_snapshot(
        self,
        snapshot_id: str,
    ) -> SurfaceSnapshot | None:
        """Return the latest snapshot before the supplied one."""
        async with self._database.session() as session:
            current = await session.get(
                SurfaceSnapshotRecord,
                snapshot_id,
            )
            if current is None:
                raise KeyError(f"unknown snapshot: {snapshot_id}")

            previous = await session.scalar(
                select(SurfaceSnapshotRecord)
                .where(
                    SurfaceSnapshotRecord.asset_id
                    == current.asset_id,
                    SurfaceSnapshotRecord.snapshot_kind
                    == current.snapshot_kind,
                    SurfaceSnapshotRecord.snapshot_id
                    != current.snapshot_id,
                    SurfaceSnapshotRecord.observed_at
                    < current.observed_at,
                )
                .order_by(
                    SurfaceSnapshotRecord.observed_at.desc(),
                    SurfaceSnapshotRecord.snapshot_id.desc(),
                )
                .limit(1)
            )

            if previous is None:
                return None

            asset = await session.get(
                AssetRecord,
                current.asset_id,
            )
            if asset is None:
                raise RuntimeError(
                    "surface snapshot references missing asset"
                )

            return _snapshot_from_record(
                previous,
                asset_event_type=EventType(asset.event_type),
            )

    async def diff_and_record(
        self,
        snapshot_id: str,
    ) -> tuple[PersistedSurfaceChange, ...]:
        """Compare a snapshot to its predecessor and persist the diff."""
        async with self._database.transaction(immediate=True) as session:
            current_record = await session.get(
                SurfaceSnapshotRecord,
                snapshot_id,
            )
            if current_record is None:
                raise KeyError(f"unknown snapshot: {snapshot_id}")

            asset = await session.get(
                AssetRecord,
                current_record.asset_id,
            )
            if asset is None:
                raise RuntimeError(
                    "surface snapshot references missing asset"
                )

            previous_record = await session.scalar(
                select(SurfaceSnapshotRecord)
                .where(
                    SurfaceSnapshotRecord.asset_id
                    == current_record.asset_id,
                    SurfaceSnapshotRecord.snapshot_kind
                    == current_record.snapshot_kind,
                    SurfaceSnapshotRecord.snapshot_id
                    != current_record.snapshot_id,
                    SurfaceSnapshotRecord.observed_at
                    < current_record.observed_at,
                )
                .order_by(
                    SurfaceSnapshotRecord.observed_at.desc(),
                    SurfaceSnapshotRecord.snapshot_id.desc(),
                )
                .limit(1)
            )

            current = _snapshot_from_record(
                current_record,
                asset_event_type=EventType(asset.event_type),
            )
            previous = (
                _snapshot_from_record(
                    previous_record,
                    asset_event_type=EventType(asset.event_type),
                )
                if previous_record is not None
                else None
            )

            changes = diff_snapshots(
                previous=previous,
                current=current,
            )

            persisted: list[PersistedSurfaceChange] = []

            for change in changes:
                change_key = _change_key(
                    asset_id=current.asset_id,
                    previous_snapshot_id=(
                        previous.snapshot_id
                        if previous is not None
                        else None
                    ),
                    current_snapshot_id=current.snapshot_id,
                    change=change,
                )

                existing = await session.scalar(
                    select(SnapshotChangeRecord).where(
                        SnapshotChangeRecord.run_id == current.run_id,
                        SnapshotChangeRecord.change_key == change_key,
                    )
                )

                if existing is None:
                    record = SnapshotChangeRecord(
                        run_id=current.run_id,
                        asset_id=current.asset_id,
                        previous_snapshot_id=(
                            previous.snapshot_id
                            if previous is not None
                            else None
                        ),
                        current_snapshot_id=current.snapshot_id,
                        change_type=change.change_type.value,
                        change_key=change_key,
                        detected_at=current.observed_at,
                        before_json=dict(change.before),
                        after_json=dict(change.after),
                        details_json=dict(change.details),
                    )
                    session.add(record)
                    await session.flush()
                else:
                    record = existing

                persisted.append(
                    _persisted_change_from_record(record)
                )

            return tuple(persisted)

    async def changes_for_run(
        self,
        run_id: str,
    ) -> tuple[PersistedSurfaceChange, ...]:
        """Return all recorded changes for a run."""
        async with self._database.session() as session:
            rows = list(
                (
                    await session.scalars(
                        select(SnapshotChangeRecord)
                        .where(
                            SnapshotChangeRecord.run_id == run_id
                        )
                        .order_by(
                            SnapshotChangeRecord.detected_at,
                            SnapshotChangeRecord.change_id,
                        )
                    )
                ).all()
            )
            return tuple(
                _persisted_change_from_record(row)
                for row in rows
            )


def diff_snapshots(
    *,
    previous: SurfaceSnapshot | None,
    current: SurfaceSnapshot,
) -> tuple[SurfaceChange, ...]:
    """Pure deterministic diff engine.

    Initial presence is a NEW_* change.
    Initial explicit absence produces no change because there is no evidence
    that the asset previously existed.
    """
    if previous is not None:
        if previous.asset_id != current.asset_id:
            raise ValueError(
                "cannot diff snapshots for different assets"
            )
        if previous.kind is not current.kind:
            raise ValueError(
                "cannot diff different snapshot kinds"
            )

    current_state = current.state

    if previous is None:
        if not current_state.present:
            return ()

        return (
            SurfaceChange(
                change_type=_initial_change_type(
                    current.asset_event_type
                ),
                after=_state_summary(current_state),
                details={"initial_observation": True},
            ),
        )

    previous_state = previous.state

    if not previous_state.present and current_state.present:
        return (
            SurfaceChange(
                change_type=_reappearance_change_type(
                    current.asset_event_type
                ),
                before=_state_summary(previous_state),
                after=_state_summary(current_state),
            ),
        )

    if previous_state.present and not current_state.present:
        return (
            SurfaceChange(
                change_type=_disappearance_change_type(
                    current.asset_event_type
                ),
                before=_state_summary(previous_state),
                after=_state_summary(current_state),
            ),
        )

    if not previous_state.present and not current_state.present:
        return ()

    changes: list[SurfaceChange] = []

    if previous_state.ips != current_state.ips:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.IP_CHANGED,
                before={"ips": list(previous_state.ips)},
                after={"ips": list(current_state.ips)},
                details={
                    "added": sorted(
                        set(current_state.ips)
                        - set(previous_state.ips)
                    ),
                    "removed": sorted(
                        set(previous_state.ips)
                        - set(current_state.ips)
                    ),
                },
            )
        )

    if previous_state.status_code != current_state.status_code:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.STATUS_CHANGED,
                before={
                    "status_code": previous_state.status_code
                },
                after={
                    "status_code": current_state.status_code
                },
            )
        )

    if previous_state.title != current_state.title:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.TITLE_CHANGED,
                before={"title": previous_state.title},
                after={"title": current_state.title},
            )
        )

    if previous_state.body_hash != current_state.body_hash:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.BODY_HASH_CHANGED,
                before={"body_hash": previous_state.body_hash},
                after={"body_hash": current_state.body_hash},
            )
        )

    if (
        previous_state.certificate_fingerprints
        != current_state.certificate_fingerprints
    ):
        changes.append(
            SurfaceChange(
                change_type=ChangeType.CERTIFICATE_CHANGED,
                before={
                    "certificate_fingerprints": list(
                        previous_state.certificate_fingerprints
                    )
                },
                after={
                    "certificate_fingerprints": list(
                        current_state.certificate_fingerprints
                    )
                },
            )
        )

    new_sans = sorted(
        set(current_state.certificate_sans)
        - set(previous_state.certificate_sans)
    )
    if new_sans:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.NEW_CERT_SAN,
                after={"certificate_sans": new_sans},
                details={"added": new_sans},
            )
        )

    new_js = sorted(
        set(current_state.javascript_hashes)
        - set(previous_state.javascript_hashes)
    )
    if new_js:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.NEW_JAVASCRIPT,
                after={"javascript_hashes": new_js},
                details={"added": new_js},
            )
        )

    new_endpoints = sorted(
        set(current_state.endpoint_keys)
        - set(previous_state.endpoint_keys)
    )
    if new_endpoints:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.NEW_ENDPOINT,
                after={"endpoint_keys": new_endpoints},
                details={"added": new_endpoints},
            )
        )

    if previous_state.scope_state != current_state.scope_state:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.SCOPE_CHANGED,
                before={
                    "scope_state": (
                        previous_state.scope_state.value
                        if previous_state.scope_state is not None
                        else None
                    )
                },
                after={
                    "scope_state": (
                        current_state.scope_state.value
                        if current_state.scope_state is not None
                        else None
                    )
                },
            )
        )

    if previous_state.extra != current_state.extra:
        changes.append(
            SurfaceChange(
                change_type=ChangeType.STATE_CHANGED,
                before={"extra": previous_state.extra},
                after={"extra": current_state.extra},
            )
        )

    return tuple(changes)


def _initial_change_type(
    event_type: EventType,
) -> ChangeType:
    if event_type is EventType.DNS_NAME:
        return ChangeType.NEW_HOST
    if event_type is EventType.URL:
        return ChangeType.NEW_URL
    if event_type is EventType.API_ENDPOINT:
        return ChangeType.NEW_ENDPOINT
    if event_type is EventType.CERT_SAN:
        return ChangeType.NEW_CERT_SAN
    if event_type is EventType.JAVASCRIPT:
        return ChangeType.NEW_JAVASCRIPT
    return ChangeType.NEW_ASSET


def _reappearance_change_type(
    event_type: EventType,
) -> ChangeType:
    if event_type is EventType.DNS_NAME:
        return ChangeType.RESURRECTED_HOST
    return ChangeType.REAPPEARED_ASSET


def _disappearance_change_type(
    event_type: EventType,
) -> ChangeType:
    if event_type is EventType.DNS_NAME:
        return ChangeType.DISAPPEARED_HOST
    return ChangeType.DISAPPEARED_ASSET


def _state_summary(
    state: SurfaceState,
) -> dict[str, Any]:
    """Return complete normalized state for change context."""
    return state.model_dump(
        mode="json",
        exclude_none=False,
    )


def _snapshot_from_record(
    record: SurfaceSnapshotRecord,
    *,
    asset_event_type: EventType,
) -> SurfaceSnapshot:
    return SurfaceSnapshot(
        snapshot_id=record.snapshot_id,
        run_id=record.run_id,
        asset_id=record.asset_id,
        asset_event_type=asset_event_type,
        kind=SnapshotKind(record.snapshot_kind),
        observed_at=record.observed_at,
        state=SurfaceState.model_validate(record.state_json),
    )


def _persisted_change_from_record(
    record: SnapshotChangeRecord,
) -> PersistedSurfaceChange:
    return PersistedSurfaceChange(
        change_id=record.change_id,
        run_id=record.run_id,
        asset_id=record.asset_id,
        previous_snapshot_id=record.previous_snapshot_id,
        current_snapshot_id=record.current_snapshot_id,
        change_type=ChangeType(record.change_type),
        detected_at=record.detected_at,
        before=dict(record.before_json),
        after=dict(record.after_json),
        details=dict(record.details_json),
    )


def _change_key(
    *,
    asset_id: str,
    previous_snapshot_id: str | None,
    current_snapshot_id: str,
    change: SurfaceChange,
) -> str:
    payload = {
        "asset_id": asset_id,
        "previous_snapshot_id": previous_snapshot_id,
        "current_snapshot_id": current_snapshot_id,
        "change_fingerprint": change.fingerprint,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
