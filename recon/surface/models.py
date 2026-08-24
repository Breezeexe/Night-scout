"""Versioned, immutable models for the user-facing attack-surface graph."""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from recon.core.events import ScopeState


class SurfaceNodeKind(StrEnum):
    DOMAIN = "DOMAIN"
    DNS_RECORD = "DNS_RECORD"
    IP_ADDRESS = "IP_ADDRESS"
    CIDR = "CIDR"
    ASN = "ASN"
    HTTP_SERVICE = "HTTP_SERVICE"
    NETWORK_SERVICE = "NETWORK_SERVICE"
    ENDPOINT = "ENDPOINT"
    JAVASCRIPT = "JAVASCRIPT"
    CERTIFICATE = "CERTIFICATE"
    TECHNOLOGY = "TECHNOLOGY"
    FINGERPRINT = "FINGERPRINT"
    FAVICON = "FAVICON"
    PARAMETER = "PARAMETER"
    INTELLIGENCE = "INTELLIGENCE"
    ARTIFACT = "ARTIFACT"
    MOBILE_ARTIFACT = "MOBILE_ARTIFACT"
    VULNERABILITY_CANDIDATE = "VULNERABILITY_CANDIDATE"
    VULNERABILITY_FINDING = "VULNERABILITY_FINDING"


class DiscoveryState(StrEnum):
    CONFIRMED = "CONFIRMED"
    HYPOTHESIS = "HYPOTHESIS"
    HISTORICAL = "HISTORICAL"
    OBSERVED = "OBSERVED"
    STALE = "STALE"


class LivenessState(StrEnum):
    LIVE = "LIVE"
    UNVERIFIED = "UNVERIFIED"
    NOT_OBSERVED = "NOT_OBSERVED"
    UNKNOWN = "UNKNOWN"


class SurfaceEvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str
    source: str
    event_type: str
    first_seen: datetime


class SurfaceNode(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    node_id: str
    kind: SurfaceNodeKind
    value: str
    label: str
    roles: tuple[str, ...] = ()
    scope_state: ScopeState = ScopeState.UNKNOWN
    discovery_state: DiscoveryState = DiscoveryState.OBSERVED
    liveness_state: LivenessState = LivenessState.UNKNOWN
    confidence: float = Field(ge=0.0, le=1.0)
    novelty: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    observation_count: int = Field(ge=1)
    asset_ids: tuple[str, ...]
    sources: tuple[str, ...]
    tags: tuple[str, ...] = ()
    evidence: tuple[SurfaceEvidenceRef, ...] = ()
    metadata: dict[str, Any] = Field(default_factory=dict)


class SurfaceEdge(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    edge_id: str
    source_node_id: str
    target_node_id: str
    relation: str
    confidence: float = Field(ge=0.0, le=1.0)
    first_seen: datetime
    last_seen: datetime
    supporting_event_ids: tuple[str, ...] = ()
    derived: bool = False
    metadata: dict[str, Any] = Field(default_factory=dict)


class SurfaceGraphStatistics(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    observations_considered: int = Field(ge=0)
    observations_excluded: int = Field(ge=0)
    nodes_by_kind: dict[str, int] = Field(default_factory=dict)
    nodes_by_state: dict[str, int] = Field(default_factory=dict)


class SurfaceGraphFilter(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    confirmed_only: bool = False
    include_hypotheses: bool = True
    include_historical: bool = True
    include_out_of_scope: bool = False
    include_intelligence: bool = False
    include_provenance: bool = False
    root: str | None = None
    max_depth: int | None = Field(default=None, ge=0, le=128)
    min_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    max_nodes: int = Field(default=100_000, ge=1, le=1_000_000)
    max_edges: int = Field(default=250_000, ge=1, le=2_000_000)


class SurfaceGraphSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: int = 1
    target_id: str
    generated_at: datetime
    fingerprint: str
    roots: tuple[str, ...]
    nodes: tuple[SurfaceNode, ...]
    edges: tuple[SurfaceEdge, ...]
    statistics: SurfaceGraphStatistics
    warnings: tuple[str, ...] = ()
