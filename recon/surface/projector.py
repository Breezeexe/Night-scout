"""Idempotent semantic relationship projection from durable observations."""

from __future__ import annotations

from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from recon.core.events import Event, EventType
from recon.storage.database import EventRepository
from recon.storage.provenance import (
    AssetRelationType,
    EvidenceKind,
    ProvenanceRepository,
)
from recon.surface.identity import surface_identity


class ProjectionReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    observations_processed: int = Field(ge=0)
    relationships_projected: int = Field(ge=0)
    relationship_ids: tuple[str, ...] = ()
    skipped: int = Field(ge=0)
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class RelationshipCandidate:
    source_event_id: str
    target_event_id: str
    relation: AssetRelationType
    confidence: float
    reason: str


class SurfaceRelationshipProjector:
    """Project only type- and context-supported relationships.

    Scope remains an attribute of observations. Relationships are informational
    and must never be interpreted as authorization to schedule target traffic.
    """

    def __init__(
        self,
        *,
        events: EventRepository,
        provenance: ProvenanceRepository,
    ) -> None:
        self._events = events
        self._provenance = provenance

    async def project(self, event: Event) -> ProjectionReport:
        if event.parent_event_id is None:
            return ProjectionReport(observations_processed=1, relationships_projected=0, skipped=1)
        parent = await self._events.get_event(event.parent_event_id)
        if parent is None:
            return ProjectionReport(
                observations_processed=1,
                relationships_projected=0,
                skipped=1,
                warnings=(f"missing parent observation: {event.parent_event_id}",),
            )

        candidates = list(relationship_candidates(parent, event))
        if parent.parent_event_id is not None and parent.type is EventType.DNS_RECORD:
            grandparent = await self._events.get_event(parent.parent_event_id)
            if grandparent is not None:
                candidates.extend(dns_owner_candidates(grandparent, parent, event))

        projected: list[str] = []
        warnings: list[str] = []
        skipped = 0
        for candidate in candidates:
            source = await self._events.get_event(candidate.source_event_id)
            target = await self._events.get_event(candidate.target_event_id)
            if source is None or target is None or _same_surface_identity(source, target):
                skipped += 1
                continue
            try:
                relationship = await self._provenance.add_asset_relationship(
                    source_event_id=candidate.source_event_id,
                    target_event_id=candidate.target_event_id,
                    relation_type=candidate.relation,
                    confidence=candidate.confidence,
                    metadata={
                        "projector": "surface-v1",
                        "reason": candidate.reason,
                        "supporting_event_ids": [event.event_id],
                    },
                )
                await self._provenance.add_evidence(
                    kind=_evidence_kind(event),
                    source="surface:projector",
                    event_id=event.event_id,
                    relationship_id=relationship.relationship_id,
                    summary=f"{candidate.relation.value} supported by {event.type.value}",
                    metadata={"source": event.source},
                )
                projected.append(relationship.relationship_id)
            except (KeyError, ValueError) as exc:
                warnings.append(f"{candidate.relation.value}: {exc}")

        return ProjectionReport(
            observations_processed=1,
            relationships_projected=len(projected),
            relationship_ids=tuple(sorted(set(projected))),
            skipped=skipped,
            warnings=tuple(warnings),
        )


def relationship_candidates(parent: Event, child: Event) -> tuple[RelationshipCandidate, ...]:
    relation = _direct_relation(parent, child)
    if relation is None:
        return ()
    return (
        RelationshipCandidate(
            source_event_id=parent.event_id,
            target_event_id=child.event_id,
            relation=relation,
            confidence=min(parent.confidence, child.confidence),
            reason=f"typed parent {parent.type.value} -> {child.type.value}",
        ),
    )


def dns_owner_candidates(
    owner: Event,
    record: Event,
    child: Event,
) -> tuple[RelationshipCandidate, ...]:
    if owner.type not in {EventType.ROOT_DOMAIN, EventType.DNS_NAME}:
        return ()
    if child.type is EventType.IP_ADDRESS:
        relation = AssetRelationType.RESOLVES_TO
    elif child.type is EventType.DNS_NAME:
        relation = AssetRelationType.ALIASES_TO
    else:
        return ()
    return (
        RelationshipCandidate(
            source_event_id=owner.event_id,
            target_event_id=child.event_id,
            relation=relation,
            confidence=min(record.confidence, child.confidence),
            reason="DNS owner and typed record value",
        ),
    )


def _direct_relation(parent: Event, child: Event) -> AssetRelationType | None:
    parent_kind = parent.type
    child_kind = child.type
    domain_types = {EventType.ROOT_DOMAIN, EventType.DNS_NAME}
    endpoint_types = {EventType.URL, EventType.API_ENDPOINT}

    if parent_kind in domain_types and child_kind is EventType.DNS_NAME:
        parent_value = parent.value.lower().rstrip(".")
        child_value = child.value.lower().rstrip(".")
        if child_value != parent_value and child_value.endswith(f".{parent_value}"):
            return AssetRelationType.HAS_SUBDOMAIN
        return None
    if parent_kind in domain_types and child_kind is EventType.DNS_RECORD:
        return AssetRelationType.HAS_DNS_RECORD
    if parent_kind is EventType.DNS_RECORD and child_kind is EventType.IP_ADDRESS:
        return AssetRelationType.RESOLVES_TO
    if parent_kind is EventType.DNS_RECORD and child_kind is EventType.DNS_NAME:
        return AssetRelationType.ALIASES_TO
    if parent_kind in domain_types and child_kind is EventType.HTTP_SERVICE:
        return AssetRelationType.EXPOSES_SERVICE
    if parent_kind in domain_types and child_kind in endpoint_types:
        return AssetRelationType.HAS_ENDPOINT
    if parent_kind is EventType.HTTP_SERVICE and child_kind in endpoint_types:
        return AssetRelationType.HAS_ENDPOINT
    if parent_kind in endpoint_types and child_kind in endpoint_types:
        return (
            AssetRelationType.REDIRECTS_TO
            if "redirect-target" in child.tags
            else AssetRelationType.LINKS_TO
        )
    if parent_kind in endpoint_types and child_kind is EventType.JAVASCRIPT:
        return AssetRelationType.REFERENCES
    if parent_kind in endpoint_types and child_kind is EventType.PARAMETER_NAME:
        return AssetRelationType.HAS_PARAMETER
    if parent_kind is EventType.HTTP_SERVICE and child_kind is EventType.CERTIFICATE:
        return AssetRelationType.PRESENTS_CERTIFICATE
    if parent_kind is EventType.CERTIFICATE and child_kind is EventType.CERT_SAN:
        return AssetRelationType.CERTIFICATE_NAMES
    if (
        parent_kind in {EventType.HTTP_SERVICE, *endpoint_types}
        and child_kind is EventType.TECHNOLOGY
    ):
        return AssetRelationType.USES_TECHNOLOGY
    if parent_kind in {EventType.HTTP_SERVICE, *endpoint_types} and child_kind in {
        EventType.FINGERPRINT,
        EventType.FAVICON,
    }:
        return AssetRelationType.FINGERPRINT_MATCH
    if parent_kind is EventType.TECHNOLOGY and child_kind is EventType.VULNERABILITY_CANDIDATE:
        return AssetRelationType.POTENTIALLY_AFFECTED_BY
    if (
        parent_kind is EventType.VULNERABILITY_CANDIDATE
        and child_kind is EventType.VULNERABILITY_FINDING
    ):
        return AssetRelationType.CONFIRMED_AFFECTED_BY
    if child_kind in {EventType.ARTIFACT, EventType.MOBILE_ARTIFACT}:
        return AssetRelationType.HAS_ARTIFACT
    return None


def _same_surface_identity(left: Event, right: Event) -> bool:
    left_identity = surface_identity(left.type, left.value)
    right_identity = surface_identity(right.type, right.value)
    return left_identity is not None and left_identity == right_identity


def _evidence_kind(event: Event) -> EvidenceKind:
    if event.type in {EventType.DNS_RECORD, EventType.IP_ADDRESS, EventType.DNS_NAME}:
        return EvidenceKind.DNS_RESPONSE
    if event.type in {EventType.URL, EventType.HTTP_SERVICE, EventType.HTTP_RESPONSE}:
        return EvidenceKind.HTTP_RESPONSE
    if event.type in {EventType.CERTIFICATE, EventType.CERT_SAN}:
        return EvidenceKind.TLS_CERTIFICATE
    return EvidenceKind.TOOL_OUTPUT
