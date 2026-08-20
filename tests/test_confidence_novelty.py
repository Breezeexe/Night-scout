from __future__ import annotations

from datetime import datetime, timezone

from recon.core.events import Event, EventType
from recon.intelligence.confidence import (
    ConfidenceEvidence,
    EvidenceClass,
    EvidencePolarity,
    assess_confidence,
)
from recon.intelligence.novelty import NoveltyHistory, assess_novelty, novelty_subject_key


NOW = datetime(2026, 8, 19, tzinfo=timezone.utc)


def evidence(eid: str, *, independence: str, upstream: str | None, cls: EvidenceClass):
    return ConfidenceEvidence(
        evidence_id=eid,
        subject_key="DNS_NAME:api.example.com",
        polarity=EvidencePolarity.SUPPORTS,
        evidence_class=cls,
        source=eid,
        source_family=eid.split(":", 1)[0],
        source_provider=eid,
        independence_key=independence,
        upstream_key=upstream,
        confidence=0.9,
        observed_at=NOW,
    )


def test_independent_evidence_beats_repeated_shared_upstream():
    shared = assess_confidence(
        subject_key="DNS_NAME:api.example.com",
        event_type=EventType.DNS_NAME,
        evidence=[
            evidence(f"javascript:{i}", independence="js-root", upstream="archive-1", cls=EvidenceClass.STATIC_EXTRACTION)
            for i in range(5)
        ],
    )
    independent = assess_confidence(
        subject_key="DNS_NAME:api.example.com",
        event_type=EventType.DNS_NAME,
        evidence=[
            evidence("dns:1", independence="dns", upstream=None, cls=EvidenceClass.ACTIVE_CONFIRMATION),
            evidence("tls:1", independence="tls", upstream=None, cls=EvidenceClass.PASSIVE_OBSERVATION),
        ],
    )
    assert independent.confidence > shared.confidence


def test_contradicting_nxdomain_reduces_confidence():
    positive = evidence("dns:ok", independence="dns-ok", upstream=None, cls=EvidenceClass.ACTIVE_CONFIRMATION)
    contradiction = ConfidenceEvidence(
        evidence_id="dns:nxdomain",
        subject_key=positive.subject_key,
        polarity=EvidencePolarity.CONTRADICTS,
        evidence_class=EvidenceClass.ACTIVE_CONFIRMATION,
        source="dns:nxdomain",
        source_family="dns",
        source_provider="dnsx",
        independence_key="dns-negative",
        confidence=0.95,
        observed_at=NOW,
    )
    before = assess_confidence(subject_key=positive.subject_key, event_type=EventType.DNS_NAME, evidence=[positive])
    after = assess_confidence(subject_key=positive.subject_key, event_type=EventType.DNS_NAME, evidence=[positive, contradiction])
    assert after.confidence < before.confidence


def test_resurrected_preprod_asset_more_novel_than_repeated_static_asset():
    preprod = Event(
        type=EventType.DNS_NAME,
        value="api-preprod.example.com",
        source="dns:test",
        tags={"confirmed", "preprod"},
    )
    preprod_history = NoveltyHistory(
        subject_key=novelty_subject_key(preprod),
        observation_count=2,
        live_observation_count=1,
        historical_observation_count=1,
        distinct_source_families=2,
        live_after_historical=True,
        change_types=("RESURRECTED_HOST",),
        fingerprint_peer_count=0,
        fingerprint_peer_count_known=True,
    )

    static = Event(
        type=EventType.URL,
        value="https://cdn.example.com/static/app.js",
        source="crawler:test",
        tags={"static", "cdn"},
    )
    static_history = NoveltyHistory(
        subject_key=novelty_subject_key(static),
        observation_count=40,
        live_observation_count=40,
        distinct_source_families=2,
        fingerprint_peer_count=25,
        fingerprint_peer_count_known=True,
        naming_frequency=0.9,
    )

    assert assess_novelty(preprod, history=preprod_history).novelty > assess_novelty(static, history=static_history).novelty
