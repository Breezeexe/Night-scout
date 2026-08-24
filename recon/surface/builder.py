"""Deterministic assembly of the canonical, user-facing surface graph."""

from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from publicsuffix2 import get_tld  # type: ignore[import-untyped]
from sqlalchemy import select

from recon.core.events import EventType, ScopeState, utc_now
from recon.core.queue import TaskStatus
from recon.storage.database import Database
from recon.storage.models import (
    AssetRecord,
    EventObservationRecord,
    EvidenceRecord,
    RelationshipRecord,
    TaskRecord,
)
from recon.surface.identity import (
    SurfaceIdentity,
    domain_from_url,
    service_from_url,
    surface_identity,
)
from recon.surface.models import (
    DiscoveryState,
    LivenessState,
    SurfaceEdge,
    SurfaceEvidenceRef,
    SurfaceGraphFilter,
    SurfaceGraphSnapshot,
    SurfaceGraphStatistics,
    SurfaceNode,
    SurfaceNodeKind,
)

_METADATA_KEYS = frozenset(
    {
        "hostname",
        "port",
        "scheme",
        "url",
        "observed_on",
        "record_type",
        "record_value",
        "owner",
        "status_code",
        "title",
        "content_type",
        "location",
        "path",
        "parameter_location",
        "target_url",
        "cve_id",
        "template_id",
        "severity",
        "historical",
        "confirmed",
        "requires_dns_confirmation",
        "requires_live_confirmation",
        "scope_matched_rule_id",
        "scope_tier",
        "sha256",
        "fingerprint",
        "serial_number",
        "not_before",
        "not_after",
    }
)

_EXPECTED_WORKERS: dict[SurfaceNodeKind, tuple[str, ...]] = {
    SurfaceNodeKind.DOMAIN: ("dns", "http", "tls", "passive_domains"),
    SurfaceNodeKind.IP_ADDRESS: ("http", "tls", "asn"),
    SurfaceNodeKind.HTTP_SERVICE: ("http", "tls", "crawler", "nuclei"),
    SurfaceNodeKind.ENDPOINT: ("crawler", "parameters", "nuclei"),
    SurfaceNodeKind.JAVASCRIPT: ("content", "javascript", "fingerprints"),
    SurfaceNodeKind.MOBILE_ARTIFACT: ("mobile",),
}

_HTTP_HISTORY_LIMIT = 25
_HTTP_RESPONSE_DETAIL_KEYS = (
    "title",
    "content_type",
    "content_length",
    "location",
    "webserver",
    "response_time",
)


@dataclass(slots=True)
class _NodeAccumulator:
    identity: SurfaceIdentity
    values: Counter[str] = field(default_factory=Counter)
    asset_ids: set[str] = field(default_factory=set)
    event_types: set[EventType] = field(default_factory=set)
    observations: list[EventObservationRecord] = field(default_factory=list)
    sources: set[str] = field(default_factory=set)
    tags: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    confidence: float = 0.0
    novelty: float = 0.0
    scope_states: set[ScopeState] = field(default_factory=set)
    coverage: dict[str, Counter[str]] = field(default_factory=lambda: defaultdict(Counter))
    http_responses: list[EventObservationRecord] = field(default_factory=list)

    def add(self, asset: AssetRecord, observation: EventObservationRecord) -> None:
        self.values[observation.value] += 1
        self.asset_ids.add(asset.asset_id)
        self.event_types.add(EventType(observation.event_type))
        self.observations.append(observation)
        self.sources.add(observation.source)
        self.tags.update(observation.tags_json)
        self.first_seen = (
            observation.first_seen
            if self.first_seen is None
            else min(self.first_seen, observation.first_seen)
        )
        self.last_seen = (
            observation.last_seen
            if self.last_seen is None
            else max(self.last_seen, observation.last_seen)
        )
        self.confidence = max(self.confidence, observation.confidence)
        self.novelty = max(self.novelty, observation.novelty)
        self.scope_states.add(ScopeState(observation.scope_state))
        for key, value in observation.metadata_json.items():
            if key in _METADATA_KEYS and value is not None:
                self.metadata[key] = value

    def attach_http_response(
        self,
        asset: AssetRecord,
        observation: EventObservationRecord,
    ) -> None:
        """Attach an HTTP measurement without changing the endpoint identity."""
        self.asset_ids.add(asset.asset_id)
        self.event_types.add(EventType.HTTP_RESPONSE)
        self.observations.append(observation)
        self.http_responses.append(observation)
        self.sources.add(observation.source)
        self.tags.update(observation.tags_json)
        self.first_seen = (
            observation.first_seen
            if self.first_seen is None
            else min(self.first_seen, observation.first_seen)
        )
        self.last_seen = (
            observation.last_seen
            if self.last_seen is None
            else max(self.last_seen, observation.last_seen)
        )
        self.confidence = max(self.confidence, observation.confidence)
        self.novelty = max(self.novelty, observation.novelty)
        self.scope_states.add(ScopeState(observation.scope_state))


@dataclass(slots=True)
class _EdgeAccumulator:
    source: str
    target: str
    relation: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    supporting_event_ids: set[str] = field(default_factory=set)
    derived: bool = False
    metadata: dict[str, Any] = field(default_factory=dict)


class SurfaceGraphBuilder:
    def __init__(
        self,
        database: Database,
        *,
        target_id: str,
        disabled_workers: frozenset[str] = frozenset(),
    ) -> None:
        self._database = database
        self._target_id = target_id
        self._disabled_workers = disabled_workers

    async def build(
        self,
        graph_filter: SurfaceGraphFilter | None = None,
    ) -> SurfaceGraphSnapshot:
        selected_filter = graph_filter or SurfaceGraphFilter()
        async with self._database.session() as session:
            assets = list((await session.scalars(select(AssetRecord))).all())
            observations = list(
                (
                    await session.scalars(
                        select(EventObservationRecord).order_by(
                            EventObservationRecord.first_seen,
                            EventObservationRecord.event_id,
                        )
                    )
                ).all()
            )
            relationships = list((await session.scalars(select(RelationshipRecord))).all())
            evidence = list((await session.scalars(select(EvidenceRecord))).all())
            tasks = list((await session.scalars(select(TaskRecord))).all())

        assets_by_id = {asset.asset_id: asset for asset in assets}
        accumulators: dict[str, _NodeAccumulator] = {}
        asset_to_node: dict[str, str] = {}
        event_to_node: dict[str, str] = {}
        excluded = 0
        http_responses: list[tuple[AssetRecord, EventObservationRecord]] = []

        for observation in observations:
            identity = surface_identity(
                observation.event_type,
                observation.value,
                include_intelligence=selected_filter.include_intelligence,
            )
            asset = assets_by_id.get(observation.asset_id)
            if identity is None and observation.event_type == EventType.HTTP_RESPONSE.value:
                if asset is not None:
                    http_responses.append((asset, observation))
                else:
                    excluded += 1
                continue
            if identity is None or asset is None:
                excluded += 1
                continue
            accumulator = accumulators.setdefault(
                identity.node_id,
                _NodeAccumulator(identity=identity),
            )
            accumulator.add(asset, observation)
            asset_to_node[asset.asset_id] = identity.node_id
            event_to_node[observation.event_id] = identity.node_id

        endpoints = {
            item.identity.canonical_value: (node_id, item)
            for node_id, item in accumulators.items()
            if item.identity.kind is SurfaceNodeKind.ENDPOINT
        }
        for asset, observation in http_responses:
            endpoint_value = _http_response_endpoint(observation)
            endpoint = endpoints.get(endpoint_value) if endpoint_value is not None else None
            if endpoint is None or _http_status_code(observation) is None:
                excluded += 1
                continue
            node_id, accumulator = endpoint
            accumulator.attach_http_response(asset, observation)
            asset_to_node[asset.asset_id] = node_id
            event_to_node[observation.event_id] = node_id

        for task in tasks:
            task_node_id = event_to_node.get(task.input_event_id)
            if task_node_id is not None:
                accumulators[task_node_id].coverage[task.worker][task.status] += 1

        edges: dict[tuple[str, str, str], _EdgeAccumulator] = {}
        relationship_evidence: dict[str, set[str]] = defaultdict(set)
        for pointer in evidence:
            if pointer.relationship_id and pointer.event_id:
                relationship_evidence[pointer.relationship_id].add(pointer.event_id)

        for relationship in relationships:
            source = asset_to_node.get(relationship.source_asset_id)
            target = asset_to_node.get(relationship.target_asset_id)
            if source is None or target is None or source == target:
                continue
            supporting = set(relationship_evidence.get(relationship.relationship_id, set()))
            if relationship.first_source_event_id:
                supporting.add(relationship.first_source_event_id)
            raw_support = relationship.metadata_json.get("supporting_event_ids", [])
            if isinstance(raw_support, list):
                supporting.update(str(item) for item in raw_support if isinstance(item, str))
            self._merge_edge(
                edges,
                source=source,
                target=target,
                relation=relationship.relation_type,
                confidence=relationship.confidence,
                first_seen=relationship.first_seen,
                last_seen=relationship.last_seen,
                supporting=supporting,
                derived=False,
                metadata={"relationship_id": relationship.relationship_id},
            )

        self._derive_presentation_edges(accumulators, edges, event_to_node)
        nodes: list[SurfaceNode] = []
        for item in accumulators.values():
            finished = self._finish_node(
                item,
                selected_filter,
                disabled_workers=self._disabled_workers,
            )
            if finished is not None:
                nodes.append(finished)
        visible_ids = {node.node_id for node in nodes}
        finished_edges = [
            self._finish_edge(edge)
            for edge in edges.values()
            if edge.source in visible_ids and edge.target in visible_ids
        ]

        nodes.sort(key=lambda node: (node.kind.value, node.value, node.node_id))
        finished_edges.sort(
            key=lambda edge: (edge.source_node_id, edge.relation, edge.target_node_id)
        )
        warnings: list[str] = []
        if len(nodes) > selected_filter.max_nodes:
            warnings.append(f"node limit applied: {selected_filter.max_nodes} of {len(nodes)}")
            nodes = nodes[: selected_filter.max_nodes]
            visible_ids = {node.node_id for node in nodes}
            finished_edges = [
                edge
                for edge in finished_edges
                if edge.source_node_id in visible_ids and edge.target_node_id in visible_ids
            ]
        if len(finished_edges) > selected_filter.max_edges:
            warnings.append(
                f"edge limit applied: {selected_filter.max_edges} of {len(finished_edges)}"
            )
            finished_edges = finished_edges[: selected_filter.max_edges]

        roots = tuple(
            node.node_id
            for node in nodes
            if "ROOT" in node.roles
            and (
                selected_filter.root is None
                or node.value == selected_filter.root.lower().rstrip(".")
            )
        )
        if selected_filter.root is not None and not roots:
            warnings.append(f"requested root not found: {selected_filter.root}")

        nodes, finished_edges = _bounded_subgraph(
            nodes,
            finished_edges,
            roots=roots,
            max_depth=selected_filter.max_depth,
        )
        statistics = SurfaceGraphStatistics(
            node_count=len(nodes),
            edge_count=len(finished_edges),
            observations_considered=len(observations),
            observations_excluded=excluded,
            nodes_by_kind=dict(sorted(Counter(node.kind.value for node in nodes).items())),
            nodes_by_state=dict(
                sorted(Counter(node.discovery_state.value for node in nodes).items())
            ),
        )
        fingerprint = _graph_fingerprint(nodes, finished_edges, roots)
        return SurfaceGraphSnapshot(
            target_id=self._target_id,
            generated_at=utc_now(),
            fingerprint=fingerprint,
            roots=roots,
            nodes=tuple(nodes),
            edges=tuple(finished_edges),
            statistics=statistics,
            warnings=tuple(warnings),
        )

    @staticmethod
    def _merge_edge(
        edges: dict[tuple[str, str, str], _EdgeAccumulator],
        *,
        source: str,
        target: str,
        relation: str,
        confidence: float,
        first_seen: datetime,
        last_seen: datetime,
        supporting: set[str] | None = None,
        derived: bool,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if source == target:
            return
        key = (source, target, relation)
        existing = edges.get(key)
        if existing is None:
            edges[key] = _EdgeAccumulator(
                source=source,
                target=target,
                relation=relation,
                confidence=confidence,
                first_seen=first_seen,
                last_seen=last_seen,
                supporting_event_ids=set(supporting or set()),
                derived=derived,
                metadata=dict(metadata or {}),
            )
            return
        existing.confidence = max(existing.confidence, confidence)
        existing.first_seen = min(existing.first_seen, first_seen)
        existing.last_seen = max(existing.last_seen, last_seen)
        existing.supporting_event_ids.update(supporting or set())
        existing.derived = existing.derived and derived
        existing.metadata.update(metadata or {})

    def _derive_presentation_edges(
        self,
        nodes: dict[str, _NodeAccumulator],
        edges: dict[tuple[str, str, str], _EdgeAccumulator],
        event_to_node: dict[str, str],
    ) -> None:
        if not nodes:
            return
        earliest = min(item.first_seen for item in nodes.values() if item.first_seen is not None)
        latest = max(item.last_seen for item in nodes.values() if item.last_seen is not None)
        domains = {
            item.identity.canonical_value: node_id
            for node_id, item in nodes.items()
            if item.identity.kind is SurfaceNodeKind.DOMAIN
            and not item.identity.canonical_value.startswith("*.")
        }
        services = {
            item.identity.canonical_value: node_id
            for node_id, item in nodes.items()
            if item.identity.kind is SurfaceNodeKind.HTTP_SERVICE
        }
        endpoints = {
            item.identity.canonical_value: node_id
            for node_id, item in nodes.items()
            if item.identity.kind is SurfaceNodeKind.ENDPOINT
        }

        for domain, node_id in sorted(domains.items(), key=lambda item: item[0].count(".")):
            candidates = [
                candidate
                for candidate in domains
                if domain.endswith(f".{candidate}") and not _is_public_suffix(candidate)
            ]
            if candidates:
                parent = max(candidates, key=lambda candidate: candidate.count("."))
                self._merge_edge(
                    edges,
                    source=domains[parent],
                    target=node_id,
                    relation="HAS_SUBDOMAIN",
                    confidence=1.0,
                    first_seen=earliest,
                    last_seen=latest,
                    derived=True,
                    metadata={"presentation": "dns-suffix"},
                )

        for service, node_id in services.items():
            host = domain_from_url(service)
            if host in domains:
                self._merge_edge(
                    edges,
                    source=domains[host],
                    target=node_id,
                    relation="EXPOSES_SERVICE",
                    confidence=1.0,
                    first_seen=earliest,
                    last_seen=latest,
                    derived=True,
                )

        for endpoint, node_id in endpoints.items():
            endpoint_service = service_from_url(endpoint)
            if endpoint_service is not None and endpoint_service in services:
                self._merge_edge(
                    edges,
                    source=services[endpoint_service],
                    target=node_id,
                    relation="HAS_ENDPOINT",
                    confidence=1.0,
                    first_seen=earliest,
                    last_seen=latest,
                    derived=True,
                )
            else:
                host = domain_from_url(endpoint)
                if host in domains:
                    self._merge_edge(
                        edges,
                        source=domains[host],
                        target=node_id,
                        relation="HAS_ENDPOINT",
                        confidence=0.8,
                        first_seen=earliest,
                        last_seen=latest,
                        derived=True,
                    )

        endpoint_groups: dict[str, list[tuple[str, str]]] = defaultdict(list)
        for endpoint, node_id in endpoints.items():
            endpoint_service = service_from_url(endpoint)
            if endpoint_service is not None:
                endpoint_groups[endpoint_service].append((endpoint, node_id))
        for group in endpoint_groups.values():
            for endpoint, node_id in group:
                path = urlsplit(endpoint).path or "/"
                parents = [
                    (candidate, candidate_id)
                    for candidate, candidate_id in group
                    if candidate_id != node_id
                    and _is_path_parent(urlsplit(candidate).path or "/", path)
                ]
                if not parents:
                    continue
                parent_endpoint, parent_id = max(
                    parents,
                    key=lambda item: len(PurePosixPath(urlsplit(item[0]).path).parts),
                )
                self._merge_edge(
                    edges,
                    source=parent_id,
                    target=node_id,
                    relation="HAS_CHILD_PATH",
                    confidence=1.0,
                    first_seen=earliest,
                    last_seen=latest,
                    derived=True,
                    metadata={"presentation_only": True, "parent_url": parent_endpoint},
                )

        for node_id, item in nodes.items():
            kind = item.identity.kind
            if kind in {
                SurfaceNodeKind.DOMAIN,
                SurfaceNodeKind.HTTP_SERVICE,
                SurfaceNodeKind.ENDPOINT,
            }:
                continue
            anchor = _anchor_node(item, domains=domains, services=services, endpoints=endpoints)
            if anchor is None:
                for observation in item.observations:
                    observed_parent_id = event_to_node.get(observation.parent_event_id or "")
                    if observed_parent_id is not None and observed_parent_id != node_id:
                        anchor = observed_parent_id
                        break
            if anchor is None:
                continue
            relation = _relation_for_kind(kind)
            self._merge_edge(
                edges,
                source=anchor,
                target=node_id,
                relation=relation,
                confidence=item.confidence,
                first_seen=item.first_seen or earliest,
                last_seen=item.last_seen or latest,
                supporting={observation.event_id for observation in item.observations},
                derived=True,
                metadata={"presentation": "metadata-anchor"},
            )

    @staticmethod
    def _finish_node(
        item: _NodeAccumulator,
        graph_filter: SurfaceGraphFilter,
        *,
        disabled_workers: frozenset[str],
    ) -> SurfaceNode | None:
        state = _discovery_state(item)
        scope = _scope_state(item.scope_states)
        if item.confidence < graph_filter.min_confidence:
            return None
        if graph_filter.confirmed_only and state is not DiscoveryState.CONFIRMED:
            return None
        if not graph_filter.include_hypotheses and state is DiscoveryState.HYPOTHESIS:
            return None
        if not graph_filter.include_historical and state is DiscoveryState.HISTORICAL:
            return None
        if not graph_filter.include_out_of_scope and scope is ScopeState.OUT_OF_SCOPE:
            return None
        assert item.first_seen is not None and item.last_seen is not None
        roles = _roles(item.event_types, item.tags)
        metadata = dict(item.metadata)
        if item.http_responses:
            metadata.update(_http_response_metadata(item.http_responses))
        expected_workers = _EXPECTED_WORKERS.get(item.identity.kind, ())
        coverage_workers = set(item.coverage) | set(expected_workers)
        if coverage_workers:
            metadata["coverage"] = {
                worker: _coverage_summary(
                    item.coverage.get(worker, Counter()),
                    disabled=worker in disabled_workers,
                )
                for worker in sorted(coverage_workers)
            }
        evidence = (
            tuple(
                SurfaceEvidenceRef(
                    event_id=observation.event_id,
                    source=observation.source,
                    event_type=observation.event_type,
                    first_seen=observation.first_seen,
                )
                for observation in item.observations
            )
            if graph_filter.include_provenance
            else ()
        )
        display_value = item.values.most_common(1)[0][0]
        return SurfaceNode(
            node_id=item.identity.node_id,
            kind=item.identity.kind,
            value=item.identity.canonical_value,
            label=display_value,
            roles=roles,
            scope_state=scope,
            discovery_state=state,
            liveness_state=_liveness_state(item),
            confidence=round(item.confidence, 6),
            novelty=round(item.novelty, 6),
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            observation_count=len(item.observations),
            asset_ids=tuple(sorted(item.asset_ids)),
            sources=tuple(sorted(item.sources)),
            tags=tuple(sorted(item.tags)),
            evidence=evidence,
            metadata=metadata,
        )

    @staticmethod
    def _finish_edge(item: _EdgeAccumulator) -> SurfaceEdge:
        material = f"{item.source}|{item.relation}|{item.target}"
        edge_id = f"sge_{hashlib.sha256(material.encode('utf-8')).hexdigest()[:24]}"
        return SurfaceEdge(
            edge_id=edge_id,
            source_node_id=item.source,
            target_node_id=item.target,
            relation=item.relation,
            confidence=round(item.confidence, 6),
            first_seen=item.first_seen,
            last_seen=item.last_seen,
            supporting_event_ids=tuple(sorted(item.supporting_event_ids)),
            derived=item.derived,
            metadata=item.metadata,
        )


def _roles(event_types: set[EventType], tags: set[str]) -> tuple[str, ...]:
    roles: set[str] = set()
    if EventType.ROOT_DOMAIN in event_types:
        roles.add("ROOT")
    if "seed" in tags:
        roles.add("SEED")
    if EventType.API_ENDPOINT in event_types:
        roles.add("API")
    if "redirect-target" in tags:
        roles.add("REDIRECT_TARGET")
    return tuple(sorted(roles))


def _http_response_endpoint(observation: EventObservationRecord) -> str | None:
    raw_url = observation.metadata_json.get("url")
    if not isinstance(raw_url, str):
        return None
    try:
        identity = surface_identity(EventType.URL, raw_url)
    except (TypeError, ValueError):
        return None
    if identity is None or identity.kind is not SurfaceNodeKind.ENDPOINT:
        return None
    return identity.canonical_value


def _http_status_code(observation: EventObservationRecord) -> int | None:
    raw_status = observation.metadata_json.get("status_code")
    if isinstance(raw_status, bool):
        return None
    if isinstance(raw_status, int):
        status_code = raw_status
    elif isinstance(raw_status, str) and raw_status.isdigit():
        status_code = int(raw_status)
    else:
        return None
    return status_code if 100 <= status_code <= 599 else None


def _http_response_metadata(
    observations: list[EventObservationRecord],
) -> dict[str, Any]:
    ordered = sorted(observations, key=lambda item: (item.last_seen, item.event_id))
    history: list[dict[str, Any]] = []
    for observation in ordered:
        fact = _http_response_fact(observation)
        if fact is not None:
            history.append(fact)
    if not history:
        return {}
    visible_history = history[-_HTTP_HISTORY_LIMIT:]
    latest = history[-1]
    result: dict[str, Any] = {
        "method": latest["method"],
        "status_code": latest["status_code"],
        "status_observed_at": latest["observed_at"],
        "http": {
            "latest": latest,
            "history": visible_history,
            "history_total": len(history),
            "history_truncated": len(history) > len(visible_history),
        },
    }
    location = latest.get("location")
    if location is not None:
        result["location"] = location
    return result


def _http_response_fact(observation: EventObservationRecord) -> dict[str, Any] | None:
    status_code = _http_status_code(observation)
    endpoint = _http_response_endpoint(observation)
    if status_code is None or endpoint is None:
        return None
    raw_method = observation.metadata_json.get("method")
    method = raw_method.strip().upper() if isinstance(raw_method, str) else "UNKNOWN"
    if not method:
        method = "UNKNOWN"
    fact: dict[str, Any] = {
        "event_id": observation.event_id,
        "url": endpoint,
        "method": method,
        "status_code": status_code,
        "status_class": f"{status_code // 100}xx",
        "observed_at": observation.last_seen.isoformat(),
        "source": observation.source,
    }
    for key in _HTTP_RESPONSE_DETAIL_KEYS:
        value = observation.metadata_json.get(key)
        if value is not None:
            fact[key] = value
    return fact


def _coverage_summary(statuses: Counter[str], *, disabled: bool) -> dict[str, Any]:
    counts = dict(sorted(statuses.items()))
    if disabled:
        state = "DISABLED"
    elif not statuses:
        state = "NOT_SCHEDULED"
    elif statuses.get(TaskStatus.RUNNING.value):
        state = "RUNNING"
    elif statuses.get(TaskStatus.REVIEW.value):
        state = "REVIEW"
    elif statuses.get(TaskStatus.PENDING.value) or statuses.get(TaskStatus.DEFERRED.value):
        state = "PENDING"
    elif statuses.get(TaskStatus.FAILED.value):
        state = "FAILED"
    else:
        state = "DONE"
    return {"state": state, "task_counts": counts}


def _discovery_state(item: _NodeAccumulator) -> DiscoveryState:
    tags = {tag.lower() for tag in item.tags}
    if "confirmed" in tags or item.metadata.get("confirmed") is True:
        return DiscoveryState.CONFIRMED
    if "historical" in tags or item.metadata.get("historical") is True:
        return DiscoveryState.HISTORICAL
    if EventType.ROOT_DOMAIN in item.event_types:
        # The companion DNS seed may still be a hypothesis, but it must not
        # downgrade the shared explicit root anchor. Liveness stays separate.
        return DiscoveryState.OBSERVED
    if "hypothesis" in tags or any(
        item.metadata.get(key) is True
        for key in ("requires_dns_confirmation", "requires_live_confirmation")
    ):
        return DiscoveryState.HYPOTHESIS
    return DiscoveryState.OBSERVED


def _liveness_state(item: _NodeAccumulator) -> LivenessState:
    tags = {tag.lower() for tag in item.tags}
    if "confirmed" in tags and item.identity.kind in {
        SurfaceNodeKind.HTTP_SERVICE,
        SurfaceNodeKind.ENDPOINT,
    }:
        return LivenessState.LIVE
    if "negative" in tags:
        return LivenessState.NOT_OBSERVED
    if _discovery_state(item) in {DiscoveryState.HYPOTHESIS, DiscoveryState.HISTORICAL}:
        return LivenessState.UNVERIFIED
    return LivenessState.UNKNOWN


def _scope_state(states: set[ScopeState]) -> ScopeState:
    material = states - {ScopeState.UNKNOWN}
    if not material:
        return ScopeState.UNKNOWN
    if len(material) == 1:
        return next(iter(material))
    if ScopeState.OUT_OF_SCOPE in material:
        return ScopeState.AMBIGUOUS
    if ScopeState.AMBIGUOUS in material:
        return ScopeState.AMBIGUOUS
    if ScopeState.PASSIVE_ONLY in material:
        return ScopeState.PASSIVE_ONLY
    return ScopeState.IN_SCOPE


def _anchor_node(
    item: _NodeAccumulator,
    *,
    domains: dict[str, str],
    services: dict[str, str],
    endpoints: dict[str, str],
) -> str | None:
    candidates = [
        item.metadata.get("observed_on"),
        item.metadata.get("target_url"),
        item.metadata.get("url"),
    ]
    for raw in candidates:
        if not isinstance(raw, str):
            continue
        try:
            endpoint_identity = surface_identity(EventType.URL, raw)
        except (ValueError, TypeError):
            endpoint_identity = None
        if endpoint_identity is not None and endpoint_identity.canonical_value in endpoints:
            return endpoints[endpoint_identity.canonical_value]
        service = service_from_url(raw)
        if service in services:
            return services[service]
        host = domain_from_url(raw)
        if host in domains:
            return domains[host]
    hostname = item.metadata.get("hostname") or item.metadata.get("owner")
    if isinstance(hostname, str):
        normalized = hostname.lower().rstrip(".")
        matches = [
            node_id
            for service, node_id in services.items()
            if domain_from_url(service) == normalized
        ]
        if len(matches) == 1:
            return matches[0]
        return domains.get(normalized)
    return None


def _relation_for_kind(kind: SurfaceNodeKind) -> str:
    return {
        SurfaceNodeKind.DNS_RECORD: "HAS_DNS_RECORD",
        SurfaceNodeKind.IP_ADDRESS: "RESOLVES_TO",
        SurfaceNodeKind.CIDR: "BELONGS_TO_CIDR",
        SurfaceNodeKind.ASN: "ANNOUNCED_BY_ASN",
        SurfaceNodeKind.JAVASCRIPT: "REFERENCES",
        SurfaceNodeKind.CERTIFICATE: "PRESENTS_CERTIFICATE",
        SurfaceNodeKind.TECHNOLOGY: "USES_TECHNOLOGY",
        SurfaceNodeKind.FINGERPRINT: "HAS_FINGERPRINT",
        SurfaceNodeKind.FAVICON: "HAS_FINGERPRINT",
        SurfaceNodeKind.PARAMETER: "HAS_PARAMETER",
        SurfaceNodeKind.INTELLIGENCE: "HAS_INTELLIGENCE",
        SurfaceNodeKind.ARTIFACT: "HAS_ARTIFACT",
        SurfaceNodeKind.MOBILE_ARTIFACT: "HAS_ARTIFACT",
        SurfaceNodeKind.VULNERABILITY_CANDIDATE: "POTENTIALLY_AFFECTED_BY",
        SurfaceNodeKind.VULNERABILITY_FINDING: "CONFIRMED_AFFECTED_BY",
    }.get(kind, "RELATED_TO")


def _is_path_parent(parent: str, child: str) -> bool:
    parent_parts = PurePosixPath(parent).parts
    child_parts = PurePosixPath(child).parts
    return len(parent_parts) < len(child_parts) and child_parts[: len(parent_parts)] == parent_parts


def _is_public_suffix(domain: str) -> bool:
    """Return whether a DNS name is itself an ICANN/private public suffix."""
    try:
        suffix = get_tld(domain, strict=True)
    except (UnicodeError, ValueError):
        return False
    return isinstance(suffix, str) and suffix == domain


def _bounded_subgraph(
    nodes: list[SurfaceNode],
    edges: list[SurfaceEdge],
    *,
    roots: tuple[str, ...],
    max_depth: int | None,
) -> tuple[list[SurfaceNode], list[SurfaceEdge]]:
    if max_depth is None or not roots:
        return nodes, edges
    outgoing: dict[str, list[str]] = defaultdict(list)
    for edge in edges:
        outgoing[edge.source_node_id].append(edge.target_node_id)
    depths = {root: 0 for root in roots}
    queue = deque(roots)
    while queue:
        source = queue.popleft()
        if depths[source] >= max_depth:
            continue
        for target in outgoing.get(source, []):
            if target not in depths:
                depths[target] = depths[source] + 1
                queue.append(target)
    visible = set(depths)
    return (
        [node for node in nodes if node.node_id in visible],
        [
            edge
            for edge in edges
            if edge.source_node_id in visible and edge.target_node_id in visible
        ],
    )


def _graph_fingerprint(
    nodes: list[SurfaceNode],
    edges: list[SurfaceEdge],
    roots: tuple[str, ...],
) -> str:
    payload = {
        "roots": roots,
        "nodes": [
            node.model_dump(mode="json", exclude={"first_seen", "last_seen"}) for node in nodes
        ],
        "edges": [
            edge.model_dump(mode="json", exclude={"first_seen", "last_seen"}) for edge in edges
        ],
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()
