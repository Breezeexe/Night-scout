from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select

from recon.core.events import Event, EventType, ScopeState
from recon.exporters.surface import export_graph_json, export_surface_html, export_tree_json
from recon.storage.database import Database, EventRepository
from recon.storage.models import EvidenceRecord, RelationshipRecord
from recon.storage.provenance import ProvenanceRepository
from recon.storage.schema import upgrade_database
from recon.surface.builder import SurfaceGraphBuilder
from recon.surface.identity import service_from_url, surface_identity
from recon.surface.models import SurfaceGraphFilter, SurfaceNodeKind
from recon.surface.projector import SurfaceRelationshipProjector
from recon.surface.rebuild import SurfaceGraphRebuilder


def test_surface_identity_collapses_domain_observation_roles() -> None:
    root = surface_identity(EventType.ROOT_DOMAIN, "Example.COM.")
    dns = surface_identity(EventType.DNS_NAME, "example.com")
    san = surface_identity(EventType.CERT_SAN, "example.com")

    assert root is not None
    assert root == dns == san
    assert root.kind is SurfaceNodeKind.DOMAIN
    assert root.node_id.startswith("sgn_")


def test_surface_identity_excludes_intelligence_and_normalizes_urls() -> None:
    assert surface_identity(EventType.VOCAB_TOKEN, "api") is None
    endpoint = surface_identity(
        EventType.URL,
        "HTTPS://Example.COM:443/v1/users?q=1#fragment",
    )
    assert endpoint is not None
    assert endpoint.canonical_value == "https://example.com/v1/users?q=1"
    assert service_from_url(endpoint.canonical_value) == "https://example.com"


@pytest.mark.asyncio
async def test_relationship_projector_materializes_typed_edge_with_evidence(tmp_path) -> None:
    path = tmp_path / "surface.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    events = EventRepository(database)
    projector = SurfaceRelationshipProjector(
        events=events,
        provenance=ProvenanceRepository(database),
    )
    try:
        domain = Event(type=EventType.DNS_NAME, value="api.example.com", source="test")
        service = Event(
            type=EventType.HTTP_SERVICE,
            value="https://api.example.com",
            source="test:http",
            parent_event_id=domain.event_id,
            confidence=0.9,
        )
        await events.ingest(domain)
        await events.ingest(service)

        first = await projector.project(service)
        second = await projector.project(service)

        assert first.relationships_projected == 1
        assert second.relationship_ids == first.relationship_ids
        async with database.session() as session:
            assert await session.scalar(select(func.count()).select_from(RelationshipRecord)) == 1
            assert await session.scalar(select(func.count()).select_from(EvidenceRecord)) == 1
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_surface_builder_produces_readable_deduplicated_graph(tmp_path) -> None:
    path = tmp_path / "builder.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    events = EventRepository(database)
    projector = SurfaceRelationshipProjector(
        events=events,
        provenance=ProvenanceRepository(database),
    )
    root = Event(
        type=EventType.ROOT_DOMAIN,
        value="example.com",
        source="cli:seed",
        scope_state=ScopeState.IN_SCOPE,
        confidence=1.0,
        tags={"root-domain", "seed"},
    )
    hypothesis = Event(
        type=EventType.DNS_NAME,
        value="example.com",
        source="cli:seed",
        parent_event_id=root.event_id,
        scope_state=ScopeState.IN_SCOPE,
        confidence=1.0,
        tags={"seed", "hypothesis", "requires-dns-confirmation"},
    )
    subdomain = Event(
        type=EventType.DNS_NAME,
        value="api.example.com",
        source="dns:fixture",
        parent_event_id=hypothesis.event_id,
        scope_state=ScopeState.IN_SCOPE,
        confidence=0.9,
        tags={"confirmed"},
    )
    service = Event(
        type=EventType.HTTP_SERVICE,
        value="https://api.example.com",
        source="http:fixture",
        parent_event_id=subdomain.event_id,
        scope_state=ScopeState.IN_SCOPE,
        confidence=0.9,
        tags={"confirmed"},
        metadata={"hostname": "api.example.com", "scheme": "https", "port": 443},
    )
    endpoint = Event(
        type=EventType.URL,
        value="https://api.example.com/v1/users",
        source="crawler:fixture",
        parent_event_id=service.event_id,
        scope_state=ScopeState.IN_SCOPE,
        confidence=0.85,
        tags={"confirmed"},
    )
    technology = Event(
        type=EventType.TECHNOLOGY,
        value="nginx",
        source="http:fixture",
        parent_event_id=subdomain.event_id,
        scope_state=ScopeState.IN_SCOPE,
        confidence=0.8,
        metadata={"observed_on": "https://api.example.com/v1/users"},
    )
    try:
        for event in (root, hypothesis, subdomain, service, endpoint, technology):
            await events.ingest(event)
            await projector.project(event)
        builder = SurfaceGraphBuilder(database, target_id="fixture")
        first = await builder.build()
        second = await builder.build()

        assert first.fingerprint == second.fingerprint
        assert first.statistics.node_count == 5
        domains = [node for node in first.nodes if node.kind is SurfaceNodeKind.DOMAIN]
        assert len(domains) == 2
        apex = next(node for node in domains if node.value == "example.com")
        assert apex.observation_count == 2
        assert apex.roles == ("ROOT", "SEED")
        relations = {edge.relation for edge in first.edges}
        assert {"HAS_SUBDOMAIN", "EXPOSES_SERVICE", "HAS_ENDPOINT", "USES_TECHNOLOGY"} <= relations
        graph_path = await export_graph_json(first, tmp_path / "surface.json")
        tree_path = await export_tree_json(first, tmp_path / "tree.json")
        html_path = await export_surface_html(first, tmp_path / "surface.html")
        assert '"target_id": "fixture"' in graph_path.read_text(encoding="utf-8")
        assert '"tree"' in tree_path.read_text(encoding="utf-8")
        assert "Night Scout · Surface Graph" in html_path.read_text(encoding="utf-8")
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_surface_builder_attaches_http_status_history_to_endpoint(tmp_path) -> None:
    path = tmp_path / "http-status.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    events = EventRepository(database)
    observed_at = datetime(2026, 8, 24, 12, 0, tzinfo=UTC)
    endpoint = Event(
        type=EventType.URL,
        value="https://api.example.com/v1/users",
        source="crawler:fixture",
        tags={"confirmed"},
        first_seen=observed_at,
        last_seen=observed_at,
    )
    redirect = Event(
        type=EventType.HTTP_RESPONSE,
        value="GET https://api.example.com/v1/users -> 301",
        source="http:fixture",
        parent_event_id=endpoint.event_id,
        tags={"confirmed", "response"},
        first_seen=observed_at + timedelta(seconds=1),
        last_seen=observed_at + timedelta(seconds=1),
        metadata={
            "url": "HTTPS://API.EXAMPLE.COM:443/v1/users#fragment",
            "method": "get",
            "status_code": "301",
            "location": "https://api.example.com/v2/users",
        },
    )
    success = Event(
        type=EventType.HTTP_RESPONSE,
        value="GET https://api.example.com/v1/users -> 200",
        source="crawler:fixture",
        parent_event_id=endpoint.event_id,
        tags={"confirmed", "response"},
        first_seen=observed_at + timedelta(seconds=2),
        last_seen=observed_at + timedelta(seconds=2),
        metadata={
            "url": "https://api.example.com/v1/users",
            "method": "GET",
            "status_code": 200,
            "content_type": "application/json",
        },
    )
    timeout = Event(
        type=EventType.HTTP_RESPONSE,
        value="GET https://api.example.com/v1/users PROBE_FAILED",
        source="http:fixture:failure",
        parent_event_id=endpoint.event_id,
        tags={"negative", "probe-failed"},
        first_seen=observed_at + timedelta(seconds=3),
        last_seen=observed_at + timedelta(seconds=3),
        metadata={
            "url": "https://api.example.com/v1/users",
            "method": "GET",
            "error": "timeout",
        },
    )
    try:
        for event in (endpoint, redirect, success, timeout):
            await events.ingest(event)

        graph = await SurfaceGraphBuilder(database, target_id="fixture").build(
            SurfaceGraphFilter(include_provenance=True)
        )

        assert graph.statistics.node_count == 1
        assert graph.statistics.observations_considered == 4
        assert graph.statistics.observations_excluded == 1
        node = graph.nodes[0]
        assert node.kind is SurfaceNodeKind.ENDPOINT
        assert node.observation_count == 3
        assert node.metadata["method"] == "GET"
        assert node.metadata["status_code"] == 200
        assert "location" not in node.metadata
        http = node.metadata["http"]
        assert http["latest"]["event_id"] == success.event_id
        assert http["latest"]["content_type"] == "application/json"
        assert [item["status_code"] for item in http["history"]] == [301, 200]
        assert http["history_total"] == 2
        assert http["history_truncated"] is False
        assert {item.event_id for item in node.evidence} == {
            endpoint.event_id,
            redirect.event_id,
            success.event_id,
        }
        output = await export_surface_html(graph, tmp_path / "http-status.html")
        payload = output.read_text(encoding="utf-8")
        assert "HTTP response history" in payload
        assert "http-2xx" in payload
        assert '"status_code":200' in payload
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_surface_html_escapes_target_controlled_script_sequences(tmp_path) -> None:
    path = tmp_path / "html-safe.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    try:
        event = Event(
            type=EventType.TECHNOLOGY,
            value="</script><script>alert(1)</script>",
            source="fixture",
        )
        await EventRepository(database).ingest(event)
        snapshot = await SurfaceGraphBuilder(database, target_id="safe").build()
        output = await export_surface_html(snapshot, tmp_path / "safe.html")
        payload = output.read_text(encoding="utf-8")
        assert "</script><script>alert(1)</script>" not in payload
        assert "\\u003c/script\\u003e" in payload
        assert "let loaded=false" in payload
        assert ".slice(0,500)" in payload
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_surface_rebuild_is_idempotent(tmp_path) -> None:
    path = tmp_path / "rebuild.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    events = EventRepository(database)
    parent = Event(type=EventType.DNS_NAME, value="api.example.com", source="fixture")
    child = Event(
        type=EventType.HTTP_SERVICE,
        value="https://api.example.com",
        source="fixture",
        parent_event_id=parent.event_id,
        confidence=0.9,
    )
    try:
        await events.ingest(parent)
        await events.ingest(child)
        rebuilder = SurfaceGraphRebuilder(database)
        dry_run = await rebuilder.rebuild(dry_run=True)
        first = await rebuilder.rebuild()
        second = await rebuilder.rebuild()

        assert dry_run.candidates == 1
        assert first.edges_created == 1
        assert second.edges_created == 0
        assert second.edges_merged == 1
    finally:
        await database.dispose()


@pytest.mark.asyncio
async def test_dns_hierarchy_stops_at_public_suffix(tmp_path) -> None:
    path = tmp_path / "public-suffix.sqlite3"
    upgrade_database(path)
    database = Database.from_path(path)
    events = EventRepository(database)
    projector = SurfaceRelationshipProjector(
        events=events,
        provenance=ProvenanceRepository(database),
    )
    public_suffix = Event(type=EventType.ROOT_DOMAIN, value="co.uk", source="fixture")
    registrable = Event(type=EventType.ROOT_DOMAIN, value="example.co.uk", source="fixture")
    child = Event(
        type=EventType.DNS_NAME,
        value="api.example.co.uk",
        source="fixture",
        parent_event_id=registrable.event_id,
        tags={"confirmed"},
    )
    try:
        for event in (public_suffix, registrable, child):
            await events.ingest(event)
            await projector.project(event)

        graph = await SurfaceGraphBuilder(database, target_id="fixture").build()
        by_value = {node.value: node.node_id for node in graph.nodes}
        hierarchy = {
            (edge.source_node_id, edge.target_node_id)
            for edge in graph.edges
            if edge.relation == "HAS_SUBDOMAIN"
        }
        assert (by_value["example.co.uk"], by_value["api.example.co.uk"]) in hierarchy
        assert (by_value["co.uk"], by_value["example.co.uk"]) not in hierarchy
    finally:
        await database.dispose()
