"""Rooted, cycle-safe presentation projection of a surface graph."""

from __future__ import annotations

from collections import defaultdict
from typing import Any

from recon.surface.models import SurfaceEdge, SurfaceGraphSnapshot, SurfaceNode

_RELATION_PRIORITY = {
    "HAS_SUBDOMAIN": 10,
    "EXPOSES_SERVICE": 20,
    "HAS_CHILD_PATH": 25,
    "HAS_ENDPOINT": 30,
    "HAS_DNS_RECORD": 40,
    "RESOLVES_TO": 41,
    "ALIASES_TO": 42,
    "PRESENTS_CERTIFICATE": 50,
    "CERTIFICATE_NAMES": 51,
    "USES_TECHNOLOGY": 60,
    "HAS_PARAMETER": 61,
    "REFERENCES": 62,
    "HAS_FINGERPRINT": 63,
    "POTENTIALLY_AFFECTED_BY": 70,
    "CONFIRMED_AFFECTED_BY": 71,
    "RELATED_TO": 90,
}


def build_tree_projection(snapshot: SurfaceGraphSnapshot) -> dict[str, Any]:
    nodes = {node.node_id: node for node in snapshot.nodes}
    incoming: dict[str, list[SurfaceEdge]] = defaultdict(list)
    for edge in snapshot.edges:
        incoming[edge.target_node_id].append(edge)

    primary: dict[str, SurfaceEdge] = {}
    for target, candidates in incoming.items():
        primary[target] = min(candidates, key=lambda edge: _parent_rank(edge, nodes))

    children: dict[str, list[SurfaceEdge]] = defaultdict(list)
    related: dict[str, list[SurfaceEdge]] = defaultdict(list)
    for edge in snapshot.edges:
        if primary.get(edge.target_node_id) == edge:
            children[edge.source_node_id].append(edge)
        else:
            related[edge.source_node_id].append(edge)
    for values in children.values():
        values.sort(key=lambda edge: _child_rank(edge, nodes))
    for values in related.values():
        values.sort(key=lambda edge: _child_rank(edge, nodes))

    roots = list(snapshot.roots)
    roots.extend(
        node.node_id
        for node in snapshot.nodes
        if node.node_id not in incoming and node.node_id not in roots
    )
    seen: set[str] = set()

    def visit(node_id: str, ancestry: frozenset[str]) -> dict[str, Any]:
        node = nodes[node_id]
        if node_id in seen or node_id in ancestry:
            return {"$ref": node_id, "label": node.label}
        seen.add(node_id)
        next_ancestry = ancestry | {node_id}
        item: dict[str, Any] = {
            "node": _tree_node(node),
            "children": [],
        }
        for edge in children.get(node_id, []):
            child = visit(edge.target_node_id, next_ancestry)
            child["relation"] = edge.relation
            item["children"].append(child)
        references = [
            {
                "$ref": edge.target_node_id,
                "label": nodes[edge.target_node_id].label,
                "relation": edge.relation,
            }
            for edge in related.get(node_id, [])
            if edge.target_node_id in nodes
        ]
        if references:
            item["references"] = references
        return item

    forest = [visit(root, frozenset()) for root in roots if root in nodes]
    forest.extend(
        visit(node.node_id, frozenset()) for node in snapshot.nodes if node.node_id not in seen
    )
    return {
        "schema_version": snapshot.schema_version,
        "target_id": snapshot.target_id,
        "generated_at": snapshot.generated_at.isoformat(),
        "fingerprint": snapshot.fingerprint,
        "statistics": snapshot.statistics.model_dump(mode="json"),
        "warnings": list(snapshot.warnings),
        "tree": forest,
    }


def _tree_node(node: SurfaceNode) -> dict[str, Any]:
    return {
        "id": node.node_id,
        "kind": node.kind.value,
        "value": node.value,
        "label": node.label,
        "roles": list(node.roles),
        "scope_state": node.scope_state.value,
        "discovery_state": node.discovery_state.value,
        "liveness_state": node.liveness_state.value,
        "confidence": node.confidence,
        "observation_count": node.observation_count,
        "sources": list(node.sources),
        "metadata": node.metadata,
    }


def _parent_rank(edge: SurfaceEdge, nodes: dict[str, SurfaceNode]) -> tuple[int, str, str]:
    priority = _RELATION_PRIORITY.get(edge.relation, 80)
    if edge.relation == "HAS_CHILD_PATH":
        priority = 15
    source = nodes.get(edge.source_node_id)
    return (priority, source.value if source is not None else "", edge.source_node_id)


def _child_rank(edge: SurfaceEdge, nodes: dict[str, SurfaceNode]) -> tuple[int, str, str]:
    target = nodes.get(edge.target_node_id)
    return (
        _RELATION_PRIORITY.get(edge.relation, 80),
        target.value if target is not None else "",
        edge.target_node_id,
    )
