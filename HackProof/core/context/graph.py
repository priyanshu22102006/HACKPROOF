"""In-memory directed Evidence Graph for entity-level correlation."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any


class NodeType:
    REPOSITORY = "Repository"
    FILE = "File"
    COMMIT = "Commit"
    AUTHOR = "Author"
    EMAIL = "Email"
    KEY = "Key"
    TIMESTAMP = "Timestamp"
    GITHUB_EVENT = "GitHubEvent"
    SIMILARITY_CANDIDATE = "SimilarityCandidate"


class EdgeType:
    AUTHORED_BY = "AUTHORED_BY"
    SIGNED_BY = "SIGNED_BY"
    MATCHES = "MATCHES"
    BLAMED_TO = "BLAMED_TO"
    INTRODUCED_BY = "INTRODUCED_BY"
    PUSHED_IN = "PUSHED_IN"
    OCCURRED_AT = "OCCURRED_AT"
    PREDATES = "PREDATES"
    HIDDEN_BY = "HIDDEN_BY"
    RELATED_TO = "RELATED_TO"


@dataclass
class GraphNode:
    id: str
    type: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "attrs": self.attrs,
        }


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str
    attrs: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "type": self.type,
            "attrs": self.attrs,
        }


class EvidenceGraph:
    """Directed graph representing entities and relationships across security findings."""

    def __init__(self) -> None:
        self.nodes: dict[str, GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self._adj_out: dict[str, list[GraphEdge]] = {}
        self._adj_in: dict[str, list[GraphEdge]] = {}

    def add_node(self, id: str, type: str, attrs: dict[str, Any] | None = None) -> GraphNode:
        if id in self.nodes:
            if attrs:
                self.nodes[id].attrs.update(attrs)
            return self.nodes[id]

        node = GraphNode(id=id, type=type, attrs=attrs or {})
        self.nodes[id] = node
        self._adj_out[id] = []
        self._adj_in[id] = []
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        type: str,
        attrs: dict[str, Any] | None = None,
    ) -> GraphEdge:
        if source not in self.nodes:
            self.add_node(source, NodeType.FILE if "/" in source else "Entity")
        if target not in self.nodes:
            self.add_node(target, NodeType.FILE if "/" in target else "Entity")

        edge = GraphEdge(source=source, target=target, type=type, attrs=attrs or {})
        self.edges.append(edge)
        self._adj_out.setdefault(source, []).append(edge)
        self._adj_in.setdefault(target, []).append(edge)
        return edge

    def get_node(self, id: str) -> GraphNode | None:
        return self.nodes.get(id)

    def get_edges(
        self,
        source: str | None = None,
        target: str | None = None,
        type: str | None = None,
    ) -> list[GraphEdge]:
        if source is not None:
            candidates = self._adj_out.get(source, [])
        elif target is not None:
            candidates = self._adj_in.get(target, [])
        else:
            candidates = self.edges

        res = []
        for e in candidates:
            if source is not None and e.source != source:
                continue
            if target is not None and e.target != target:
                continue
            if type is not None and e.type != type:
                continue
            res.append(e)
        return res

    def neighbors(self, node_id: str, direction: str = "both") -> list[str]:
        """Return connected node IDs."""
        result: set[str] = set()
        if direction in ("out", "both"):
            for e in self._adj_out.get(node_id, []):
                result.add(e.target)
        if direction in ("in", "both"):
            for e in self._adj_in.get(node_id, []):
                result.add(e.source)
        return list(result)

    def connected_component(self, start_node_id: str) -> set[str]:
        """Return all node IDs reachable via undirected traversal from start_node_id."""
        visited: set[str] = set()
        queue = [start_node_id]
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            for nbr in self.neighbors(curr, direction="both"):
                if nbr not in visited:
                    queue.append(nbr)
        return visited

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges],
        }
