"""Reachability / taint engine over the agent workflow graph.

We build a directed "taint graph" whose edges model how data and control can
flow through a multi-agent system:

    agent  --> owned tool     (the agent can invoke the tool)
    tool   --> owning agent   (the tool's result flows back into the agent)
    agent  --> agent          (an explicit handoff edge from the workflow)

Given that graph we answer two questions:

  * reachable_capabilities(agent): every capability an agent can ultimately
    exercise, directly or by handing off to another agent.
  * attack_paths(): every simple path from an untrusted *source* node to a
    dangerous *sink* node, bounded in depth.

This is path-based taint (reachability of capability), not value-level
dataflow. Confidence is labelled honestly: a source and sink owned by the
same agent is HIGH confidence; a path that crosses an agent handoff is MEDIUM.
"""

from collections import defaultdict, deque
from typing import Dict, List, Set

from agentsec.models import (
    AttackPath,
    Capability,
    Confidence,
    GraphDefinition,
    NodeType,
)


class ReachabilityEngine:
    MAX_PATH_DEPTH = 8

    def __init__(self, graph: GraphDefinition):
        self.graph = graph
        self.adj: Dict[str, Set[str]] = defaultdict(set)
        self._agent_of_tool: Dict[str, Set[str]] = defaultdict(set)
        self._agent_node_ids: Set[str] = set()
        self._build()

    def _build(self) -> None:
        node_ids = {n.id for n in self.graph.nodes}

        # agent <-> owned tool (bidirectional: invoke + result flows back)
        for agent in self.graph.agents:
            an = agent.node_id
            if not an:
                continue
            self._agent_node_ids.add(an)
            for tid in agent.tool_ids:
                if tid in node_ids:
                    self.adj[an].add(tid)
                    self.adj[tid].add(an)
                    self._agent_of_tool[tid].add(an)

        # explicit handoff edges (directed)
        for edge in self.graph.edges:
            if edge.source in node_ids and edge.target in node_ids:
                self.adj[edge.source].add(edge.target)

    # ------------------------------------------------------------------ #
    # Per-agent reachable capabilities
    # ------------------------------------------------------------------ #
    def reachable_capabilities(self, agent_node_id: str) -> List[Capability]:
        if not agent_node_id:
            return []
        caps: Set[Capability] = set()
        for nid in self._bfs(agent_node_id):
            node = self.graph.get_node(nid)
            if node and node.type in (
                NodeType.TOOL,
                NodeType.CUSTOM_TOOL,
                NodeType.MCP_SERVER,
            ):
                caps.update(node.capabilities)
        return sorted(caps, key=lambda c: c.value)

    def reachable_source_nodes(self, agent_node_id: str) -> List[str]:
        out = []
        for nid in self._bfs(agent_node_id):
            node = self.graph.get_node(nid)
            if node and node.is_source:
                out.append(nid)
        return out

    def _bfs(self, start: str) -> Set[str]:
        seen: Set[str] = set()
        q = deque([start])
        while q:
            cur = q.popleft()
            if cur in seen:
                continue
            seen.add(cur)
            for nxt in self.adj.get(cur, ()):
                if nxt not in seen:
                    q.append(nxt)
        return seen

    # ------------------------------------------------------------------ #
    # Source -> sink attack paths
    # ------------------------------------------------------------------ #
    def attack_paths(self) -> List[AttackPath]:
        sources = [n for n in self.graph.nodes if n.is_source]
        sinks = [n for n in self.graph.nodes if n.is_sink()]

        # Deduplicate by (sink, capability): many untrusted sources can reach the
        # same sink, but the actionable finding is "this sink is reachable by
        # untrusted input". Keep the strongest representative (HIGH > MEDIUM,
        # then shortest path).
        best: Dict[str, AttackPath] = {}
        for src in sources:
            for sink in sinks:
                if src.id == sink.id:
                    continue
                simple = self._simple_paths(src.id, sink.id)
                if not simple:
                    continue
                node_path = simple[0]
                conf = self._confidence(node_path)
                for cap in sink.sink_capabilities():
                    key = "%s|%s" % (sink.id, cap.value)
                    candidate = AttackPath(
                        source_id=src.id,
                        sink_id=sink.id,
                        node_ids=node_path,
                        sink_capability=cap,
                        confidence=conf,
                    )
                    if key not in best or self._is_better(candidate, best[key]):
                        best[key] = candidate
        return list(best.values())

    @staticmethod
    def _is_better(a: AttackPath, b: AttackPath) -> bool:
        rank = {Confidence.HIGH: 0, Confidence.MEDIUM: 1, Confidence.LOW: 2}
        if rank[a.confidence] != rank[b.confidence]:
            return rank[a.confidence] < rank[b.confidence]
        return len(a.node_ids) < len(b.node_ids)

    def _simple_paths(self, start: str, goal: str) -> List[List[str]]:
        """Return simple paths start->goal, shortest-first, bounded in depth."""
        results: List[List[str]] = []
        stack = [(start, [start])]
        while stack:
            node, path = stack.pop()
            if len(path) > self.MAX_PATH_DEPTH:
                continue
            if node == goal:
                results.append(path)
                continue
            for nxt in sorted(self.adj.get(node, ())):
                if nxt not in path:
                    stack.append((nxt, path + [nxt]))
        results.sort(key=len)
        return results

    def _confidence(self, node_path: List[str]) -> Confidence:
        """HIGH when a single agent owns both source and sink; MEDIUM across a handoff."""
        agents_on_path = [nid for nid in node_path if nid in self._agent_node_ids]
        if len(agents_on_path) <= 1:
            return Confidence.HIGH
        return Confidence.MEDIUM
