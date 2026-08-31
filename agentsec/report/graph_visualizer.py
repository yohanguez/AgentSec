import pydot
from typing import Set, Tuple

from agentsec.models import GraphDefinition, NodeType


class GraphVisualizer:
    def generate_svg(self, graph: GraphDefinition) -> str:
        dot_graph = pydot.Dot(graph_type="digraph", rankdir="LR")
        dot_graph.set_node_defaults(fontname="Arial", fontsize="10")
        dot_graph.set_edge_defaults(fontname="Arial", fontsize="9")

        # Directed edges that lie on an attack path get highlighted red.
        path_nodes: Set[str] = set(graph.attack_path_node_ids())
        path_edges: Set[Tuple[str, str]] = set()
        for f in graph.findings:
            if f.path:
                ids = f.path.node_ids
                for a, b in zip(ids, ids[1:]):
                    path_edges.add((a, b))

        # agent -> owned tool ownership pairs.
        ownership: Set[Tuple[str, str]] = set()
        for a in graph.agents:
            if a.node_id:
                for tid in a.tool_ids:
                    ownership.add((a.node_id, tid))

        grade_by_node = {a.node_id: a.privilege_grade for a in graph.agents if a.node_id}

        for node in graph.nodes:
            dot_graph.add_node(
                self._create_dot_node(node, node.id in path_nodes, grade_by_node.get(node.id))
            )

        drawn: Set[Tuple[str, str]] = set()

        # 1. Workflow handoff edges (red if on an attack path).
        for edge in graph.edges:
            directed = (edge.source, edge.target)
            on_path = directed in path_edges
            kwargs = {"label": edge.condition or ""}
            if on_path:
                kwargs.update({"color": "#C0392B", "penwidth": "2.5"})
            dot_graph.add_edge(
                pydot.Edge(self._sanitize(edge.source), self._sanitize(edge.target), **kwargs)
            )
            drawn.add(directed)

        # 2. Ownership edges — grey/dashed for context, UNLESS the pair is on an
        #    attack path (in which case the red path edge below represents it).
        for (aid, tid) in sorted(ownership):
            if (aid, tid) in path_edges or (tid, aid) in path_edges:
                continue
            dot_graph.add_edge(
                pydot.Edge(
                    self._sanitize(aid), self._sanitize(tid),
                    dir="none", style="dashed", color="#AEB6BF", penwidth="1",
                )
            )

        # 3. Explicit red attack-path segments not already drawn (e.g. the
        #    source->agent and agent->sink hops that aren't workflow handoffs).
        for (u, v) in path_edges:
            if (u, v) in drawn:
                continue
            dot_graph.add_edge(
                pydot.Edge(self._sanitize(u), self._sanitize(v), color="#C0392B", penwidth="2.5")
            )

        try:
            svg_data = dot_graph.create_svg()
            if isinstance(svg_data, bytes):
                return svg_data.decode("utf-8")
            return svg_data
        except Exception as e:
            print(f"Warning: Failed to generate SVG: {e}")
            return self._generate_fallback_svg(graph)

    @staticmethod
    def _sanitize(node_id: str) -> str:
        return node_id.replace('"', "").replace("'", "").replace(" ", "_")

    def _create_dot_node(self, node, on_attack_path: bool, grade) -> pydot.Node:
        style_map = {
            NodeType.AGENT: {"shape": "box", "style": '"rounded,filled"', "fillcolor": "#5DADE2", "color": "#2874A6"},
            NodeType.TOOL: {"shape": "ellipse", "style": '"filled"', "fillcolor": "#F8B400", "color": "#D68910"},
            NodeType.CUSTOM_TOOL: {"shape": "ellipse", "style": '"filled"', "fillcolor": "#F39C12", "color": "#B9770E"},
            NodeType.MCP_SERVER: {"shape": "hexagon", "style": '"filled"', "fillcolor": "#AF7AC5", "color": "#7D3C98"},
            NodeType.BASIC: {"shape": "circle", "style": '"filled"', "fillcolor": "#52BE80", "color": "#27AE60"},
        }
        style = dict(style_map.get(node.type, style_map[NodeType.BASIC]))

        label = node.name.replace('"', '\\"')

        # Agent grade badge.
        if grade:
            label += f"\\n[grade {grade}]"
            if grade == "F":
                style["fillcolor"] = "#E74C3C"
                style["color"] = "#922B21"
            elif grade == "D":
                style["fillcolor"] = "#EB984E"

        # Tool capability badge.
        if node.type in (NodeType.TOOL, NodeType.CUSTOM_TOOL) and node.capabilities:
            caps = ",".join(c.value for c in node.capabilities)
            label += f"\\n({caps})"
        if node.is_source:
            label += "\\n[untrusted source]"

        # Red highlight for anything on an attack path.
        if on_attack_path:
            style["color"] = "#C0392B"
            style["penwidth"] = "3"

        node_id = self._sanitize(node.id)
        return pydot.Node(node_id, label=label, **style)

    def _generate_fallback_svg(self, graph: GraphDefinition) -> str:
        return f"""
        <svg width="400" height="200" xmlns="http://www.w3.org/2000/svg">
            <rect width="400" height="200" fill="#f0f0f0"/>
            <text x="200" y="100" text-anchor="middle" font-family="Arial" font-size="14">
                Graph visualization unavailable
            </text>
            <text x="200" y="120" text-anchor="middle" font-family="Arial" font-size="12">
                ({len(graph.nodes)} nodes, {len(graph.edges)} edges)
            </text>
        </svg>
        """
