import pydot
from typing import Optional

from agentsec.models import GraphDefinition, NodeType


class GraphVisualizer:
    def generate_svg(self, graph: GraphDefinition) -> str:
        dot_graph = pydot.Dot(graph_type="digraph", rankdir="TB")
        dot_graph.set_node_defaults(fontname="Arial", fontsize="10")
        dot_graph.set_edge_defaults(fontname="Arial", fontsize="9")

        # Add nodes
        for node in graph.nodes:
            dot_node = self._create_dot_node(node)
            dot_graph.add_node(dot_node)

        # Add edges
        for edge in graph.edges:
            # Sanitize edge source/target IDs
            source_id = edge.source.replace('"', '').replace("'", "").replace(" ", "_")
            target_id = edge.target.replace('"', '').replace("'", "").replace(" ", "_")
            label = edge.condition if edge.condition else ""
            dot_edge = pydot.Edge(source_id, target_id, label=label)
            dot_graph.add_edge(dot_edge)

        # Generate SVG
        try:
            svg_data = dot_graph.create_svg()
            if isinstance(svg_data, bytes):
                return svg_data.decode("utf-8")
            return svg_data
        except Exception as e:
            print(f"Warning: Failed to generate SVG: {e}")
            return self._generate_fallback_svg(graph)

    def _create_dot_node(self, node) -> pydot.Node:
        style_map = {
            NodeType.AGENT: {
                "shape": "box",
                "style": '"rounded,filled"',
                "fillcolor": "#5DADE2",
                "color": "#2874A6",
            },
            NodeType.TOOL: {
                "shape": "ellipse",
                "style": '"filled"',
                "fillcolor": "#F8B400",
                "color": "#D68910",
            },
            NodeType.CUSTOM_TOOL: {
                "shape": "ellipse",
                "style": '"filled"',
                "fillcolor": "#F39C12",
                "color": "#B9770E",
            },
            NodeType.MCP_SERVER: {
                "shape": "hexagon",
                "style": '"filled"',
                "fillcolor": "#AF7AC5",
                "color": "#7D3C98",
            },
            NodeType.BASIC: {
                "shape": "circle",
                "style": '"filled"',
                "fillcolor": "#52BE80",
                "color": "#27AE60",
            },
        }

        style = style_map.get(node.type, style_map[NodeType.BASIC])

        # Add vulnerability indicator - escape special characters
        label = node.name.replace('"', '\\"')
        if node.vulnerabilities:
            # Use parentheses instead of square brackets to avoid DOT syntax issues
            label += f"\\n({len(node.vulnerabilities)} vuln)"

        # Sanitize node ID for Graphviz
        node_id = node.id.replace('"', '').replace("'", "").replace(" ", "_")

        return pydot.Node(
            node_id,
            label=label,
            **style,
        )

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
