import json
from pathlib import Path
from typing import Dict, List

from agentsec.analyzers.base import BaseAnalyzer
from agentsec.models import (
    EdgeDefinition,
    GraphDefinition,
    NodeDefinition,
    NodeType,
    ToolCategory,
)
from agentsec.utils import find_json_files


class N8NAnalyzer(BaseAnalyzer):
    @property
    def framework_name(self) -> str:
        return "n8n"

    def analyze(self) -> GraphDefinition:
        graph = GraphDefinition(framework=self.framework_name)

        all_nodes: Dict[str, NodeDefinition] = {}
        all_edges: List[EdgeDefinition] = []

        json_files = find_json_files(self.input_dir)

        for file_path in json_files:
            workflow_data = self._load_workflow_json(file_path)
            if not workflow_data:
                continue

            # Parse nodes
            nodes = workflow_data.get("nodes", [])
            for node_data in nodes:
                node = self._parse_node(node_data)
                if node:
                    all_nodes[node.id] = node

            # Parse connections
            connections = workflow_data.get("connections", {})
            edges = self._parse_connections(connections)
            all_edges.extend(edges)

        graph.nodes = list(all_nodes.values())
        graph.edges = all_edges

        return graph

    def _load_workflow_json(self, file_path: Path) -> dict:
        try:
            with open(file_path, "r") as f:
                data = json.load(f)

            # Validate it's an n8n workflow
            if "nodes" in data and "connections" in data:
                return data
        except Exception as e:
            print(f"Warning: Failed to parse JSON {file_path}: {e}")

        return None

    def _parse_node(self, node_data: dict) -> NodeDefinition:
        node_id = node_data.get("id") or node_data.get("name")
        node_type = node_data.get("type", "")
        node_name = node_data.get("name", node_id)

        category = self._categorize_n8n_node(node_type)

        return NodeDefinition(
            id=node_id,
            name=node_name,
            type=NodeType.TOOL,
            category=category,
            description=f"n8n node: {node_type}",
        )

    def _parse_connections(self, connections: dict) -> List[EdgeDefinition]:
        edges = []
        for source_name, outputs in connections.items():
            if isinstance(outputs, dict):
                for output_type, connections_list in outputs.items():
                    if isinstance(connections_list, list):
                        for connection in connections_list:
                            for target in connection:
                                target_name = target.get("node")
                                if target_name:
                                    edge = EdgeDefinition(source=source_name, target=target_name)
                                    edges.append(edge)
        return edges

    def _categorize_n8n_node(self, node_type: str) -> ToolCategory:
        node_lower = node_type.lower()

        if "http" in node_lower or "webhook" in node_lower:
            return ToolCategory.WEB_SEARCH
        elif "code" in node_lower or "function" in node_lower:
            return ToolCategory.CODE_INTERPRETER
        elif "file" in node_lower or "read" in node_lower or "write" in node_lower:
            return ToolCategory.DOCUMENT_LOADER
        elif "sql" in node_lower or "mysql" in node_lower or "postgres" in node_lower:
            return ToolCategory.DATABASE
        elif "openai" in node_lower or "anthropic" in node_lower:
            return ToolCategory.LLM

        return ToolCategory.DEFAULT
