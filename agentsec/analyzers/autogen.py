import ast
from pathlib import Path
from typing import Dict, List, Set

from agentsec.analyzers.base import BaseAnalyzer
from agentsec.models import (
    AgentDefinition,
    EdgeDefinition,
    GraphDefinition,
    NodeDefinition,
    NodeType,
    ToolCategory,
)
from agentsec.utils import (
    extract_string_argument,
    find_class_instantiations,
    find_python_files,
    parse_python_file,
)


class AutogenAnalyzer(BaseAnalyzer):
    @property
    def framework_name(self) -> str:
        return "Autogen"

    def analyze(self) -> GraphDefinition:
        graph = GraphDefinition(framework=self.framework_name)

        all_agents: List[AgentDefinition] = []
        all_nodes: Dict[str, NodeDefinition] = {}
        all_edges: List[EdgeDefinition] = []
        tools: Set[str] = set()

        python_files = find_python_files(self.input_dir)

        for file_path in python_files:
            tree = parse_python_file(file_path)
            if not tree:
                continue

            # Find ConversableAgent instantiations
            agent_classes = ["ConversableAgent", "AssistantAgent", "UserProxyAgent"]
            agent_calls = find_class_instantiations(tree, agent_classes)
            for call in agent_calls:
                agent = self._extract_agent_from_call(call)
                if agent:
                    all_agents.append(agent)
                    # Add agent as node
                    node = NodeDefinition(
                        id=f"agent_{agent.name}",
                        name=agent.name,
                        type=NodeType.AGENT,
                        description=f"Autogen Agent: {agent.name}",
                    )
                    all_nodes[node.id] = node

            # Find GroupChat instantiations to identify agent connections
            groupchat_calls = find_class_instantiations(tree, ["GroupChat"])
            for call in groupchat_calls:
                edges = self._extract_groupchat_edges(call)
                all_edges.extend(edges)

            # Extract tools from function registration
            detected_tools = self._extract_tools_from_tree(tree)
            tools.update(detected_tools)

        # Add tool nodes
        for tool_name in tools:
            tool_node = NodeDefinition(
                id=f"tool_{tool_name}",
                name=tool_name,
                type=NodeType.TOOL,
                category=self._categorize_tool(tool_name),
                description=f"Tool: {tool_name}",
            )
            all_nodes[tool_node.id] = tool_node

        graph.nodes = list(all_nodes.values())
        graph.edges = all_edges
        graph.agents = all_agents

        return graph

    def _extract_agent_from_call(self, call: ast.Call) -> AgentDefinition:
        name = extract_string_argument(call, "name")
        system_message = extract_string_argument(call, "system_message")
        llm_config = extract_string_argument(call, "llm_config")

        if name:
            return AgentDefinition(
                name=name,
                llm_model="gpt-4" if llm_config else "LLM",
                system_prompt=system_message,
                has_guardrails=False,
            )
        return None

    def _extract_groupchat_edges(self, call: ast.Call) -> List[EdgeDefinition]:
        edges = []
        # Try to find agents parameter
        for keyword in call.keywords:
            if keyword.arg == "agents" and isinstance(keyword.value, ast.List):
                # Create edges between consecutive agents
                agents = []
                for elt in keyword.value.elts:
                    if isinstance(elt, ast.Name):
                        agents.append(f"agent_{elt.id}")

                for i in range(len(agents) - 1):
                    edge = EdgeDefinition(source=agents[i], target=agents[i + 1])
                    edges.append(edge)
        return edges

    def _extract_tools_from_tree(self, tree: ast.AST) -> Set[str]:
        tools = set()
        for node in ast.walk(tree):
            # Look for register_function calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "register_function":
                    if len(node.args) >= 1 and isinstance(node.args[0], ast.Name):
                        tools.add(node.args[0].id)
        return tools

    def _categorize_tool(self, tool_name: str) -> ToolCategory:
        tool_lower = tool_name.lower()
        if "search" in tool_lower:
            return ToolCategory.WEB_SEARCH
        elif "code" in tool_lower or "execute" in tool_lower:
            return ToolCategory.CODE_INTERPRETER
        elif "file" in tool_lower:
            return ToolCategory.DOCUMENT_LOADER
        return ToolCategory.DEFAULT
