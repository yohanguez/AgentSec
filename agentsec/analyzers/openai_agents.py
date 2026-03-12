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
    find_function_calls,
    find_python_files,
    parse_python_file,
)


class OpenAIAgentsAnalyzer(BaseAnalyzer):
    @property
    def framework_name(self) -> str:
        return "OpenAI Agents"

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

            # Find Agent() instantiations
            agent_calls = find_class_instantiations(tree, ["Agent"])
            for call in agent_calls:
                agent = self._extract_agent_from_call(call)
                if agent:
                    all_agents.append(agent)
                    # Add agent as node
                    node = NodeDefinition(
                        id=f"agent_{agent.name}",
                        name=agent.name,
                        type=NodeType.AGENT,
                        description=f"OpenAI Agent: {agent.name}",
                    )
                    all_nodes[node.id] = node

            # Find handoffs (transfer_to_agent patterns)
            handoff_calls = find_function_calls(tree, ["transfer_to_agent", "handoff"])
            for call in handoff_calls:
                edge = self._extract_handoff_edge(call)
                if edge:
                    all_edges.append(edge)

            # Extract tools from function definitions
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
        instructions = extract_string_argument(call, "instructions")
        model = extract_string_argument(call, "model")

        if name:
            return AgentDefinition(
                name=name,
                llm_model=model or "gpt-4",
                system_prompt=instructions,
                has_guardrails=False,
            )
        return None

    def _extract_handoff_edge(self, call: ast.Call) -> EdgeDefinition:
        if len(call.args) >= 1:
            target = self._extract_arg_value(call.args[0])
            if target:
                return EdgeDefinition(source="current_agent", target=f"agent_{target}")
        return None

    def _extract_arg_value(self, arg: ast.expr) -> str:
        if isinstance(arg, ast.Constant):
            return str(arg.value)
        elif isinstance(arg, ast.Str):
            return arg.s
        elif isinstance(arg, ast.Name):
            return arg.id
        return ""

    def _extract_tools_from_tree(self, tree: ast.AST) -> Set[str]:
        tools = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                # Check if function has @tool decorator or is passed to Agent
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Name) and decorator.id == "tool":
                        tools.add(node.name)
        return tools

    def _categorize_tool(self, tool_name: str) -> ToolCategory:
        tool_lower = tool_name.lower()
        if "search" in tool_lower:
            return ToolCategory.WEB_SEARCH
        elif "code" in tool_lower or "execute" in tool_lower:
            return ToolCategory.CODE_INTERPRETER
        elif "file" in tool_lower or "read" in tool_lower:
            return ToolCategory.DOCUMENT_LOADER
        return ToolCategory.DEFAULT
