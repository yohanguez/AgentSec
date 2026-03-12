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
    find_imports,
    find_python_files,
    parse_python_file,
)


class LangGraphAnalyzer(BaseAnalyzer):
    @property
    def framework_name(self) -> str:
        return "LangGraph"

    def analyze(self) -> GraphDefinition:
        graph = GraphDefinition(framework=self.framework_name)

        python_files = find_python_files(self.input_dir)

        all_nodes: Dict[str, NodeDefinition] = {}
        all_edges: List[EdgeDefinition] = []
        all_agents: List[AgentDefinition] = []
        tools: Set[str] = set()

        for file_path in python_files:
            tree = parse_python_file(file_path)
            if not tree:
                continue

            # Find StateGraph instantiations
            state_graphs = find_class_instantiations(tree, ["StateGraph"])

            # Find add_node calls
            add_node_calls = find_function_calls(tree, ["add_node"])
            for call in add_node_calls:
                node_name = self._extract_node_name(call)
                if node_name:
                    node = NodeDefinition(
                        id=node_name,
                        name=node_name,
                        type=NodeType.AGENT,
                        description=f"LangGraph node: {node_name}",
                    )
                    all_nodes[node_name] = node

            # Find add_edge calls
            add_edge_calls = find_function_calls(tree, ["add_edge"])
            for call in add_edge_calls:
                edge = self._extract_edge(call)
                if edge:
                    all_edges.append(edge)

            # Find add_conditional_edges calls
            conditional_calls = find_function_calls(tree, ["add_conditional_edges"])
            for call in conditional_calls:
                edges = self._extract_conditional_edges(call)
                all_edges.extend(edges)

            # Find tool bindings
            bind_tools_calls = find_function_calls(tree, ["bind_tools"])
            for call in bind_tools_calls:
                detected_tools = self._extract_tools_from_bind(call)
                tools.update(detected_tools)

            # Extract system prompts and create agents
            imports = find_imports(tree)
            agent = self._extract_agent_info(tree, imports)
            if agent:
                all_agents.append(agent)

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

        # Add START and END nodes if we have a graph
        if all_nodes:
            start_node = NodeDefinition(
                id="START", name="START", type=NodeType.BASIC, description="Start node"
            )
            end_node = NodeDefinition(
                id="END", name="END", type=NodeType.BASIC, description="End node"
            )
            all_nodes["START"] = start_node
            all_nodes["END"] = end_node

        graph.nodes = list(all_nodes.values())
        graph.edges = all_edges
        graph.agents = all_agents

        return graph

    def _extract_node_name(self, call: ast.Call) -> str:
        if len(call.args) >= 1:
            if isinstance(call.args[0], ast.Constant):
                return str(call.args[0].value)
            elif isinstance(call.args[0], ast.Str):
                return call.args[0].s
        return ""

    def _extract_edge(self, call: ast.Call) -> EdgeDefinition:
        if len(call.args) >= 2:
            source = self._extract_arg_value(call.args[0])
            target = self._extract_arg_value(call.args[1])
            if source and target:
                return EdgeDefinition(source=source, target=target)
        return None

    def _extract_conditional_edges(self, call: ast.Call) -> List[EdgeDefinition]:
        edges = []
        if len(call.args) >= 2:
            source = self._extract_arg_value(call.args[0])
            if source:
                # Try to extract condition dict (simplified)
                edges.append(EdgeDefinition(source=source, target="conditional_target"))
        return edges

    def _extract_arg_value(self, arg: ast.expr) -> str:
        if isinstance(arg, ast.Constant):
            return str(arg.value)
        elif isinstance(arg, ast.Str):
            return arg.s
        elif isinstance(arg, ast.Name):
            return arg.id
        return ""

    def _extract_tools_from_bind(self, call: ast.Call) -> Set[str]:
        tools = set()
        if len(call.args) >= 1:
            if isinstance(call.args[0], ast.List):
                for elt in call.args[0].elts:
                    if isinstance(elt, ast.Name):
                        tools.add(elt.id)
        return tools

    def _extract_agent_info(self, tree: ast.AST, imports: Set[str]) -> AgentDefinition:
        # Look for ChatOpenAI, ChatAnthropic, etc.
        llm_classes = ["ChatOpenAI", "ChatAnthropic", "ChatGooglePalm", "Ollama"]
        llm_instantiations = find_class_instantiations(tree, llm_classes)

        if llm_instantiations:
            llm_model = "LLM"
            # Try to extract model name
            for inst in llm_instantiations:
                model = extract_string_argument(inst, "model")
                if model:
                    llm_model = model
                    break

            # Try to find system prompt
            system_prompt = None
            for node in ast.walk(tree):
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name) and "prompt" in target.id.lower():
                            if isinstance(node.value, ast.Constant):
                                system_prompt = str(node.value.value)
                            elif isinstance(node.value, ast.Str):
                                system_prompt = node.value.s

            return AgentDefinition(
                name="LangGraph Agent",
                llm_model=llm_model,
                system_prompt=system_prompt,
                has_guardrails=False,
            )
        return None

    def _categorize_tool(self, tool_name: str) -> ToolCategory:
        tool_lower = tool_name.lower()
        if "search" in tool_lower or "duckduckgo" in tool_lower or "tavily" in tool_lower:
            return ToolCategory.WEB_SEARCH
        elif "python" in tool_lower or "repl" in tool_lower or "code" in tool_lower:
            return ToolCategory.CODE_INTERPRETER
        elif "file" in tool_lower or "pdf" in tool_lower or "document" in tool_lower:
            return ToolCategory.DOCUMENT_LOADER
        elif "chat" in tool_lower or "llm" in tool_lower or "gpt" in tool_lower:
            return ToolCategory.LLM
        elif "sql" in tool_lower or "database" in tool_lower or "db" in tool_lower:
            return ToolCategory.DATABASE
        return ToolCategory.DEFAULT
