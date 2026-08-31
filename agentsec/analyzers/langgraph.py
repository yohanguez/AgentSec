import ast
from pathlib import Path
from typing import Dict, List, Optional, Set

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
        loose_tools: Set[str] = set()

        # var_name -> [tool display names]  (from create_react_agent assignments)
        agent_var_tools: Dict[str, List[str]] = {}
        # node name -> agent var name  (from add_node("name", var))
        node_to_var: Dict[str, str] = {}
        # var_name -> model string
        agent_var_model: Dict[str, str] = {}

        for file_path in python_files:
            tree = parse_python_file(file_path)
            if not tree:
                continue

            self._collect_react_agents(tree, agent_var_tools, agent_var_model)

            # add_node calls (create AGENT nodes + record var mapping)
            for call in find_function_calls(tree, ["add_node"]):
                node_name = self._extract_node_name(call)
                if node_name:
                    all_nodes[node_name] = NodeDefinition(
                        id=node_name,
                        name=node_name,
                        type=NodeType.AGENT,
                        description=f"LangGraph node: {node_name}",
                    )
                    var = self._second_arg_name(call)
                    if var:
                        node_to_var[node_name] = var

            # edges
            for call in find_function_calls(tree, ["add_edge"]):
                edge = self._extract_edge(call)
                if edge:
                    all_edges.append(edge)
            for call in find_function_calls(tree, ["add_conditional_edges"]):
                all_edges.extend(self._extract_conditional_edges(call))

            # legacy bind_tools (tools not attributed to a specific agent)
            for call in find_function_calls(tree, ["bind_tools"]):
                loose_tools.update(self._extract_tools_from_bind(call))

            # entry point -> edge from START
            for call in find_function_calls(tree, ["set_entry_point"]):
                name = self._extract_node_name(call)
                if name:
                    all_edges.append(EdgeDefinition(source="START", target=name))

        # Build agents + attributed tool nodes.
        for node_name, node in list(all_nodes.items()):
            if node.type != NodeType.AGENT:
                continue
            var = node_to_var.get(node_name)
            tool_names = agent_var_tools.get(var, []) if var else []
            tool_ids: List[str] = []
            for tname in tool_names:
                tid = f"tool_{tname}"
                if tid not in all_nodes:
                    all_nodes[tid] = NodeDefinition(
                        id=tid,
                        name=tname,
                        type=NodeType.TOOL,
                        category=self._categorize_tool(tname),
                        description=f"Tool: {tname}",
                    )
                tool_ids.append(tid)
            all_agents.append(
                AgentDefinition(
                    name=node_name,
                    llm_model=agent_var_model.get(var, "LLM") if var else "LLM",
                    system_prompt=None,
                    has_guardrails=False,
                    node_id=node_name,
                    tool_ids=tool_ids,
                )
            )

        # Loose bind_tools tools (no agent attribution): still add as nodes.
        for tool_name in loose_tools:
            tid = f"tool_{tool_name}"
            if tid not in all_nodes:
                all_nodes[tid] = NodeDefinition(
                    id=tid,
                    name=tool_name,
                    type=NodeType.TOOL,
                    category=self._categorize_tool(tool_name),
                    description=f"Tool: {tool_name}",
                )

        # START / END
        if all_nodes:
            all_nodes.setdefault(
                "START",
                NodeDefinition(id="START", name="START", type=NodeType.BASIC, description="Start"),
            )
            all_nodes.setdefault(
                "END",
                NodeDefinition(id="END", name="END", type=NodeType.BASIC, description="End"),
            )

        graph.nodes = list(all_nodes.values())
        graph.edges = all_edges
        graph.agents = all_agents
        return graph

    # ------------------------------------------------------------------ #
    # create_react_agent extraction
    # ------------------------------------------------------------------ #
    def _collect_react_agents(
        self,
        tree: ast.AST,
        agent_var_tools: Dict[str, List[str]],
        agent_var_model: Dict[str, str],
    ) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if not isinstance(node.value, ast.Call):
                continue
            call = node.value
            func_name = self._call_name(call.func)
            if func_name not in ("create_react_agent", "create_tool_calling_agent", "create_openai_functions_agent"):
                continue
            # target variable name
            if not node.targets or not isinstance(node.targets[0], ast.Name):
                continue
            var = node.targets[0].id

            tools = self._extract_tools_list(call)
            agent_var_tools[var] = tools

            model = self._extract_model_from_react(call)
            if model:
                agent_var_model[var] = model

    def _extract_tools_list(self, call: ast.Call) -> List[str]:
        """Pull tool display names from create_react_agent(..., tools=[...])."""
        tools_expr = None
        for kw in call.keywords:
            if kw.arg == "tools":
                tools_expr = kw.value
                break
        if tools_expr is None and len(call.args) >= 2:
            tools_expr = call.args[1]  # second positional is tools in create_react_agent
        names: List[str] = []
        if isinstance(tools_expr, (ast.List, ast.Tuple)):
            for elt in tools_expr.elts:
                name = self._tool_name_from_expr(elt)
                if name:
                    names.append(name)
        elif isinstance(tools_expr, ast.Name):
            names.append(tools_expr.id)
        return names

    def _extract_model_from_react(self, call: ast.Call) -> Optional[str]:
        model_expr = None
        for kw in call.keywords:
            if kw.arg in ("model", "llm"):
                model_expr = kw.value
        if model_expr is None and call.args:
            model_expr = call.args[0]
        if isinstance(model_expr, ast.Constant) and isinstance(model_expr.value, str):
            return model_expr.value
        if isinstance(model_expr, ast.Call):
            m = extract_string_argument(model_expr, "model")
            if m:
                return m
        return None

    def _tool_name_from_expr(self, expr: ast.expr) -> Optional[str]:
        if isinstance(expr, ast.Call):
            return self._call_name(expr.func)
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return expr.attr
        return None

    def _call_name(self, func: ast.expr) -> Optional[str]:
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            return func.attr
        return None

    # ------------------------------------------------------------------ #
    # existing helpers
    # ------------------------------------------------------------------ #
    def _extract_node_name(self, call: ast.Call) -> str:
        if len(call.args) >= 1:
            if isinstance(call.args[0], ast.Constant):
                return str(call.args[0].value)
            elif isinstance(call.args[0], ast.Str):
                return call.args[0].s
        return ""

    def _second_arg_name(self, call: ast.Call) -> Optional[str]:
        if len(call.args) >= 2 and isinstance(call.args[1], ast.Name):
            return call.args[1].id
        return None

    def _extract_edge(self, call: ast.Call) -> Optional[EdgeDefinition]:
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
                edges.append(EdgeDefinition(source=source, target="conditional_target"))
        return edges

    def _extract_arg_value(self, arg: ast.expr) -> str:
        if isinstance(arg, ast.Constant):
            return str(arg.value)
        elif isinstance(arg, ast.Str):
            return arg.s
        elif isinstance(arg, ast.Name):
            # START / END constants resolve to their names
            return arg.id
        return ""

    def _extract_tools_from_bind(self, call: ast.Call) -> Set[str]:
        tools = set()
        if len(call.args) >= 1 and isinstance(call.args[0], ast.List):
            for elt in call.args[0].elts:
                name = self._tool_name_from_expr(elt)
                if name:
                    tools.add(name)
        return tools

    def _categorize_tool(self, tool_name: str) -> ToolCategory:
        tool_lower = tool_name.lower()
        if "search" in tool_lower or "duckduckgo" in tool_lower or "tavily" in tool_lower or "serper" in tool_lower:
            return ToolCategory.WEB_SEARCH
        elif "python" in tool_lower or "repl" in tool_lower or "code" in tool_lower or "interpreter" in tool_lower:
            return ToolCategory.CODE_INTERPRETER
        elif "shell" in tool_lower or "bash" in tool_lower or "terminal" in tool_lower:
            return ToolCategory.SHELL
        elif "email" in tool_lower or "mail" in tool_lower or "smtp" in tool_lower:
            return ToolCategory.EMAIL
        elif "file" in tool_lower or "pdf" in tool_lower or "document" in tool_lower or "directory" in tool_lower:
            return ToolCategory.DOCUMENT_LOADER
        elif "sql" in tool_lower or "database" in tool_lower or "postgres" in tool_lower or "db" in tool_lower:
            return ToolCategory.DATABASE
        elif "http" in tool_lower or "request" in tool_lower or "webhook" in tool_lower:
            return ToolCategory.HTTP_REQUEST
        elif "chat" in tool_lower or "llm" in tool_lower or "gpt" in tool_lower:
            return ToolCategory.LLM
        return ToolCategory.DEFAULT
