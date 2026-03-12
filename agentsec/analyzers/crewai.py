import ast
import yaml
from pathlib import Path
from typing import Dict, List

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
    find_yaml_files,
    parse_python_file,
)


class CrewAIAnalyzer(BaseAnalyzer):
    @property
    def framework_name(self) -> str:
        return "CrewAI"

    def analyze(self) -> GraphDefinition:
        graph = GraphDefinition(framework=self.framework_name)

        all_agents: List[AgentDefinition] = []
        all_nodes: Dict[str, NodeDefinition] = {}
        all_edges: List[EdgeDefinition] = []

        # Check for YAML configuration files
        yaml_files = find_yaml_files(self.input_dir)
        for yaml_file in yaml_files:
            if "agent" in yaml_file.name.lower():
                agents = self._parse_agents_yaml(yaml_file)
                all_agents.extend(agents)

        # Parse Python files
        python_files = find_python_files(self.input_dir)
        for file_path in python_files:
            tree = parse_python_file(file_path)
            if not tree:
                continue

            # Find Agent instantiations
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
                        description=f"CrewAI Agent: {agent.name}",
                    )
                    all_nodes[node.id] = node

            # Find Task instantiations
            task_calls = find_class_instantiations(tree, ["Task"])
            for idx, call in enumerate(task_calls):
                description = extract_string_argument(call, "description")
                task_name = f"task_{idx}"
                node = NodeDefinition(
                    id=task_name,
                    name=task_name,
                    type=NodeType.AGENT,
                    description=description or "CrewAI Task",
                )
                all_nodes[task_name] = node

            # Find tool usage
            tools = self._extract_tools_from_tree(tree)
            for tool_name in tools:
                tool_node = NodeDefinition(
                    id=f"tool_{tool_name}",
                    name=tool_name,
                    type=NodeType.TOOL,
                    category=self._categorize_tool(tool_name),
                    description=f"Tool: {tool_name}",
                )
                all_nodes[tool_node.id] = tool_node

        # Create sequential edges for tasks
        task_nodes = [n for n in all_nodes.values() if "task_" in n.id]
        for i in range(len(task_nodes) - 1):
            edge = EdgeDefinition(source=task_nodes[i].id, target=task_nodes[i + 1].id)
            all_edges.append(edge)

        graph.nodes = list(all_nodes.values())
        graph.edges = all_edges
        graph.agents = all_agents

        return graph

    def _parse_agents_yaml(self, yaml_path: Path) -> List[AgentDefinition]:
        agents = []
        try:
            with open(yaml_path, "r") as f:
                data = yaml.safe_load(f)

            if isinstance(data, dict):
                for agent_name, agent_config in data.items():
                    if isinstance(agent_config, dict):
                        agent = AgentDefinition(
                            name=agent_name,
                            llm_model=agent_config.get("llm"),
                            system_prompt=agent_config.get("role") or agent_config.get("goal"),
                            has_guardrails=False,
                        )
                        agents.append(agent)
        except Exception as e:
            print(f"Warning: Failed to parse YAML {yaml_path}: {e}")

        return agents

    def _extract_agent_from_call(self, call: ast.Call) -> AgentDefinition:
        role = extract_string_argument(call, "role")
        goal = extract_string_argument(call, "goal")
        llm = extract_string_argument(call, "llm")

        if role:
            return AgentDefinition(
                name=role,
                llm_model=llm or "LLM",
                system_prompt=goal,
                has_guardrails=False,
            )
        return None

    def _extract_tools_from_tree(self, tree: ast.AST) -> List[str]:
        tools = []
        # Look for tool imports and instantiations
        crewai_tools = [
            "SerperDevTool",
            "FileReadTool",
            "DirectoryReadTool",
            "WebsiteSearchTool",
        ]
        tool_calls = find_class_instantiations(tree, crewai_tools)
        for call in tool_calls:
            if isinstance(call.func, ast.Name):
                tools.append(call.func.id)
            elif isinstance(call.func, ast.Attribute):
                tools.append(call.func.attr)
        return tools

    def _categorize_tool(self, tool_name: str) -> ToolCategory:
        tool_lower = tool_name.lower()
        if "search" in tool_lower or "serper" in tool_lower:
            return ToolCategory.WEB_SEARCH
        elif "file" in tool_lower or "directory" in tool_lower:
            return ToolCategory.DOCUMENT_LOADER
        elif "website" in tool_lower:
            return ToolCategory.WEB_SEARCH
        return ToolCategory.DEFAULT
