from enum import Enum
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class NodeType(str, Enum):
    AGENT = "AGENT"
    TOOL = "TOOL"
    CUSTOM_TOOL = "CUSTOM_TOOL"
    MCP_SERVER = "MCP_SERVER"
    BASIC = "BASIC"  # START/END nodes


class ToolCategory(str, Enum):
    WEB_SEARCH = "web_search"
    CODE_INTERPRETER = "code_interpreter"
    DOCUMENT_LOADER = "document_loader"
    LLM = "llm"
    DATABASE = "database"
    DEFAULT = "default"


class Vulnerability(BaseModel):
    name: str = Field(description="Short vulnerability name")
    description: str = Field(description="Detailed explanation of the risk")
    security_framework_mapping: Dict[str, str] = Field(
        default_factory=dict,
        description="Mapping to security frameworks (OWASP, CWE, etc.)",
    )
    remediation: str = Field(description="Step-by-step mitigation instructions")


class NodeDefinition(BaseModel):
    id: str = Field(description="Unique identifier for the node")
    name: str = Field(description="Display name")
    type: NodeType = Field(description="Type of node")
    category: ToolCategory = Field(
        default=ToolCategory.DEFAULT, description="Category for tools"
    )
    description: Optional[str] = Field(default=None, description="Node description")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Associated vulnerabilities"
    )


class EdgeDefinition(BaseModel):
    source: str = Field(description="Source node ID")
    target: str = Field(description="Target node ID")
    condition: Optional[str] = Field(
        default=None, description="Condition label for conditional routing"
    )


class AgentDefinition(BaseModel):
    name: str = Field(description="Agent name")
    llm_model: Optional[str] = Field(default=None, description="LLM model name")
    system_prompt: Optional[str] = Field(default=None, description="System prompt text")
    has_guardrails: bool = Field(default=False, description="Whether agent has guardrails")
    vulnerabilities: List[Vulnerability] = Field(
        default_factory=list, description="Agent-level vulnerabilities"
    )


class GraphDefinition(BaseModel):
    nodes: List[NodeDefinition] = Field(
        default_factory=list, description="All nodes in the graph"
    )
    edges: List[EdgeDefinition] = Field(
        default_factory=list, description="All edges in the graph"
    )
    agents: List[AgentDefinition] = Field(
        default_factory=list, description="All agents in the workflow"
    )
    framework: str = Field(description="Source framework name")
    metadata: Dict[str, str] = Field(
        default_factory=dict, description="Additional metadata"
    )

    def get_tools(self) -> List[NodeDefinition]:
        return [
            node
            for node in self.nodes
            if node.type in [NodeType.TOOL, NodeType.CUSTOM_TOOL]
        ]

    def get_mcp_servers(self) -> List[NodeDefinition]:
        return [node for node in self.nodes if node.type == NodeType.MCP_SERVER]

    def get_total_vulnerabilities(self) -> int:
        node_vulns = sum(len(node.vulnerabilities) for node in self.nodes)
        agent_vulns = sum(len(agent.vulnerabilities) for agent in self.agents)
        return node_vulns + agent_vulns
