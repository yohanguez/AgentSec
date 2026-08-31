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
    HTTP_REQUEST = "http_request"
    EMAIL = "email"
    SHELL = "shell"
    DEFAULT = "default"


class Capability(str, Enum):
    """A discrete power a tool/node grants to whatever agent can reach it.

    These are the building blocks for privilege scoring, excessive-agency
    detection, and the lethal-trifecta verdict.
    """

    CODE_EXEC = "code_exec"        # run arbitrary code (PythonREPL, interpreters)
    SHELL_EXEC = "shell_exec"      # run shell commands (subprocess, os.system)
    FS_READ = "fs_read"            # read files from disk
    FS_WRITE = "fs_write"          # write/modify files on disk
    DB_READ = "db_read"            # read from a database
    DB_WRITE = "db_write"          # write to a database
    NETWORK_READ = "network_read"  # fetch external content (web search, HTTP GET)
    NETWORK_WRITE = "network_write"  # send data out (HTTP POST, webhooks)
    EMAIL_SEND = "email_send"      # send email / messages
    SECRETS_ACCESS = "secrets_access"  # read credentials / secrets


class TrustLevel(str, Enum):
    TRUSTED = "trusted"
    UNTRUSTED = "untrusted"


class DataClass(str, Enum):
    PUBLIC = "public"
    PRIVATE = "private"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


# Capabilities that represent a dangerous endpoint an attacker would want to reach.
SINK_CAPABILITIES = frozenset(
    {
        Capability.CODE_EXEC,
        Capability.SHELL_EXEC,
        Capability.FS_WRITE,
        Capability.DB_WRITE,
        Capability.NETWORK_WRITE,
        Capability.EMAIL_SEND,
    }
)

# Capabilities that let an agent move data out of the trust boundary (exfiltration).
EXFIL_CAPABILITIES = frozenset(
    {
        Capability.NETWORK_WRITE,
        Capability.EMAIL_SEND,
        Capability.NETWORK_READ,  # GET with attacker-controlled URL/query exfiltrates too
    }
)

# Capabilities that grant access to sensitive/private data.
PRIVATE_DATA_CAPABILITIES = frozenset(
    {
        Capability.DB_READ,
        Capability.FS_READ,
        Capability.SECRETS_ACCESS,
    }
)


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
    # --- Capability / privilege annotations (populated by the audit layer) ---
    capabilities: List[Capability] = Field(
        default_factory=list, description="Powers this node grants"
    )
    is_source: bool = Field(
        default=False, description="Whether this node introduces untrusted data"
    )
    trust: TrustLevel = Field(
        default=TrustLevel.TRUSTED, description="Trust level of data from this node"
    )
    data_class: DataClass = Field(
        default=DataClass.PUBLIC, description="Sensitivity of data this node touches"
    )
    signature_evidence: List[str] = Field(
        default_factory=list,
        description="AST evidence when capabilities were inferred from custom code",
    )

    def sink_capabilities(self) -> List["Capability"]:
        return [c for c in self.capabilities if c in SINK_CAPABILITIES]

    def is_sink(self) -> bool:
        return bool(self.sink_capabilities())


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
    # --- Privilege audit results ---
    node_id: Optional[str] = Field(
        default=None, description="ID of this agent's node in the graph, if any"
    )
    tool_ids: List[str] = Field(
        default_factory=list, description="Node IDs of tools directly owned by this agent"
    )
    direct_capabilities: List[Capability] = Field(
        default_factory=list,
        description="Capabilities from tools this agent directly owns",
    )
    reachable_capabilities: List[Capability] = Field(
        default_factory=list,
        description="All capabilities reachable by this agent (direct + via handoffs)",
    )
    privilege_score: int = Field(
        default=0, description="Weighted privilege score (higher = more powerful)"
    )
    privilege_grade: str = Field(
        default="A", description="Letter grade A-F for privilege exposure"
    )


class AttackPath(BaseModel):
    """A reachable route from an untrusted source to a dangerous sink."""

    source_id: str = Field(description="Untrusted source node ID")
    sink_id: str = Field(description="Dangerous sink node ID")
    node_ids: List[str] = Field(description="Ordered node IDs along the path")
    sink_capability: Capability = Field(description="Dangerous capability at the sink")
    confidence: Confidence = Field(description="Confidence the path is exploitable")


class Finding(BaseModel):
    """A security finding produced by the audit layer."""

    id: str = Field(description="Stable finding identifier, e.g. AGS-TRIFECTA-01")
    title: str = Field(description="Short human-readable title")
    severity: Severity = Field(description="Severity of the finding")
    confidence: Confidence = Field(default=Confidence.HIGH, description="Detection confidence")
    category: str = Field(description="Finding category, e.g. 'Excessive Agency'")
    description: str = Field(description="What the finding is and why it matters")
    remediation: str = Field(description="How to remediate")
    security_framework_mapping: Dict[str, str] = Field(
        default_factory=dict, description="OWASP/CWE mappings"
    )
    agent_name: Optional[str] = Field(default=None, description="Affected agent, if any")
    node_ids: List[str] = Field(
        default_factory=list, description="Nodes involved (for graph highlighting)"
    )
    path: Optional[AttackPath] = Field(default=None, description="Attack path, if applicable")


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
    findings: List[Finding] = Field(
        default_factory=list, description="Audit findings for this workflow"
    )

    def get_tools(self) -> List[NodeDefinition]:
        return [
            node
            for node in self.nodes
            if node.type in [NodeType.TOOL, NodeType.CUSTOM_TOOL]
        ]

    def get_mcp_servers(self) -> List[NodeDefinition]:
        return [node for node in self.nodes if node.type == NodeType.MCP_SERVER]

    def get_node(self, node_id: str) -> Optional[NodeDefinition]:
        for node in self.nodes:
            if node.id == node_id:
                return node
        return None

    def get_total_vulnerabilities(self) -> int:
        node_vulns = sum(len(node.vulnerabilities) for node in self.nodes)
        agent_vulns = sum(len(agent.vulnerabilities) for agent in self.agents)
        return node_vulns + agent_vulns

    def get_findings_by_severity(self, severity: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == severity]

    def attack_path_node_ids(self) -> List[str]:
        """All node IDs that lie on at least one attack path (for red highlighting)."""
        ids = set()
        for f in self.findings:
            if f.path:
                ids.update(f.path.node_ids)
        return sorted(ids)
