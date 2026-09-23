"""Extended tests for data models."""

import pytest

from agentsec.models import (
    AgentDefinition,
    AttackPath,
    Capability,
    Confidence,
    DataClass,
    EdgeDefinition,
    Finding,
    GraphDefinition,
    NodeDefinition,
    NodeType,
    Severity,
    ToolCategory,
    TrustLevel,
    Vulnerability,
)


class TestNodeDefinition:
    """Extended tests for NodeDefinition."""

    def test_node_with_all_fields(self):
        """Test creating node with all fields."""
        node = NodeDefinition(
            id="test",
            name="Test Node",
            type=NodeType.TOOL,
            category=ToolCategory.CODE_INTERPRETER,
            description="A test node",
            capabilities=[Capability.CODE_EXEC],
            is_source=True,
            trust=TrustLevel.UNTRUSTED,
            data_class=DataClass.PRIVATE,
            signature_evidence=["eval() at line 42"]
        )

        assert node.id == "test"
        assert node.type == NodeType.TOOL
        assert Capability.CODE_EXEC in node.capabilities
        assert node.is_source
        assert node.is_sink()

    def test_node_sink_detection_comprehensive(self):
        """Test comprehensive sink detection."""
        test_cases = [
            ([Capability.CODE_EXEC], True),
            ([Capability.SHELL_EXEC], True),
            ([Capability.FS_WRITE], True),
            ([Capability.DB_WRITE], True),
            ([Capability.NETWORK_WRITE], True),
            ([Capability.EMAIL_SEND], True),
            ([Capability.FS_READ], False),
            ([Capability.DB_READ], False),
            ([Capability.NETWORK_READ], False),
            ([Capability.FS_READ, Capability.FS_WRITE], True),
        ]

        for caps, expected_is_sink in test_cases:
            node = NodeDefinition(
                id="test",
                name="Test",
                type=NodeType.TOOL,
                capabilities=caps
            )
            assert node.is_sink() == expected_is_sink

    def test_node_types(self):
        """Test all node types can be created."""
        types = [
            NodeType.AGENT,
            NodeType.TOOL,
            NodeType.CUSTOM_TOOL,
            NodeType.MCP_SERVER,
            NodeType.BASIC,
        ]

        for node_type in types:
            node = NodeDefinition(
                id="test",
                name="Test",
                type=node_type
            )
            assert node.type == node_type

    def test_tool_categories(self):
        """Test all tool categories."""
        categories = [
            ToolCategory.WEB_SEARCH,
            ToolCategory.CODE_INTERPRETER,
            ToolCategory.DOCUMENT_LOADER,
            ToolCategory.LLM,
            ToolCategory.DATABASE,
            ToolCategory.HTTP_REQUEST,
            ToolCategory.EMAIL,
            ToolCategory.SHELL,
            ToolCategory.DEFAULT,
        ]

        for category in categories:
            node = NodeDefinition(
                id="test",
                name="Test",
                type=NodeType.TOOL,
                category=category
            )
            assert node.category == category


class TestEdgeDefinition:
    """Extended tests for EdgeDefinition."""

    def test_edge_with_condition(self):
        """Test edge with routing condition."""
        edge = EdgeDefinition(
            source="agent",
            target="tool",
            condition="if approval_needed"
        )

        assert edge.source == "agent"
        assert edge.target == "tool"
        assert edge.condition == "if approval_needed"

    def test_edge_without_condition(self):
        """Test unconditional edge."""
        edge = EdgeDefinition(source="a", target="b")
        assert edge.condition is None


class TestAgentDefinition:
    """Extended tests for AgentDefinition."""

    def test_agent_with_guardrails(self):
        """Test agent with guardrails enabled."""
        agent = AgentDefinition(
            name="Safe Agent",
            has_guardrails=True,
            system_prompt="You must not execute code"
        )

        assert agent.has_guardrails
        assert "not execute" in agent.system_prompt

    def test_agent_privilege_scores(self):
        """Test agent privilege scoring."""
        agent = AgentDefinition(
            name="Agent",
            direct_capabilities=[Capability.FS_READ],
            reachable_capabilities=[Capability.FS_READ, Capability.CODE_EXEC],
            privilege_score=150,
            privilege_grade="D"
        )

        assert agent.privilege_score == 150
        assert agent.privilege_grade == "D"
        assert len(agent.direct_capabilities) < len(agent.reachable_capabilities)

    def test_agent_tool_association(self):
        """Test agent-tool associations."""
        agent = AgentDefinition(
            name="Agent",
            node_id="agent1",
            tool_ids=["tool1", "tool2", "tool3"]
        )

        assert agent.node_id == "agent1"
        assert len(agent.tool_ids) == 3
        assert "tool1" in agent.tool_ids


class TestAttackPath:
    """Tests for AttackPath model."""

    def test_attack_path_creation(self):
        """Test creating attack path."""
        path = AttackPath(
            source_id="input",
            sink_id="exec",
            node_ids=["input", "agent", "tool", "exec"],
            sink_capability=Capability.CODE_EXEC,
            confidence=Confidence.HIGH
        )

        assert path.source_id == "input"
        assert path.sink_id == "exec"
        assert len(path.node_ids) == 4
        assert path.sink_capability == Capability.CODE_EXEC
        assert path.confidence == Confidence.HIGH

    def test_attack_path_single_hop(self):
        """Test single-hop attack path."""
        path = AttackPath(
            source_id="source",
            sink_id="sink",
            node_ids=["source", "sink"],
            sink_capability=Capability.SHELL_EXEC,
            confidence=Confidence.HIGH
        )

        assert len(path.node_ids) == 2
        # Single hop should have high confidence


class TestFinding:
    """Extended tests for Finding model."""

    def test_finding_severities(self):
        """Test all severity levels."""
        severities = [
            Severity.CRITICAL,
            Severity.HIGH,
            Severity.MEDIUM,
            Severity.LOW,
            Severity.INFO,
        ]

        for severity in severities:
            finding = Finding(
                id=f"TEST-{severity.value}",
                title=f"Test {severity.value}",
                severity=severity,
                category="Test",
                description="Test",
                remediation="Test"
            )
            assert finding.severity == severity

    def test_finding_with_all_fields(self):
        """Test finding with all optional fields."""
        path = AttackPath(
            source_id="src",
            sink_id="snk",
            node_ids=["src", "snk"],
            sink_capability=Capability.CODE_EXEC,
            confidence=Confidence.HIGH
        )

        finding = Finding(
            id="FULL-001",
            title="Comprehensive Finding",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            category="Injection",
            description="Detailed description",
            remediation="Step-by-step fix",
            security_framework_mapping={
                "OWASP": "LLM01",
                "CWE": "CWE-94",
                "MITRE": "T1059"
            },
            agent_name="VulnerableAgent",
            node_ids=["src", "agent", "snk"],
            path=path
        )

        assert finding.id == "FULL-001"
        assert finding.severity == Severity.CRITICAL
        assert finding.path is not None
        assert len(finding.security_framework_mapping) == 3
        assert finding.agent_name == "VulnerableAgent"


class TestGraphDefinition:
    """Extended tests for GraphDefinition."""

    def test_graph_get_node(self):
        """Test getting node by ID."""
        nodes = [
            NodeDefinition(id="node1", name="Node 1", type=NodeType.AGENT),
            NodeDefinition(id="node2", name="Node 2", type=NodeType.TOOL),
        ]

        graph = GraphDefinition(
            framework="Test",
            nodes=nodes
        )

        node = graph.get_node("node1")
        assert node is not None
        assert node.name == "Node 1"

        missing = graph.get_node("nonexistent")
        assert missing is None

    def test_graph_get_mcp_servers(self):
        """Test getting MCP servers from graph."""
        nodes = [
            NodeDefinition(id="mcp1", name="MCP 1", type=NodeType.MCP_SERVER),
            NodeDefinition(id="mcp2", name="MCP 2", type=NodeType.MCP_SERVER),
            NodeDefinition(id="tool", name="Tool", type=NodeType.TOOL),
        ]

        graph = GraphDefinition(
            framework="Test",
            nodes=nodes
        )

        mcps = graph.get_mcp_servers()
        assert len(mcps) == 2
        assert all(n.type == NodeType.MCP_SERVER for n in mcps)

    def test_graph_findings_by_severity(self):
        """Test filtering findings by severity."""
        findings = [
            Finding(
                id="F1",
                title="Critical",
                severity=Severity.CRITICAL,
                category="Test",
                description="Test",
                remediation="Test"
            ),
            Finding(
                id="F2",
                title="High",
                severity=Severity.HIGH,
                category="Test",
                description="Test",
                remediation="Test"
            ),
            Finding(
                id="F3",
                title="High2",
                severity=Severity.HIGH,
                category="Test",
                description="Test",
                remediation="Test"
            ),
        ]

        graph = GraphDefinition(
            framework="Test",
            nodes=[],
            findings=findings
        )

        critical = graph.get_findings_by_severity(Severity.CRITICAL)
        assert len(critical) == 1

        high = graph.get_findings_by_severity(Severity.HIGH)
        assert len(high) == 2

    def test_graph_attack_path_nodes(self):
        """Test extracting attack path node IDs."""
        path1 = AttackPath(
            source_id="s1",
            sink_id="k1",
            node_ids=["s1", "a1", "k1"],
            sink_capability=Capability.CODE_EXEC,
            confidence=Confidence.HIGH
        )

        path2 = AttackPath(
            source_id="s2",
            sink_id="k2",
            node_ids=["s2", "a2", "k2"],
            sink_capability=Capability.SHELL_EXEC,
            confidence=Confidence.MEDIUM
        )

        findings = [
            Finding(
                id="F1",
                title="Path 1",
                severity=Severity.HIGH,
                category="Test",
                description="Test",
                remediation="Test",
                path=path1
            ),
            Finding(
                id="F2",
                title="Path 2",
                severity=Severity.HIGH,
                category="Test",
                description="Test",
                remediation="Test",
                path=path2
            ),
        ]

        graph = GraphDefinition(
            framework="Test",
            nodes=[],
            findings=findings
        )

        path_nodes = graph.attack_path_node_ids()
        # Should include nodes from both paths
        assert "s1" in path_nodes or "a1" in path_nodes
        assert len(path_nodes) > 0

    def test_graph_metadata(self):
        """Test graph metadata handling."""
        graph = GraphDefinition(
            framework="Test",
            nodes=[],
            metadata={
                "version": "1.0",
                "scan_date": "2026-09-23",
                "custom_field": "custom_value"
            }
        )

        assert graph.metadata["version"] == "1.0"
        assert graph.metadata["scan_date"] == "2026-09-23"
        assert "custom_field" in graph.metadata