import pytest

from agentsec.models import (
    AgentDefinition,
    EdgeDefinition,
    GraphDefinition,
    NodeDefinition,
    NodeType,
    ToolCategory,
    Vulnerability,
)


def test_node_definition():
    node = NodeDefinition(
        id="test_node",
        name="Test Node",
        type=NodeType.AGENT,
        category=ToolCategory.DEFAULT,
    )
    assert node.id == "test_node"
    assert node.name == "Test Node"
    assert node.type == NodeType.AGENT
    assert len(node.vulnerabilities) == 0


def test_edge_definition():
    edge = EdgeDefinition(source="node1", target="node2")
    assert edge.source == "node1"
    assert edge.target == "node2"
    assert edge.condition is None


def test_vulnerability():
    vuln = Vulnerability(
        name="Test Vulnerability",
        description="A test vulnerability",
        security_framework_mapping={"OWASP": "LLM01"},
        remediation="Fix it",
    )
    assert vuln.name == "Test Vulnerability"
    assert "OWASP" in vuln.security_framework_mapping


def test_graph_definition():
    node1 = NodeDefinition(
        id="agent1", name="Agent 1", type=NodeType.AGENT
    )
    node2 = NodeDefinition(
        id="tool1", name="Tool 1", type=NodeType.TOOL, category=ToolCategory.WEB_SEARCH
    )
    edge = EdgeDefinition(source="agent1", target="tool1")
    agent = AgentDefinition(name="Test Agent", llm_model="gpt-4")

    graph = GraphDefinition(
        framework="Test",
        nodes=[node1, node2],
        edges=[edge],
        agents=[agent],
    )

    assert graph.framework == "Test"
    assert len(graph.nodes) == 2
    assert len(graph.edges) == 1
    assert len(graph.agents) == 1

    # Test get_tools
    tools = graph.get_tools()
    assert len(tools) == 1
    assert tools[0].id == "tool1"

    # Test get_total_vulnerabilities
    assert graph.get_total_vulnerabilities() == 0

    # Add vulnerabilities
    vuln = Vulnerability(
        name="Test", description="Test", remediation="Test"
    )
    node2.vulnerabilities.append(vuln)
    assert graph.get_total_vulnerabilities() == 1
