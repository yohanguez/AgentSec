"""Tests for capability detection and assignment."""

from pathlib import Path

from agentsec.audit.capabilities import CapabilityAssigner
from agentsec.models import (
    EXFIL_CAPABILITIES,
    PRIVATE_DATA_CAPABILITIES,
    SINK_CAPABILITIES,
    Capability,
    NodeDefinition,
    NodeType,
    ToolCategory,
)


def test_sink_capabilities():
    """Test that sink capabilities are correctly identified."""
    assert Capability.CODE_EXEC in SINK_CAPABILITIES
    assert Capability.SHELL_EXEC in SINK_CAPABILITIES
    assert Capability.FS_WRITE in SINK_CAPABILITIES
    assert Capability.DB_WRITE in SINK_CAPABILITIES
    assert Capability.NETWORK_WRITE in SINK_CAPABILITIES
    assert Capability.EMAIL_SEND in SINK_CAPABILITIES
    # Read capabilities should not be sinks
    assert Capability.FS_READ not in SINK_CAPABILITIES
    assert Capability.DB_READ not in SINK_CAPABILITIES


def test_exfil_capabilities():
    """Test that exfiltration capabilities are correctly identified."""
    assert Capability.NETWORK_WRITE in EXFIL_CAPABILITIES
    assert Capability.EMAIL_SEND in EXFIL_CAPABILITIES
    assert Capability.NETWORK_READ in EXFIL_CAPABILITIES


def test_private_data_capabilities():
    """Test that private data access capabilities are correctly identified."""
    assert Capability.DB_READ in PRIVATE_DATA_CAPABILITIES
    assert Capability.FS_READ in PRIVATE_DATA_CAPABILITIES
    assert Capability.SECRETS_ACCESS in PRIVATE_DATA_CAPABILITIES


def test_node_sink_detection():
    """Test node sink capability detection."""
    node = NodeDefinition(
        id="test",
        name="Test",
        type=NodeType.TOOL,
        capabilities=[Capability.CODE_EXEC, Capability.FS_READ],
    )
    assert node.is_sink()
    sink_caps = node.sink_capabilities()
    assert Capability.CODE_EXEC in sink_caps
    assert Capability.FS_READ not in sink_caps


def test_node_not_sink():
    """Test node without sink capabilities."""
    node = NodeDefinition(
        id="test",
        name="Test",
        type=NodeType.TOOL,
        capabilities=[Capability.FS_READ, Capability.NETWORK_READ],
    )
    assert not node.is_sink()
    assert len(node.sink_capabilities()) == 0


def test_capability_assigner_initialization():
    """Test CapabilityAssigner can be initialized."""
    assigner = CapabilityAssigner(input_dir=Path("."))
    assert assigner is not None
    assert isinstance(assigner.input_dir, Path)


def test_assign_known_tool_capabilities():
    """Test capability assignment for known tools."""
    assigner = CapabilityAssigner(input_dir=Path("."))

    # Python REPL tool
    node = NodeDefinition(
        id="repl", name="PythonREPL", type=NodeType.TOOL, category=ToolCategory.CODE_INTERPRETER
    )
    assigner.assign_capabilities(node)
    assert Capability.CODE_EXEC in node.capabilities

    # Shell tool
    node = NodeDefinition(
        id="shell", name="ShellTool", type=NodeType.TOOL, category=ToolCategory.SHELL
    )
    assigner.assign_capabilities(node)
    assert Capability.SHELL_EXEC in node.capabilities

    # Web search tool
    node = NodeDefinition(
        id="search", name="DuckDuckGoSearch", type=NodeType.TOOL, category=ToolCategory.WEB_SEARCH
    )
    assigner.assign_capabilities(node)
    assert Capability.NETWORK_READ in node.capabilities


def test_assign_database_tool_capabilities():
    """Test capability assignment for database tools."""
    assigner = CapabilityAssigner(input_dir=Path("."))

    node = NodeDefinition(
        id="db", name="DatabaseQuery", type=NodeType.TOOL, category=ToolCategory.DATABASE
    )
    assigner.assign_capabilities(node)
    assert Capability.DB_READ in node.capabilities or Capability.DB_WRITE in node.capabilities


def test_assign_http_tool_capabilities():
    """Test capability assignment for HTTP request tools."""
    assigner = CapabilityAssigner(input_dir=Path("."))

    node = NodeDefinition(
        id="http", name="HTTPRequest", type=NodeType.TOOL, category=ToolCategory.HTTP_REQUEST
    )
    assigner.assign_capabilities(node)
    # HTTP tools can read and potentially write
    assert (
        Capability.NETWORK_READ in node.capabilities
        or Capability.NETWORK_WRITE in node.capabilities
    )


def test_multiple_capabilities():
    """Test that nodes can have multiple capabilities."""
    node = NodeDefinition(
        id="multi",
        name="MultiTool",
        type=NodeType.TOOL,
        capabilities=[
            Capability.FS_READ,
            Capability.FS_WRITE,
            Capability.NETWORK_READ,
        ],
    )
    assert len(node.capabilities) == 3
    assert node.is_sink()  # FS_WRITE makes it a sink


def test_custom_tool_capabilities():
    """Test that custom tools can be assigned capabilities."""
    node = NodeDefinition(
        id="custom", name="CustomTool", type=NodeType.CUSTOM_TOOL, capabilities=[]
    )
    # Custom tools start with no capabilities
    assert len(node.capabilities) == 0

    # Capabilities should be added via AST analysis
    node.capabilities.append(Capability.SHELL_EXEC)
    node.signature_evidence.append("subprocess.run() found at line 42")
    assert Capability.SHELL_EXEC in node.capabilities
    assert len(node.signature_evidence) > 0
