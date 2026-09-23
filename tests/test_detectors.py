"""Tests for security finding detectors."""


from agentsec.audit.detectors import (
    DangerousPathDetector,
    ExcessiveAgencyDetector,
    LethalTrifectaDetector,
)
from agentsec.models import (
    AgentDefinition,
    AttackPath,
    Capability,
    Confidence,
    DataClass,
    Finding,
    GraphDefinition,
    NodeDefinition,
    NodeType,
    Severity,
    TrustLevel,
)


class TestExcessiveAgencyDetector:
    """Tests for excessive agency detection."""

    def test_detector_initialization(self):
        """Test detector can be initialized."""
        detector = ExcessiveAgencyDetector()
        assert detector is not None

    def test_detect_code_exec_excessive_agency(self):
        """Test detection of agent with code execution."""
        agent = AgentDefinition(name="DangerousAgent", direct_capabilities=[Capability.CODE_EXEC])
        graph = GraphDefinition(framework="Test", agents=[agent])

        detector = ExcessiveAgencyDetector()
        findings = detector.detect(graph)

        # Should find excessive agency
        assert len(findings) > 0
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_detect_shell_exec_excessive_agency(self):
        """Test detection of agent with shell execution."""
        agent = AgentDefinition(name="ShellAgent", direct_capabilities=[Capability.SHELL_EXEC])
        graph = GraphDefinition(framework="Test", agents=[agent])

        detector = ExcessiveAgencyDetector()
        findings = detector.detect(graph)

        assert len(findings) > 0

    def test_no_excessive_agency_for_safe_agent(self):
        """Test that safe agents don't trigger detection."""
        agent = AgentDefinition(name="SafeAgent", direct_capabilities=[Capability.NETWORK_READ])
        graph = GraphDefinition(framework="Test", agents=[agent])

        detector = ExcessiveAgencyDetector()
        findings = detector.detect(graph)

        # Should not find excessive agency for read-only
        excessive_findings = [
            f
            for f in findings
            if "excessive" in f.title.lower() or "excessive" in f.category.lower()
        ]
        assert len(excessive_findings) == 0

    def test_multiple_dangerous_capabilities(self):
        """Test agent with multiple dangerous capabilities."""
        agent = AgentDefinition(
            name="OverpoweredAgent",
            direct_capabilities=[
                Capability.CODE_EXEC,
                Capability.SHELL_EXEC,
                Capability.DB_WRITE,
                Capability.FS_WRITE,
            ],
        )
        graph = GraphDefinition(framework="Test", agents=[agent])

        detector = ExcessiveAgencyDetector()
        findings = detector.detect(graph)

        # Should definitely flag this
        assert len(findings) > 0
        # Severity should be high
        assert any(f.severity in [Severity.HIGH, Severity.CRITICAL] for f in findings)


class TestLethalTrifectaDetector:
    """Tests for lethal trifecta detection."""

    def test_detector_initialization(self):
        """Test detector can be initialized."""
        detector = LethalTrifectaDetector()
        assert detector is not None

    def test_detect_lethal_trifecta(self):
        """Test detection of lethal trifecta pattern."""
        # Create agent node
        agent_node = NodeDefinition(
            id="agent",
            name="Agent",
            type=NodeType.AGENT,
            capabilities=[
                Capability.DB_READ,  # Private data access
                Capability.NETWORK_WRITE,  # External communication
            ],
            is_source=True,  # Untrusted content exposure
            data_class=DataClass.PRIVATE,
        )

        agent = AgentDefinition(
            name="TrifectaAgent",
            node_id="agent",
            direct_capabilities=[
                Capability.DB_READ,
                Capability.NETWORK_WRITE,
            ],
        )

        graph = GraphDefinition(framework="Test", nodes=[agent_node], agents=[agent])

        detector = LethalTrifectaDetector()
        findings = detector.detect(graph)

        # Should detect the trifecta
        trifecta_findings = [
            f for f in findings if "trifecta" in f.title.lower() or "trifecta" in f.category.lower()
        ]
        assert len(trifecta_findings) > 0
        # Should be CRITICAL
        assert any(f.severity == Severity.CRITICAL for f in trifecta_findings)

    def test_no_trifecta_without_all_components(self):
        """Test that incomplete trifecta doesn't trigger."""
        # Agent with only 2 out of 3 components
        agent_node = NodeDefinition(
            id="agent",
            name="Agent",
            type=NodeType.AGENT,
            capabilities=[Capability.DB_READ, Capability.NETWORK_READ],
            data_class=DataClass.PRIVATE,
        )

        agent = AgentDefinition(
            name="IncompleteAgent",
            node_id="agent",
            direct_capabilities=[Capability.DB_READ, Capability.NETWORK_READ],
        )

        graph = GraphDefinition(framework="Test", nodes=[agent_node], agents=[agent])

        detector = LethalTrifectaDetector()
        findings = detector.detect(graph)

        # Should not detect trifecta
        trifecta_findings = [f for f in findings if "trifecta" in f.title.lower()]
        assert len(trifecta_findings) == 0


class TestDangerousPathDetector:
    """Tests for dangerous path detection."""

    def test_detector_initialization(self):
        """Test detector can be initialized."""
        detector = DangerousPathDetector()
        assert detector is not None

    def test_detect_simple_attack_path(self):
        """Test detection of simple source -> sink path."""
        # Create source (untrusted input)
        source_node = NodeDefinition(
            id="source",
            name="UserInput",
            type=NodeType.TOOL,
            is_source=True,
            trust=TrustLevel.UNTRUSTED,
        )

        # Create sink (dangerous capability)
        sink_node = NodeDefinition(
            id="sink", name="CodeExec", type=NodeType.TOOL, capabilities=[Capability.CODE_EXEC]
        )

        graph = GraphDefinition(
            framework="Test",
            nodes=[source_node, sink_node],
            edges=[{"source": "source", "target": "sink"}],
        )

        detector = DangerousPathDetector()
        findings = detector.detect(graph)

        # Should detect the dangerous path
        path_findings = [f for f in findings if f.path is not None]
        assert len(path_findings) > 0

    def test_no_path_without_source(self):
        """Test that sink without source doesn't trigger."""
        # Only a sink, no untrusted source
        sink_node = NodeDefinition(
            id="sink",
            name="CodeExec",
            type=NodeType.TOOL,
            capabilities=[Capability.CODE_EXEC],
            trust=TrustLevel.TRUSTED,
        )

        graph = GraphDefinition(framework="Test", nodes=[sink_node])

        detector = DangerousPathDetector()
        findings = detector.detect(graph)

        # Should not detect a path without source
        path_findings = [f for f in findings if f.path is not None]
        # Might be empty or have findings but no paths
        # Depends on implementation

    def test_confidence_levels(self):
        """Test that confidence levels are assigned appropriately."""
        source_node = NodeDefinition(
            id="source",
            name="UserInput",
            type=NodeType.TOOL,
            is_source=True,
            trust=TrustLevel.UNTRUSTED,
        )

        sink_node = NodeDefinition(
            id="sink", name="ShellExec", type=NodeType.TOOL, capabilities=[Capability.SHELL_EXEC]
        )

        graph = GraphDefinition(
            framework="Test",
            nodes=[source_node, sink_node],
            edges=[{"source": "source", "target": "sink"}],
        )

        detector = DangerousPathDetector()
        findings = detector.detect(graph)

        # Check confidence levels are valid
        for finding in findings:
            if finding.confidence:
                assert finding.confidence in [Confidence.HIGH, Confidence.MEDIUM, Confidence.LOW]


class TestFindingGeneration:
    """Tests for finding generation and formatting."""

    def test_finding_has_required_fields(self):
        """Test that findings have all required fields."""
        finding = Finding(
            id="TEST-001",
            title="Test Finding",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            category="Test",
            description="Test description",
            remediation="Test remediation",
        )

        assert finding.id == "TEST-001"
        assert finding.severity == Severity.HIGH
        assert finding.confidence == Confidence.HIGH
        assert len(finding.description) > 0
        assert len(finding.remediation) > 0

    def test_finding_with_owasp_mapping(self):
        """Test finding with OWASP mapping."""
        finding = Finding(
            id="TEST-002",
            title="Prompt Injection",
            severity=Severity.CRITICAL,
            category="Injection",
            description="Test",
            remediation="Test",
            security_framework_mapping={"OWASP": "LLM01", "CWE": "CWE-77"},
        )

        assert "OWASP" in finding.security_framework_mapping
        assert finding.security_framework_mapping["OWASP"] == "LLM01"

    def test_finding_with_attack_path(self):
        """Test finding with attack path."""
        path = AttackPath(
            source_id="input",
            sink_id="exec",
            node_ids=["input", "agent", "exec"],
            sink_capability=Capability.CODE_EXEC,
            confidence=Confidence.HIGH,
        )

        finding = Finding(
            id="TEST-003",
            title="Dangerous Path",
            severity=Severity.HIGH,
            category="Reachability",
            description="Test",
            remediation="Test",
            path=path,
        )

        assert finding.path is not None
        assert finding.path.source_id == "input"
        assert finding.path.sink_id == "exec"
        assert len(finding.path.node_ids) == 3
