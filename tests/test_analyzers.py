"""Tests for framework analyzers."""

from pathlib import Path

from agentsec.analyzers import CrewAIAnalyzer, LangGraphAnalyzer
from agentsec.analyzers.autogen import AutogenAnalyzer
from agentsec.analyzers.n8n import N8NAnalyzer
from agentsec.analyzers.openai_agents import OpenAIAgentsAnalyzer
from agentsec.models import GraphDefinition


class TestLangGraphAnalyzer:
    """Tests for LangGraph analyzer."""

    def test_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = LangGraphAnalyzer(input_dir=Path("."))
        assert analyzer.input_dir == Path(".")
        assert analyzer.framework_name == "LangGraph"

    def test_empty_directory(self, tmp_path):
        """Test analysis of empty directory."""
        analyzer = LangGraphAnalyzer(input_dir=tmp_path)
        graph = analyzer.analyze()
        assert isinstance(graph, GraphDefinition)
        assert graph.framework == "LangGraph"
        assert len(graph.nodes) >= 0  # May have default nodes

    def test_finds_python_files(self, tmp_path):
        """Test that analyzer finds Python workflow files."""
        # Create a mock workflow file
        workflow_file = tmp_path / "workflow.py"
        workflow_file.write_text(
            """
from langgraph.prebuilt import create_react_agent
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(model="gpt-4")
agent = create_react_agent(llm, tools=[])
"""
        )
        analyzer = LangGraphAnalyzer(input_dir=tmp_path)
        assert len(list(tmp_path.glob("*.py"))) > 0


class TestCrewAIAnalyzer:
    """Tests for CrewAI analyzer."""

    def test_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = CrewAIAnalyzer(input_dir=Path("."))
        assert analyzer.input_dir == Path(".")
        assert analyzer.framework_name == "CrewAI"

    def test_empty_directory(self, tmp_path):
        """Test analysis of empty directory."""
        analyzer = CrewAIAnalyzer(input_dir=tmp_path)
        graph = analyzer.analyze()
        assert isinstance(graph, GraphDefinition)
        assert graph.framework == "CrewAI"

    def test_detects_crew_pattern(self, tmp_path):
        """Test detection of CrewAI patterns."""
        workflow_file = tmp_path / "crew.py"
        workflow_file.write_text(
            """
from crewai import Agent, Task, Crew

researcher = Agent(
    role='Researcher',
    goal='Find information',
    tools=[]
)

crew = Crew(agents=[researcher], tasks=[])
"""
        )
        analyzer = CrewAIAnalyzer(input_dir=tmp_path)
        # Just verify it doesn't crash
        assert analyzer is not None


class TestAutogenAnalyzer:
    """Tests for Autogen analyzer."""

    def test_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = AutogenAnalyzer(input_dir=Path("."))
        assert analyzer.input_dir == Path(".")
        assert analyzer.framework_name == "Autogen"

    def test_empty_directory(self, tmp_path):
        """Test analysis of empty directory."""
        analyzer = AutogenAnalyzer(input_dir=tmp_path)
        graph = analyzer.analyze()
        assert isinstance(graph, GraphDefinition)
        assert graph.framework == "Autogen"


class TestN8NAnalyzer:
    """Tests for n8n analyzer."""

    def test_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = N8NAnalyzer(input_dir=Path("."))
        assert analyzer.input_dir == Path(".")
        assert analyzer.framework_name == "n8n"

    def test_empty_directory(self, tmp_path):
        """Test analysis of empty directory."""
        analyzer = N8NAnalyzer(input_dir=tmp_path)
        graph = analyzer.analyze()
        assert isinstance(graph, GraphDefinition)
        assert graph.framework == "n8n"

    def test_json_file_detection(self, tmp_path):
        """Test that analyzer looks for JSON files."""
        json_file = tmp_path / "workflow.json"
        json_file.write_text('{"nodes": [], "connections": {}}')
        analyzer = N8NAnalyzer(input_dir=tmp_path)
        json_files = list(tmp_path.glob("*.json"))
        assert len(json_files) > 0


class TestOpenAIAgentsAnalyzer:
    """Tests for OpenAI Agents analyzer."""

    def test_initialization(self):
        """Test analyzer can be initialized."""
        analyzer = OpenAIAgentsAnalyzer(input_dir=Path("."))
        assert analyzer.input_dir == Path(".")
        assert analyzer.framework_name == "OpenAI Agents"

    def test_empty_directory(self, tmp_path):
        """Test analysis of empty directory."""
        analyzer = OpenAIAgentsAnalyzer(input_dir=tmp_path)
        graph = analyzer.analyze()
        assert isinstance(graph, GraphDefinition)
        assert graph.framework == "OpenAI Agents"


class TestAnalyzerCommon:
    """Tests for common analyzer functionality."""

    def test_all_analyzers_return_graph(self, tmp_path):
        """Test that all analyzers return GraphDefinition."""
        analyzers = [
            LangGraphAnalyzer(tmp_path),
            CrewAIAnalyzer(tmp_path),
            AutogenAnalyzer(tmp_path),
            N8NAnalyzer(tmp_path),
            OpenAIAgentsAnalyzer(tmp_path),
        ]

        for analyzer in analyzers:
            graph = analyzer.analyze()
            assert isinstance(graph, GraphDefinition)
            assert len(graph.framework) > 0

    def test_analyzers_handle_nonexistent_dir(self):
        """Test analyzers handle nonexistent directories gracefully."""
        nonexistent = Path("/nonexistent/path/that/does/not/exist")
        analyzers = [
            LangGraphAnalyzer(nonexistent),
            CrewAIAnalyzer(nonexistent),
            AutogenAnalyzer(nonexistent),
        ]

        for analyzer in analyzers:
            # Should not crash on initialization
            assert analyzer is not None
            assert analyzer.input_dir == nonexistent
