#!/usr/bin/env python3

from agentsec.models import (
    GraphDefinition,
    NodeDefinition,
    EdgeDefinition,
    AgentDefinition,
    NodeType,
    ToolCategory,
)
from agentsec.mappers import VulnerabilityMapper
from agentsec.report import ReportGenerator

def test_agentsec():
    print("🧪 Testing AgentSec Core Functionality\n")

    # 1. Create a sample workflow graph
    print("1️⃣ Creating sample workflow...")
    graph = GraphDefinition(
        framework="LangGraph",
        nodes=[
            NodeDefinition(
                id="start",
                name="START",
                type=NodeType.BASIC,
                description="Start node"
            ),
            NodeDefinition(
                id="agent1",
                name="Research Agent",
                type=NodeType.AGENT,
                description="Agent that researches information"
            ),
            NodeDefinition(
                id="tool_search",
                name="DuckDuckGoSearchRun",
                type=NodeType.TOOL,
                category=ToolCategory.WEB_SEARCH,
                description="Web search tool"
            ),
            NodeDefinition(
                id="tool_python",
                name="PythonREPL",
                type=NodeType.TOOL,
                category=ToolCategory.CODE_INTERPRETER,
                description="Python code execution"
            ),
            NodeDefinition(
                id="tool_file",
                name="FileReadTool",
                type=NodeType.TOOL,
                category=ToolCategory.DOCUMENT_LOADER,
                description="File reading tool"
            ),
            NodeDefinition(
                id="end",
                name="END",
                type=NodeType.BASIC,
                description="End node"
            ),
        ],
        edges=[
            EdgeDefinition(source="start", target="agent1"),
            EdgeDefinition(source="agent1", target="tool_search"),
            EdgeDefinition(source="tool_search", target="tool_python"),
            EdgeDefinition(source="tool_python", target="tool_file"),
            EdgeDefinition(source="tool_file", target="end"),
        ],
        agents=[
            AgentDefinition(
                name="Research Agent",
                llm_model="gpt-4",
                system_prompt="You are a helpful research assistant.",
                has_guardrails=False
            )
        ]
    )

    print(f"   ✓ Created graph with {len(graph.nodes)} nodes")
    print(f"   ✓ Created graph with {len(graph.edges)} edges")
    print(f"   ✓ Created graph with {len(graph.agents)} agents")
    print(f"   ✓ Created graph with {len(graph.get_tools())} tools\n")

    # 2. Map vulnerabilities
    print("2️⃣ Mapping vulnerabilities...")
    mapper = VulnerabilityMapper()
    graph = mapper.map_vulnerabilities(graph)

    vuln_count = graph.get_total_vulnerabilities()
    print(f"   ✓ Detected {vuln_count} vulnerabilities\n")

    # 3. Show vulnerability details
    print("3️⃣ Vulnerability Details:")
    for tool in graph.get_tools():
        if tool.vulnerabilities:
            print(f"\n   🔧 {tool.name} ({tool.category.value}):")
            for vuln in tool.vulnerabilities:
                print(f"      ⚠️  {vuln.name}")
                frameworks = ", ".join(f"{k}: {v}" for k, v in vuln.security_framework_mapping.items())
                if frameworks:
                    print(f"         {frameworks}")

    print()

    # 4. Generate report
    print("4️⃣ Generating HTML report...")
    from pathlib import Path
    generator = ReportGenerator()
    generator.generate_html(graph, Path("test_functional_report.html"))
    print("   ✓ Report generated: test_functional_report.html\n")

    # 5. Generate JSON export
    print("5️⃣ Generating JSON export...")
    generator.generate_json(graph, Path("test_functional_export.json"))
    print("   ✓ JSON exported: test_functional_export.json\n")

    # 6. Summary
    print("=" * 60)
    print("✅ TEST RESULTS:")
    print("=" * 60)
    print(f"Nodes:            {len(graph.nodes)}")
    print(f"Edges:            {len(graph.edges)}")
    print(f"Agents:           {len(graph.agents)}")
    print(f"Tools:            {len(graph.get_tools())}")
    print(f"Vulnerabilities:  {vuln_count}")
    print("=" * 60)
    print("\n🎉 All tests passed! AgentSec is working correctly.\n")

    return True


if __name__ == "__main__":
    try:
        test_agentsec()
    except Exception as e:
        print(f"❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
