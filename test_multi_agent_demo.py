#!/usr/bin/env python3

from pathlib import Path
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


def create_multi_agent_graph():
    print("🏗️  Building Multi-Agent Workflow Graph...\n")

    # Define nodes
    nodes = [
        # Start/End nodes
        NodeDefinition(
            id="start",
            name="START",
            type=NodeType.BASIC,
            description="Workflow entry point"
        ),
        NodeDefinition(
            id="supervisor",
            name="Supervisor",
            type=NodeType.AGENT,
            description="Coordinates agent activities and logs to database"
        ),

        # Agent 1: Research Agent
        NodeDefinition(
            id="research_agent",
            name="Research Agent",
            type=NodeType.AGENT,
            description="Gathers information from web, databases, and repositories"
        ),

        # Agent 2: Developer Agent
        NodeDefinition(
            id="developer_agent",
            name="Developer Agent",
            type=NodeType.AGENT,
            description="Writes code, manages files, and commits changes"
        ),

        # Tools for Research Agent
        NodeDefinition(
            id="tool_search",
            name="DuckDuckGoSearchRun",
            type=NodeType.TOOL,
            category=ToolCategory.WEB_SEARCH,
            description="Web search for gathering information"
        ),

        # Tools for Developer Agent
        NodeDefinition(
            id="tool_python",
            name="PythonREPL",
            type=NodeType.TOOL,
            category=ToolCategory.CODE_INTERPRETER,
            description="Execute Python code for development tasks"
        ),

        # MCP Servers (External Services)
        NodeDefinition(
            id="mcp_filesystem",
            name="MCP Filesystem Server",
            type=NodeType.MCP_SERVER,
            category=ToolCategory.DOCUMENT_LOADER,
            description="Provides file system operations (read, write, list directories)"
        ),
        NodeDefinition(
            id="mcp_git",
            name="MCP Git Server",
            type=NodeType.MCP_SERVER,
            category=ToolCategory.DEFAULT,
            description="Provides Git operations (clone, commit, push, pull)"
        ),
        NodeDefinition(
            id="mcp_database",
            name="MCP PostgreSQL Server",
            type=NodeType.MCP_SERVER,
            category=ToolCategory.DATABASE,
            description="Provides database operations (query, insert, update)"
        ),

        # End node
        NodeDefinition(
            id="end",
            name="END",
            type=NodeType.BASIC,
            description="Workflow completion"
        ),
    ]

    # Define edges (workflow connections)
    edges = [
        # Entry flow
        EdgeDefinition(source="start", target="supervisor"),
        EdgeDefinition(source="supervisor", target="research_agent"),

        # Research Agent connections
        EdgeDefinition(source="research_agent", target="tool_search"),
        EdgeDefinition(source="research_agent", target="mcp_database"),
        EdgeDefinition(source="research_agent", target="mcp_git"),

        # Agent handoff: Research -> Developer
        EdgeDefinition(
            source="research_agent",
            target="developer_agent",
            condition="has_data"
        ),

        # Developer Agent connections
        EdgeDefinition(source="developer_agent", target="tool_python"),
        EdgeDefinition(source="developer_agent", target="mcp_filesystem"),
        EdgeDefinition(source="developer_agent", target="mcp_git"),

        # Agent handoff: Developer -> Research (for more info)
        EdgeDefinition(
            source="developer_agent",
            target="research_agent",
            condition="needs_more_info"
        ),

        # Supervisor logging
        EdgeDefinition(source="tool_search", target="supervisor"),
        EdgeDefinition(source="tool_python", target="supervisor"),

        # Exit flow
        EdgeDefinition(
            source="developer_agent",
            target="end",
            condition="complete"
        ),
    ]

    # Define agents with their prompts
    agents = [
        AgentDefinition(
            name="Supervisor",
            llm_model="gpt-4",
            system_prompt="""You are a Supervisor Agent that coordinates multiple specialized agents.

Your responsibilities:
- Route tasks to appropriate agents
- Monitor agent activities
- Log all operations to database
- Ensure workflow completion

You coordinate between Research Agent and Developer Agent.""",
            has_guardrails=False
        ),
        AgentDefinition(
            name="Research Agent",
            llm_model="gpt-4-turbo",
            system_prompt="""You are a Research Agent specialized in information gathering.

Your responsibilities:
- Search the web for relevant information using DuckDuckGo
- Query databases for historical data using PostgreSQL
- Access code repositories via Git for technical details

Tools available:
- Web Search (DuckDuckGo) - for internet research
- Database Query (PostgreSQL via MCP) - for structured data
- Git Repository Access (GitHub via MCP) - for code analysis

When you complete your research, hand off to the Developer Agent.

SECURITY NOTE: Validate all URLs and sanitize database queries.""",
            has_guardrails=False
        ),
        AgentDefinition(
            name="Developer Agent",
            llm_model="gpt-4-turbo",
            system_prompt="""You are a Developer Agent specialized in code development.

Your responsibilities:
- Write Python code based on research findings
- Execute code in Python REPL environment
- Manage files via filesystem MCP server
- Commit changes via Git MCP server

Tools available:
- Python REPL - for code execution
- Filesystem Access (via MCP) - for file operations
- Git Operations (via MCP) - for version control

When you need more information, hand off back to Research Agent.

SECURITY NOTE: Validate file paths and never execute untrusted code.""",
            has_guardrails=False
        ),
    ]

    # Create graph
    graph = GraphDefinition(
        framework="LangGraph",
        nodes=nodes,
        edges=edges,
        agents=agents,
        metadata={
            "description": "Multi-agent system with MCP server integration",
            "agent_count": "3",
            "mcp_server_count": "3",
            "communication_pattern": "bidirectional handoffs"
        }
    )

    print(f"✓ Created graph with {len(nodes)} nodes")
    print(f"✓ Created {len(agents)} agents:")
    for agent in agents:
        print(f"  - {agent.name} ({agent.llm_model})")
    print(f"✓ Created {len(edges)} edges (including {sum(1 for e in edges if e.condition)} conditional)")
    print(f"✓ Integrated {len([n for n in nodes if n.type == NodeType.MCP_SERVER])} MCP servers\n")

    return graph


def main():
    print("=" * 70)
    print("  Multi-Agent System with MCP Servers - Security Analysis")
    print("=" * 70)
    print()

    # Step 1: Create the graph
    graph = create_multi_agent_graph()

    # Step 2: Map vulnerabilities
    print("🔍 Mapping Vulnerabilities...")
    mapper = VulnerabilityMapper()
    graph = mapper.map_vulnerabilities(graph)

    vuln_count = graph.get_total_vulnerabilities()
    print(f"⚠️  Detected {vuln_count} vulnerabilities across tools and MCP servers\n")

    # Step 3: Show vulnerability summary
    print("📋 Vulnerability Summary:")
    print("-" * 70)

    tools_with_vulns = [n for n in graph.get_tools() if n.vulnerabilities]
    mcp_with_vulns = [n for n in graph.get_mcp_servers() if n.vulnerabilities]

    for node in tools_with_vulns + mcp_with_vulns:
        print(f"\n🔧 {node.name} ({node.type.value}):")
        for vuln in node.vulnerabilities:
            print(f"   ⚠️  {vuln.name}")
            if vuln.security_framework_mapping:
                frameworks = ", ".join(
                    f"{k}: {v}" for k, v in vuln.security_framework_mapping.items()
                )
                print(f"      {frameworks}")

    print()

    # Step 4: Show agent communication
    print("💬 Agent Communication Flow:")
    print("-" * 70)
    print("1. Supervisor coordinates the workflow")
    print("2. Research Agent → gathers data → uses Web Search + MCP Database + MCP Git")
    print("3. Research Agent → hands off to → Developer Agent")
    print("4. Developer Agent → implements code → uses Python REPL + MCP Filesystem + MCP Git")
    print("5. Developer Agent → can hand back to → Research Agent (if more info needed)")
    print("6. Supervisor → logs all activities → via MCP Database")
    print()

    # Step 5: Generate report
    print("📝 Generating HTML Report...")
    generator = ReportGenerator()
    output_path = Path("multi_agent_mcp_report.html")
    generator.generate_html(graph, output_path)
    print(f"✅ Report generated: {output_path.absolute()}\n")

    # Step 6: Generate JSON export
    print("📊 Generating JSON Export...")
    json_path = Path("multi_agent_mcp_export.json")
    generator.generate_json(graph, json_path)
    print(f"✅ JSON exported: {json_path.absolute()}\n")

    # Final summary
    print("=" * 70)
    print("✅ ANALYSIS COMPLETE")
    print("=" * 70)
    print(f"Agents:           {len(graph.agents)}")
    print(f"Total Nodes:      {len(graph.nodes)}")
    print(f"Tools:            {len(graph.get_tools())}")
    print(f"MCP Servers:      {len(graph.get_mcp_servers())}")
    print(f"Edges:            {len(graph.edges)}")
    print(f"Vulnerabilities:  {vuln_count}")
    print("=" * 70)
    print()
    print("🌐 Open the report to see:")
    print("   • Visual workflow graph with agent handoffs")
    print("   • Agent communication patterns")
    print("   • MCP server integrations")
    print("   • Complete vulnerability analysis")
    print()
    print("📂 Files created:")
    print(f"   • multi_agent_mcp_report.html")
    print(f"   • multi_agent_mcp_export.json")
    print()


if __name__ == "__main__":
    main()
