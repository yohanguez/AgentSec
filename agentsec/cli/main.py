import os
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional

import typer

from agentsec import __version__
from agentsec.analyzers import (
    AutogenAnalyzer,
    CrewAIAnalyzer,
    LangGraphAnalyzer,
    N8NAnalyzer,
    OpenAIAgentsAnalyzer,
)
from agentsec.mappers import VulnerabilityMapper
from agentsec.report import ReportGenerator

app = typer.Typer(
    name="agentsec",
    help="Static security analysis for AI agent workflows",
    add_completion=False,
)


class Framework(str, Enum):
    LANGGRAPH = "langgraph"
    CREWAI = "crewai"
    OPENAI_AGENTS = "openai-agents"
    AUTOGEN = "autogen"
    N8N = "n8n"


@app.command()
def scan(
    framework: Framework = typer.Argument(
        ..., help="Framework to analyze (langgraph, crewai, openai-agents, autogen, n8n)"
    ),
    input_dir: Optional[Path] = typer.Option(
        None,
        "--input-dir",
        "-i",
        help="Directory containing the code to analyze (default: current directory)",
    ),
    output_file: Optional[Path] = typer.Option(
        None,
        "--output-file",
        "-o",
        help="Output file path (default: report_TIMESTAMP.html)",
    ),
    export_json: bool = typer.Option(
        False, "--export-graph-json", help="Export GraphDefinition as JSON instead of HTML"
    ),
    harden_prompts: bool = typer.Option(
        False, "--harden-prompts", help="Enable prompt hardening (requires OPENAI_API_KEY)"
    ),
):
    # Set defaults
    if input_dir is None:
        input_dir = Path(os.getenv("AGENTSEC_INPUT_DIRECTORY", "."))

    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        extension = "json" if export_json else "html"
        output_file = Path(
            os.getenv("AGENTSEC_OUTPUT_FILE", f"report_{timestamp}.{extension}")
        )

    # Validate input directory
    if not input_dir.exists():
        typer.echo(f"❌ Error: Input directory not found: {input_dir}", err=True)
        raise typer.Exit(1)

    typer.echo(f"🔍 Analyzing {input_dir} for {framework.value} workflows...")

    # Select analyzer
    analyzer_map = {
        Framework.LANGGRAPH: LangGraphAnalyzer,
        Framework.CREWAI: CrewAIAnalyzer,
        Framework.OPENAI_AGENTS: OpenAIAgentsAnalyzer,
        Framework.AUTOGEN: AutogenAnalyzer,
        Framework.N8N: N8NAnalyzer,
    }

    analyzer_class = analyzer_map[framework]
    analyzer = analyzer_class(input_dir)

    # Run analysis
    try:
        graph = analyzer.analyze()
    except Exception as e:
        typer.echo(f"❌ Error during analysis: {e}", err=True)
        raise typer.Exit(1)

    # Check if workflow was found
    if len(graph.nodes) < 3:
        typer.echo(
            f"⚠️  Warning: No significant workflow found in {input_dir}. "
            f"Found only {len(graph.nodes)} nodes.",
            err=True,
        )
        typer.echo(
            "Please ensure the directory contains agent workflow code for "
            f"{framework.value}.",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"✓ Found {len(graph.agents)} agents and {len(graph.get_tools())} tools")

    # Map vulnerabilities
    typer.echo("🔍 Mapping vulnerabilities...")
    mapper = VulnerabilityMapper()
    graph = mapper.map_vulnerabilities(graph)

    vuln_count = graph.get_total_vulnerabilities()
    if vuln_count > 0:
        typer.echo(f"⚠️  Found {vuln_count} vulnerabilities")
    else:
        typer.echo("✓ No vulnerabilities detected")

    # Prompt hardening (optional)
    if harden_prompts:
        try:
            from agentsec.hardening import PromptHardener

            typer.echo("🛡️  Hardening prompts...")
            hardener = PromptHardener()
            hardened_prompts = hardener.harden_all(graph.agents)
            # TODO: Add hardened prompts to graph metadata
            typer.echo(f"✓ Hardened {len(hardened_prompts)} prompts")
        except ImportError:
            typer.echo(
                "⚠️  Prompt hardening requires OpenAI package. "
                "Install with: pip install agentsec[prompt-hardening]",
                err=True,
            )
        except Exception as e:
            typer.echo(f"⚠️  Warning: Prompt hardening failed: {e}", err=True)

    # Generate report
    typer.echo("📝 Generating report...")
    generator = ReportGenerator()

    try:
        if export_json:
            generator.generate_json(graph, output_file)
        else:
            generator.generate_html(graph, output_file)

        typer.echo(f"✅ Report generated: {output_file.absolute()}")

        # Summary
        typer.echo("\n" + "=" * 50)
        typer.echo("📊 Summary:")
        typer.echo(f"  • Agents: {len(graph.agents)}")
        typer.echo(f"  • Tools: {len(graph.get_tools())}")
        typer.echo(f"  • Vulnerabilities: {vuln_count}")
        if vuln_count > 0:
            typer.echo(
                f"\n⚠️  Found {vuln_count} security issues. "
                f"Review the report for details."
            )
        typer.echo("=" * 50)

    except Exception as e:
        typer.echo(f"❌ Error generating report: {e}", err=True)
        raise typer.Exit(1)


@app.command()
def version():
    typer.echo(f"AgentSec v{__version__}")
    typer.echo("Static Security Analysis for AI Agent Workflows")


if __name__ == "__main__":
    app()
