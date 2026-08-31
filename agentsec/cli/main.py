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
from agentsec.audit import Auditor
from agentsec.models import Severity
from agentsec.report import ReportGenerator

app = typer.Typer(
    name="agentsec",
    help="Audit AI agent workflows for excessive agency and abusable attack paths",
    add_completion=False,
)


class Framework(str, Enum):
    LANGGRAPH = "langgraph"
    CREWAI = "crewai"
    OPENAI_AGENTS = "openai-agents"
    AUTOGEN = "autogen"
    N8N = "n8n"


ANALYZER_MAP = {
    Framework.LANGGRAPH: LangGraphAnalyzer,
    Framework.CREWAI: CrewAIAnalyzer,
    Framework.OPENAI_AGENTS: OpenAIAgentsAnalyzer,
    Framework.AUTOGEN: AutogenAnalyzer,
    Framework.N8N: N8NAnalyzer,
}

_SEV_ICON = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH: "🟠",
    Severity.MEDIUM: "🟡",
    Severity.LOW: "🔵",
    Severity.INFO: "⚪",
}


@app.command()
def scan(
    framework: Framework = typer.Argument(
        ..., help="Framework to analyze (langgraph, crewai, openai-agents, autogen, n8n)"
    ),
    input_dir: Optional[Path] = typer.Option(
        None, "--input-dir", "-i", help="Directory containing the code to analyze"
    ),
    output_file: Optional[Path] = typer.Option(
        None, "--output-file", "-o", help="Output file path (default: report_TIMESTAMP.html)"
    ),
    export_json: bool = typer.Option(
        False, "--export-graph-json", help="Export the audited graph as JSON instead of HTML"
    ),
):
    if input_dir is None:
        input_dir = Path(os.getenv("AGENTSEC_INPUT_DIRECTORY", "."))
    if output_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "json" if export_json else "html"
        output_file = Path(os.getenv("AGENTSEC_OUTPUT_FILE", f"report_{timestamp}.{ext}"))

    if not input_dir.exists():
        typer.echo(f"❌ Input directory not found: {input_dir}", err=True)
        raise typer.Exit(1)

    typer.echo(f"🔍 Analyzing {input_dir} for {framework.value} workflows...")
    analyzer = ANALYZER_MAP[framework](input_dir)
    try:
        graph = analyzer.analyze()
    except Exception as e:
        typer.echo(f"❌ Error during analysis: {e}", err=True)
        raise typer.Exit(1)

    if len(graph.nodes) < 3:
        typer.echo(
            f"⚠️  No significant workflow found in {input_dir} "
            f"(only {len(graph.nodes)} nodes).",
            err=True,
        )
        raise typer.Exit(1)

    typer.echo(f"✓ Found {len(graph.agents)} agents and {len(graph.get_tools())} tools")

    typer.echo("🔬 Auditing privileges and attack paths...")
    graph = Auditor(input_dir).audit(graph)

    _print_summary(graph)

    typer.echo("📝 Generating report...")
    generator = ReportGenerator()
    try:
        if export_json:
            generator.generate_json(graph, output_file)
        else:
            generator.generate_html(graph, output_file)
    except Exception as e:
        typer.echo(f"❌ Error generating report: {e}", err=True)
        raise typer.Exit(1)

    typer.echo(f"✅ Report generated: {output_file.absolute()}")


def _print_summary(graph) -> None:
    typer.echo("\n" + "=" * 60)
    typer.echo("🪪  PRIVILEGE REPORT CARD")
    for a in graph.agents:
        caps = ", ".join(c.value for c in a.direct_capabilities) or "none"
        typer.echo(f"   [{a.privilege_grade}] {a.name:<16} {caps}")
    typer.echo("-" * 60)
    counts = {s: len(graph.get_findings_by_severity(s)) for s in Severity}
    typer.echo(
        "⚠️  Findings: "
        + f"{counts[Severity.CRITICAL]} critical, "
        + f"{counts[Severity.HIGH]} high, "
        + f"{counts[Severity.MEDIUM]} medium"
    )
    for f in graph.findings:
        typer.echo(f"   {_SEV_ICON.get(f.severity, '•')} [{f.severity.value:<8}] {f.title}")
    typer.echo("=" * 60 + "\n")


@app.command()
def monitor(
    duration: int = typer.Option(30, "--duration", "-d", help="Seconds to observe"),
    output_file: Optional[Path] = typer.Option(
        None, "--output-file", "-o", help="Write the JSON summary here"
    ),
):
    """Observe live network connections and flag runtime AI/LLM traffic."""
    try:
        from agentsec.monitor import monitor_network
    except ImportError:
        typer.echo("❌ Runtime monitor requires psutil: pip install agentsec[monitor]", err=True)
        raise typer.Exit(1)
    monitor_network(duration=duration, output_file=output_file)


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host"),
    port: int = typer.Option(8000, "--port", "-p"),
):
    """Launch the local AgentSec web dashboard."""
    try:
        from agentsec.server import run_server
    except ImportError:
        typer.echo("❌ Web dashboard requires FastAPI: pip install agentsec[server]", err=True)
        raise typer.Exit(1)
    run_server(host=host, port=port)


@app.command()
def version():
    typer.echo(f"AgentSec v{__version__}")
    typer.echo("Auditing AI Agents — Because Your Autonomous AI Probably Shouldn't Have Root")


if __name__ == "__main__":
    app()
