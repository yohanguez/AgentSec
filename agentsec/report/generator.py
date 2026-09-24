from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agentsec import __version__
from agentsec.audit import privilege
from agentsec.models import GraphDefinition, Severity
from agentsec.report.graph_visualizer import GraphVisualizer


class ReportGenerator:
    def __init__(self):
        template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.visualizer = GraphVisualizer()

    def _context(self, graph: GraphDefinition) -> dict:
        severity_counts = {s.value: len(graph.get_findings_by_severity(s)) for s in Severity}
        # Per-agent report card rows.
        report_card = []
        for a in graph.agents:
            report_card.append(
                {
                    "name": a.name,
                    "model": a.llm_model or "N/A",
                    "grade": a.privilege_grade,
                    "grade_label": privilege.grade_label(a.privilege_grade),
                    "score": a.privilege_score,
                    "direct": [c.value for c in a.direct_capabilities],
                    "reachable": [c.value for c in a.reachable_capabilities],
                }
            )
        return {
            "framework": graph.framework,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": __version__,
            "total_findings": len(graph.findings),
            "total_agents": len(graph.agents),
            "total_tools": len(graph.get_tools()),
            "severity_counts": severity_counts,
            "findings": graph.findings,
            "report_card": report_card,
            "tools": graph.get_tools(),
            "mcp_servers": graph.get_mcp_servers(),
            "graph_svg": self.visualizer.generate_svg(graph),
            "has_findings": len(graph.findings) > 0,
        }

    def render_html(self, graph: GraphDefinition) -> str:
        template = self.env.get_template("report.html")
        return template.render(**self._context(graph))

    def generate_html(self, graph: GraphDefinition, output_path: Path) -> None:
        html_content = self.render_html(graph)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def generate_json(self, graph: GraphDefinition, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(graph.model_dump_json(indent=2))
