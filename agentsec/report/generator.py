from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from agentsec import __version__
from agentsec.models import GraphDefinition
from agentsec.report.graph_visualizer import GraphVisualizer


class ReportGenerator:
    def __init__(self):
        template_dir = Path(__file__).parent.parent / "templates"
        self.env = Environment(
            loader=FileSystemLoader(str(template_dir)),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.visualizer = GraphVisualizer()

    def generate_html(self, graph: GraphDefinition, output_path: Path) -> None:
        # Generate graph visualization
        graph_svg = self.visualizer.generate_svg(graph)

        # Prepare template context
        context = {
            "framework": graph.framework,
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "version": __version__,
            "total_vulnerabilities": graph.get_total_vulnerabilities(),
            "total_agents": len(graph.agents),
            "total_tools": len(graph.get_tools()),
            "graph_svg": graph_svg,
            "agents": graph.agents,
            "tools": graph.get_tools(),
            "mcp_servers": graph.get_mcp_servers(),
            "has_vulnerabilities": graph.get_total_vulnerabilities() > 0,
        }

        # Render template
        template = self.env.get_template("report.html")
        html_content = template.render(**context)

        # Write to file
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)

    def generate_json(self, graph: GraphDefinition, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(graph.model_dump_json(indent=2))
