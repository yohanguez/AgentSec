"""Local AgentSec web dashboard (FastAPI).

Unified dashboard, separate pages:
  GET  /                  dashboard listing all scan + monitor runs
  GET  /scan/{id}         full interactive audit report for a static scan
  GET  /monitor/{id}      runtime connection report
  POST /api/scan          {framework, path} -> run static audit -> {id}
  POST /api/monitor       {duration}        -> run runtime monitor -> {id}
  GET  /api/scan/{id}     raw audited-graph JSON (CI/CD friendly)
"""

from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel

from agentsec import __version__
from agentsec.audit import Auditor
from agentsec.models import GraphDefinition, Severity
from agentsec.report import ReportGenerator
from agentsec.server.store import RunStore


class ScanRequest(BaseModel):
    framework: str
    path: str


class MonitorRequest(BaseModel):
    duration: int = 15


class ConsoleRequest(BaseModel):
    ticket: str
    mode: str = "deterministic"


# Directories the interactive Agent Console demonstrates against.
_CONSOLE_TARGET = Path(__file__).parent.parent.parent / "demo" / "autoops"
_CONSOLE_SECURE_TARGET = Path(__file__).parent.parent.parent / "demo" / "autoops_secure"


def _analyzer_map():
    from agentsec.analyzers import (
        AutogenAnalyzer,
        CrewAIAnalyzer,
        LangGraphAnalyzer,
        N8NAnalyzer,
        OpenAIAgentsAnalyzer,
    )

    return {
        "langgraph": LangGraphAnalyzer,
        "crewai": CrewAIAnalyzer,
        "openai-agents": OpenAIAgentsAnalyzer,
        "autogen": AutogenAnalyzer,
        "n8n": N8NAnalyzer,
    }


def create_app(db_path: Optional[Path] = None) -> FastAPI:
    app = FastAPI(title="AgentSec", version=__version__)
    store = RunStore(db_path)
    report_gen = ReportGenerator()
    template_dir = Path(__file__).parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "xml"]),
    )

    def _scan_summary(graph: GraphDefinition) -> dict:
        counts = {s.value: len(graph.get_findings_by_severity(s)) for s in Severity}
        return {
            "agents": len(graph.agents),
            "tools": len(graph.get_tools()),
            "findings": len(graph.findings),
            "critical": counts["critical"],
            "high": counts["high"],
            "medium": counts["medium"],
        }

    # ---------------------------------------------------------------- pages
    @app.get("/", response_class=HTMLResponse)
    def dashboard():
        return env.get_template("dashboard.html").render(
            runs=store.list(), version=__version__
        )

    @app.get("/scan/{run_id}", response_class=HTMLResponse)
    def scan_page(run_id: str):
        run = store.get(run_id)
        if not run or run["kind"] != "scan":
            raise HTTPException(status_code=404, detail="scan not found")
        graph = GraphDefinition(**run["data"])
        return report_gen.render_html(graph)

    @app.get("/monitor/{run_id}", response_class=HTMLResponse)
    def monitor_page(run_id: str):
        run = store.get(run_id)
        if not run or run["kind"] != "monitor":
            raise HTTPException(status_code=404, detail="monitor run not found")
        return env.get_template("monitor.html").render(
            run=run, summary=run["data"], version=__version__
        )

    # ---------------------------------------------------------------- api
    @app.post("/api/scan")
    def api_scan(req: ScanRequest):
        analyzers = _analyzer_map()
        if req.framework not in analyzers:
            raise HTTPException(status_code=400, detail=f"unknown framework: {req.framework}")
        input_dir = Path(req.path)
        if not input_dir.exists():
            raise HTTPException(status_code=400, detail=f"path not found: {req.path}")
        graph = analyzers[req.framework](input_dir).analyze()
        graph = Auditor(input_dir).audit(graph)
        summary = _scan_summary(graph)
        run_id = store.add(
            kind="scan",
            title=f"{req.framework}: {input_dir.name}",
            summary=summary,
            data=graph.model_dump(mode="json"),
            framework=req.framework,
        )
        return {"id": run_id, "summary": summary, "url": f"/scan/{run_id}"}

    @app.post("/api/monitor")
    def api_monitor(req: MonitorRequest):
        try:
            from agentsec.monitor import NetworkMonitor
        except ImportError:
            raise HTTPException(status_code=500, detail="psutil not installed")
        summary = NetworkMonitor().monitor(duration_seconds=req.duration)
        run_id = store.add(
            kind="monitor",
            title=f"Runtime monitor ({req.duration}s)",
            summary={
                "connections": summary["total_connections"],
                "services": len(summary["unique_services"]),
            },
            data=summary,
        )
        return {"id": run_id, "summary": summary, "url": f"/monitor/{run_id}"}

    @app.get("/api/scan/{run_id}")
    def api_get_scan(run_id: str):
        run = store.get(run_id)
        if not run:
            raise HTTPException(status_code=404, detail="not found")
        return JSONResponse(run["data"])

    # ---------------------------------------------------------------- console
    @app.get("/console", response_class=HTMLResponse)
    def console_page():
        return env.get_template("console.html").render(version=__version__)

    @app.get("/console/graph")
    def console_graph(target: str = "vulnerable"):
        from agentsec.analyzers import LangGraphAnalyzer

        tdir = _CONSOLE_SECURE_TARGET if target == "secure" else _CONSOLE_TARGET
        if not tdir.exists():
            raise HTTPException(status_code=404, detail="console target missing")
        graph = LangGraphAnalyzer(tdir).analyze()
        graph = Auditor(tdir).audit(graph)
        grade = {a.node_id: a.privilege_grade for a in graph.agents if a.node_id}
        owner = {}
        for a in graph.agents:
            for tid in a.tool_ids:
                owner[tid] = a.node_id
        return {
            "nodes": [
                {"id": n.id, "name": n.name, "type": n.type.value,
                 "capabilities": [c.value for c in n.capabilities],
                 "is_source": n.is_source, "grade": grade.get(n.id),
                 "owner": owner.get(n.id)}
                for n in graph.nodes
            ],
            "edges": [{"source": e.source, "target": e.target} for e in graph.edges],
            "agents": [{"node_id": a.node_id, "tool_ids": a.tool_ids} for a in graph.agents],
        }

    @app.get("/console/presets")
    def console_presets():
        from agentsec.server.console import preset_tickets

        return preset_tickets()

    @app.get("/console/info")
    def console_info():
        from agentsec.server.sandbox import Sandbox

        sb = Sandbox.get()
        return {
            "c2_url": sb.c2_url,
            "metadata_url": sb.metadata_url,
            "sandbox_dir": str(sb.dir),
        }

    @app.post("/console/submit")
    def console_submit(req: ConsoleRequest):
        from agentsec.server.console import (
            ConsoleAgent, SecureConsoleAgent, run_llm, run_ollama, run_ollama_secure,
        )

        # Two orthogonal axes: agent (vulnerable|hardened) × brain (rule|llm).
        # `mode` encodes the combination.
        if req.mode == "secure_llm":       # hardened agent, real LLM
            return run_ollama_secure(req.ticket)
        if req.mode == "secure":           # hardened agent, rule-based
            return SecureConsoleAgent().run(req.ticket)
        if req.mode == "ollama":           # vulnerable agent, real LLM
            return run_ollama(req.ticket)
        if req.mode == "llm":              # vulnerable agent, OpenAI
            return run_llm(req.ticket)
        return ConsoleAgent().run(req.ticket)  # vulnerable agent, rule-based

    return app


def run_server(host: str = "127.0.0.1", port: int = 8000) -> None:
    import uvicorn

    print(f"🚀 AgentSec dashboard on http://{host}:{port}")
    uvicorn.run(create_app(), host=host, port=port)
