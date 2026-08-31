import tempfile
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from agentsec.server.app import create_app  # noqa: E402

DEMO = str(Path(__file__).parent.parent / "demo" / "autoops")


@pytest.fixture()
def client():
    db = Path(tempfile.mkdtemp()) / "test.db"
    return TestClient(create_app(db_path=db))


def test_dashboard_loads(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "AgentSec Dashboard" in r.text


def test_scan_flow_and_report_page(client):
    r = client.post("/api/scan", json={"framework": "langgraph", "path": DEMO})
    assert r.status_code == 200
    body = r.json()
    assert body["summary"]["critical"] >= 1
    run_id = body["id"]

    page = client.get(f"/scan/{run_id}")
    assert page.status_code == 200
    assert "Lethal Trifecta" in page.text
    assert "<svg" in page.text

    raw = client.get(f"/api/scan/{run_id}")
    assert raw.status_code == 200
    assert "findings" in raw.json()


def test_scan_unknown_framework(client):
    r = client.post("/api/scan", json={"framework": "nope", "path": DEMO})
    assert r.status_code == 400


def test_scan_missing_path(client):
    r = client.post("/api/scan", json={"framework": "langgraph", "path": "/nonexistent"})
    assert r.status_code == 400


def test_missing_run_404(client):
    assert client.get("/scan/deadbeef").status_code == 404


# ---------------------------------------------------------------- console
def test_console_page_and_graph(client):
    assert client.get("/console").status_code == 200
    g = client.get("/console/graph").json()
    assert len(g["nodes"]) >= 3 and g["agents"]
    assert client.get("/console/presets").json().keys() >= {"rce", "exfil", "ssrf"}


def test_console_rce_really_executes(client):
    presets = client.get("/console/presets").json()
    r = client.post("/console/submit", json={"ticket": presets["rce"], "mode": "deterministic"}).json()
    assert r["compromised"] is True
    assert "tool_run_shell_fix" in r["path_node_ids"]
    # a real file was created on disk (reported in a victim panel line)
    assert any(ev["panel"] and "PWNED.txt" in ev["panel"]["line"] for ev in r["events"])


def test_console_exfil_reaches_attacker_c2(client):
    presets = client.get("/console/presets").json()
    r = client.post("/console/submit", json={"ticket": presets["exfil"], "mode": "deterministic"}).json()
    assert r["compromised"] is True
    assert any(ev["panel"] and ev["panel"]["target"] == "c2" for ev in r["events"])


def test_console_benign_ticket_not_compromised(client):
    r = client.post("/console/submit",
                    json={"ticket": "Hi, I forgot my password, can you help?", "mode": "deterministic"}).json()
    assert r["compromised"] is False
