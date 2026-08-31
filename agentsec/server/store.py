"""SQLite-backed store for scan and monitor runs.

Stateless-friendly: a single table holds every run as JSON. No ORM, stdlib only.
"""

import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


def _default_db_path() -> Path:
    home = Path.home() / ".agentsec"
    home.mkdir(parents=True, exist_ok=True)
    return home / "runs.db"


class RunStore:
    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = Path(db_path) if db_path else _default_db_path()
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id          TEXT PRIMARY KEY,
                    kind        TEXT NOT NULL,        -- 'scan' | 'monitor'
                    framework   TEXT,
                    title       TEXT,
                    created_at  TEXT NOT NULL,
                    summary     TEXT,                 -- JSON: headline metrics
                    data        TEXT                  -- JSON: full graph / summary
                )
                """
            )

    def add(self, kind: str, title: str, summary: Dict, data: Dict, framework: str = "") -> str:
        run_id = uuid.uuid4().hex[:8]
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO runs (id, kind, framework, title, created_at, summary, data) "
                "VALUES (?,?,?,?,?,?,?)",
                (
                    run_id,
                    kind,
                    framework,
                    title,
                    datetime.now().isoformat(timespec="seconds"),
                    json.dumps(summary),
                    json.dumps(data),
                ),
            )
        return run_id

    def list(self) -> List[Dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT id, kind, framework, title, created_at, summary FROM runs "
                "ORDER BY created_at DESC"
            ).fetchall()
        out = []
        for r in rows:
            out.append(
                {
                    "id": r["id"],
                    "kind": r["kind"],
                    "framework": r["framework"],
                    "title": r["title"],
                    "created_at": r["created_at"],
                    "summary": json.loads(r["summary"] or "{}"),
                }
            )
        return out

    def get(self, run_id: str) -> Optional[Dict]:
        with self._conn() as conn:
            r = conn.execute("SELECT * FROM runs WHERE id = ?", (run_id,)).fetchone()
        if not r:
            return None
        return {
            "id": r["id"],
            "kind": r["kind"],
            "framework": r["framework"],
            "title": r["title"],
            "created_at": r["created_at"],
            "summary": json.loads(r["summary"] or "{}"),
            "data": json.loads(r["data"] or "{}"),
        }
