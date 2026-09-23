"""AST signature scanner for custom tools.

This is what distinguishes AgentSec from a pure name-matching scanner: when a
tool is a user-defined function (e.g. a LangChain ``@tool`` or CrewAI custom
tool) that isn't in the capability database, we inspect the *body* of the
function for calls that grant dangerous capabilities. That way a custom tool
named ``run_helper`` that shells out via ``subprocess`` is still correctly
flagged as ``shell_exec``.

The scanner is intentionally conservative and evidence-based: every inferred
capability carries a short human-readable evidence string ("calls
subprocess.run") so findings can be explained rather than asserted.
"""

import ast
from pathlib import Path
from typing import Dict, List, Optional, Set

from agentsec.models import Capability
from agentsec.utils import find_python_files, parse_python_file

# Dotted-call patterns -> capability. Matched against the "a.b.c" form of a call.
_DOTTED_PATTERNS = {
    Capability.SHELL_EXEC: (
        "subprocess.run",
        "subprocess.call",
        "subprocess.popen",
        "subprocess.check_output",
        "subprocess.check_call",
        "os.system",
        "os.popen",
        "os.execv",
        "os.execve",
        "pty.spawn",
        "commands.getoutput",
    ),
    Capability.NETWORK_WRITE: (
        "requests.post",
        "requests.put",
        "requests.patch",
        "requests.delete",
        "httpx.post",
        "httpx.put",
        "httpx.patch",
        "session.post",
        "client.post",
        "urllib.request.urlopen",  # refined below when it's clearly a GET
    ),
    Capability.NETWORK_READ: (
        "requests.get",
        "httpx.get",
        "session.get",
        "client.get",
        "urllib.request.urlopen",
        "urlopen",
    ),
    Capability.EMAIL_SEND: (
        "smtplib.smtp",
        "server.sendmail",
        "smtp.sendmail",
        "send_message",
    ),
    Capability.DB_READ: (
        "cursor.execute",
        "session.execute",
        "engine.execute",
        "connection.execute",
        "conn.execute",
        "db.execute",
    ),
}

# Bare-name calls -> capability.
_NAME_PATTERNS = {
    Capability.CODE_EXEC: ("eval", "exec", "compile", "execfile"),
}

_SECRET_ENV_HINTS = ("key", "secret", "token", "password", "passwd", "credential")
_WRITE_SQL_HINTS = ("insert", "update", "delete", "drop", "alter", "create", "truncate")


def _dotted_name(func: ast.expr) -> str:
    """Return the lowercased dotted path of a call target, e.g. 'subprocess.run'."""
    parts: List[str] = []
    cur: Optional[ast.expr] = func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return ".".join(reversed(parts)).lower()


class _BodyVisitor(ast.NodeVisitor):
    """Collects capabilities + evidence from the statements inside one function."""

    def __init__(self) -> None:
        self.capabilities: Set[Capability] = set()
        self.evidence: List[str] = []

    def _add(self, cap: Capability, ev: str) -> None:
        if ev not in self.evidence:
            self.evidence.append(ev)
        self.capabilities.add(cap)

    def visit_Call(self, node: ast.Call) -> None:
        dotted = _dotted_name(node.func)
        bare = dotted.split(".")[-1] if dotted else ""

        # open(..., 'w'/'a'/'x') -> fs_write ; otherwise fs_read
        if bare == "open" or dotted.endswith(".open"):
            mode = self._string_arg_at(node, 1) or self._string_kwarg(node, "mode") or "r"
            if any(m in mode for m in ("w", "a", "x", "+")):
                self._add(Capability.FS_WRITE, "opens a file for writing")
            else:
                self._add(Capability.FS_READ, "reads a file via open()")
        if bare in ("write_text", "write_bytes"):
            self._add(Capability.FS_WRITE, "writes a file (Path.%s)" % bare)
        if bare in ("read_text", "read_bytes"):
            self._add(Capability.FS_READ, "reads a file (Path.%s)" % bare)

        # os.environ / os.getenv secret access
        if dotted in ("os.getenv", "os.environ.get"):
            key = self._string_arg_at(node, 0) or ""
            if any(h in key.lower() for h in _SECRET_ENV_HINTS):
                self._add(Capability.SECRETS_ACCESS, "reads secret env var %r" % key)

        # DB execute: inspect SQL text to decide read vs write. Match the known
        # dotted forms (cursor.execute, conn.execute, …) AND any `<x>.execute("<SQL>")`
        # so we aren't fooled by the cursor variable's name (cur, c, …).
        sql = (self._string_arg_at(node, 0) or "").lower()
        sql_like = any(
            k in sql for k in ("select ", "insert ", "update ", "delete ", " from ", " where ")
        ) or any(h in sql for h in _WRITE_SQL_HINTS)
        if dotted in _DOTTED_PATTERNS[Capability.DB_READ] or (bare == "execute" and sql_like):
            self._add(Capability.DB_READ, "executes a database query")
            if any(h in sql for h in _WRITE_SQL_HINTS):
                self._add(Capability.DB_WRITE, "executes a mutating SQL statement")

        # Generic dotted / name pattern matching
        for cap, patterns in _DOTTED_PATTERNS.items():
            if cap == Capability.DB_READ:
                continue  # handled above with SQL inspection
            if dotted in patterns:
                self._add(cap, "calls %s" % dotted)
        for cap, patterns in _NAME_PATTERNS.items():
            if bare in patterns and "." not in dotted:
                self._add(cap, "calls %s()" % bare)

        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        # os.environ[...] subscript-style secret access shows up as an Attribute
        if isinstance(node.value, ast.Name) and node.value.id == "os" and node.attr == "environ":
            self._add(Capability.SECRETS_ACCESS, "reads process environment (os.environ)")
        self.generic_visit(node)

    @staticmethod
    def _string_arg_at(node: ast.Call, idx: int) -> Optional[str]:
        if len(node.args) > idx:
            arg = node.args[idx]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                return arg.value
        return None

    @staticmethod
    def _string_kwarg(node: ast.Call, name: str) -> Optional[str]:
        for kw in node.keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant):
                if isinstance(kw.value.value, str):
                    return kw.value.value
        return None


class SignatureScanner:
    """Scans a directory of Python files and infers per-function capabilities."""

    # Decorators that mark a function as an agent tool.
    _TOOL_DECORATORS = ("tool", "function_tool", "langchain_tool")

    def __init__(self, input_dir: Path) -> None:
        self.input_dir = input_dir

    def scan(self) -> Dict[str, Dict]:
        """Return {function_name: {'capabilities': [...], 'evidence': [...], 'is_tool': bool}}."""
        results: Dict[str, Dict] = {}
        for file_path in find_python_files(self.input_dir):
            tree = parse_python_file(file_path)
            if not tree:
                continue
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    visitor = _BodyVisitor()
                    visitor.visit(node)
                    if not visitor.capabilities:
                        continue
                    results[node.name] = {
                        "capabilities": sorted(c.value for c in visitor.capabilities),
                        "evidence": visitor.evidence,
                        "is_tool": self._is_tool(node),
                    }
        return results

    def _is_tool(self, node: ast.AST) -> bool:
        decorators = getattr(node, "decorator_list", [])
        for dec in decorators:
            name = ""
            if isinstance(dec, ast.Name):
                name = dec.id
            elif isinstance(dec, ast.Attribute):
                name = dec.attr
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    name = dec.func.id
                elif isinstance(dec.func, ast.Attribute):
                    name = dec.func.attr
            if name.lower() in self._TOOL_DECORATORS:
                return True
        return False
