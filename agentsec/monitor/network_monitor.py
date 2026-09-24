"""Runtime AI-connection monitor.

Observes established TCP connections across all processes and classifies those
talking to known AI / LLM / vector-DB endpoints. This complements the static
audit: static analysis sees what the *code* can do; the monitor sees what is
*actually* connecting out right now — including agents whose capabilities are
constructed at runtime and therefore invisible to AST analysis.

The AI-endpoint classification table and psutil-based detection approach are
adapted from the MIT-licensed ``agent-discover-scanner`` by DefendAI
(https://github.com/Defend-AI-Tech-Inc/agent-discover-scanner). Trimmed to the
connection-observation core and made Python 3.9 compatible.
"""

import json
import socket
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None


# hostname substring -> service label
AI_SERVICES = {
    "api.openai.com": "OpenAI API",
    "openai.com": "OpenAI",
    "chatgpt.com": "ChatGPT",
    "api.anthropic.com": "Anthropic API",
    "anthropic.com": "Anthropic",
    "claude.ai": "Claude",
    "generativelanguage.googleapis.com": "Gemini API",
    "bedrock-runtime": "AWS Bedrock",
    "bedrock-agent-runtime": "AWS Bedrock Agent",
    "api.mistral.ai": "Mistral API",
    "api.groq.com": "Groq API",
    "api.deepseek.com": "DeepSeek API",
    "api.together.xyz": "Together AI",
    "api.x.ai": "Grok API",
    "api.cohere.ai": "Cohere API",
    "api.perplexity.ai": "Perplexity API",
    "openai.azure.com": "Azure OpenAI",
    "huggingface.co": "HuggingFace",
    "api.cursor.sh": "Cursor",
}

VECTOR_DBS = {
    "pinecone.io": "Pinecone",
    "weaviate.io": "Weaviate",
    "weaviate.cloud": "Weaviate",
    "qdrant.io": "Qdrant",
    "qdrant.tech": "Qdrant",
    "milvus.io": "Milvus",
    "chroma": "ChromaDB",
}

_EXTERNAL_PORTS = frozenset({443, 8443})


def _is_private_ip(ip: str) -> bool:
    if not ip or ip in ("0.0.0.0", "::1", "::"):
        return True
    if ip.startswith(("127.", "169.254.", "10.", "192.168.")):
        return True
    if ip.lower().startswith(("fc", "fd", "fe80")):
        return True
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        try:
            return 16 <= int(parts[1]) <= 31
        except ValueError:
            return False
    return False


@dataclass
class AIConnection:
    timestamp: datetime
    process_name: str
    pid: int
    remote_host: str
    remote_ip: str
    remote_port: int
    service: str
    kind: str  # 'ai' or 'vector_db'


class NetworkMonitor:
    def __init__(self) -> None:
        self._dns_cache: Dict[str, str] = {}
        self.access_denied = 0  # count of processes we couldn't inspect (perms)

    def _resolve(self, ip: str) -> str:
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            host = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            host = ip
        self._dns_cache[ip] = host
        return host

    @staticmethod
    def _classify(hostname: str):
        h = hostname.lower()
        for domain, name in AI_SERVICES.items():
            if domain in h:
                return name, "ai"
        for domain, name in VECTOR_DBS.items():
            if domain in h:
                return name, "vector_db"
        return None, None

    def snapshot(self) -> List[AIConnection]:
        if psutil is None:
            raise RuntimeError("psutil is required for the runtime monitor")
        found: List[AIConnection] = []
        self.access_denied = 0
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.pid
                name = proc.info.get("name") or "unknown"
                try:
                    conns = proc.net_connections(kind="inet")
                except psutil.AccessDenied:
                    self.access_denied += 1
                    continue
                for conn in conns:
                    if conn.status != psutil.CONN_ESTABLISHED or not conn.raddr:
                        continue
                    ip = conn.raddr.ip
                    port = conn.raddr.port
                    if not _is_private_ip(ip) and port not in _EXTERNAL_PORTS:
                        continue
                    host = self._resolve(ip)
                    service, kind = self._classify(host)
                    if service:
                        found.append(
                            AIConnection(
                                timestamp=datetime.now(),
                                process_name=name,
                                pid=pid,
                                remote_host=host,
                                remote_ip=ip,
                                remote_port=port,
                                service=service,
                                kind=kind,
                            )
                        )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        return found

    def monitor(self, duration_seconds: int = 30, interval_seconds: int = 5) -> Dict:
        seen = set()
        connections: List[AIConnection] = []
        start = time.time()
        while time.time() - start < duration_seconds:
            for c in self.snapshot():
                key = (c.process_name, c.service, c.remote_host)
                if key not in seen:
                    seen.add(key)
                    connections.append(c)
                    print(
                        f"[DETECT] {c.service} ← {c.process_name} (pid {c.pid}) → {c.remote_host}:{c.remote_port}"
                    )
            time.sleep(interval_seconds)
        summary = self._summary(connections, duration_seconds)
        summary["inaccessible_processes"] = self.access_denied
        return summary

    @staticmethod
    def _summary(connections: List[AIConnection], duration: int) -> Dict:
        services: Dict[str, int] = {}
        for c in connections:
            services[c.service] = services.get(c.service, 0) + 1
        return {
            "scan_duration": duration,
            "total_connections": len(connections),
            "unique_services": sorted(services.keys()),
            "services": services,
            "connections": [
                {
                    "timestamp": c.timestamp.isoformat(),
                    "process": c.process_name,
                    "pid": c.pid,
                    "service": c.service,
                    "kind": c.kind,
                    "remote_host": c.remote_host,
                    "remote_port": c.remote_port,
                }
                for c in connections
            ],
        }


def monitor_network(duration: int = 30, output_file: Optional[Path] = None) -> Dict:
    mon = NetworkMonitor()
    print(f"👁️  Observing runtime AI traffic for {duration}s...")
    summary = mon.monitor(duration_seconds=duration)

    print("\n" + "=" * 55)
    print("RUNTIME SCAN COMPLETE")
    print("=" * 55)
    print(f"Duration: {summary['scan_duration']}s")
    print(f"AI/LLM connections: {summary['total_connections']}")
    if summary["unique_services"]:
        print("Services: " + ", ".join(summary["unique_services"]))
    else:
        print("Services: none detected")

    denied = summary.get("inaccessible_processes", 0)
    if summary["total_connections"] == 0 and denied:
        print(
            f"\n⚠️  {denied} processes could not be inspected (insufficient "
            "permissions). On macOS/Linux the socket table needs elevated "
            "privileges — re-run with: sudo agentsec monitor"
        )

    if output_file:
        Path(output_file).write_text(json.dumps(summary, indent=2))
        print(f"\n✓ Saved: {output_file}")
    return summary
