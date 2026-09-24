"""Auditor: orchestrates the full privilege/agency audit over a workflow graph.

Pipeline:
  1. Tag every node with capabilities (name -> category -> AST signature).
  2. Build the taint graph and compute each agent's reachable capabilities.
  3. Score/grade each agent (report card).
  4. Run the detectors (excessive agency, lethal trifecta, attack paths).
  5. Attach findings to the graph, sorted by severity.
"""

from pathlib import Path
from typing import Dict, List, Optional

from agentsec.audit import detectors, privilege
from agentsec.audit.capabilities import CapabilityTagger
from agentsec.audit.reachability import ReachabilityEngine
from agentsec.audit.signatures import SignatureScanner
from agentsec.models import Finding, GraphDefinition, Severity

_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


class Auditor:
    def __init__(self, input_dir: Optional[Path] = None):
        self.input_dir = input_dir

    def audit(self, graph: GraphDefinition) -> GraphDefinition:
        # 1. Signature scan of custom tools (best-effort; needs a source dir).
        signatures: Dict = {}
        if self.input_dir is not None:
            try:
                signatures = SignatureScanner(self.input_dir).scan()
            except Exception as e:  # pragma: no cover - defensive
                print(f"Warning: signature scan failed: {e}")

        # 1b. Tag capabilities on nodes.
        CapabilityTagger(signatures=signatures).tag(graph)

        # 2. Reachability.
        engine = ReachabilityEngine(graph)

        findings: List[Finding] = []
        for agent in graph.agents:
            if not agent.node_id:
                continue
            agent.direct_capabilities = self._direct_capabilities(graph, agent)
            agent.reachable_capabilities = engine.reachable_capabilities(agent.node_id)

            # 3. Score / grade — based on the agent's OWN (direct) power, so an
            #    upstream agent isn't graded on what it can only trigger via handoff.
            agent.privilege_score = privilege.score(agent.direct_capabilities)
            agent.privilege_grade = privilege.grade(agent.privilege_score)

            # untrusted exposure for the trifecta = a source the agent DIRECTLY owns.
            has_untrusted = self._directly_owns_untrusted(graph, agent)

            # 4. Per-agent detectors (use direct capabilities).
            findings.extend(detectors.detect_excessive_agency(agent))
            findings.extend(detectors.detect_lethal_trifecta(agent, has_untrusted))

        # 4b. Graph-level attack paths.
        paths = engine.attack_paths()
        findings.extend(detectors.detect_attack_paths(graph, paths))

        # 5. Sort + attach.
        findings.sort(key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9), f.id))
        graph.findings = findings
        return graph

    @staticmethod
    def _direct_capabilities(graph, agent):
        caps = []
        for tid in agent.tool_ids:
            node = graph.get_node(tid)
            if node:
                for c in node.capabilities:
                    if c not in caps:
                        caps.append(c)
        return sorted(caps, key=lambda c: c.value)

    @staticmethod
    def _directly_owns_untrusted(graph, agent) -> bool:
        for tid in agent.tool_ids:
            node = graph.get_node(tid)
            if node and node.is_source:
                return True
        return False
