"""Detectors that turn capability/reachability data into Findings.

Three detectors, in increasing order of severity:

  * excessive_agency   - an agent reaches dangerous, high-privilege capability
  * attack_paths       - untrusted input can reach a dangerous sink (taint)
  * lethal_trifecta    - one agent has private data + untrusted input + exfil
"""

from typing import Dict, List

from agentsec.models import (
    AgentDefinition,
    AttackPath,
    Capability,
    Confidence,
    EXFIL_CAPABILITIES,
    Finding,
    GraphDefinition,
    PRIVATE_DATA_CAPABILITIES,
    Severity,
    SINK_CAPABILITIES,
)

# Capabilities that on their own represent root-equivalent power.
_ROOT_EQUIVALENT = (Capability.CODE_EXEC, Capability.SHELL_EXEC)

_CAP_LABEL = {
    Capability.CODE_EXEC: "execute arbitrary code",
    Capability.SHELL_EXEC: "run shell commands",
    Capability.FS_WRITE: "write files",
    Capability.DB_WRITE: "modify databases",
    Capability.SECRETS_ACCESS: "read secrets",
    Capability.NETWORK_WRITE: "send data to external services",
    Capability.EMAIL_SEND: "send email/messages",
    Capability.DB_READ: "read databases",
    Capability.FS_READ: "read files",
    Capability.NETWORK_READ: "fetch external content",
}


def _label(cap: Capability) -> str:
    return _CAP_LABEL.get(cap, cap.value)


def detect_excessive_agency(agent: AgentDefinition) -> List[Finding]:
    findings: List[Finding] = []
    caps = set(agent.direct_capabilities)
    dangerous = [c for c in caps if c in SINK_CAPABILITIES]

    # Root-equivalent capability present at all.
    root_caps = [c for c in caps if c in _ROOT_EQUIVALENT]
    if root_caps:
        cap_list = ", ".join(_label(c) for c in root_caps)
        findings.append(
            Finding(
                id="AGS-AGENCY-ROOT-%s" % agent.name,
                title="Agent can %s" % cap_list,
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                category="Excessive Agency",
                description=(
                    "Agent '%s' can reach a tool that lets it %s. Autonomous "
                    "agents with code/shell execution can be driven to run "
                    "attacker-supplied commands if any untrusted input reaches them."
                    % (agent.name, cap_list)
                ),
                remediation=(
                    "Remove code/shell execution from this agent unless strictly "
                    "required. If required, sandbox it (containers, seccomp), drop "
                    "network access, enforce allowlists, and require human approval."
                ),
                security_framework_mapping={
                    "OWASP_LLM": "LLM08 - Excessive Agency",
                    "CWE": "CWE-250 / CWE-94",
                },
                agent_name=agent.name,
                node_ids=[agent.node_id] if agent.node_id else [],
            )
        )

    # Over-broad: many distinct dangerous capability classes on one agent.
    if len(dangerous) >= 3:
        cap_list = ", ".join(_label(c) for c in sorted(dangerous, key=lambda c: c.value))
        findings.append(
            Finding(
                id="AGS-AGENCY-BROAD-%s" % agent.name,
                title="Over-privileged agent (%d dangerous capabilities)" % len(dangerous),
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                category="Excessive Agency",
                description=(
                    "Agent '%s' holds %d distinct dangerous capabilities (%s). "
                    "Broad capability aggregation on a single agent increases blast "
                    "radius: a single prompt injection compromises all of them at once."
                    % (agent.name, len(dangerous), cap_list)
                ),
                remediation=(
                    "Apply least privilege: split responsibilities across narrowly "
                    "scoped agents so no single agent concentrates this much power."
                ),
                security_framework_mapping={"OWASP_LLM": "LLM08 - Excessive Agency"},
                agent_name=agent.name,
                node_ids=[agent.node_id] if agent.node_id else [],
            )
        )
    return findings


def detect_lethal_trifecta(agent: AgentDefinition, has_untrusted: bool) -> List[Finding]:
    caps = set(agent.reachable_capabilities)
    has_private = bool(caps & PRIVATE_DATA_CAPABILITIES)
    has_exfil = bool(caps & EXFIL_CAPABILITIES)

    if has_private and has_untrusted and has_exfil:
        return [
            Finding(
                id="AGS-TRIFECTA-%s" % agent.name,
                title="Lethal Trifecta on agent '%s'" % agent.name,
                severity=Severity.CRITICAL,
                confidence=Confidence.HIGH,
                category="Lethal Trifecta",
                description=(
                    "Agent '%s' simultaneously has (1) access to private data, "
                    "(2) exposure to untrusted content, and (3) the ability to "
                    "communicate externally. This is the 'lethal trifecta': an "
                    "attacker who injects instructions via the untrusted channel can "
                    "make the agent read private data and exfiltrate it." % agent.name
                ),
                remediation=(
                    "Break at least one leg of the trifecta for this agent: remove "
                    "private-data access, isolate untrusted-content handling in a "
                    "separate agent with no data access, or remove the external "
                    "communication capability. Never combine all three in one agent."
                ),
                security_framework_mapping={
                    "OWASP_LLM": "LLM08 - Excessive Agency / LLM01 - Prompt Injection",
                    "CWE": "CWE-668 - Exposure of Resource to Wrong Sphere",
                },
                agent_name=agent.name,
                node_ids=[agent.node_id] if agent.node_id else [],
            )
        ]
    return []


def detect_attack_paths(graph: GraphDefinition, paths: List[AttackPath]) -> List[Finding]:
    findings: List[Finding] = []
    for i, path in enumerate(paths, 1):
        src = graph.get_node(path.source_id)
        sink = graph.get_node(path.sink_id)
        if not src or not sink:
            continue
        readable = " -> ".join(
            (graph.get_node(nid).name if graph.get_node(nid) else nid)
            for nid in path.node_ids
        )
        sev = Severity.CRITICAL if path.confidence == Confidence.HIGH else Severity.HIGH
        findings.append(
            Finding(
                id="AGS-PATH-%02d" % i,
                title="Untrusted input reaches %s (%s)"
                % (_label(path.sink_capability), sink.name),
                severity=sev,
                confidence=path.confidence,
                category="Dangerous Reachable Path",
                description=(
                    "Untrusted data from '%s' can reach the dangerous sink '%s' "
                    "(%s) along the path: %s. An attacker who influences the source "
                    "may be able to drive the sink."
                    % (src.name, sink.name, _label(path.sink_capability), readable)
                ),
                remediation=(
                    "Insert validation/sanitisation between the source and the sink, "
                    "isolate the untrusted source in an agent that cannot reach this "
                    "sink, or remove the sink capability from the reachable set."
                ),
                security_framework_mapping={
                    "OWASP_LLM": "LLM01 - Prompt Injection / LLM08 - Excessive Agency",
                    "CWE": "CWE-20 - Improper Input Validation",
                },
                node_ids=path.node_ids,
                path=path,
            )
        )
    return findings
