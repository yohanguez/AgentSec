from pathlib import Path

import pytest

from agentsec.analyzers import LangGraphAnalyzer
from agentsec.audit import Auditor
from agentsec.audit.privilege import grade, score
from agentsec.audit.signatures import SignatureScanner
from agentsec.models import Capability, Severity

DEMO = Path(__file__).parent.parent / "demo" / "autoops"


@pytest.fixture(scope="module")
def audited():
    graph = LangGraphAnalyzer(DEMO).analyze()
    return Auditor(DEMO).audit(graph)


# ---------------------------------------------------------------- signatures
def test_signature_scanner_infers_capabilities_from_custom_code():
    sigs = SignatureScanner(DEMO).scan()
    assert "shell_exec" in sigs["run_shell_fix"]["capabilities"]
    assert "network_read" in sigs["fetch_ticket"]["capabilities"]
    assert "db_read" in sigs["read_customer_record"]["capabilities"]
    assert "email_send" in sigs["send_customer_email"]["capabilities"]
    assert "network_write" in sigs["post_to_webhook"]["capabilities"]
    # write_postmortem must be fs_write ONLY — not misclassified as network
    assert sigs["write_postmortem"]["capabilities"] == ["fs_write"]


def test_signature_evidence_is_recorded():
    sigs = SignatureScanner(DEMO).scan()
    assert any("subprocess" in e for e in sigs["run_shell_fix"]["evidence"])


# ---------------------------------------------------------------- report card
def test_report_card_grades(audited):
    grades = {a.name: a.privilege_grade for a in audited.agents}
    assert grades["remediation"] == "F"  # code + shell + fs_write
    assert grades["notify"] in ("A", "B")  # only network_write
    # triage holds db_read + email_send + network_read
    assert grades["triage"] in ("C", "D")


def test_direct_vs_reachable_capabilities(audited):
    triage = next(a for a in audited.agents if a.name == "triage")
    # triage does NOT directly own code_exec ...
    assert Capability.CODE_EXEC not in triage.direct_capabilities
    # ... but can reach it via the handoff to remediation
    assert Capability.CODE_EXEC in triage.reachable_capabilities


# ---------------------------------------------------------------- detectors
def test_lethal_trifecta_detected_on_triage(audited):
    trifecta = [f for f in audited.findings if f.category == "Lethal Trifecta"]
    assert len(trifecta) == 1
    assert trifecta[0].agent_name == "triage"
    assert trifecta[0].severity == Severity.CRITICAL


def test_excessive_agency_on_remediation(audited):
    agency = [f for f in audited.findings if f.category == "Excessive Agency"]
    names = {f.agent_name for f in agency}
    assert "remediation" in names


def test_attack_paths_reach_code_execution(audited):
    paths = [f for f in audited.findings if f.category == "Dangerous Reachable Path"]
    assert paths, "expected at least one reachable attack path"
    # an untrusted source must be able to reach code execution
    assert any(f.path and f.path.sink_capability == Capability.CODE_EXEC for f in paths)


def test_high_confidence_email_exfil_path(audited):
    # within triage: untrusted source -> email_send is a single-agent HIGH path
    paths = [f for f in audited.findings if f.category == "Dangerous Reachable Path"]
    email = [f for f in paths if f.path and f.path.sink_capability == Capability.EMAIL_SEND]
    assert email and email[0].confidence.value == "high"


# ---------------------------------------------------------------- privilege
def test_privilege_scoring_monotonic():
    assert score([Capability.CODE_EXEC]) > score([Capability.NETWORK_READ])
    assert grade(30) == "F"
    assert grade(0) == "A"
