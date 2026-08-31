"""Per-agent privilege scoring and grading.

Each capability carries a weight reflecting how dangerous it is if abused. An
agent's score is the sum of weights over its *reachable* capabilities; the
score maps to a letter grade A (least privileged) through F (holds
root-equivalent power). This drives the per-agent report card.
"""

from typing import List

from agentsec.models import Capability

# Weights: code/shell execution and DB writes are the most dangerous.
_WEIGHTS = {
    Capability.CODE_EXEC: 10,
    Capability.SHELL_EXEC: 10,
    Capability.DB_WRITE: 7,
    Capability.FS_WRITE: 6,
    Capability.SECRETS_ACCESS: 6,
    Capability.NETWORK_WRITE: 5,
    Capability.EMAIL_SEND: 5,
    Capability.DB_READ: 4,
    Capability.FS_READ: 3,
    Capability.NETWORK_READ: 2,
}


def score(capabilities: List[Capability]) -> int:
    return sum(_WEIGHTS.get(c, 1) for c in set(capabilities))


def grade(privilege_score: int) -> str:
    if privilege_score >= 18:
        return "F"
    if privilege_score >= 13:
        return "D"
    if privilege_score >= 8:
        return "C"
    if privilege_score >= 4:
        return "B"
    return "A"


def grade_label(g: str) -> str:
    return {
        "A": "Minimal privilege",
        "B": "Low privilege",
        "C": "Moderate privilege",
        "D": "High privilege",
        "F": "Root-equivalent",
    }.get(g, "Unknown")
