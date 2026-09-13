"""Shared output contract for all HACKPROOF analyzer modules.

Every analyzer exposes ``run(repo_path: str) -> list[Finding]`` and returns
``Finding`` objects only. Nothing else in this module is part of the contract:
the constants below are conveniences, and analyzers are free to ignore them.
"""

from dataclasses import dataclass, field


@dataclass
class Finding:
    check_name: str
    plane: str  # "claim" | "system" | "server"
    severity: str  # "info" | "flag" | "hard_flag"
    evidence: dict
    passed: bool


# --- Conveniences (not part of the contract) ---------------------------------

PLANE_CLAIM = "claim"
PLANE_SYSTEM = "system"
PLANE_SERVER = "server"

SEVERITY_INFO = "info"
SEVERITY_FLAG = "flag"
SEVERITY_HARD_FLAG = "hard_flag"

PLANES = (PLANE_CLAIM, PLANE_SYSTEM, PLANE_SERVER)
SEVERITIES = (SEVERITY_INFO, SEVERITY_FLAG, SEVERITY_HARD_FLAG)
