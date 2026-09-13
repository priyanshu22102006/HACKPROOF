"""Shared data contracts for the HackSys system-plane agent.

`Finding` intentionally mirrors the HackProof analyzer contract
(`Finding(check_name, plane, severity, evidence, passed)`) so that the
system-plane report and the repo-plane report can be merged by the
dashboard and handed to the LLM comparator without translation.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

# --------------------------------------------------------------------------
# Severity / plane vocabularies (kept as plain strings for JSON friendliness)
# --------------------------------------------------------------------------

SEV_INFO = "info"
SEV_NOTICE = "notice"
SEV_WARN = "warn"
SEV_CRITICAL = "critical"

SEVERITY_ORDER = {SEV_INFO: 0, SEV_NOTICE: 1, SEV_WARN: 2, SEV_CRITICAL: 3}

PLANE_SYSTEM = "system"  # everything this agent produces
PLANE_REPO = "repo"      # produced by the HackProof repo analyzers


def severity_rank(sev: str) -> int:
    return SEVERITY_ORDER.get(sev, 0)


def max_severity(*sevs: str) -> str:
    best = SEV_INFO
    for s in sevs:
        if severity_rank(s) > severity_rank(best):
            best = s
    return best


# --------------------------------------------------------------------------
# Event: one observation written to the append-only log
# --------------------------------------------------------------------------


@dataclass
class Event:
    """A single observation.

    `seq`, `prev_hash` and `hash` are filled in by the EventLog at append
    time — collectors never set them.
    """

    kind: str                      # dotted namespace, e.g. "fs.create"
    collector: str                 # collector name, e.g. "filesystem"
    summary: str                   # one-line human readable description
    severity: str = SEV_INFO
    plane: str = PLANE_SYSTEM
    data: Dict[str, Any] = field(default_factory=dict)

    # assigned by EventLog.append()
    seq: Optional[int] = None
    ts: Optional[str] = None       # ISO-8601 UTC wall clock
    mono: Optional[float] = None   # seconds since daemon start (tamper cross-check)
    prev_hash: Optional[str] = None
    hash: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# --------------------------------------------------------------------------
# Finding: the analysis output, shared with HackProof's repo analyzers
# --------------------------------------------------------------------------


@dataclass
class Finding:
    check_name: str
    plane: str
    severity: str
    evidence: Dict[str, Any]
    passed: bool
    # Extra, optional fields. HackProof ignores unknown keys; the LLM
    # comparator uses them to write prose without re-deriving meaning.
    title: str = ""
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)
