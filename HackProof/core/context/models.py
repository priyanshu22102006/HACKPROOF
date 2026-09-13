"""Normalized Evidence Data Model and Correlation Types for Context Awareness Engine."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EvidenceType(str, Enum):
    SIMILARITY = "similarity"
    SIGNATURE = "signature"
    TRACKING = "tracking"
    TIMESTAMP = "timestamp"
    GITHUB = "github"
    BLAME = "blame"
    IDENTITY = "identity"


@dataclass
class EvidenceItem:
    evidence_id: str
    type: str  # EvidenceType or str
    severity: str  # "info" | "flag" | "hard_flag"
    repository: str
    file: str | None = None
    commit: str | None = None
    author: str | None = None
    email: str | None = None
    timestamp: str | None = None
    source: str | None = None  # e.g. "gpg.signature_coverage", "gitignore.pattern_audit"
    value: Any = None
    confidence: str = "HIGH"  # "HIGH" | "MEDIUM" | "LOW"
    message: str = ""
    related_evidence_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class CorrelationChain:
    chain_id: str
    title: str
    severity: str  # "info" | "flag" | "hard_flag"
    root_entity: str  # e.g. "auth.js", "Commit ABC123", "Pritim Mondal"
    items: list[EvidenceItem] = field(default_factory=list)
    narrative: list[str] = field(default_factory=list)  # Visual indented tree representation
    rule: str = ""  # Triggered correlation rule
    confidence: str = "HIGH"  # "HIGH" | "MEDIUM" | "LOW"
    status_badge: str = "INFO"  # "VERIFIED", "WARNING", "CONCERN"

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "severity": self.severity,
            "root_entity": self.root_entity,
            "items": [item.to_dict() for item in self.items],
            "narrative": self.narrative,
            "rule": self.rule,
            "confidence": self.confidence,
            "status_badge": self.status_badge,
        }


@dataclass
class ContextAssessment:
    overall_status: str  # e.g. "VERIFIED / CLEAN", "HIGH-RISK PROVENANCE CONCERN"
    risk_level: str  # "LOW" | "MEDIUM" | "HIGH"
    confidence: str  # "HIGH" | "MEDIUM" | "LOW"
    chains: list[CorrelationChain] = field(default_factory=list)
    correlated_findings: list[dict[str, Any]] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    unresolved_anomalies: list[str] = field(default_factory=list)
    total_raw_evidence_count: int = 0
    total_chains_count: int = 0
    graph: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "overall_status": self.overall_status,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "total_raw_evidence_count": self.total_raw_evidence_count,
            "total_chains_count": self.total_chains_count,
            "chains": [c.to_dict() for c in self.chains],
            "correlated_findings": self.correlated_findings,
            "reasons": self.reasons,
            "unresolved_anomalies": self.unresolved_anomalies,
            "graph": self.graph,
        }
