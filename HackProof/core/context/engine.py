"""Context Awareness Engine: Coordinates normalizer, correlator, and risk evaluation."""

from __future__ import annotations

import os
from typing import Any

from core.context.correlator import ContextCorrelator
from core.context.models import ContextAssessment
from core.context.normalizer import EvidenceNormalizer
from core.context.risk import ContextRiskEngine
from core.models import Finding


class ContextAwarenessEngine:
    """Orchestrates evidence normalization, graph correlation, and risk assessment."""

    def __init__(self, repository: str = "target_repo") -> None:
        self.repository = repository
        self.normalizer = EvidenceNormalizer(repository=repository)
        self.correlator = ContextCorrelator()
        self.risk_engine = ContextRiskEngine()

    def analyze(
        self,
        findings: list[Finding],
        blame_entries: list[Any] | None = None,
        similarity_matches: list[dict[str, Any]] | None = None,
        repo_path: str = "target_repo",
    ) -> ContextAssessment:
        """Run the full context awareness pipeline and return a ContextAssessment."""
        self.repository = repo_path
        self.normalizer.repository = repo_path

        # 1. Normalize raw findings into EvidenceItem objects
        raw_items = self.normalizer.normalize(
            findings=findings,
            blame_entries=blame_entries,
            similarity_matches=similarity_matches,
        )

        # 2. Build graph & correlate items into chains (Rules 1-7, anti-double-counting)
        chains = self.correlator.correlate(raw_items)

        # 3. Deterministic risk evaluation
        assessment = self.risk_engine.evaluate(chains=chains, raw_items=raw_items)
        assessment.graph = self.correlator.graph.to_dict()
        return assessment

    def render_terminal_summary(self, assessment: ContextAssessment) -> str:
        """Render the CONTEXT AWARENESS SUMMARY section for CLI display."""
        width = 80
        sep = "=" * width
        lines: list[str] = [
            sep,
            "                        CONTEXT AWARENESS SUMMARY",
            sep,
        ]

        if assessment.risk_level == "HIGH":
            status_badge = f"🚨 {assessment.overall_status}"
        elif assessment.risk_level == "MEDIUM":
            status_badge = f"⚠️  {assessment.overall_status}"
        else:
            status_badge = f"✅ {assessment.overall_status}"

        lines.append(f"Status:     {status_badge}  [Confidence: {assessment.confidence}]")

        flagged_chains = [c for c in assessment.chains if c.severity in ("hard_flag", "flag")]
        if not flagged_chains:
            lines.append("Correlation Overview:")
            lines.append("  • No anomalous chains detected across all analysis modules.")
            lines.append("  • All commits, keys, files, and timestamps correlate consistently with hackathon rules.")
            lines.append(sep)
            return "\n".join(lines)

        dedup_count = max(0, assessment.total_raw_evidence_count - assessment.total_chains_count)
        lines.append("Correlation Overview:")
        lines.append(
            f"  • {len(flagged_chains)} anomalous chain(s) identified from "
            f"{assessment.total_raw_evidence_count} raw evidence item(s)"
        )
        if dedup_count > 0:
            lines.append(f"  • Consolidated {dedup_count} redundant/multi-plane signal(s) into single event chains")
        lines.append("")

        for idx, chain in enumerate(flagged_chains, 1):
            badge_icon = "🚨" if chain.severity == "hard_flag" else "⚠️"
            lines.append(f"[{chain.chain_id}] {badge_icon} {chain.title} [{chain.status_badge}]")
            for n_line in chain.narrative:
                lines.append(f"  {n_line}")
            lines.append("")

        if assessment.reasons:
            lines.append("Assessment & Key Drivers:")
            for reason in assessment.reasons:
                lines.append(f"  • {reason}")

        if assessment.unresolved_anomalies:
            lines.append("")
            lines.append("Unresolved Advisory Signals:")
            for unres in assessment.unresolved_anomalies:
                lines.append(f"  • {unres}")

        lines.append(sep)
        return "\n".join(lines)
