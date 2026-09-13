"""Context Risk Engine: Deterministic rule-based evaluation of CorrelationChains."""

from __future__ import annotations

from core.context.models import ContextAssessment, CorrelationChain, EvidenceItem


class ContextRiskEngine:
    """Evaluates correlated evidence chains deterministically into an overall risk assessment."""

    def evaluate(
        self,
        chains: list[CorrelationChain],
        raw_items: list[EvidenceItem],
    ) -> ContextAssessment:
        total_raw = len(raw_items)
        total_chains = len(chains)

        hard_flag_chains = [c for c in chains if c.severity == "hard_flag"]
        flag_chains = [c for c in chains if c.severity == "flag"]
        info_chains = [c for c in chains if c.severity == "info"]

        # Determine risk level and overall status
        if hard_flag_chains:
            risk_level = "HIGH"
            overall_status = "HIGH-RISK PROVENANCE CONCERN"
            confidence = "HIGH"
        elif flag_chains:
            risk_level = "MEDIUM"
            overall_status = "EVIDENCE CORRELATION: MEDIUM RISK DETECTED"
            confidence = "HIGH" if len(flag_chains) > 1 else "MEDIUM"
        else:
            risk_level = "LOW"
            overall_status = "VERIFIED / CLEAN"
            confidence = "HIGH"

        reasons: list[str] = []
        unresolved: list[str] = []

        # Summarize primary multi-signal or flagged chains
        for chain in chains:
            if chain.severity in ("hard_flag", "flag"):
                sig_count = len(chain.items)
                if sig_count > 1:
                    reasons.append(
                        f"Multi-signal correlation on {chain.root_entity} ({sig_count} linked signals, rule: {chain.rule})"
                    )
                else:
                    reasons.append(
                        f"Isolated anomaly on {chain.root_entity}: {chain.title}"
                    )
            elif chain.status_badge == "WARNING":
                unresolved.append(f"Unresolved advisory signal on {chain.root_entity}: {chain.title}")

        if not reasons:
            reasons.append("All commits, keys, files, and timestamps correlate consistently with hackathon rules.")

        correlated_findings = [c.to_dict() for c in chains if c.severity in ("hard_flag", "flag")]

        return ContextAssessment(
            overall_status=overall_status,
            risk_level=risk_level,
            confidence=confidence,
            chains=chains,
            correlated_findings=correlated_findings,
            reasons=reasons,
            unresolved_anomalies=unresolved,
            total_raw_evidence_count=total_raw,
            total_chains_count=total_chains,
        )
