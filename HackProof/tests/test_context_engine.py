"""Unit and integration tests for HACKPROOF Context Awareness Engine."""

import pytest
from core.models import Finding
from core.context import (
    ContextAwarenessEngine,
    ContextAssessment,
    CorrelationChain,
    EvidenceGraph,
    EvidenceNormalizer,
    ContextCorrelator,
    ContextRiskEngine,
    EvidenceItem,
    EvidenceType,
)


def test_scenario_1_same_file_grouped_single_chain():
    """Scenario 1: Same file appearing across multiple checks is grouped into one narrative chain."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gitignore.hidden_tracked_files",
            plane="system",
            severity="flag",
            evidence={"tracked_hidden": [{"path": "src/core.py", "rule": "src/*.py"}]},
            passed=False,
        ),
        Finding(
            check_name="gitignore.pattern_audit",
            plane="system",
            severity="flag",
            evidence={"suspicious_patterns": [{"pattern": "src/core.py"}]},
            passed=False,
        ),
    ]

    assessment = engine.analyze(findings=findings)
    assert assessment.risk_level in ("MEDIUM", "HIGH")
    assert assessment.total_raw_evidence_count == 2
    # Should be grouped into 1 chain for src/core.py
    src_chains = [c for c in assessment.chains if c.root_entity == "src/core.py"]
    assert len(src_chains) == 1
    assert len(src_chains[0].items) == 2


def test_scenario_2_similarity_plus_blame():
    """Scenario 2: Similarity match + Git blame -> narrative shows who introduced it, when, and similarity."""
    engine = ContextAwarenessEngine()
    similarity_matches = [
        {
            "file": "src/auth.py",
            "matched_repo": "upstream/oauth",
            "matched_file": "auth.ts",
            "score": 0.92,
            "matched_repo_date": "2024-05-10",
        }
    ]
    blame_entries = [
        {
            "gitignore_path": ".gitignore",
            "line_number": 12,
            "pattern": "src/auth.py",
            "sha": "a1b2c3d",
            "author": "Alice Hacker",
            "author_email": "alice@example.com",
            "committed_at": "2026-08-24 10:00:00 +0000",
            "classification": "ACTIVE CONCEALMENT",
            "hidden_files": ["src/auth.py"],
        }
    ]

    assessment = engine.analyze(findings=[], blame_entries=blame_entries, similarity_matches=similarity_matches)
    assert assessment.risk_level == "HIGH"
    auth_chain = next(c for c in assessment.chains if c.root_entity == "src/auth.py")
    assert auth_chain.severity == "hard_flag"
    narrative_text = " ".join(auth_chain.narrative)
    assert "Alice Hacker" in narrative_text or "a1b2c3d" in narrative_text
    assert "92%" in narrative_text
    assert "upstream/oauth" in narrative_text


def test_scenario_3_pre_hackathon_commit_plus_similarity():
    """Scenario 3: Pre-hackathon commit + Similarity match -> flagged as pre-existing code importation (Rule 1)."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="claim.build_window",
            plane="claim",
            severity="hard_flag",
            evidence={
                "t0": "2026-08-24T09:00:00Z",
                "commits_before_t0": [
                    {"commit": "deadbeef1234", "committed_at": "2026-08-20T12:00:00Z", "author": "Bob"}
                ],
            },
            passed=False,
        )
    ]
    similarity_matches = [
        {
            "file": "src/algo.py",
            "matched_repo": "mit/dsp",
            "matched_file": "algo.py",
            "score": 0.95,
            "matched_repo_date": "2023-11-15",
            "commit": "deadbeef1234",
        }
    ]

    assessment = engine.analyze(findings=findings, similarity_matches=similarity_matches)
    assert assessment.risk_level == "HIGH"
    algo_chain = next(c for c in assessment.chains if c.root_entity == "src/algo.py")
    assert algo_chain.rule == "Rule 1: Similarity + Pre-hackathon source"
    assert algo_chain.severity == "hard_flag"


def test_scenario_4_verified_gpg_commit():
    """Scenario 4: Verified GPG commit -> positive evidence in graph, no false alarms."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gpg.signatures",
            plane="claim",
            severity="info",
            evidence={
                "signatures": [
                    {
                        "commit": "c0ffee1",
                        "signer": "registered-alice@team.org",
                        "valid": True,
                        "author_email": "registered-alice@team.org",
                        "status": "VALID",
                    }
                ]
            },
            passed=True,
        )
    ]

    assessment = engine.analyze(findings=findings)
    assert assessment.risk_level == "LOW"
    assert "VERIFIED" in assessment.overall_status or "CLEAN" in assessment.overall_status
    assert len(assessment.correlated_findings) == 0


def test_scenario_5_unregistered_gpg_signer():
    """Scenario 5: Unregistered GPG signer -> flagged with exact key and author details."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gpg.unregistered_signers",
            plane="claim",
            severity="hard_flag",
            evidence={
                "unregistered_signers": ["0x999888777"],
                "commits": [{"commit": "badc0de", "author": "Eve Outside"}],
            },
            passed=False,
        )
    ]

    assessment = engine.analyze(findings=findings)
    assert assessment.risk_level == "HIGH"
    chain = assessment.chains[0]
    assert "badc0de" in chain.root_entity or "Eve Outside" in " ".join(chain.narrative)


def test_scenario_6_commit_author_mismatch_signer():
    """Scenario 6: Commit author != GPG signer -> identified as signature spoofing or shared account."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gpg.identity_mismatch",
            plane="claim",
            severity="flag",
            evidence={
                "mismatches": [
                    {
                        "commit": "e1f2a3b",
                        "author": "Alice Original <alice@team.org>",
                        "signer": "Bob Impostor <bob@external.com>",
                    }
                ]
            },
            passed=False,
        )
    ]

    assessment = engine.analyze(findings=findings)
    assert assessment.risk_level in ("MEDIUM", "HIGH")
    chain = assessment.chains[0]
    assert "Rule 3" in chain.rule
    assert "Bob Impostor" in " ".join(chain.narrative)


def test_scenario_7_gitignore_concealing_source():
    """Scenario 7: .gitignore concealing source code -> connected to author who added the rule."""
    engine = ContextAwarenessEngine()
    blame_entries = [
        {
            "gitignore_path": ".gitignore",
            "line_number": 5,
            "pattern": "src/secret_model.py",
            "sha": "1122334",
            "author": "Charlie Dev",
            "author_email": "charlie@dev.io",
            "committed_at": "2026-08-24 14:00:00 +0000",
            "classification": "ACTIVE CONCEALMENT",
            "hidden_files": ["src/secret_model.py"],
        }
    ]

    assessment = engine.analyze(findings=[], blame_entries=blame_entries)
    chain = next(c for c in assessment.chains if c.root_entity == "src/secret_model.py")
    assert chain.severity == "flag"
    assert "Charlie Dev" in " ".join(chain.narrative)
    assert "1122334" in " ".join(chain.narrative)


def test_scenario_8_gitignore_concealing_benign_artifact():
    """Scenario 8: .gitignore concealing standard build artifact (node_modules, dist, .env) -> recognized as benign."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gitignore.hidden_tracked_files",
            plane="system",
            severity="info",
            evidence={"tracked_hidden": [{"path": "dist/bundle.min.js", "rule": "dist/"}]},
            passed=True,
        ),
        Finding(
            check_name="gitignore.hidden_tracked_files",
            plane="system",
            severity="info",
            evidence={"tracked_hidden": [{"path": ".env.local", "rule": ".env*"}]},
            passed=True,
        ),
    ]

    assessment = engine.analyze(findings=findings)
    # Benign artifacts must not be flagged as high risk
    assert assessment.risk_level == "LOW"
    dist_chain = next(c for c in assessment.chains if c.root_entity == "dist/bundle.min.js")
    assert dist_chain.status_badge == "CLEAN"
    assert "BENIGN BUILD ARTIFACT" in " ".join(dist_chain.narrative)


def test_scenario_9_local_commit_not_on_github():
    """Scenario 9: Local commit not on GitHub -> flagged as unpushed work (Rule 6)."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="github.local_crosscheck",
            plane="server",
            severity="flag",
            evidence={"unpushed_commits": ["778899a"]},
            passed=False,
        )
    ]

    assessment = engine.analyze(findings=findings)
    assert assessment.risk_level == "MEDIUM"
    chain = assessment.chains[0]
    assert "Rule 6" in chain.rule
    assert "778899a" in " ".join(chain.narrative)


def test_scenario_10_anti_double_counting():
    """Scenario 10: Anti-double-counting -> multiple checks on same file grouped into 1 chain."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gitignore.hidden_tracked_files",
            plane="system",
            severity="flag",
            evidence={"tracked_hidden": [{"path": "src/stolen.py", "rule": "src/stolen.py"}]},
            passed=False,
        ),
        Finding(
            check_name="gitignore.pattern_audit",
            plane="system",
            severity="flag",
            evidence={"suspicious_patterns": [{"pattern": "src/stolen.py"}]},
            passed=False,
        ),
    ]
    similarity_matches = [
        {
            "file": "src/stolen.py",
            "matched_repo": "external/repo",
            "matched_file": "stolen.py",
            "score": 0.98,
            "matched_repo_date": "2024-01-01",
        }
    ]

    assessment = engine.analyze(findings=findings, similarity_matches=similarity_matches)
    stolen_chains = [c for c in assessment.chains if c.root_entity == "src/stolen.py"]
    # Exactly 1 consolidated chain
    assert len(stolen_chains) == 1
    # Raw items count is 3, but chain count is 1
    assert assessment.total_raw_evidence_count == 3
    assert len(stolen_chains[0].items) == 3


def test_scenario_11_clean_repo():
    """Scenario 11: Clean repo -> returns VERIFIED / CLEAN status, confidence HIGH, zero anomalous chains."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gpg.signatures",
            plane="claim",
            severity="info",
            evidence={"signatures": [{"commit": "aaa111", "valid": True, "signer": "alice@team.org"}]},
            passed=True,
        ),
        Finding(
            check_name="claim.build_window",
            plane="claim",
            severity="info",
            evidence={"commits_before_t0": []},
            passed=True,
        ),
    ]

    assessment = engine.analyze(findings=findings)
    assert assessment.risk_level == "LOW"
    assert "VERIFIED / CLEAN" in assessment.overall_status
    assert assessment.confidence == "HIGH"
    assert len(assessment.correlated_findings) == 0


def test_scenario_12_separate_warnings_kept_separate():
    """Scenario 12: Multiple separate warnings are correctly kept separate (not merged into one mega-chain)."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gitignore.hidden_tracked_files",
            plane="system",
            severity="flag",
            evidence={"tracked_hidden": [{"path": "file_alpha.py", "rule": "file_alpha.py"}]},
            passed=False,
        ),
        Finding(
            check_name="gitignore.hidden_tracked_files",
            plane="system",
            severity="flag",
            evidence={"tracked_hidden": [{"path": "file_beta.py", "rule": "file_beta.py"}]},
            passed=False,
        ),
    ]

    assessment = engine.analyze(findings=findings)
    chains = assessment.chains
    alpha_chains = [c for c in chains if c.root_entity == "file_alpha.py"]
    beta_chains = [c for c in chains if c.root_entity == "file_beta.py"]
    assert len(alpha_chains) == 1
    assert len(beta_chains) == 1
    assert alpha_chains[0].chain_id != beta_chains[0].chain_id


def test_missing_optional_similarity_runs_cleanly():
    """Handles missing optional similarity or blame inputs gracefully without crashing."""
    engine = ContextAwarenessEngine()
    assessment = engine.analyze(findings=[], blame_entries=None, similarity_matches=None)
    assert assessment.risk_level == "LOW"
    assert assessment.total_raw_evidence_count == 0


def test_json_serialization_and_graph():
    """Verifies that ContextAssessment and EvidenceGraph serialize cleanly to dictionary."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gpg.signatures",
            plane="claim",
            severity="flag",
            evidence={"signatures": [{"commit": "c111", "signer": "eve@outside.com", "valid": False}]},
            passed=False,
        )
    ]
    assessment = engine.analyze(findings=findings)
    d = assessment.to_dict()
    assert "overall_status" in d
    assert "chains" in d
    assert "graph" in d
    assert "nodes" in d["graph"]
    assert "edges" in d["graph"]


def test_render_terminal_summary():
    """Verifies that terminal summary output includes headers, status, and chains."""
    engine = ContextAwarenessEngine()
    findings = [
        Finding(
            check_name="gitignore.hidden_tracked_files",
            plane="system",
            severity="flag",
            evidence={"tracked_hidden": [{"path": "src/bad.py", "rule": "src/bad.py"}]},
            passed=False,
        )
    ]
    assessment = engine.analyze(findings=findings)
    terminal_out = engine.render_terminal_summary(assessment)
    assert "CONTEXT AWARENESS SUMMARY" in terminal_out
    assert "src/bad.py" in terminal_out
