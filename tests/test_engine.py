"""Tests for core.engine -- the seam where the two analyzers meet.

These tests are about the *merge*, not about either analyzer's logic: both
modules must come through one call, under one contract, and neither may be able
to take the other down.
"""

from __future__ import annotations

import json
import os

import pytest

from analyzers import gitignore_check, gpg_check
from core.engine import (
    ANALYZERS,
    render_table,
    run_all,
    summarize,
    validate_finding,
)
from core.models import Finding

try:
    from tests.helpers import out, run as sh
except ModuleNotFoundError:  # pragma: no cover - depends on sys.path shape
    from helpers import out, run as sh


def make_repo(tmp_path, name="repo") -> str:
    repo = tmp_path / name
    repo.mkdir()
    sh(["git", "init", "-q", "-b", "main"], cwd=str(repo))
    sh(["git", "config", "user.name", "Fixture Author"], cwd=str(repo))
    sh(["git", "config", "user.email", "author@example.test"], cwd=str(repo))
    sh(["git", "config", "commit.gpgsign", "false"], cwd=str(repo))
    (repo / "app.py").write_text("value = 1\n", encoding="utf-8")
    sh(["git", "add", "-A"], cwd=str(repo))
    sh(["git", "commit", "--no-gpg-sign", "-q", "-m", "init"], cwd=str(repo))
    return str(repo)


def test_both_analyzers_come_through_one_call(tmp_path):
    repo = make_repo(tmp_path)
    findings = run_all(repo)
    prefixes = {f.check_name.split(".", 1)[0] for f in findings}
    assert "gitignore" in prefixes
    assert "gpg" in prefixes
    # 5 gitignore checks + 6 gpg checks, and no analyzer blew up.
    assert len([f for f in findings if f.check_name.startswith("gitignore.")]) == 5
    assert len([f for f in findings if f.check_name.startswith("gpg.")]) == 6
    analyzer_failures = [
        f for f in findings if f.check_name in {f"engine.{n}" for n, _ in ANALYZERS}
    ]
    assert not analyzer_failures, analyzer_failures
    # The run diagnostic is always present and qualifies everything above it.
    history = [f for f in findings if f.check_name == "engine.history_completeness"]
    assert len(history) == 1 and history[0].passed


def test_every_finding_satisfies_the_contract(tmp_path):
    repo = make_repo(tmp_path)
    findings = run_all(repo)
    problems = {f.check_name: validate_finding(f) for f in findings}
    assert not {k: v for k, v in problems.items() if v}
    # The whole report must serialize; the dashboard ships it as JSON.
    json.loads(json.dumps([f.__dict__ for f in findings], default=str))


def test_clean_repo_raises_no_flags(tmp_path):
    repo = make_repo(tmp_path)
    (tmp_path / "repo" / ".gitignore").write_text("__pycache__/\n*.pyc\ndist/\n", encoding="utf-8")
    sh(["git", "add", "-A"], cwd=repo)
    sh(["git", "commit", "--no-gpg-sign", "-q", "-m", "add gitignore"], cwd=repo)

    findings = run_all(repo)
    summary = summarize(findings)
    assert summary["by_severity"]["hard_flag"] == 0
    assert summary["by_severity"]["flag"] == 0


def test_one_analyzer_raising_does_not_stop_the_other(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)

    def explode(_repo_path):
        raise RuntimeError("simulated analyzer crash")

    monkeypatch.setattr(gpg_check, "run", explode)
    findings = run_all(repo)

    assert [f for f in findings if f.check_name.startswith("gitignore.")]
    engine_findings = [f for f in findings if f.check_name == "engine.gpg"]
    assert len(engine_findings) == 1
    assert "simulated analyzer crash" in engine_findings[0].evidence["error"]
    assert not engine_findings[0].passed


def test_contract_violations_are_reported_not_propagated(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)

    def bad_plane(_repo_path):
        return [Finding("gpg.broken", "nonsense_plane", "info", {}, True)]

    monkeypatch.setattr(gpg_check, "run", bad_plane)
    findings = run_all(repo)

    engine_findings = [f for f in findings if f.check_name == "engine.gpg"]
    assert len(engine_findings) == 1
    assert "nonsense_plane" in json.dumps(engine_findings[0].evidence["violations"])
    # The offending object must not reach the report.
    assert not [f for f in findings if f.check_name == "gpg.broken"]


def test_non_list_return_is_reported(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    monkeypatch.setattr(gitignore_check, "run", lambda _p: "not a list")
    findings = run_all(repo)
    engine_findings = [f for f in findings if f.check_name == "engine.gitignore"]
    assert len(engine_findings) == 1
    assert "must return a list" in engine_findings[0].evidence["note"]


@pytest.mark.parametrize("name", [name for name, _ in ANALYZERS])
def test_only_runs_a_single_analyzer(tmp_path, name):
    repo = make_repo(tmp_path)
    findings = run_all(repo, only=[name])
    # engine.* run diagnostics are not analyzers and are not filtered by --only.
    prefixes = {
        f.check_name.split(".", 1)[0]
        for f in findings
        if not f.check_name.startswith("engine.")
    }
    assert prefixes == {name}


def test_skip_excludes_an_analyzer(tmp_path):
    repo = make_repo(tmp_path)
    findings = run_all(repo, skip=["gpg"])
    assert not [f for f in findings if f.check_name.startswith("gpg.")]
    assert [f for f in findings if f.check_name.startswith("gitignore.")]


def test_roster_argument_reaches_the_gpg_analyzer(tmp_path, gpg_home, monkeypatch):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    (tmp_path / "repo" / "signed.py").write_text("x = 2\n", encoding="utf-8")
    sh(["git", "add", "-A"], cwd=repo)
    sh(
        [
            "git",
            "-c",
            f"user.signingkey={key}",
            "-c",
            "commit.gpgsign=true",
            "commit",
            "-S",
            "-q",
            "-m",
            "signed work",
        ],
        cwd=repo,
        env={
            **gpg_home.env,
            "GIT_AUTHOR_EMAIL": "satoru@example.test",
            "GIT_COMMITTER_EMAIL": "satoru@example.test",
        },
    )

    roster = tmp_path / "roster.json"
    roster.write_text(
        json.dumps(
            {
                "team_id": "t",
                "members": [
                    {
                        "member_id": "m1",
                        "emails": ["satoru@example.test"],
                        "keys": [{"key_id": "k", "public_key": gpg_home.export_public(key), "status": "active"}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = run_all(repo, roster_path=str(roster))
    coverage = next(f for f in findings if f.check_name == "gpg.signature_coverage")
    # One unsigned init commit plus one verified commit.
    assert coverage.evidence["verified_commit_count"] == 1
    assert os.environ["HACKPROOF_ROSTER"] == str(roster)


def test_render_table_puts_the_worst_first(tmp_path):
    findings = [
        Finding("a.info", "claim", "info", {}, True),
        Finding("b.hard", "system", "hard_flag", {"note": "bad"}, False),
        Finding("c.flag", "claim", "flag", {"note": "meh"}, False),
    ]
    lines = render_table(findings).splitlines()
    assert "b.hard" in lines[0]
    assert "c.flag" in lines[1]
    assert "a.info" in lines[2]
    assert "1 hard_flag" in lines[-1]


def test_summary_counts_planes_and_severities(tmp_path):
    repo = make_repo(tmp_path)
    summary = summarize(run_all(repo))
    assert summary["total"] == summary["passed"] + summary["failed"]
    assert sum(summary["by_plane"].values()) == summary["total"]
    assert sum(summary["by_severity"].values()) == summary["total"]


# --- history completeness -------------------------------------------------------


def test_a_shallow_clone_is_reported_as_incomplete(tmp_path):
    """A judge who clones with --depth must not get a confident partial answer."""
    origin = make_repo(tmp_path)
    for i in range(4):
        (tmp_path / "repo" / f"f{i}.py").write_text(f"x = {i}\n", encoding="utf-8")
        sh(["git", "add", "-A"], cwd=origin)
        sh(["git", "commit", "--no-gpg-sign", "-m", f"commit {i}"], cwd=origin)

    shallow = str(tmp_path / "shallow")
    sh(["git", "clone", "-q", "--depth", "1", f"file://{origin}", shallow])

    findings = {f.check_name: f for f in run_all(shallow)}
    history = findings["engine.history_completeness"]

    assert history.evidence["is_shallow_clone"] is True
    assert not history.passed
    assert "SHALLOW" in history.evidence["interpretation"]
    # It reports, it does not accuse: a shallow clone is the judge's doing.
    assert history.severity == "info"


def test_a_full_clone_is_reported_as_complete(tmp_path):
    origin = make_repo(tmp_path)
    full = str(tmp_path / "full")
    sh(["git", "clone", "-q", f"file://{origin}", full])

    history = {f.check_name: f for f in run_all(full)}["engine.history_completeness"]

    assert history.evidence["is_shallow_clone"] is False
    assert history.passed


def test_history_check_is_absent_outside_a_git_repo(tmp_path):
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    findings = run_all(str(plain))
    assert not [f for f in findings if f.check_name == "engine.history_completeness"]


def test_main_rejects_nonexistent_or_nongit_path(tmp_path, capsys):
    from core.engine import main
    # 1. Non-existent path returns exit code 1 with clear hint
    code = main(["/path/does/not/exist/ever"])
    assert code == 1
    err = capsys.readouterr().err
    assert "does not exist" in err

    # 2. Plain directory without git returns exit code 1
    plain = tmp_path / "plain_dir"
    plain.mkdir()
    code = main([str(plain)])
    assert code == 1
    err = capsys.readouterr().err
    assert "not a valid git repository" in err

