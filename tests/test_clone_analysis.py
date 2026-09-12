"""Analyzing a clone: what survives the trip, and what must not pretend to.

The premise these tests defend: a check whose evidence lives on the
participant's machine cannot be answered from a clone, and reporting "ok" there
is not a rounding error -- it hands a judge a clean bill of health for a check
that never ran. So the clone path has to report ``n/a`` while still catching
everything that genuinely does travel with the commits.
"""

from __future__ import annotations

import importlib.util
import json
import os
import time

import pytest

from analyzers import gitignore_check
from core.engine import is_evaluable, render_table, run_all, summarize

try:
    from tests.helpers import out, run
except ModuleNotFoundError:  # pragma: no cover - depends on sys.path shape
    from helpers import out, run

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")

_spec = importlib.util.spec_from_file_location(
    "analyze_repo_url", os.path.join(SCRIPTS, "analyze_repo_url.py")
)
analyze_repo_url = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(analyze_repo_url)

CLONE_BLIND_CHECKS = {
    "gitignore.assume_unchanged_skip_worktree",
    "gitignore.info_exclude",
    "gitignore.core_excludes_file",
    "gitignore.tracked_source_ratio",
}


# --- the repo the tests share ---------------------------------------------------


@pytest.fixture
def hidden_work_repo(tmp_path, gpg_home):
    """A repo carrying both an outsider commit and a skip-worktree'd stub."""
    member = gpg_home.generate_key("Satoru <satoru@example.test>")
    outsider = gpg_home.generate_key("Eve <eve@example.test>")

    repo = tmp_path / "origin"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    run(["git", "-C", str(repo), "config", "user.name", "Satoru"])
    run(["git", "-C", str(repo), "config", "user.email", "satoru@example.test"])

    env = {**gpg_home.env, "GIT_AUTHOR_NAME": "Satoru", "GIT_AUTHOR_EMAIL": "satoru@example.test",
           "GIT_COMMITTER_NAME": "Satoru", "GIT_COMMITTER_EMAIL": "satoru@example.test"}

    (repo / "app.py").write_text("print('hi')\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "app.py"])
    run(["git", "-C", str(repo), "commit", f"-S{member}", "-m", "honest work"], env=env)

    # An outsider's key, authored as Satoru. This travels with the commit.
    (repo / "helper.py").write_text("def helper(): pass\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "helper.py"])
    run(["git", "-C", str(repo), "commit", f"-S{outsider}", "-m", "outsider work"], env=env)

    # A stub, flagged skip-worktree, then rewritten. This does NOT travel.
    (repo / "sauce.py").write_text("def solve(): return None\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "sauce.py"])
    run(["git", "-C", str(repo), "commit", "--no-gpg-sign", "-m", "wip stub"], env=env)
    run(["git", "-C", str(repo), "update-index", "--skip-worktree", "sauce.py"])
    (repo / "sauce.py").write_text("def solve(): return 'the real thing'\n", encoding="utf-8")
    # The check compares mtime against the last commit with a 2s tolerance. Push
    # the mtime forward rather than sleeping through it.
    edited_at = time.time() + 60
    os.utime(repo / "sauce.py", (edited_at, edited_at))

    roster = {
        "team_id": "team-07",
        "members": [
            {
                "member_id": "satoru",
                "emails": ["satoru@example.test"],
                "keys": [{"key_id": "k1", "public_key": gpg_home.export_public(member)}],
            }
        ],
    }
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(roster), encoding="utf-8")

    clone = tmp_path / "clone"
    run(["git", "clone", "-q", str(repo), str(clone)])

    return {"origin": str(repo), "clone": str(clone), "roster": str(roster_path)}


def by_name(findings):
    return {f.check_name: f for f in findings}


# --- the bug this exists to prevent ---------------------------------------------


def test_on_a_clone_the_blind_checks_report_not_evaluable(monkeypatch, hidden_work_repo):
    monkeypatch.setenv("HACKPROOF_SOURCE", "clone")

    findings = by_name(run_all(hidden_work_repo["clone"], roster_path=hidden_work_repo["roster"], skip=["github"]))

    for name in CLONE_BLIND_CHECKS:
        finding = findings[name]
        assert not is_evaluable(finding), f"{name} claimed to be evaluable on a clone"
        assert finding.evidence["not_evaluable_reason"]


def test_the_same_checks_are_evaluable_on_the_original(monkeypatch, hidden_work_repo):
    monkeypatch.setenv("HACKPROOF_SOURCE", "local")

    findings = by_name(run_all(hidden_work_repo["origin"], roster_path=hidden_work_repo["roster"], skip=["github"]))

    for name in CLONE_BLIND_CHECKS:
        assert is_evaluable(findings[name]), f"{name} should be evaluable on the author's own checkout"


def test_skip_worktree_is_caught_locally_and_never_claimed_clean_on_the_clone(monkeypatch, hidden_work_repo):
    """The exact regression: hard_flag locally, n/a on the clone -- never 'ok'."""
    monkeypatch.setenv("HACKPROOF_SOURCE", "local")
    local = by_name(run_all(hidden_work_repo["origin"], roster_path=hidden_work_repo["roster"], skip=["github"]))
    assert local["gitignore.assume_unchanged_skip_worktree"].severity == "hard_flag"

    monkeypatch.setenv("HACKPROOF_SOURCE", "clone")
    cloned = by_name(run_all(hidden_work_repo["clone"], roster_path=hidden_work_repo["roster"], skip=["github"]))
    assert not is_evaluable(cloned["gitignore.assume_unchanged_skip_worktree"])


def test_the_outsider_is_still_caught_from_the_clone(monkeypatch, hidden_work_repo):
    """Signatures travel with commits, so the identity half loses nothing."""
    monkeypatch.setenv("HACKPROOF_SOURCE", "clone")

    findings = by_name(run_all(hidden_work_repo["clone"], roster_path=hidden_work_repo["roster"], skip=["github"]))

    unregistered = findings["gpg.unregistered_key"]
    assert not unregistered.passed
    assert unregistered.severity == "hard_flag"
    assert is_evaluable(unregistered)


# --- how it is presented ----------------------------------------------------------


def test_summary_counts_and_names_the_unevaluated(monkeypatch, hidden_work_repo):
    monkeypatch.setenv("HACKPROOF_SOURCE", "clone")
    findings = run_all(hidden_work_repo["clone"], roster_path=hidden_work_repo["roster"], skip=["github"])

    summary = summarize(findings)

    assert summary["not_evaluable"] == len(CLONE_BLIND_CHECKS)
    assert set(summary["not_evaluable_checks"]) == CLONE_BLIND_CHECKS
    assert summary["checks_evaluated"] == summary["total"] - summary["not_evaluable"]


def test_the_table_says_n_a_and_explains_itself(monkeypatch, hidden_work_repo):
    monkeypatch.setenv("HACKPROOF_SOURCE", "clone")
    findings = run_all(hidden_work_repo["clone"], roster_path=hidden_work_repo["roster"], skip=["github"])

    table = render_table(findings)

    assert "n/a " in table
    assert "NOT clean" in table
    for name in CLONE_BLIND_CHECKS:
        assert name in table
    # The blind checks must never be printed as ok.
    for line in table.splitlines():
        if any(line.startswith(f"ok   {n}") for n in CLONE_BLIND_CHECKS):
            pytest.fail(f"a clone-blind check was rendered as ok: {line}")


def test_pattern_audit_stays_evaluable_and_explains_the_clone_limit(monkeypatch, hidden_work_repo):
    """The committed .gitignore and its history DO travel, so this one still runs."""
    monkeypatch.setenv("HACKPROOF_SOURCE", "clone")
    findings = by_name(run_all(hidden_work_repo["clone"], roster_path=hidden_work_repo["roster"], skip=["github"]))

    audit = findings["gitignore.pattern_audit"]

    assert is_evaluable(audit)
    assert "clone" in audit.evidence["clone_limitation"]


def test_local_runs_carry_no_clone_caveat(monkeypatch, hidden_work_repo):
    monkeypatch.setenv("HACKPROOF_SOURCE", "local")
    findings = by_name(run_all(hidden_work_repo["origin"], roster_path=hidden_work_repo["roster"], skip=["github"]))

    assert "clone_limitation" not in findings["gitignore.pattern_audit"].evidence


def test_default_source_is_local(monkeypatch):
    monkeypatch.delenv("HACKPROOF_SOURCE", raising=False)
    assert gitignore_check.analysis_source() == "local"


# --- the URL entry point -----------------------------------------------------------


@pytest.mark.parametrize(
    "target,slug",
    [
        ("https://github.com/team-07/project", "team-07/project"),
        ("https://github.com/team-07/project.git", "team-07/project"),
        ("https://github.com/team-07/project/", "team-07/project"),
        ("git@github.com:team-07/project.git", "team-07/project"),
        ("ssh://git@github.com/team-07/project.git", "team-07/project"),
        ("team-07/project", "team-07/project"),
    ],
)
def test_target_parsing(target, slug):
    assert analyze_repo_url.parse_target(target)[0] == slug


def test_an_ssh_target_keeps_its_ssh_remote():
    """Rewriting it to https would throw away the user's ssh-agent credentials."""
    _, clone_url = analyze_repo_url.parse_target("git@github.com:team-07/project.git")
    assert clone_url.startswith("git@")


def test_a_slug_becomes_an_https_clone_url():
    _, clone_url = analyze_repo_url.parse_target("team-07/project")
    assert clone_url == "https://github.com/team-07/project.git"


def test_a_non_github_target_is_refused():
    with pytest.raises(analyze_repo_url.AnalyzeError):
        analyze_repo_url.parse_target("https://gitlab.com/team-07/project.git")


def test_tokens_are_scrubbed_from_error_text():
    assert "ghp_secret" not in analyze_repo_url.scrub("failed for ghp_secret", "ghp_secret")


def test_describe_reports_commits_left_on_other_branches(tmp_path):
    """A third person's commit could be sitting on a branch; never miss it silently."""
    repo = tmp_path / "r"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    run(["git", "-C", str(repo), "config", "user.email", "t@t.test"])
    run(["git", "-C", str(repo), "config", "user.name", "T"])
    (repo / "a.py").write_text("a\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "a.py"])
    run(["git", "-C", str(repo), "commit", "--no-gpg-sign", "-q", "-m", "one"])
    run(["git", "-C", str(repo), "checkout", "-q", "-b", "side"])
    (repo / "b.py").write_text("b\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "b.py"])
    run(["git", "-C", str(repo), "commit", "--no-gpg-sign", "-q", "-m", "two"])
    run(["git", "-C", str(repo), "checkout", "-q", "main"])

    clone = tmp_path / "c"
    run(["git", "clone", "-q", "--no-single-branch", str(repo), str(clone)])

    info = analyze_repo_url.describe(str(clone))

    assert info["commits_on_analyzed_branch"] == 1
    assert info["commits_on_all_branches"] == 2
    assert info["commits_not_on_analyzed_branch"] == 1
    assert "side" in info["branches"]
    assert "origin/HEAD" not in info["branches"]
