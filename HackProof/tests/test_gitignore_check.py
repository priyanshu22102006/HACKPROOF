"""Tests for analyzers.gitignore_check against real temporary git repositories.

Each test builds a fixture repo with plain ``git`` subprocess calls, so the
analyzer is exercised against actual git behaviour rather than mocks.
"""

from __future__ import annotations

import os
import subprocess
import time

import pytest

from analyzers.gitignore_check import (
    CHECK_ASSUME_UNCHANGED,
    CHECK_CORE_EXCLUDES_FILE,
    CHECK_GITIGNORE,
    CHECK_INFO_EXCLUDE,
    CHECK_SOURCE_RATIO,
    run,
)

BENIGN_GITIGNORE = "__pycache__/\n*.pyc\nnode_modules/\n.env\ndist/\n"


@pytest.fixture(autouse=True)
def isolated_git_env(tmp_path, monkeypatch):
    """Keep the developer's real global/system git config out of the fixtures."""
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Fixture Author")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "author@example.test")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Fixture Author")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "author@example.test")


def git(repo, *args):
    return subprocess.run(
        ["git", *args], cwd=repo, check=True, capture_output=True, text=True
    ).stdout


def write(repo, rel, content):
    path = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(content)
    return path


def init_repo(tmp_path, name="repo"):
    repo = str(tmp_path / name)
    os.makedirs(repo)
    git(repo, "init", "-q")
    git(repo, "checkout", "-q", "-b", "main")
    return repo


def commit_all(repo, message):
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def by_name(findings):
    return {f.check_name: f for f in findings}


def test_clean_repo_raises_no_flags(tmp_path):
    repo = init_repo(tmp_path)
    write(repo, ".gitignore", BENIGN_GITIGNORE)
    write(repo, "README.md", "# fixture\n")
    write(repo, "src/main.py", "def main():\n    return 42\n")
    write(repo, "src/util.py", "VALUE = 1\n")
    commit_all(repo, "initial commit")

    findings = run(repo)
    assert len(findings) == 5
    assert all(f.passed for f in findings), [
        (f.check_name, f.evidence) for f in findings if not f.passed
    ]
    assert {f.severity for f in findings} == {"info"}

    gitignore = by_name(findings)[CHECK_GITIGNORE]
    assert gitignore.plane == "claim"
    assert gitignore.evidence["suspicious_patterns"] == []
    assert gitignore.evidence["late_added_rules"] == []

    ratio = by_name(findings)[CHECK_SOURCE_RATIO]
    assert ratio.severity == "info"
    assert ratio.evidence["source_files_on_disk"] == 2
    assert ratio.evidence["tracked_ratio"] == 1.0


def test_gitignore_hiding_src_directory_is_flagged(tmp_path):
    repo = init_repo(tmp_path)
    write(repo, ".gitignore", BENIGN_GITIGNORE)
    write(repo, "README.md", "# fixture\n")
    commit_all(repo, "initial commit")

    # Source added late and hidden by a rule appended to .gitignore.
    write(repo, "src/secret.py", "SECRET = True\n")
    write(repo, "src/engine.py", "def go():\n    pass\n")
    write(repo, ".gitignore", BENIGN_GITIGNORE + "src/\n")
    commit_all(repo, "tidy up ignores")

    findings = by_name(run(repo))
    gitignore = findings[CHECK_GITIGNORE]
    assert gitignore.passed is False
    assert gitignore.severity == "hard_flag"  # rule added late over existing source
    assert any(p["pattern"] == "src/" for p in gitignore.evidence["suspicious_patterns"])
    assert gitignore.evidence["hidden_source_file_count"] == 2
    assert {rec["path"] for rec in gitignore.evidence["hidden_source_files"]} == {
        "src/secret.py",
        "src/engine.py",
    }
    late = gitignore.evidence["late_added_rules"]
    assert late and late[0]["pattern"] == "src/"
    assert late[0]["gitignore"] == ".gitignore"

    ratio = findings[CHECK_SOURCE_RATIO]
    assert ratio.severity == "info"
    assert ratio.evidence["source_files_on_disk"] == 2
    assert ratio.evidence["source_files_tracked"] == 0
    assert ratio.evidence["tracked_ratio"] == 0.0
    assert ratio.passed is False

    # The other mechanisms stay quiet.
    assert findings[CHECK_INFO_EXCLUDE].passed is True
    assert findings[CHECK_ASSUME_UNCHANGED].passed is True


def test_skip_worktree_file_edited_after_commit_is_hard_flagged(tmp_path):
    repo = init_repo(tmp_path)
    write(repo, ".gitignore", BENIGN_GITIGNORE)
    write(repo, "src/app.py", "STUB = True\n")
    write(repo, "src/untouched.py", "CONSTANT = 7\n")
    commit_all(repo, "commit a stub")

    git(repo, "update-index", "--skip-worktree", "src/app.py")
    # A second flagged-but-unedited file: reported, but not evidence of hiding.
    git(repo, "update-index", "--assume-unchanged", "src/untouched.py")
    real_path = write(repo, "src/app.py", "REAL = 'the actual implementation'\n")
    future = time.time() + 300  # unambiguously after the commit timestamp
    os.utime(real_path, (future, future))

    findings = by_name(run(repo))
    check = findings[CHECK_ASSUME_UNCHANGED]
    assert check.plane == "system"
    assert check.passed is False
    assert check.severity == "hard_flag"
    assert check.evidence["flagged_file_count"] == 2

    records = {r["path"]: r for r in check.evidence["flagged_files"]}
    assert "skip-worktree" in records["src/app.py"]["mechanisms"]
    assert records["src/app.py"]["modified_after_last_commit"] is True
    assert records["src/app.py"]["content_differs_from_index"] is True

    assert "assume-unchanged" in records["src/untouched.py"]["mechanisms"]
    assert records["src/untouched.py"]["modified_after_last_commit"] is False
    assert records["src/untouched.py"]["content_differs_from_index"] is False

    assert check.evidence["modified_after_flagging"] == ["src/app.py"]

    # A tracked-but-skipped file still counts as tracked in the ratio metric.
    assert findings[CHECK_SOURCE_RATIO].evidence["tracked_ratio"] == 1.0


def test_info_exclude_hiding_a_directory_is_flagged(tmp_path):
    repo = init_repo(tmp_path)
    write(repo, ".gitignore", BENIGN_GITIGNORE)
    write(repo, "README.md", "# fixture\n")
    commit_all(repo, "initial commit")

    write(repo, "secret_src/hidden.py", "def hidden():\n    return 'not in the repo'\n")
    write(repo, ".git/info/exclude", "# local excludes\nsecret_src/\n")

    findings = by_name(run(repo))
    check = findings[CHECK_INFO_EXCLUDE]
    assert check.plane == "system"
    assert check.passed is False
    assert check.severity == "hard_flag"  # weighted above the same rule in .gitignore
    assert check.evidence["path"].endswith(os.path.join(".git", "info", "exclude"))
    assert any(
        p["pattern"] == "secret_src/" for p in check.evidence["suspicious_patterns"]
    )
    assert [rec["path"] for rec in check.evidence["hidden_source_files"]] == [
        "secret_src/hidden.py"
    ]

    # .gitignore itself is clean; the hiding is attributed to info/exclude only.
    assert findings[CHECK_GITIGNORE].passed is True
    assert findings[CHECK_SOURCE_RATIO].evidence["untracked_source_file_count"] == 1


def test_non_git_path_returns_passing_findings_without_crashing(tmp_path):
    plain = tmp_path / "not-a-repo"
    plain.mkdir()
    (plain / "main.py").write_text("x = 1\n")

    findings = run(str(plain))
    assert len(findings) == 5
    assert all(f.passed for f in findings)
    assert all(f.evidence.get("skipped") for f in findings)

    missing = run(str(tmp_path / "does-not-exist"))
    assert len(missing) == 5
    assert all(f.passed for f in missing)


def test_core_excludes_file_hiding_source_is_flagged(tmp_path):
    repo = init_repo(tmp_path)
    write(repo, ".gitignore", BENIGN_GITIGNORE)
    write(repo, "README.md", "# fixture\n")
    commit_all(repo, "initial commit")

    global_ignore = tmp_path / "global_ignore"
    global_ignore.write_text("src_hidden/\n")
    git(repo, "config", "--local", "core.excludesFile", str(global_ignore))

    write(repo, "src_hidden/secret.py", "def secret():\n    return 42\n")

    findings = by_name(run(repo))
    check = findings[CHECK_CORE_EXCLUDES_FILE]
    assert check.plane == "system"
    assert check.passed is False
    assert check.severity == "hard_flag"
    assert check.evidence["hidden_source_file_count"] == 1
    assert [rec["path"] for rec in check.evidence["hidden_source_files"]] == ["src_hidden/secret.py"]


def test_nested_gitignore_hiding_directory_is_flagged(tmp_path):
    repo = init_repo(tmp_path)
    write(repo, ".gitignore", BENIGN_GITIGNORE)
    write(repo, "README.md", "# fixture\n")
    commit_all(repo, "initial commit")

    # Nested gitignore inside sub/ directory that hides sub/modules/
    write(repo, "sub/.gitignore", "modules/\n")
    write(repo, "sub/modules/secret.py", "def secret():\n    return 123\n")
    commit_all(repo, "add nested gitignore")

    findings = by_name(run(repo))
    gitignore = findings[CHECK_GITIGNORE]
    assert gitignore.passed is False
    assert "sub/.gitignore" in gitignore.evidence["gitignore_files"]
    assert any(
        p["pattern"] == "modules/" and p.get("file") == "sub/.gitignore"
        for p in gitignore.evidence["suspicious_patterns"]
    )
    assert gitignore.evidence["hidden_source_file_count"] >= 1
    assert any(
        rec["path"] == "sub/modules/secret.py"
        for rec in gitignore.evidence["hidden_source_files"]
    )


def test_gitignore_blame_view_initial_vs_late(tmp_path):
    from analyzers.gitignore_check import get_gitignore_blame_view, render_gitignore_blame_table
    repo = init_repo(tmp_path)
    # Commit 1: Initial housekeeping
    write(repo, ".gitignore", "node_modules/\n__pycache__/\n")
    write(repo, "README.md", "# project\n")
    commit_all(repo, "initial commit")

    # Commit 2: Late added rule
    write(repo, ".gitignore", "node_modules/\n__pycache__/\nsrc/hidden_module/\n")
    commit_all(repo, "late ignore rule")

    # Working tree uncommitted file under the late pattern
    write(repo, "src/hidden_module/algo.py", "def secret(): return 42\n")

    blame_entries = get_gitignore_blame_view(repo)
    assert len(blame_entries) == 3

    # Entry 1 & 2: initial
    assert blame_entries[0].line_number == 1
    assert blame_entries[0].pattern == "node_modules/"
    assert blame_entries[0].is_initial is True
    assert blame_entries[0].timing_label == "[INIT]"
    assert blame_entries[0].classification == "BENIGN"

    # Entry 3: late added and actively concealing
    assert blame_entries[2].line_number == 3
    assert blame_entries[2].pattern == "src/hidden_module/"
    assert blame_entries[2].is_initial is False
    assert "LATE" in blame_entries[2].timing_label
    assert blame_entries[2].classification == "ACTIVE CONCEALMENT"
    assert "src/hidden_module/algo.py" in blame_entries[2].hidden_files

    table = render_gitignore_blame_table(blame_entries)
    assert "FORENSIC BLAME VIEW" in table
    assert "src/hidden_module/" in table
    assert "CONCEALED" in table
    assert "src/hidden_module/algo.py" in table


