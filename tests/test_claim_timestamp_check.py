"""Tests for analyzers.claim_timestamp_check against real Git repositories."""

from __future__ import annotations

import os
import subprocess
import pytest

from analyzers.claim_timestamp_check import (
    CHECK_AUTHOR_COMMITTER_SPREAD,
    CHECK_BUILD_WINDOW,
    CHECK_DIFF_CHURN,
    CHECK_INTERVAL_QUANTIZATION,
    CHECK_PARENT_MONOTONICITY,
    CHECK_TIMEZONE_CONSISTENCY,
    run,
)


@pytest.fixture(autouse=True)
def isolated_git_env(tmp_path, monkeypatch):
    """Keep developer's real global/system git config out of fixtures."""
    home = tmp_path / "fake-home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Team Member")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "member@team.test")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Team Member")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "member@team.test")


def git(repo: str, *args: str, env: dict | None = None) -> str:
    full_env = dict(os.environ)
    full_env["LC_ALL"] = "C"
    if env:
        full_env.update(env)
    res = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=full_env,
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout


def init_repo(tmp_path, name="repo") -> str:
    repo = str(tmp_path / name)
    os.makedirs(repo)
    git(repo, "init", "-q", "-b", "main")
    return repo


def write_file(repo: str, rel: str, content: str) -> str:
    path = os.path.join(repo, rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(content)
    return path


def by_name(findings):
    return {f.check_name: f for f in findings}


# ------------------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------------------


def test_clean_monotonic_history_passes(tmp_path):
    repo = init_repo(tmp_path)
    
    # 3 natural commits with realistic intervals (e.g. 15 mins, 42 mins)
    write_file(repo, "README.md", "# Test Project\n")
    git(repo, "add", "README.md")
    git(repo, "commit", "-m", "init", env={
        "GIT_AUTHOR_DATE": "2026-09-12T10:00:00+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T10:00:01+05:30",
    })

    write_file(repo, "app.py", "def main(): pass\n")
    git(repo, "add", "app.py")
    git(repo, "commit", "-m", "add app", env={
        "GIT_AUTHOR_DATE": "2026-09-12T10:15:23+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T10:15:25+05:30",
    })

    write_file(repo, "utils.py", "def add(a, b): return a + b\n")
    git(repo, "add", "utils.py")
    git(repo, "commit", "-m", "add utils", env={
        "GIT_AUTHOR_DATE": "2026-09-12T10:57:41+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T10:57:42+05:30",
    })

    findings = by_name(run(repo))
    assert len(findings) == 6
    assert all(f.passed for f in findings.values())


def test_parent_monotonicity_violation_is_hard_flagged(tmp_path):
    repo = init_repo(tmp_path)

    write_file(repo, "f1.py", "x = 1\n")
    git(repo, "add", "f1.py")
    git(repo, "commit", "-m", "c1", env={
        "GIT_AUTHOR_DATE": "2026-09-12T12:00:00+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T12:00:00+05:30",
    })

    # Child commit dated 2 hours earlier than parent!
    write_file(repo, "f2.py", "y = 2\n")
    git(repo, "add", "f2.py")
    git(repo, "commit", "-m", "c2", env={
        "GIT_AUTHOR_DATE": "2026-09-12T10:00:00+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T10:00:00+05:30",
    })

    findings = by_name(run(repo))
    mono = findings[CHECK_PARENT_MONOTONICITY]
    assert mono.passed is False
    assert mono.severity == "hard_flag"
    assert mono.evidence["violation_count"] == 1
    assert mono.evidence["worst_reversal_seconds"] == 7200.0


def test_timezone_offset_jump_is_flagged(tmp_path):
    repo = init_repo(tmp_path)

    # 3 commits with +05:30
    for i in range(3):
        write_file(repo, f"f{i}.py", f"x = {i}\n")
        git(repo, "add", f"f{i}.py")
        git(repo, "commit", "-m", f"c{i}", env={
            "GIT_AUTHOR_DATE": f"2026-09-12T10:{i*10:02d}:00+05:30",
            "GIT_COMMITTER_DATE": f"2026-09-12T10:{i*10:02d}:00+05:30",
        })

    # Sudden commit with +00:00 (UTC)
    write_file(repo, "f_foreign.py", "z = 9\n")
    git(repo, "add", "f_foreign.py")
    git(repo, "commit", "-m", "c_foreign", env={
        "GIT_AUTHOR_DATE": "2026-09-12T10:45:00+00:00",
        "GIT_COMMITTER_DATE": "2026-09-12T10:45:00+00:00",
    })

    findings = by_name(run(repo))
    tz = findings[CHECK_TIMEZONE_CONSISTENCY]
    assert tz.passed is False
    assert tz.severity == "flag"
    assert tz.evidence["dominant_offset"] == "+05:30"
    assert tz.evidence["outlier_count"] == 1


def test_committer_before_author_is_hard_flagged(tmp_path):
    repo = init_repo(tmp_path)

    write_file(repo, "f1.py", "x = 1\n")
    git(repo, "add", "f1.py")
    # Committer date is 1 hour before Author date
    git(repo, "commit", "-m", "impossible dates", env={
        "GIT_AUTHOR_DATE": "2026-09-12T12:00:00+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T11:00:00+05:30",
    })

    findings = by_name(run(repo))
    spread = findings[CHECK_AUTHOR_COMMITTER_SPREAD]
    assert spread.passed is False
    assert spread.severity == "hard_flag"
    assert spread.evidence["inversion_count"] == 1


def test_scripted_fixed_interval_quantization_is_flagged(tmp_path):
    repo = init_repo(tmp_path)

    # 5 commits spaced by exactly 60.0 seconds (e.g. sleep 60 script)
    base_ts = 1726150000
    for i in range(5):
        write_file(repo, f"step_{i}.py", f"val = {i}\n")
        git(repo, "add", f"step_{i}.py")
        ts = base_ts + (i * 60)
        # Format as ISO string
        iso = f"2026-09-12T10:{i:02d}:15+05:30"
        git(repo, "commit", "-m", f"step {i}", env={
            "GIT_AUTHOR_DATE": iso,
            "GIT_COMMITTER_DATE": iso,
        })

    findings = by_name(run(repo))
    quant = findings[CHECK_INTERVAL_QUANTIZATION]
    assert quant.passed is False
    assert quant.severity == "hard_flag"
    assert quant.evidence["interval_std_dev"] == 0.0


def test_diff_churn_large_dump_is_flagged(tmp_path):
    repo = init_repo(tmp_path)

    # Big initial drop of 1,200 lines
    big_content = "\n".join(f"def func_{i}(): pass" for i in range(1200)) + "\n"
    write_file(repo, "big_module.py", big_content)
    git(repo, "add", "big_module.py")
    git(repo, "commit", "-m", "massive code drop")

    # Followed by 2 trivial 1-line commits without touching the code
    for i in range(2):
        write_file(repo, f"doc_{i}.txt", "doc\n")
        git(repo, "add", f"doc_{i}.txt")
        git(repo, "commit", "-m", f"trivial doc {i}")

    findings = by_name(run(repo))
    churn = findings[CHECK_DIFF_CHURN]
    assert churn.passed is False
    assert churn.severity == "flag"
    assert churn.evidence["largest_single_drop_lines"] >= 1200


def test_empty_or_non_git_repo_returns_clean_findings(tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    findings = run(str(plain))
    assert len(findings) == 6
    assert all(f.passed for f in findings)
    assert all(f.evidence.get("skipped") for f in findings)


def test_commits_predating_t0_are_hard_flagged(tmp_path, monkeypatch):
    repo = init_repo(tmp_path)
    monkeypatch.setenv("HACKPROOF_T0", "2026-09-12T12:00:00+05:30")

    write_file(repo, "f1.py", "x = 1\n")
    git(repo, "add", "f1.py")
    # Commit authored 2 hours BEFORE T0
    git(repo, "commit", "-m", "prebuilt code", env={
        "GIT_AUTHOR_DATE": "2026-09-12T10:00:00+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T10:00:00+05:30",
    })

    findings = by_name(run(repo))
    bw = findings[CHECK_BUILD_WINDOW]
    assert bw.passed is False
    assert bw.severity == "hard_flag"
    assert bw.evidence["predating_count"] == 1
    assert bw.evidence["predating_commits"][0]["hours_before_t0"] == 2.0


def test_commits_within_build_window_pass(tmp_path, monkeypatch):
    repo = init_repo(tmp_path)
    monkeypatch.setenv("HACKPROOF_T0", "2026-09-12T12:00:00+05:30")

    write_file(repo, "f1.py", "x = 1\n")
    git(repo, "add", "f1.py")
    # Commit authored 15 minutes AFTER T0
    git(repo, "commit", "-m", "legit code", env={
        "GIT_AUTHOR_DATE": "2026-09-12T12:15:00+05:30",
        "GIT_COMMITTER_DATE": "2026-09-12T12:15:00+05:30",
    })

    findings = by_name(run(repo))
    bw = findings[CHECK_BUILD_WINDOW]
    assert bw.passed is True
    assert bw.evidence["predating_count"] == 0
