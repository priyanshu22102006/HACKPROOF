"""Claim-plane timestamp and diff-shape analyzer for HACKPROOF.

Implements the 5 claim-plane integrity checks defined in HACKPROOF Spec §8.d (checks 10-14):
  10. Parent monotonicity: commits must not be dated earlier than their parent commits.
  11. Timezone-offset consistency: sudden shifts or foreign offsets without plausible travel windows.
  12. Author-date vs. committer-date spread: detects impossible dates (committer < author) and uniform artificial gaps.
  13. Commit-interval quantization: detects automated commit bot scripts (even intervals / round modulo).
  14. Diff-shape churn: detects large pre-built code dumps with near-zero subsequent modification/churn.

All checks run against standard Git metadata and diff logs with zero infrastructure required.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import math
import os
import subprocess
import sys

try:
    from core.models import Finding
except ModuleNotFoundError:  # pragma: no cover - path fallback
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.models import Finding

CHECK_BUILD_WINDOW = "claim.build_window"
CHECK_PARENT_MONOTONICITY = "claim.parent_monotonicity"
CHECK_TIMEZONE_CONSISTENCY = "claim.timezone_consistency"
CHECK_AUTHOR_COMMITTER_SPREAD = "claim.author_committer_spread"
CHECK_INTERVAL_QUANTIZATION = "claim.interval_quantization"
CHECK_DIFF_CHURN = "claim.diff_churn"

# Tolerances & Thresholds
MONOTONICITY_TOLERANCE_SECONDS = 2.0  # allow minor local clock skew
HARD_REVERSAL_SECONDS = 60.0  # reversals greater than 1 minute are hard flags
MIN_COMMITS_FOR_QUANTIZATION = 4  # need statistical sample for interval clustering
MAX_EVIDENCE_ITEMS = 25


def _git(repo_path: str, args: list[str], timeout: int = 60) -> tuple[int, str, str]:
    """Subprocess helper running git inside repo_path with isolated locale."""
    env = dict(os.environ)
    env["LC_ALL"] = "C"
    env["GIT_OPTIONAL_LOCKS"] = "0"
    cmd = ["git", "--no-pager", *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError) as exc:
        return 1, "", str(exc)
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def _is_git_repo(repo_path: str) -> bool:
    if not os.path.isdir(repo_path):
        return False
    rc, out, _ = _git(repo_path, ["rev-parse", "--is-inside-work-tree"])
    return rc == 0 and out.strip() == "true"


def _has_commits(repo_path: str) -> bool:
    rc, _, _ = _git(repo_path, ["rev-parse", "--verify", "--quiet", "HEAD"])
    return rc == 0


def _parse_iso(iso_str: str) -> datetime | None:
    """Parse an ISO 8601 string from git %aI / %cI into a timezone-aware datetime."""
    try:
        return datetime.fromisoformat(iso_str.strip())
    except (ValueError, TypeError):
        return None


def _get_commit_history(repo_path: str) -> list[dict]:
    """Extract commit metadata: SHA, parents, author info, committer info, timestamps."""
    # Field separator \x1f (Unit Separator), record separator \x1e (Record Separator)
    fmt = "%H%x1f%P%x1f%an%x1f%ae%x1f%aI%x1f%cn%x1f%ce%x1f%cI%x1e"
    rc, out, _ = _git(repo_path, ["log", f"--format={fmt}"])
    if rc != 0 or not out.strip():
        return []

    commits: list[dict] = []
    records = out.strip("\x1e").split("\x1e")
    for rec in records:
        if not rec.strip():
            continue
        parts = rec.strip().split("\x1f")
        if len(parts) != 8:
            continue
        sha, parents_str, author_name, author_email, author_iso, committer_name, committer_email, committer_iso = parts
        
        a_dt = _parse_iso(author_iso)
        c_dt = _parse_iso(committer_iso)
        if not a_dt or not c_dt:
            continue

        commits.append({
            "sha": sha,
            "parents": parents_str.split() if parents_str else [],
            "author_name": author_name,
            "author_email": author_email,
            "author_iso": author_iso,
            "author_dt": a_dt,
            "committer_name": committer_name,
            "committer_email": committer_email,
            "committer_iso": committer_iso,
            "committer_dt": c_dt,
        })
    return commits


# ------------------------------------------------------------------------------
# Check 0: Build-Window Verification (Spec §8.d / §8.i)
# ------------------------------------------------------------------------------


def check_build_window(commits: list[dict], t0_raw: str | None = None, t_end_raw: str | None = None) -> Finding:
    """Detect commits authored before hackathon start time (T0) or after deadline."""
    if not t0_raw:
        t0_raw = os.environ.get("HACKPROOF_T0", "").strip() or None
    if not t_end_raw:
        t_end_raw = os.environ.get("HACKPROOF_T_END", "").strip() or os.environ.get("HACKPROOF_DEADLINE", "").strip() or None

    evidence: dict = {
        "mechanism": "hackathon build-window verification (spec §8.d / §8.i)",
        "t0": t0_raw,
        "t_end": t_end_raw,
        "commit_count": len(commits),
        "first_commit": (
            {
                "sha": commits[-1]["sha"][:7],
                "date": commits[-1]["author_iso"],
                "author": f"{commits[-1]['author_name']} <{commits[-1]['author_email']}>",
            }
            if commits
            else None
        ),
        "latest_commit": (
            {
                "sha": commits[0]["sha"][:7],
                "date": commits[0]["author_iso"],
                "author": f"{commits[0]['author_name']} <{commits[0]['author_email']}>",
            }
            if commits
            else None
        ),
        "duration_seconds": (
            max(0.0, (commits[0]["author_dt"] - commits[-1]["author_dt"]).total_seconds())
            if commits
            else 0.0
        ),
        "predating_commits": [],
        "predating_count": 0,
        "post_deadline_commits": [],
        "post_deadline_count": 0,
    }

    if not t0_raw and not t_end_raw:
        evidence["note"] = "no hackathon start time given; set --t0 or $HACKPROOF_T0 to verify commits against build window"
        return Finding(
            check_name=CHECK_BUILD_WINDOW,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    t0_dt = _parse_iso(t0_raw) if t0_raw else None
    t_end_dt = _parse_iso(t_end_raw) if t_end_raw else None

    predating = []
    post_deadline = []

    for c in commits:
        a_dt = c["author_dt"]
        if t0_dt and a_dt < t0_dt:
            delta = (t0_dt - a_dt).total_seconds()
            predating.append({
                "sha": c["sha"][:12],
                "author": f"{c['author_name']} <{c['author_email']}>",
                "author_date": c["author_iso"],
                "hours_before_t0": round(delta / 3600.0, 2),
            })
        if t_end_dt and a_dt > t_end_dt:
            delta = (a_dt - t_end_dt).total_seconds()
            post_deadline.append({
                "sha": c["sha"][:12],
                "author": f"{c['author_name']} <{c['author_email']}>",
                "author_date": c["author_iso"],
                "hours_after_deadline": round(delta / 3600.0, 2),
            })

    evidence["predating_commits"] = predating[:MAX_EVIDENCE_ITEMS]
    evidence["predating_count"] = len(predating)
    evidence["post_deadline_commits"] = post_deadline[:MAX_EVIDENCE_ITEMS]
    evidence["post_deadline_count"] = len(post_deadline)

    if predating:
        evidence["interpretation"] = (
            f"PRE-BUILT CODE DETECTED: {len(predating)} commit(s) were authored BEFORE "
            f"the hackathon started ({t0_raw}). Code was created outside the hackathon build window!"
        )
        return Finding(
            check_name=CHECK_BUILD_WINDOW,
            plane="claim",
            severity="hard_flag",
            evidence=evidence,
            passed=False,
        )

    if post_deadline:
        evidence["interpretation"] = (
            f"LATE COMMITS DETECTED: {len(post_deadline)} commit(s) were authored AFTER "
            f"the hackathon deadline ({t_end_raw})."
        )
        return Finding(
            check_name=CHECK_BUILD_WINDOW,
            plane="claim",
            severity="flag",
            evidence=evidence,
            passed=False,
        )

    evidence["note"] = f"all {len(commits)} commits were authored within the official hackathon build window"
    return Finding(
        check_name=CHECK_BUILD_WINDOW,
        plane="claim",
        severity="info",
        evidence=evidence,
        passed=True,
    )


# ------------------------------------------------------------------------------
# Check 1: Parent Monotonicity (Spec §8.d #10)
# ------------------------------------------------------------------------------


def check_parent_monotonicity(commits: list[dict]) -> Finding:
    """Detect commits with author timestamps earlier than their parents."""
    evidence: dict = {
        "mechanism": "parent-date monotonicity (spec §8.d check 10)",
        "tolerance_seconds": MONOTONICITY_TOLERANCE_SECONDS,
        "violations": [],
        "violation_count": 0,
    }

    if not commits:
        evidence["note"] = "no commits to evaluate"
        return Finding(
            check_name=CHECK_PARENT_MONOTONICITY,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    by_sha = {c["sha"]: c for c in commits}
    violations: list[dict] = []
    worst_delta = 0.0

    for commit in commits:
        c_time = commit["author_dt"].timestamp()
        for parent_sha in commit["parents"]:
            parent = by_sha.get(parent_sha)
            if not parent:
                continue
            p_time = parent["author_dt"].timestamp()
            # If child committed earlier than parent
            delta = p_time - c_time
            if delta > MONOTONICITY_TOLERANCE_SECONDS:
                violations.append({
                    "sha": commit["sha"][:12],
                    "parent_sha": parent_sha[:12],
                    "author_date": commit["author_iso"],
                    "parent_author_date": parent["author_iso"],
                    "seconds_earlier_than_parent": round(delta, 1),
                })
                if delta > worst_delta:
                    worst_delta = delta

    evidence["violations"] = violations[:MAX_EVIDENCE_ITEMS]
    evidence["violation_count"] = len(violations)
    evidence["worst_reversal_seconds"] = round(worst_delta, 1)

    if not violations:
        evidence["note"] = "all commits are chronologically monotonic with their parents"
        return Finding(
            check_name=CHECK_PARENT_MONOTONICITY,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    severity = "hard_flag" if worst_delta >= HARD_REVERSAL_SECONDS else "flag"
    evidence["interpretation"] = (
        f"{len(violations)} commit(s) appear dated earlier than their parent commits. "
        f"Worst delta: {round(worst_delta, 1)}s. Strongly indicates backdated or scripted commit timestamps."
    )
    return Finding(
        check_name=CHECK_PARENT_MONOTONICITY,
        plane="claim",
        severity=severity,
        evidence=evidence,
        passed=False,
    )


# ------------------------------------------------------------------------------
# Check 2: Timezone-Offset Consistency (Spec §8.d #11)
# ------------------------------------------------------------------------------


def check_timezone_consistency(commits: list[dict]) -> Finding:
    """Detect timezone jumps or foreign offsets inconsistent with team location."""
    evidence: dict = {
        "mechanism": "timezone-offset consistency (spec §8.d check 11)",
        "offsets_observed": [],
        "outlier_commits": [],
    }

    if not commits:
        evidence["note"] = "no commits to evaluate"
        return Finding(
            check_name=CHECK_TIMEZONE_CONSISTENCY,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    # Extract author timezone offset string e.g. "+05:30" or "+00:00"
    offsets: list[str] = []
    for c in commits:
        tz = c["author_dt"].tzinfo
        if tz:
            offset_delta = tz.utcoffset(c["author_dt"])
            if offset_delta is not None:
                total_min = int(offset_delta.total_seconds() // 60)
                sign = "+" if total_min >= 0 else "-"
                hours, mins = divmod(abs(total_min), 60)
                offsets.append(f"{sign}{hours:02d}:{mins:02d}")

    if not offsets:
        evidence["note"] = "no timezone information found in commits"
        return Finding(
            check_name=CHECK_TIMEZONE_CONSISTENCY,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    counts = Counter(offsets)
    dominant_offset, dominant_count = counts.most_common(1)[0]
    evidence["dominant_offset"] = dominant_offset
    evidence["offsets_observed"] = dict(counts)

    # Detect outliers (offsets differing from the dominant team offset)
    outliers = []
    for c in commits:
        tz = c["author_dt"].tzinfo
        if tz:
            offset_delta = tz.utcoffset(c["author_dt"])
            if offset_delta is not None:
                total_min = int(offset_delta.total_seconds() // 60)
                sign = "+" if total_min >= 0 else "-"
                hours, mins = divmod(abs(total_min), 60)
                cur_offset = f"{sign}{hours:02d}:{mins:02d}"
                if cur_offset != dominant_offset:
                    outliers.append({
                        "sha": c["sha"][:12],
                        "author": f"{c['author_name']} <{c['author_email']}>",
                        "author_date": c["author_iso"],
                        "offset": cur_offset,
                        "expected_offset": dominant_offset,
                    })

    evidence["outlier_commits"] = outliers[:MAX_EVIDENCE_ITEMS]
    evidence["outlier_count"] = len(outliers)

    if not outliers:
        evidence["note"] = f"all commits consistent with team timezone {dominant_offset}"
        return Finding(
            check_name=CHECK_TIMEZONE_CONSISTENCY,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    # If more than 10% of commits or > 1 commit is foreign, raise a flag
    passed = len(outliers) == 0
    severity = "flag" if not passed else "info"
    evidence["interpretation"] = (
        f"{len(outliers)} commit(s) originated with timezone offset differing from "
        f"team dominant {dominant_offset}. May indicate outside contributors or proxy environments."
    )
    return Finding(
        check_name=CHECK_TIMEZONE_CONSISTENCY,
        plane="claim",
        severity=severity,
        evidence=evidence,
        passed=passed,
    )


# ------------------------------------------------------------------------------
# Check 3: Author vs Committer Date Spread (Spec §8.d #12)
# ------------------------------------------------------------------------------


def check_author_committer_spread(commits: list[dict]) -> Finding:
    """Detect impossible timestamps (committer < author) or uniform artificial spreads."""
    evidence: dict = {
        "mechanism": "author-date vs. committer-date spread (spec §8.d check 12)",
        "inversions": [],
        "large_spread_commits": [],
    }

    if not commits:
        evidence["note"] = "no commits to evaluate"
        return Finding(
            check_name=CHECK_AUTHOR_COMMITTER_SPREAD,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    inversions = []
    spreads: list[float] = []

    for c in commits:
        a_ts = c["author_dt"].timestamp()
        c_ts = c["committer_dt"].timestamp()
        delta = c_ts - a_ts  # normally >= 0

        # Impossible: committer timestamp before author timestamp
        if delta < -1.0:  # 1s tolerance for rounding
            inversions.append({
                "sha": c["sha"][:12],
                "author_date": c["author_iso"],
                "committer_date": c["committer_iso"],
                "delta_seconds": round(delta, 1),
            })
        else:
            spreads.append(delta)

    evidence["inversions"] = inversions[:MAX_EVIDENCE_ITEMS]
    evidence["inversion_count"] = len(inversions)

    if inversions:
        evidence["interpretation"] = (
            f"{len(inversions)} commit(s) have committer dates occurring BEFORE author dates. "
            "Chronologically impossible in natural git operation -- indicates manually crafted or faked dates."
        )
        return Finding(
            check_name=CHECK_AUTHOR_COMMITTER_SPREAD,
            plane="claim",
            severity="hard_flag",
            evidence=evidence,
            passed=False,
        )

    # Check for suspicious uniform spread across all commits (> 1 hour, standard deviation ~ 0)
    if len(spreads) >= 4:
        mean_spread = sum(spreads) / len(spreads)
        variance = sum((s - mean_spread) ** 2 for s in spreads) / len(spreads)
        std_dev = math.sqrt(variance)
        evidence["mean_spread_seconds"] = round(mean_spread, 1)
        evidence["spread_std_dev"] = round(std_dev, 2)

        if mean_spread > 3600.0 and std_dev < 1.0:
            evidence["interpretation"] = (
                f"Suspiciously uniform large spread ({round(mean_spread, 1)}s ± {round(std_dev, 2)}s) "
                "across commits indicates automated history rewriting (e.g. git rebase / filter-branch)."
            )
            return Finding(
                check_name=CHECK_AUTHOR_COMMITTER_SPREAD,
                plane="claim",
                severity="flag",
                evidence=evidence,
                passed=False,
            )

    evidence["note"] = "committer and author dates are chronologically sound"
    return Finding(
        check_name=CHECK_AUTHOR_COMMITTER_SPREAD,
        plane="claim",
        severity="info",
        evidence=evidence,
        passed=True,
    )


# ------------------------------------------------------------------------------
# Check 4: Commit-Interval Quantization (Spec §8.d #13)
# ------------------------------------------------------------------------------


def check_interval_quantization(commits: list[dict]) -> Finding:
    """Detect bot script loops with unnaturally uniform intervals or exact round minute boundaries."""
    evidence: dict = {
        "mechanism": "commit-interval quantization & bot detection (spec §8.d check 13)",
        "commit_count": len(commits),
    }

    if len(commits) < MIN_COMMITS_FOR_QUANTIZATION:
        evidence["note"] = f"fewer than {MIN_COMMITS_FOR_QUANTIZATION} commits; interval analysis skipped"
        return Finding(
            check_name=CHECK_INTERVAL_QUANTIZATION,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    # Sort chronologically by author date
    sorted_commits = sorted(commits, key=lambda c: c["author_dt"].timestamp())
    intervals: list[float] = []
    exact_round_minutes = 0
    exact_round_seconds = 0

    for i in range(1, len(sorted_commits)):
        prev_dt = sorted_commits[i - 1]["author_dt"]
        curr_dt = sorted_commits[i]["author_dt"]
        delta = curr_dt.timestamp() - prev_dt.timestamp()
        if delta >= 0:
            intervals.append(delta)

    for c in sorted_commits:
        if c["author_dt"].second == 0 and c["author_dt"].microsecond == 0:
            exact_round_minutes += 1
        if c["author_dt"].microsecond == 0:
            exact_round_seconds += 1

    if not intervals:
        evidence["note"] = "no forward commit intervals available"
        return Finding(
            check_name=CHECK_INTERVAL_QUANTIZATION,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    mean_int = sum(intervals) / len(intervals)
    variance = sum((x - mean_int) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)

    evidence["mean_interval_seconds"] = round(mean_int, 1)
    evidence["interval_std_dev"] = round(std_dev, 2)
    evidence["exact_round_minute_commits"] = exact_round_minutes
    evidence["total_commits"] = len(commits)

    # Bot Signal 1: Identical intervals (e.g. sleep 60 in a bash loop)
    # std_dev < 1.0 second across at least 4 intervals
    if len(intervals) >= 4 and std_dev < 1.5 and mean_int > 5.0:
        evidence["interpretation"] = (
            f"Automated bot script detected: {len(intervals)} consecutive commits spaced "
            f"with near-zero variance ({round(mean_int, 1)}s ± {round(std_dev, 2)}s)."
        )
        return Finding(
            check_name=CHECK_INTERVAL_QUANTIZATION,
            plane="claim",
            severity="hard_flag",
            evidence=evidence,
            passed=False,
        )

    # Bot Signal 2: 100% of commits land precisely on XX:00:00 round minutes (e.g. cron job)
    if len(commits) >= 4 and exact_round_minutes == len(commits):
        evidence["interpretation"] = (
            "All commits land on exact round minutes (:00 seconds) without fractional variation. "
            "Indicates cron or automated scheduler script."
        )
        return Finding(
            check_name=CHECK_INTERVAL_QUANTIZATION,
            plane="claim",
            severity="flag",
            evidence=evidence,
            passed=False,
        )

    evidence["note"] = "commit intervals follow natural human lumpy distribution"
    return Finding(
        check_name=CHECK_INTERVAL_QUANTIZATION,
        plane="claim",
        severity="info",
        evidence=evidence,
        passed=True,
    )


# ------------------------------------------------------------------------------
# Check 5: Diff-Shape Churn Analysis (Spec §8.d #14)
# ------------------------------------------------------------------------------


def check_diff_churn(repo_path: str, commits: list[dict]) -> Finding:
    """Detect massive pre-built code dumps with near-zero subsequent code iteration/churn."""
    evidence: dict = {
        "mechanism": "diff-shape churn analysis (spec §8.d check 14)",
        "commit_count": len(commits),
    }

    if not commits or len(commits) < 2:
        evidence["note"] = "fewer than 2 commits; diff churn analysis skipped"
        return Finding(
            check_name=CHECK_DIFF_CHURN,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    # Run git log --numstat to count additions and deletions per commit
    rc, out, _ = _git(repo_path, ["log", "--numstat", "--format=COMMIT %H"])
    if rc != 0 or not out.strip():
        evidence["note"] = "git numstat log unavailable"
        return Finding(
            check_name=CHECK_DIFF_CHURN,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    total_added = 0
    total_deleted = 0
    commit_added_lines: dict[str, int] = {}
    current_commit = None

    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("COMMIT "):
            current_commit = line.split()[1]
            commit_added_lines.setdefault(current_commit, 0)
            continue
        parts = line.split("\t")
        if len(parts) >= 3 and parts[0].isdigit() and parts[1].isdigit():
            added = int(parts[0])
            deleted = int(parts[1])
            total_added += added
            total_deleted += deleted
            if current_commit:
                commit_added_lines[current_commit] = commit_added_lines.get(current_commit, 0) + added

    evidence["total_lines_added"] = total_added
    evidence["total_lines_deleted"] = total_deleted

    if total_added < 100:
        evidence["note"] = "small project (< 100 lines added); churn check clean"
        return Finding(
            check_name=CHECK_DIFF_CHURN,
            plane="claim",
            severity="info",
            evidence=evidence,
            passed=True,
        )

    churn_ratio = total_deleted / total_added if total_added > 0 else 0.0
    evidence["churn_ratio"] = round(churn_ratio, 3)

    # Check for huge initial/single drop followed by virtually zero edits
    # e.g., > 1000 lines added in one commit, and total deletions < 1% across 4+ commits
    largest_single_drop = max(commit_added_lines.values()) if commit_added_lines else 0
    evidence["largest_single_drop_lines"] = largest_single_drop

    if total_added >= 1000 and len(commits) >= 3 and churn_ratio < 0.01 and largest_single_drop / total_added > 0.85:
        evidence["interpretation"] = (
            f"Pre-built code dump pattern detected: {largest_single_drop} lines added in a single drop "
            f"with only {round(churn_ratio * 100, 2)}% subsequent churn across {len(commits)} commits."
        )
        return Finding(
            check_name=CHECK_DIFF_CHURN,
            plane="claim",
            severity="flag",
            evidence=evidence,
            passed=False,
        )

    evidence["note"] = f"code churn ratio is {round(churn_ratio * 100, 1)}% across {total_added} additions"
    return Finding(
        check_name=CHECK_DIFF_CHURN,
        plane="claim",
        severity="info",
        evidence=evidence,
        passed=True,
    )


# ------------------------------------------------------------------------------
# Entry Point
# ------------------------------------------------------------------------------


def run(repo_path: str) -> list[Finding]:
    """Run all 6 Claim-plane timestamp, build-window & diff-shape checks over a git repo."""
    if not _is_git_repo(repo_path) or not _has_commits(repo_path):
        return [
            Finding(check_name=CHECK_BUILD_WINDOW, plane="claim", severity="info", evidence={"skipped": "no commits"}, passed=True),
            Finding(check_name=CHECK_PARENT_MONOTONICITY, plane="claim", severity="info", evidence={"skipped": "no commits"}, passed=True),
            Finding(check_name=CHECK_TIMEZONE_CONSISTENCY, plane="claim", severity="info", evidence={"skipped": "no commits"}, passed=True),
            Finding(check_name=CHECK_AUTHOR_COMMITTER_SPREAD, plane="claim", severity="info", evidence={"skipped": "no commits"}, passed=True),
            Finding(check_name=CHECK_INTERVAL_QUANTIZATION, plane="claim", severity="info", evidence={"skipped": "no commits"}, passed=True),
            Finding(check_name=CHECK_DIFF_CHURN, plane="claim", severity="info", evidence={"skipped": "no commits"}, passed=True),
        ]

    commits = _get_commit_history(repo_path)

    return [
        check_build_window(commits),
        check_parent_monotonicity(commits),
        check_timezone_consistency(commits),
        check_author_committer_spread(commits),
        check_interval_quantization(commits),
        check_diff_churn(repo_path, commits),
    ]
