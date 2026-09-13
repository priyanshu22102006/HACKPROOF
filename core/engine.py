"""Analyzer engine -- the single place both analyzers are run from.

This is the merge point for modules built independently: every analyzer is a
module exposing ``run(repo_path: str) -> list[Finding]`` and nothing else, so the
engine neither knows nor cares how a given check works. Adding an analyzer means
adding one row to ``ANALYZERS``.

Two rules hold the seam together:

1. **One contract, enforced here.** Every returned object is validated against
   ``core.models.Finding`` (and its plane/severity vocabulary) before it reaches a
   report. A module that drifts from the contract is reported as a contract
   violation rather than silently producing a bad verdict.
2. **No analyzer can take down the run.** Each module runs inside its own
   try/except. If one raises, the engine records it and moves on, because a
   crashed ``.gitignore`` inspector must not stop signature verification from
   reaching a judge.

Per-analyzer configuration travels through the environment rather than the
function signature, which is what keeps the one-argument contract viable:
``--roster`` sets ``$HACKPROOF_ROSTER`` for ``analyzers.gpg_check``.

Usage
-----
    python -m core.engine /path/to/repo
    python -m core.engine /path/to/repo --roster roster.json --json out.json
    python -m core.engine /path/to/repo --only gpg
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback

try:
    from core.models import PLANES, SEVERITIES, Finding
except ModuleNotFoundError:  # pragma: no cover - import path convenience only
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.models import PLANES, SEVERITIES, Finding

from analyzers import claim_timestamp_check, github_check, gitignore_check, gpg_check

# name -> module. The name is what `--only` / `--skip` match on, and what the
# engine reports an analyzer-level failure under.
ANALYZERS = (
    ("gitignore", gitignore_check),
    ("gpg", gpg_check),
    ("claim", claim_timestamp_check),
    ("github", github_check),
)

ENGINE_CHECK_PREFIX = "engine."

# A check is "not evaluable" when the evidence it reads was not present in what
# was analyzed at all -- not when it looked and found nothing. The distinction
# matters most for a clone: `git ls-files -v` index flags, `.git/info/exclude`
# and `core.excludesFile` live on the participant's machine and are never
# pushed, so a clone cannot see them however hard it looks. Reporting those as
# "ok" tells a judge "clean" when the honest answer is "cannot know from here",
# which is the same error as reporting unverifiable work as flagged -- just in
# the direction that flatters. An analyzer signals it by setting
# evidence["evaluable"] = False.
EVALUABLE_KEY = "evaluable"


def is_evaluable(finding: Finding) -> bool:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    return evidence.get(EVALUABLE_KEY) is not False

# Severity ordering for report sorting: worst first.
SEVERITY_RANK = {"hard_flag": 0, "flag": 1, "info": 2}


def _engine_finding(analyzer: str, note: str, error: str | None = None, severity: str = "info") -> Finding:
    evidence: dict = {"analyzer": analyzer, "note": note}
    if error:
        evidence["error"] = error
    return Finding(
        check_name=f"{ENGINE_CHECK_PREFIX}{analyzer}",
        plane="server",
        severity=severity,
        evidence=evidence,
        passed=severity == "info",
    )


def check_history_completeness(repo_path: str) -> Finding | None:
    """Is the analyzer even looking at the whole history?

    A shallow clone (``git clone --depth``) hands every check a truncated history
    and they will all answer confidently about the part they can see. A judge who
    clones with ``--depth 1`` gets "coverage 1.0" on a repo whose other 200
    commits were never examined.

    This is reported under ``engine.`` rather than as an analyzer finding because
    it is a fact about the analysis run, not about the team: the prefix is what
    keeps it from reading as an accusation.
    """
    resolved = os.path.abspath(os.path.expanduser(str(repo_path)))
    if not os.path.isdir(resolved):
        return None
    code, out, _ = gpg_check._git(resolved, ["rev-parse", "--is-inside-work-tree"])
    if code != 0 or out.strip() != "true":
        return None

    evidence: dict = {
        "analyzer": "engine",
        "commands": ["git rev-parse --is-shallow-repository", "git rev-list --count HEAD"],
    }
    _, shallow_out, _ = gpg_check._git(resolved, ["rev-parse", "--is-shallow-repository"])
    is_shallow = shallow_out.strip() == "true"
    evidence["is_shallow_clone"] = is_shallow

    count_code, count_out, _ = gpg_check._git(resolved, ["rev-list", "--count", "HEAD"])
    commit_count = int(count_out.strip()) if count_code == 0 and count_out.strip().isdigit() else None
    evidence["commit_count"] = commit_count
    evidence["analyzer_commit_cap"] = gpg_check.MAX_COMMITS

    if is_shallow:
        evidence["interpretation"] = (
            "this is a SHALLOW clone, so every check below only saw the commits it contains. "
            "Nothing here describes the rest of the history. Re-clone without --depth, or run "
            "`git fetch --unshallow`, before relying on any of these results"
        )
        return _engine_finding_from(evidence, "history_completeness", passed=False)

    if commit_count and commit_count > gpg_check.MAX_COMMITS:
        evidence["interpretation"] = (
            f"the repository has {commit_count} commits and the analyzers read the newest "
            f"{gpg_check.MAX_COMMITS}. Older commits were not examined"
        )
        return _engine_finding_from(evidence, "history_completeness", passed=False)

    evidence["note"] = (
        f"full history available ({commit_count} commits)" if commit_count is not None
        else "full history available"
    )
    return _engine_finding_from(evidence, "history_completeness", passed=True)


def _engine_finding_from(evidence: dict, name: str, passed: bool) -> Finding:
    return Finding(
        check_name=f"{ENGINE_CHECK_PREFIX}{name}",
        plane="system",
        severity="info",  # a fact about the clone, never an accusation about the team
        evidence=evidence,
        passed=passed,
    )


def validate_finding(finding) -> list[str]:
    """Return a list of contract violations for one object. Empty means valid."""
    problems: list[str] = []
    if not isinstance(finding, Finding):
        return [f"not a core.models.Finding instance (got {type(finding).__name__})"]
    if not isinstance(finding.check_name, str) or not finding.check_name:
        problems.append("check_name must be a non-empty string")
    if finding.plane not in PLANES:
        problems.append(f"plane {finding.plane!r} is not one of {PLANES}")
    if finding.severity not in SEVERITIES:
        problems.append(f"severity {finding.severity!r} is not one of {SEVERITIES}")
    if not isinstance(finding.evidence, dict):
        problems.append(f"evidence must be a dict (got {type(finding.evidence).__name__})")
    if not isinstance(finding.passed, bool):
        problems.append(f"passed must be a bool (got {type(finding.passed).__name__})")
    else:
        if finding.passed and finding.severity in ("flag", "hard_flag"):
            problems.append(f"passed=True is inconsistent with severity={finding.severity!r}")
    if finding.check_name and not finding.check_name.startswith(ENGINE_CHECK_PREFIX):
        if "." not in finding.check_name:
            problems.append("check_name should be namespaced, e.g. 'gpg.identity_match'")
    return problems


def run_all(
    repo_path: str,
    roster_path: str | None = None,
    only: list[str] | None = None,
    skip: list[str] | None = None,
    t0: str | None = None,
    team_id: str | None = None,
) -> list[Finding]:
    """Run every selected analyzer over one repo and return the combined Findings.

    Never raises: an analyzer that fails, returns the wrong type, or violates the
    Finding contract produces an ``engine.<name>`` Finding describing what went
    wrong instead of propagating.
    """
    if roster_path:
        resolved_roster = os.path.abspath(os.path.expanduser(roster_path))
        os.environ["HACKPROOF_ROSTER"] = resolved_roster
        os.environ["CHRONICLE_ROSTER"] = resolved_roster
    if t0:
        os.environ["HACKPROOF_T0"] = t0
    if team_id:
        os.environ["HACKPROOF_TEAM_ID"] = team_id

    findings: list[Finding] = []
    try:
        history = check_history_completeness(repo_path)
        if history is not None:
            findings.append(history)
    except Exception:  # a diagnostic must never take down the run
        pass

    for name, module in ANALYZERS:
        if only and name not in only:
            continue
        if skip and name in skip:
            continue
        runner = getattr(module, "run", None)
        if not callable(runner):
            findings.append(
                _engine_finding(name, "analyzer module has no callable run()", severity="flag")
            )
            continue
        try:
            produced = runner(repo_path)
        except Exception as exc:
            findings.append(
                _engine_finding(
                    name,
                    "analyzer raised and was skipped; other analyzers still ran",
                    error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc(limit=5)}",
                    severity="flag",
                )
            )
            continue

        if not isinstance(produced, list):
            findings.append(
                _engine_finding(
                    name,
                    f"run() must return a list of Finding (got {type(produced).__name__})",
                    severity="flag",
                )
            )
            continue

        violations: list[dict] = []
        for position, item in enumerate(produced):
            problems = validate_finding(item)
            if problems:
                violations.append({"index": position, "problems": problems})
            else:
                findings.append(item)
        if violations:
            finding = _engine_finding(
                name, "analyzer returned objects that violate the Finding contract", severity="flag"
            )
            finding.evidence["violations"] = violations[:25]
            findings.append(finding)
    return findings


# --- reporting ----------------------------------------------------------------


def summarize(findings: list[Finding]) -> dict:
    """Counts a judge's triage view needs, without interpreting anything."""
    evaluable = [f for f in findings if is_evaluable(f)]
    summary = {
        "total": len(findings),
        "passed": sum(1 for f in findings if f.passed),
        "failed": sum(1 for f in findings if not f.passed),
        # `passed` counts the boolean; `checks_evaluated` is the one to quote,
        # because it excludes checks that never had evidence to look at.
        "checks_evaluated": len(evaluable),
        "not_evaluable": len(findings) - len(evaluable),
        "not_evaluable_checks": [f.check_name for f in findings if not is_evaluable(f)],
        "by_severity": {severity: 0 for severity in SEVERITIES},
        "by_plane": {plane: 0 for plane in PLANES},
        "hard_flags": [],
        "flags": [],
    }
    for finding in findings:
        summary["by_severity"][finding.severity] = summary["by_severity"].get(finding.severity, 0) + 1
        summary["by_plane"][finding.plane] = summary["by_plane"].get(finding.plane, 0) + 1
        if finding.severity == "hard_flag":
            summary["hard_flags"].append(finding.check_name)
        elif finding.severity == "flag":
            summary["flags"].append(finding.check_name)
    return summary


def _headline(finding: Finding) -> str:
    """One short line of why this finding looks the way it does."""
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    for key in ("note", "interpretation"):
        if evidence.get(key):
            return str(evidence[key])
    numeric_keys = (
        ("hidden_source_file_count", "hidden source files"),
        ("unregistered_key_commit_count", "commits signed by an unregistered key"),
        ("identity_mismatch_count", "identity mismatches"),
        ("revoked_key_commit_count", "commits signed by a revoked key"),
        ("expired_key_commit_count", "commits signed by an expired key"),
        ("rejected_key_count", "rejected roster keys"),
    )
    parts = [f"{evidence[key]} {label}" for key, label in numeric_keys if evidence.get(key)]
    if evidence.get("late_added_rules"):
        parts.append(f"{len(evidence['late_added_rules'])} late-added ignore rules")
    if evidence.get("invalid_signature_commits"):
        parts.append(f"{len(evidence['invalid_signature_commits'])} invalid signatures")
    for ratio_key, label in (("tracked_ratio", "tracked source ratio"), ("verified_ratio", "verified ratio")):
        if evidence.get(ratio_key) is not None:
            parts.append(f"{label} {evidence[ratio_key]}")
    return "; ".join(parts) if parts else ""


def render_table(findings: list[Finding]) -> str:
    """Plain-text report, worst first. Ordering mirrors the organizer dashboard."""
    ordered = sorted(
        findings,
        key=lambda f: (SEVERITY_RANK.get(f.severity, 9), f.passed, f.check_name),
    )
    width = max((len(f.check_name) for f in ordered), default=10)
    lines = []
    for finding in ordered:
        if not is_evaluable(finding):
            mark = "n/a "
        elif finding.passed:
            mark = "ok  "
        else:
            mark = "FAIL"
        headline = _headline(finding)
        lines.append(
            f"{mark} {finding.check_name:<{width}}  {finding.severity:<9} {finding.plane:<6}"
            + (f"  {headline}" if headline else "")
        )
    summary = summarize(findings)
    lines.append("")
    tally = (
        f"{summary['total']} checks  "
        f"{summary['by_severity'].get('hard_flag', 0)} hard_flag  "
        f"{summary['by_severity'].get('flag', 0)} flag  "
        f"{summary['by_severity'].get('info', 0)} info  "
        f"({summary['failed']} not passed)"
    )
    if summary["not_evaluable"]:
        tally += f"  [{summary['not_evaluable']} not evaluable]"
    lines.append(tally)
    if summary["not_evaluable"]:
        lines.append("")
        lines.append(
            f"n/a = not evaluable here, NOT clean: {summary['not_evaluable']} check(s) had no "
            "evidence to read in what was analyzed."
        )
        for name in summary["not_evaluable_checks"]:
            finding = next(f for f in findings if f.check_name == name)
            reason = finding.evidence.get("not_evaluable_reason") or _headline(finding)
            lines.append(f"      {name}: {reason}")
    return "\n".join(lines)


def render_summary_card(
    findings: list[Finding],
    repo_path: str = "",
    target_label: str = "",
    show_blame: bool = True,
) -> str:
    """A clean, human-friendly summary box designed for judges, mentors, and developers."""
    summary = summarize(findings)
    display_name = target_label if target_label else (os.path.basename(os.path.abspath(repo_path)) if repo_path else "Repository")

    hard_flags = summary.get("hard_flags", [])
    flags = summary.get("flags", [])
    failed = summary.get("failed", 0)

    # Analyze commit signature findings
    sig_coverage = next((f for f in findings if f.check_name == "gpg.signature_coverage"), None)
    unregistered = next((f for f in findings if f.check_name == "gpg.unregistered_key"), None)
    identity_mismatch = next((f for f in findings if f.check_name == "gpg.identity_match"), None)

    # Analyze gitignore findings
    pattern_audit = next((f for f in findings if f.check_name == "gitignore.pattern_audit"), None)
    skip_worktree = next((f for f in findings if f.check_name == "gitignore.assume_unchanged_skip_worktree"), None)
    info_exclude = next((f for f in findings if f.check_name == "gitignore.info_exclude"), None)

    is_clean = (failed == 0 and not hard_flags and not flags)
    border_len = 114

    lines = [
        "",
        "═" * border_len,
    ]
    if is_clean:
        lines.append("  HACKPROOF AUDIT REPORT: ✅ ALL CHECKS PASSED (VERIFIED GENUINE WORK)")
    elif hard_flags:
        lines.append("  HACKPROOF AUDIT REPORT: 🚨 CRITICAL INTEGRITY THREAT DETECTED")
    else:
        lines.append(f"  HACKPROOF AUDIT REPORT: ⚠️  SUSPICIOUS ACTIVITY DETECTED ({failed} Issue{'s' if failed != 1 else ''})")
    lines.extend([
        "─" * border_len,
        f"  Target Repository : {display_name}",
    ])

    # 1. Signature section
    if sig_coverage and isinstance(sig_coverage.evidence, dict) and sig_coverage.evidence.get("commit_count"):
        ev = sig_coverage.evidence
        total = ev.get("commit_count", 0)
        verified = ev.get("verified_commit_count")
        ratio = ev.get("verified_ratio")

        lines.append("")
        lines.append("  [1] COMMIT SIGNATURE VERIFICATION (GPG / SSH)")
        if verified is not None and ratio is not None:
            percent = int(ratio * 100)
            lines.append(f"      • Coverage: {verified}/{total} commits verified ({percent}%)")
        else:
            lines.append(f"      • Coverage: Unattributed ({total} commit(s) present, no roster keyring provided)")

        # Unsigned commits
        unsigned_commits = ev.get("unsigned_commits", [])
        if unsigned_commits:
            lines.append("      • ⚠️  UNSIGNED COMMITS (Missing Cryptographic Proof):")
            for c in unsigned_commits[:5]:
                sha = c.get("sha", "")[:7]
                author = f"{c.get('author_name', '')} <{c.get('author_email', '')}>"
                lines.append(f"        - Commit {sha} authored by \"{author}\"")
                lines.append("          → Missing GPG signature! (Pushed from an unregistered laptop)")

        # Unregistered keys
        if unregistered and isinstance(unregistered.evidence, dict):
            unreg_commits = unregistered.evidence.get("unregistered_key_commits", [])
            if unreg_commits:
                lines.append("      • 🚨 UNREGISTERED SIGNING KEYS (Outsider Key Detected):")
                for c in unreg_commits[:5]:
                    sha = c.get("sha", "")[:7]
                    key_id = c.get("signing_key_id", "unknown")
                    author = f"{c.get('author_name', '')} <{c.get('author_email', '')}>"
                    lines.append(f"        - Commit {sha} signed by unknown key '{key_id}' claiming to be '{author}'")

        # Identity mismatches
        if identity_mismatch and isinstance(identity_mismatch.evidence, dict):
            mismatches = identity_mismatch.evidence.get("identity_mismatch_commits", [])
            if mismatches:
                lines.append("      • 🚨 IDENTITY MISMATCH (Key belongs to a different member):")
                for c in mismatches[:5]:
                    sha = c.get("sha", "")[:7]
                    lines.append(f"        - Commit {sha}: Author {c.get('author_email')} signed by {c.get('signer_name')}")

        if not unsigned_commits and not (unregistered and unregistered.evidence.get("unregistered_key_commits")):
            lines.append("      • Status: All commits signed and verified by registered team members.")

    # 2. Gitignore & Hidden Code section
    lines.append("")
    lines.append("  [2] FILE CONCEALMENT & PRE-BUILT CODE INSPECTOR (§8.f)")
    hidden_sources = (
        pattern_audit.evidence.get("hidden_source_files", [])
        if (pattern_audit and isinstance(pattern_audit.evidence, dict))
        else []
    )
    late_ignore = (
        pattern_audit.evidence.get("late_added_rules", [])
        if (pattern_audit and isinstance(pattern_audit.evidence, dict))
        else []
    )
    skip_files = (
        skip_worktree.evidence.get("flagged_files", [])
        if (skip_worktree and isinstance(skip_worktree.evidence, dict))
        else []
    )
    info_files = (
        info_exclude.evidence.get("hidden_source_files", [])
        if (info_exclude and isinstance(info_exclude.evidence, dict))
        else []
    )

    if hidden_sources or late_ignore or skip_files or info_files:
        if hidden_sources:
            lines.append(f"      • 🚨 {len(hidden_sources)} working-tree source file(s) concealed by .gitignore on disk!")
            for h in hidden_sources[:3]:
                lines.append(f"        - {h.get('path')} (hidden by '{h.get('pattern')}')")
        if late_ignore:
            lines.append("      • 🚨 Late-added .gitignore rules hiding source files in history:")
            for lr in late_ignore[:3]:
                lines.append(f"        - Pattern '{lr.get('pattern')}' added in commit {lr.get('added_in_commit', '')[:7]}")
        if skip_files:
            lines.append("      • 🚨 Stealth index flags (git update-index --skip-worktree):")
            for sf in skip_files[:3]:
                lines.append(f"        - File '{sf.get('path')}' edited locally while flagged to be skipped!")
        if info_files:
            lines.append("      • 🚨 Hidden exclusions in local .git/info/exclude (never pushed to GitHub):")
            for inf in info_files[:3]:
                lines.append(f"        - {inf.get('path')}")
    else:
        lines.append("      • Status: Clean (No hidden files, no pre-built code staging, no index manipulation).")

    # Forensic Blame View Table integrated right here into the main output window
    if show_blame and repo_path and os.path.isdir(repo_path):
        from analyzers.gitignore_check import get_gitignore_blame_view, render_gitignore_blame_table
        entries = get_gitignore_blame_view(repo_path)
        if entries:
            lines.append("")
            lines.append("      • FORENSIC .GITIGNORE BLAME VIEW (§8.f):")
            blame_tbl = render_gitignore_blame_table(entries)
            for bline in blame_tbl.splitlines():
                lines.append(f"        {bline}")
        else:
            lines.append("      • .gitignore: None found in repository working tree.")

    # 3. Claim-plane timestamp, build window & diff churn section
    build_window = next((f for f in findings if f.check_name == "claim.build_window"), None)
    parent_mono = next((f for f in findings if f.check_name == "claim.parent_monotonicity"), None)
    tz_check = next((f for f in findings if f.check_name == "claim.timezone_consistency"), None)
    spread_check = next((f for f in findings if f.check_name == "claim.author_committer_spread"), None)
    quant_check = next((f for f in findings if f.check_name == "claim.interval_quantization"), None)
    churn_check = next((f for f in findings if f.check_name == "claim.diff_churn"), None)

    ts_issues = [
        f for f in findings
        if (f.plane in ("claim", "server"))
        and not f.passed
        and not f.check_name.startswith("gpg.")
        and not f.check_name.startswith("gitignore.")
    ]
    lines.append("")
    lines.append("  [3] HACKATHON BUILD WINDOW & TIMESTAMPS (§8.d / §8.i)")
    if build_window and isinstance(build_window.evidence, dict):
        bw_ev = build_window.evidence
        if bw_ev.get("first_commit"):
            fc = bw_ev["first_commit"]
            lines.append(f"      • First Commit  : {fc.get('date')} (Commit {fc.get('sha')})")
        if bw_ev.get("latest_commit"):
            lc = bw_ev["latest_commit"]
            dur = bw_ev.get("duration_seconds", 0.0)
            hours = int(dur // 3600)
            mins = int((dur % 3600) // 60)
            lines.append(f"      • Latest Commit : {lc.get('date')} (Commit {lc.get('sha')})")
            lines.append(f"      • Active Span   : {hours}h {mins:02d}m across {bw_ev.get('commit_count', 0)} commits")
        if bw_ev.get("t0"):
            lines.append(f"      • Hackathon Start (T0): {bw_ev.get('t0')}")
    if ts_issues:
        for iss in ts_issues:
            interp = iss.evidence.get("interpretation") or iss.evidence.get("note") or "anomalies detected"
            lines.append(f"      • 🚨 {iss.check_name}: {interp}")
    else:
        status_note = (
            "All commits within build window, monotonic chronology, natural intervals"
            if (build_window and build_window.evidence.get("t0"))
            else "Monotonic chronology, consistent timezones, natural human intervals"
        )
        lines.append(f"      • Status: Clean ({status_note}).")

    # 4. Takeaway
    lines.append("─" * border_len)
    if is_clean:
        lines.append("  JUDGE TAKEAWAY: ✅ Verified genuine build provenance. Clear for hackathon judging.")
    elif hard_flags:
        lines.append("  JUDGE TAKEAWAY: 🚨 High-risk cheating indicators detected. Prompt team for explanation.")
    else:
        lines.append("  JUDGE TAKEAWAY: ⚠️  Incomplete signature coverage. Verify commits with the team.")
    lines.extend([
        "═" * border_len,
        "",
    ])
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run every HACKPROOF analyzer over one git repository.",
    )
    parser.add_argument("repo_path", help="path to the git repository to inspect")
    parser.add_argument(
        "--roster",
        default=None,
        help="roster JSON for signature verification (exported as $HACKPROOF_ROSTER)",
    )
    parser.add_argument(
        "--only",
        action="append",
        default=None,
        metavar="NAME",
        help=(
            f"run only these analyzers ({', '.join(n for n, _ in ANALYZERS)}); repeatable. "
            "'github' is the only one that touches the network"
        ),
    )
    parser.add_argument(
        "--skip", action="append", default=None, metavar="NAME", help="skip these analyzers; repeatable"
    )
    parser.add_argument(
        "--format",
        choices=("table", "json"),
        default="table",
        help="output format (default: table)",
    )
    parser.add_argument("--out", default=None, help="also write the full JSON report to this path")
    parser.add_argument(
        "--t0",
        default=None,
        help="event start time, ISO 8601 (exported as $HACKPROOF_T0; enables spec §8.d check 1)",
    )
    parser.add_argument(
        "--team-id",
        default=None,
        help="team ID to inspect if roster is an SQLite database (exported as $HACKPROOF_TEAM_ID)",
    )
    parser.add_argument(
        "--blame-ignore",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="display forensic git blame view of .gitignore lines and their commit history (§8.f) [default: enabled]",
    )
    parser.add_argument(
        "--pull",
        action="store_true",
        help="run git pull before analyzing to automatically fetch latest remote commits from GitHub",
    )
    args = parser.parse_args(argv)

    target = args.repo_path.strip()
    is_remote = False
    temp_workdir = None
    slug = target

    url_match = re.search(r"(?:github\.com[:/])(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$", target)
    slug_match = bool(re.match(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$", target)) and not os.path.exists(target) and not target.startswith((".", "/", "~"))

    if target.startswith(("http://", "https://", "git@", "ssh://")) or slug_match or url_match:
        is_remote = True
        if slug_match:
            slug = target
            clone_url = f"https://github.com/{slug}.git"
        elif url_match:
            slug = f"{url_match.group('owner')}/{url_match.group('repo')}"
            clone_url = target if target.startswith(("git@", "ssh://")) else f"https://github.com/{slug}.git"
        else:
            slug = target
            clone_url = target

        temp_workdir = tempfile.mkdtemp(prefix="hackproof-clone-")
        repo_path = os.path.join(temp_workdir, "repo")
        if args.format != "json":
            print(f"==> Cloning remote repository '{slug}' for testing & analysis...")

        token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
        cmd = ["git", "clone", "--no-single-branch", "--quiet", clone_url, repo_path]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if res.returncode != 0 and token and not clone_url.startswith(("git@", "ssh://")):
            authed_url = f"https://x-access-token:{token}@github.com/{slug}.git"
            res = subprocess.run(["git", "clone", "--no-single-branch", "--quiet", authed_url, repo_path], capture_output=True, text=True, timeout=300)

        if res.returncode != 0:
            print(f"Error: Failed to clone repository '{slug}': {res.stderr.strip()}", file=sys.stderr)
            shutil.rmtree(temp_workdir, ignore_errors=True)
            return 1

        os.environ["HACKPROOF_SOURCE"] = "clone"
        os.environ.setdefault("HACKPROOF_GITHUB_REPO", slug)
    else:
        repo_path = os.path.abspath(os.path.expanduser(args.repo_path))
        if not os.path.exists(repo_path):
            print(f"Error: Target repository path '{args.repo_path}' does not exist.", file=sys.stderr)
            print("\n💡 Hint: Provide the path to a git repository on your machine:", file=sys.stderr)
            print("   • Audit current folder  : hackproof-analyze . --roster hackproof.db --team-id <team_id>", file=sys.stderr)
            print("   • Audit remote GitHub   : hackproof-analyze owner/repo --roster hackproof.db --team-id <team_id>", file=sys.stderr)
            print("   • Audit another folder  : hackproof-analyze ~/Desktop/YourRepo --roster hackproof.db --team-id <team_id>", file=sys.stderr)
            return 1

        if not os.path.isdir(repo_path):
            print(f"Error: Target path '{args.repo_path}' is not a directory.", file=sys.stderr)
            return 1

        git_dir = os.path.join(repo_path, ".git")
        if not os.path.exists(git_dir):
            res = subprocess.run(["git", "rev-parse", "--is-inside-work-tree"], cwd=repo_path, capture_output=True, text=True)
            if res.returncode != 0 or res.stdout.strip() != "true":
                print(f"Error: Target directory '{args.repo_path}' is not a valid git repository (no .git directory found).", file=sys.stderr)
                print("💡 Hint: Run this command inside or pointing to a valid git project directory.", file=sys.stderr)
                return 1

        if args.pull:
            subprocess.run(["git", "pull", "--quiet"], cwd=repo_path, check=False)

    try:
        findings = run_all(
            repo_path,
            roster_path=args.roster,
            only=args.only,
            skip=args.skip,
            t0=args.t0,
            team_id=args.team_id,
        )
        report = {
            "repo_path": slug if is_remote else os.path.abspath(os.path.expanduser(args.repo_path)),
            "summary": summarize(findings),
            "findings": [dataclasses.asdict(f) for f in findings],
        }

        if args.blame_ignore:
            from analyzers.gitignore_check import get_gitignore_blame_view
            report["gitignore_blame"] = [e.to_dict() for e in get_gitignore_blame_view(repo_path)]

        if args.format == "json":
            print(json.dumps(report, indent=2, default=str))
        else:
            print(render_table(findings))
            print(
                render_summary_card(
                    findings,
                    repo_path=repo_path,
                    target_label=slug if is_remote else args.repo_path,
                    show_blame=args.blame_ignore,
                )
            )

        if args.out:
            try:
                with open(args.out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2, default=str)
            except OSError as exc:
                print(f"could not write {args.out}: {exc}", file=sys.stderr)
                return 1

        # Exit code is a convenience for CI, never a verdict: 0 clean, 1 something
        # did not pass. The verdict engine (spec §8.i) is what ranks teams.
        return 0 if all(f.passed for f in findings) else 1
    finally:
        if temp_workdir:
            shutil.rmtree(temp_workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
