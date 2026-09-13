#!/usr/bin/env python3
"""Paste a GitHub repo, get a provenance report.

    python3 scripts/analyze_repo_url.py https://github.com/team-07/project \
        --roster roster.json --t0 2026-09-12T09:00:00Z

Clones the repository into a throwaway directory, runs every analyzer over it,
prints the report, and deletes the clone. Accepts any of:

    https://github.com/owner/repo        git@github.com:owner/repo.git
    https://github.com/owner/repo.git    owner/repo

**What a clone can and cannot tell you.** This matters more than anything else
about this script, so it is printed in the report too, not just documented here.

Signatures travel with commits, so the whole identity half of spec §8.e works
perfectly from a clone: a commit signed by a key that is not on the roster is
found here exactly as it would be on the author's own laptop. That is the
"did someone outside the team push code" question, and a clone answers it.

The hiding half of §8.f largely does not survive. Three of its four mechanisms
are *system plane* -- the skip-worktree bits, `.git/info/exclude`, and
`core.excludesFile` all live on the participant's machine and are never pushed --
and the tracked-vs-disk ratio compares two sets that a clone makes identical by
construction. Those checks report ``n/a`` here rather than ``ok``, because a
check that never ran must not read as a clean bill of health. What *does* survive
is the committed ``.gitignore`` and its full history, so a rule added to hide a
directory is still visible.

Private repositories clone with whatever git credentials you already have. If
that fails and ``GITHUB_TOKEN`` is set, the clone is retried with the token; it
is never printed, and is scrubbed from any error text.
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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import render_table, run_all, summarize  # noqa: E402

SLUG_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")
URL_RE = re.compile(
    r"(?:github\.com[:/])(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$"
)
CLONE_TIMEOUT = 600


class AnalyzeError(RuntimeError):
    pass


def scrub(text: str, *secrets: str) -> str:
    for secret in secrets:
        if secret:
            text = text.replace(secret, "***")
    return text


def parse_target(target: str) -> tuple[str, str]:
    """(slug, clone_url). Accepts a slug, an https URL, or an ssh remote."""
    target = target.strip()
    if SLUG_RE.match(target) and "github.com" not in target:
        return target, f"https://github.com/{target}.git"
    match = URL_RE.search(target)
    if not match:
        raise AnalyzeError(
            f"could not read a GitHub repository out of {target!r}. "
            "Use https://github.com/owner/repo, git@github.com:owner/repo.git, or owner/repo"
        )
    slug = f"{match.group('owner')}/{match.group('repo')}"
    # Keep an ssh remote as-is so an ssh-agent key is used; otherwise https.
    clone_url = target if target.startswith(("git@", "ssh://")) else f"https://github.com/{slug}.git"
    return slug, clone_url


def git(args: list[str], cwd: str | None = None, timeout: int = 60) -> tuple[int, str, str]:
    proc = subprocess.run(
        ["git", *args],
        cwd=cwd,
        env={**os.environ, "LC_ALL": "C", "GIT_TERMINAL_PROMPT": "0"},
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=timeout,
    )
    return proc.returncode, proc.stdout.decode("utf-8", "replace"), proc.stderr.decode("utf-8", "replace")


def clone(clone_url: str, slug: str, into: str, branch: str | None) -> None:
    """Full history, every branch. Never shallow -- see engine.history_completeness."""
    args = ["clone", "--no-single-branch", "--quiet"]
    if branch:
        args += ["--branch", branch]
    code, _, err = git([*args, clone_url, into], timeout=CLONE_TIMEOUT)
    if code == 0:
        return

    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if not token or clone_url.startswith(("git@", "ssh://")):
        raise AnalyzeError(
            f"could not clone {slug}: {scrub(err.strip(), token)}\n"
            "For a private repo, either set GITHUB_TOKEN or make sure your git credentials "
            "(ssh key / credential helper) can reach it."
        )

    shutil.rmtree(into, ignore_errors=True)
    authed = f"https://x-access-token:{token}@github.com/{slug}.git"
    code, _, err = git([*args, authed, into], timeout=CLONE_TIMEOUT)
    if code != 0:
        raise AnalyzeError(f"could not clone {slug} with GITHUB_TOKEN either: {scrub(err.strip(), token)}")
    # Leave no credential behind in the clone's config, even though it is a temp dir.
    git(["remote", "set-url", "origin", f"https://github.com/{slug}.git"], cwd=into)


def describe(repo: str) -> dict:
    """What was actually analyzed, so the report can say so for itself."""
    def one(args, default=""):
        code, out, _ = git(args, cwd=repo)
        return out.strip() if code == 0 else default

    head_count = one(["rev-list", "--count", "HEAD"], "0")
    all_count = one(["rev-list", "--count", "--all"], "0")
    branches = [
        b.strip().replace("origin/", "", 1)
        for b in one(["branch", "-r", "--format=%(refname:short)"]).splitlines()
        if b.strip() and "HEAD ->" not in b and b.strip() != "origin/HEAD"
    ]
    info = {
        "default_branch": one(["rev-parse", "--abbrev-ref", "HEAD"]),
        "head_sha": one(["rev-parse", "HEAD"]),
        "commits_on_analyzed_branch": int(head_count) if head_count.isdigit() else None,
        "commits_on_all_branches": int(all_count) if all_count.isdigit() else None,
        "branches": branches,
    }
    if info["commits_on_all_branches"] and info["commits_on_analyzed_branch"] is not None:
        info["commits_not_on_analyzed_branch"] = (
            info["commits_on_all_branches"] - info["commits_on_analyzed_branch"]
        )
    return info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Clone a GitHub repository and run every HACKPROOF analyzer over it.",
    )
    parser.add_argument("target", help="https URL, ssh remote, or owner/repo")
    parser.add_argument("--roster", default=None, help="roster JSON (required to attribute signatures)")
    parser.add_argument("--t0", default=None, help="event start, ISO 8601 (spec §8.d check 1)")
    parser.add_argument("--branch", default=None, help="analyze this branch instead of the default")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    parser.add_argument("--out", default=None, help="also write the full JSON report here")
    parser.add_argument("--keep", action="store_true", help="keep the clone and print its path")
    parser.add_argument("--skip", action="append", default=None, metavar="NAME")
    parser.add_argument("--only", action="append", default=None, metavar="NAME")
    args = parser.parse_args(argv)

    try:
        slug, clone_url = parse_target(args.target)
    except AnalyzeError as exc:
        print(f"{exc}", file=sys.stderr)
        return 2

    workdir = tempfile.mkdtemp(prefix="hackproof-clone-")
    repo = os.path.join(workdir, "repo")
    try:
        if args.format == "table":
            print(f"==> cloning {slug}")
        try:
            clone(clone_url, slug, repo, args.branch)
        except AnalyzeError as exc:
            print(f"{exc}", file=sys.stderr)
            return 2

        info = describe(repo)

        # Two facts the analyzers need, passed the way every other bit of
        # per-analyzer config travels: through the environment.
        os.environ["HACKPROOF_SOURCE"] = "clone"
        os.environ.setdefault("HACKPROOF_GITHUB_REPO", slug)

        findings = run_all(
            repo, roster_path=args.roster, only=args.only, skip=args.skip, t0=args.t0
        )
        summary = summarize(findings)
        report = {
            "repo": slug,
            "analyzed": info,
            "analysis_source": "clone",
            "roster": os.path.abspath(os.path.expanduser(args.roster)) if args.roster else None,
            "summary": summary,
            "findings": [dataclasses.asdict(f) for f in findings],
        }

        if args.format == "json":
            print(json.dumps(report, indent=2, default=str))
        else:
            print(f"    {info['commits_on_analyzed_branch']} commits on "
                  f"{info['default_branch']} @ {info['head_sha'][:8]}")
            if info.get("commits_not_on_analyzed_branch"):
                print(
                    f"    note: {info['commits_not_on_analyzed_branch']} commit(s) exist on other "
                    f"branches and were NOT analyzed. Branches: {', '.join(info['branches'])}"
                )
                print("          re-run with --branch <name> to analyze one of them")
            if not args.roster:
                print(
                    "    note: no --roster given, so signatures cannot be attributed to anyone. "
                    "Every identity check degrades to info"
                )
            print()
            print(render_table(findings))

        if args.out:
            try:
                with open(args.out, "w", encoding="utf-8") as handle:
                    json.dump(report, handle, indent=2, default=str)
                if args.format == "table":
                    print(f"\nfull evidence written to {args.out}")
            except OSError as exc:
                print(f"could not write {args.out}: {exc}", file=sys.stderr)
                return 1

        return 0 if all(f.passed for f in findings) else 1
    finally:
        if args.keep:
            print(f"\nclone kept at {repo}")
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
