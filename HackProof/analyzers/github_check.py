"""GitHub cross-check -- spec §8.e check 2, plus the repo-metadata half of §8.d.

HACKPROOF's local roster verification (``analyzers/gpg_check.py``) is the
stronger evidence, and §8.e check 1 is explicit that GitHub's own "Verified"
badge must never be trusted alone. This module does not replace that verdict --
it asks a second, independently-controlled source the same question and reports
where the two answers *disagree*, which is the three-plane model (§4) applied to
signatures: the claim plane says one thing, the server plane says another, and
the disagreement is the evidence.

Three checks:

``github.repo_metadata``      spec §8.d check 1 -- repo created before T0, forks
``github.signature_crosscheck`` spec §8.e check 2 -- GitHub's verdict vs ours
``github.author_login_match`` closes the gap the GPG module documents as a known
                              limit: locally a commit carries only an author
                              email, so a participant committing under an
                              unregistered personal address reads as UNKNOWN.
                              GitHub resolves that commit to an actual account.

What disagreement means, and what it does not
---------------------------------------------
The expensive failure mode here is a false positive against an honest team, and
there is one very common benign disagreement: a participant registers a key with
the organizer but never uploads it to their GitHub account. HACKPROOF then says
VERIFIED and GitHub says unverified, for a team that did nothing wrong. That case
is recorded as ``roster_only`` and is deliberately **info**, never a flag.

The disagreements that do carry weight run the other way -- GitHub verifying
something HACKPROOF cannot, or the two sources contradicting each other outright.

Degradation
-----------
Every unreachable state -- no network, no token, rate limited, private repo, no
GitHub remote, not a git repo -- returns ``info`` with a note. "Unverifiable"
must never render as "flagged": that rule is why this module is safe to run in a
hall with bad wifi.

Configuration travels through the environment, keeping the engine's
``run(repo_path)`` contract intact:

    GITHUB_TOKEN / GH_TOKEN      a token; without one the API allows ~60 req/hr
    HACKPROOF_T0                 event start, ISO 8601 -- enables the §8.d check
    HACKPROOF_GITHUB_REPO        "owner/name", overrides the origin remote
    HACKPROOF_GITHUB_API         API base URL, for pointing at a test server

    python3 analyzers/github_check.py /path/to/repo --roster roster.json --t0 2026-09-12T09:00:00Z
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    from core.models import Finding
except ModuleNotFoundError:  # pragma: no cover - import path convenience only
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.models import Finding

from analyzers import gpg_check

CHECK_REPO_METADATA = "github.repo_metadata"
CHECK_CROSSCHECK = "github.signature_crosscheck"
CHECK_AUTHOR_LOGIN = "github.author_login_match"
CHECK_FORCE_PUSH = "github.force_push"
CHECK_PUSH_GAP = "github.push_gap"

ALL_CHECKS = (
    (CHECK_REPO_METADATA, "server"),
    (CHECK_CROSSCHECK, "server"),
    (CHECK_AUTHOR_LOGIN, "server"),
    (CHECK_FORCE_PUSH, "server"),
    (CHECK_PUSH_GAP, "server"),
)

DEFAULT_API = "https://api.github.com"
PER_PAGE = 100
MAX_PAGES = 20  # 2000 commits, matching gpg_check.MAX_COMMITS
HTTP_TIMEOUT = 20
MAX_EVIDENCE_ITEMS = 50

# github.com/owner/repo(.git), git@github.com:owner/repo(.git), ssh://git@github.com/owner/repo
REMOTE_RE = re.compile(
    r"(?:github\.com[:/])(?P<owner>[A-Za-z0-9._-]+)/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?/?$"
)

# How each (local status, GitHub verified?) pair reads. severity is the worst
# this pairing can justify on its own; "why" is what a judge is shown.
AGREEMENT = "agreement"
BENIGN = "benign_disagreement"
DISAGREEMENT = "disagreement"


def _classify_pair(local_status: str | None, gh_verified: bool, gh_reason: str) -> dict:
    """One commit's two verdicts, reduced to a kind + severity + explanation."""
    if local_status is None:
        return {
            "kind": AGREEMENT,
            "severity": "info",
            "why": "no roster available locally; GitHub's verdict recorded without comparison",
        }

    if local_status == gpg_check.STATUS_VERIFIED:
        if gh_verified:
            return {"kind": AGREEMENT, "severity": "info", "why": "both HACKPROOF and GitHub verified this signature"}
        return {
            "kind": BENIGN,
            "severity": "info",
            "why": (
                "HACKPROOF verified this against the roster but GitHub did not "
                f"(reason: {gh_reason}). The usual cause is a key registered with the organizer "
                "but never uploaded to the participant's GitHub account -- not evidence of anything"
            ),
        }

    if local_status == gpg_check.STATUS_NO_SIGNATURE:
        if gh_verified:
            return {
                "kind": DISAGREEMENT,
                "severity": "hard_flag",
                "why": (
                    "git reports no signature on this commit object, but GitHub reports it as verified. "
                    "The two sources cannot both be describing the same commit"
                ),
            }
        return {"kind": AGREEMENT, "severity": "info", "why": "both sources agree this commit is unsigned"}

    if local_status == gpg_check.STATUS_INVALID_SIGNATURE:
        if gh_verified:
            return {
                "kind": DISAGREEMENT,
                "severity": "hard_flag",
                "why": (
                    "HACKPROOF reports the signature does not match the commit object, "
                    "while GitHub reports it verified -- a direct contradiction worth resolving by hand"
                ),
            }
        return {
            "kind": AGREEMENT,
            "severity": "info",
            "why": f"both sources reject this signature (GitHub reason: {gh_reason})",
        }

    if local_status == gpg_check.STATUS_UNKNOWN_KEY:
        if gh_verified:
            return {
                "kind": DISAGREEMENT,
                "severity": "flag",
                "why": (
                    "GitHub verified this signature against a key on the author's GitHub account, "
                    "but that key was never registered with the organizer. The commit is real work by "
                    "a real account -- it is the enrollment that is missing, so ask before concluding anything"
                ),
            }
        return {
            "kind": AGREEMENT,
            "severity": "info",
            "why": (
                "neither HACKPROOF nor GitHub can attribute this signature "
                f"(GitHub reason: {gh_reason}) -- two independent sources agreeing"
            ),
        }

    if local_status in (gpg_check.STATUS_EXPIRED_KEY, gpg_check.STATUS_REVOKED_KEY):
        if gh_verified:
            return {
                "kind": DISAGREEMENT,
                "severity": "flag",
                "why": (
                    f"HACKPROOF records this key as {local_status.lower().replace('_', ' ')} "
                    "while GitHub still verifies it; the roster and GitHub disagree on the key's validity"
                ),
            }
        return {"kind": AGREEMENT, "severity": "info", "why": "both sources decline to verify this signature"}

    if local_status == gpg_check.STATUS_IDENTITY_MISMATCH:
        return {
            "kind": AGREEMENT if not gh_verified else BENIGN,
            "severity": "info",
            "why": (
                "HACKPROOF attributes this signature to a different member than the commit's author. "
                "GitHub checks the key against the author's account, not against a team roster, "
                "so it cannot see a teammate-for-teammate swap at all"
            ),
        }

    return {"kind": AGREEMENT, "severity": "info", "why": f"unhandled local status {local_status!r}"}


# --- API ----------------------------------------------------------------------


class GitHubError(RuntimeError):
    """Anything that makes the API unusable. Always degrades to info."""


def api_base() -> str:
    return (os.environ.get("HACKPROOF_GITHUB_API") or DEFAULT_API).rstrip("/")


def token() -> str | None:
    for name in ("HACKPROOF_GITHUB_TOKEN", "GITHUB_TOKEN", "GH_TOKEN"):
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    try:
        res = subprocess.run(
            ["git", "credential", "fill"],
            input="protocol=https\nhost=github.com\n",
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0:
            for line in res.stdout.splitlines():
                if line.startswith("password="):
                    pw = line.split("=", 1)[1].strip()
                    if pw:
                        return pw
    except Exception:
        pass
    return None


def _get(path: str, params: dict | None = None) -> tuple[object, dict]:
    url = f"{api_base()}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url)
    request.add_header("Accept", "application/vnd.github+json")
    request.add_header("X-GitHub-Api-Version", "2022-11-28")
    request.add_header("User-Agent", "hackproof-analyzer")
    auth = token()
    if auth:
        request.add_header("Authorization", f"Bearer {auth}")
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
            body = response.read().decode("utf-8", "replace")
            headers = {k.lower(): v for k, v in response.headers.items()}
            return json.loads(body) if body.strip() else None, headers
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace")).get("message", "")
        except Exception:  # pragma: no cover - error body is best-effort
            pass
        if exc.code == 403 and "rate limit" in detail.lower():
            raise GitHubError(
                "GitHub API rate limit reached"
                + ("" if auth else " -- set GITHUB_TOKEN to raise the limit from ~60/hr to 5000/hr")
            ) from exc
        if exc.code == 404:
            raise GitHubError(
                "repository not found or not visible to this token (a private repo needs a token with access)"
            ) from exc
        if exc.code == 401:
            raise GitHubError("GitHub rejected the token (401)") from exc
        raise GitHubError(f"GitHub API returned HTTP {exc.code}: {detail or exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise GitHubError(f"could not reach the GitHub API: {exc.reason}") from exc
    except (TimeoutError, OSError) as exc:
        raise GitHubError(f"could not reach the GitHub API: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise GitHubError(f"GitHub returned a response that is not JSON: {exc}") from exc


def detect_repo(repo_path: str) -> tuple[str | None, str]:
    """(owner/name, how_it_was_found). Env override wins over the origin remote."""
    override = (os.environ.get("HACKPROOF_GITHUB_REPO") or "").strip()
    if override:
        return override.strip("/"), "$HACKPROOF_GITHUB_REPO"
    code, out, _ = gpg_check._git(repo_path, ["remote", "get-url", "origin"])
    if code != 0 or not out.strip():
        return None, "no 'origin' remote configured"
    remote = out.strip()
    match = REMOTE_RE.search(remote)
    if not match:
        return None, f"origin remote is not a GitHub URL: {remote}"
    return f"{match.group('owner')}/{match.group('repo')}", f"origin remote {remote}"


def fetch_repo_metadata(slug: str) -> dict:
    data, _ = _get(f"/repos/{slug}")
    if not isinstance(data, dict):
        raise GitHubError("unexpected response shape for the repository endpoint")
    return data


def fetch_commits(slug: str, max_pages: int = MAX_PAGES) -> list[dict]:
    """List commits with their verification verdicts.

    The list endpoint carries ``commit.verification`` and the resolved
    ``author.login`` for every entry, so this is a handful of calls for a whole
    repo rather than the one-call-per-commit the design note budgeted for.
    """
    collected: list[dict] = []
    for page in range(1, max_pages + 1):
        data, _ = _get(f"/repos/{slug}/commits", {"per_page": PER_PAGE, "page": page})
        if not isinstance(data, list) or not data:
            break
        collected.extend(entry for entry in data if isinstance(entry, dict))
        if len(data) < PER_PAGE:
            break
    return collected


# --- checks -------------------------------------------------------------------


def _parse_iso(value) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _skipped(repo_path: str, note: str, detail: str | None = None) -> list[Finding]:
    """Every check, info and passed, carrying why it could not run."""
    evidence: dict = {"repo_path": repo_path, "note": note}
    if detail:
        evidence["detail"] = detail
    return [
        Finding(name, plane, "info", dict(evidence), True) for name, plane in ALL_CHECKS
    ]


def check_repo_metadata(slug: str, metadata: dict, t0_raw: str | None) -> Finding:
    created_at = metadata.get("created_at")
    evidence: dict = {
        "mechanism": "GET /repos/{owner}/{repo}",
        "repo": slug,
        "created_at": created_at,
        "pushed_at": metadata.get("pushed_at"),
        "is_fork": bool(metadata.get("fork")),
        "fork_parent": (metadata.get("parent") or {}).get("full_name"),
        "private": metadata.get("private"),
        "default_branch": metadata.get("default_branch"),
    }

    t0 = _parse_iso(t0_raw)
    created = _parse_iso(created_at)
    if t0 is None:
        evidence["note"] = (
            "no event start given, so the build-window comparison was skipped; "
            "set $HACKPROOF_T0 (or --t0) to enable spec §8.d check 1"
        )
        evidence["t0"] = None
        return Finding(CHECK_REPO_METADATA, "server", "info", evidence, True)

    evidence["t0"] = t0.isoformat()
    if created is None:
        evidence["note"] = "GitHub did not report a repository creation time"
        return Finding(CHECK_REPO_METADATA, "server", "info", evidence, True)

    delta_hours = round((t0 - created).total_seconds() / 3600.0, 2)
    evidence["created_before_t0_by_hours"] = delta_hours if delta_hours > 0 else None
    if created < t0:
        evidence["interpretation"] = (
            f"the repository existed on GitHub {delta_hours} hours before the event started. "
            "Per spec §7 phase 0 every team starts from an organizer template created inside the "
            "window, so this is the server plane -- the one plane a participant cannot rewrite -- "
            "saying the codebase predates T0"
        )
        return Finding(CHECK_REPO_METADATA, "server", "hard_flag", evidence, False)

    if evidence["is_fork"]:
        evidence["interpretation"] = (
            f"repository was created inside the window but is a fork of {evidence['fork_parent']}; "
            "forked history is inherited, not authored, so check what arrived with the fork"
        )
        return Finding(CHECK_REPO_METADATA, "server", "flag", evidence, False)

    evidence["note"] = f"repository created {created.isoformat()}, inside the event window"
    return Finding(CHECK_REPO_METADATA, "server", "info", evidence, True)


def check_signature_crosscheck(local_commits: list[dict], gh_commits: list[dict], attribution_enabled: bool) -> Finding:
    by_sha = {entry.get("sha"): entry for entry in gh_commits if entry.get("sha")}
    evidence: dict = {
        "mechanism": "GET /repos/{owner}/{repo}/commits -> commit.verification",
        "github_commits_seen": len(by_sha),
        "local_commits_seen": len(local_commits),
    }

    rows: list[dict] = []
    counts = {AGREEMENT: 0, BENIGN: 0, DISAGREEMENT: 0}
    worst = "info"
    for commit in local_commits:
        sha = commit.get("sha")
        entry = by_sha.get(sha)
        if entry is None:
            continue  # local-only commit (unpushed, or beyond the page budget)
        verification = ((entry.get("commit") or {}).get("verification")) or {}
        gh_verified = bool(verification.get("verified"))
        gh_reason = str(verification.get("reason") or "unknown")
        local_status = commit.get("status") if attribution_enabled else None
        verdict = _classify_pair(local_status, gh_verified, gh_reason)
        counts[verdict["kind"]] += 1
        if verdict["severity"] == "hard_flag":
            worst = "hard_flag"
        elif verdict["severity"] == "flag" and worst != "hard_flag":
            worst = "flag"
        if verdict["kind"] != AGREEMENT:
            rows.append(
                {
                    "sha": sha,
                    "author_email": commit.get("author_email"),
                    "hackproof_status": local_status,
                    "github_verified": gh_verified,
                    "github_reason": gh_reason,
                    "kind": verdict["kind"],
                    "severity": verdict["severity"],
                    "why": verdict["why"],
                }
            )

    evidence["compared"] = sum(counts.values())
    evidence["agreements"] = counts[AGREEMENT]
    evidence["benign_disagreements"] = counts[BENIGN]
    evidence["disagreements"] = counts[DISAGREEMENT]
    evidence["rows"] = rows[:MAX_EVIDENCE_ITEMS]
    evidence["local_only_commits"] = [
        c.get("sha") for c in local_commits if c.get("sha") not in by_sha
    ][:MAX_EVIDENCE_ITEMS]

    if not attribution_enabled:
        evidence["note"] = (
            "no roster keys available locally, so GitHub's verdicts were recorded but not "
            "compared against anything. Unverifiable is not the same as flagged"
        )
        return Finding(CHECK_CROSSCHECK, "server", "info", evidence, True)

    if not evidence["compared"]:
        evidence["note"] = "no commit appears in both the local clone and the GitHub API response"
        return Finding(CHECK_CROSSCHECK, "server", "info", evidence, True)

    if worst == "info":
        evidence["note"] = (
            f"{counts[AGREEMENT]} of {evidence['compared']} commits: HACKPROOF and GitHub agree"
            + (f"; {counts[BENIGN]} benign disagreement(s), see rows" if counts[BENIGN] else "")
        )
        return Finding(CHECK_CROSSCHECK, "server", "info", evidence, True)

    evidence["interpretation"] = (
        f"{counts[DISAGREEMENT]} commit(s) where GitHub's verdict and HACKPROOF's roster verdict "
        "disagree in a way that is not explained by an unuploaded key. Spec §8.e check 2: the "
        "disagreement itself is the finding -- read the rows before drawing a conclusion"
    )
    return Finding(CHECK_CROSSCHECK, "server", worst, evidence, False)


def check_author_login(local_commits: list[dict], gh_commits: list[dict], roster: dict | None) -> Finding:
    """GitHub resolves each commit to an account; the roster says who that should be.

    Locally a commit carries an author email and nothing else, which is why the
    GPG module records an unregistered address as UNKNOWN rather than as a
    mismatch. GitHub knows which account actually owns the email.
    """
    evidence: dict = {
        "mechanism": "GET /repos/{owner}/{repo}/commits -> author.login",
        "registered_logins": [],
    }
    if not roster or not roster.get("members"):
        evidence["note"] = "no roster, so there is nothing to compare GitHub's author logins against"
        return Finding(CHECK_AUTHOR_LOGIN, "server", "info", evidence, True)

    login_to_member = {}
    email_to_member = {}
    for member in roster["members"]:
        login = (member.get("github_login") or "").strip().lower()
        if login:
            login_to_member[login] = member["member_id"]
        for email in member.get("emails") or []:
            email_to_member[email.strip().lower()] = member["member_id"]
    evidence["registered_logins"] = sorted(login_to_member)

    if not login_to_member:
        evidence["note"] = (
            "no member has a github_login registered, so this check has nothing to compare. "
            "Add github_login at enrollment to enable it"
        )
        return Finding(CHECK_AUTHOR_LOGIN, "server", "info", evidence, True)

    local_by_sha = {c.get("sha"): c for c in local_commits}
    unregistered: list[dict] = []
    unattributed: list[dict] = []
    seen = 0
    for entry in gh_commits:
        sha = entry.get("sha")
        if sha not in local_by_sha:
            continue
        seen += 1
        author = entry.get("author") or {}
        login = (author.get("login") or "").strip()
        author_email = ((entry.get("commit") or {}).get("author") or {}).get("email", "")
        row = {
            "sha": sha,
            "github_author_login": login or None,
            "commit_author_email": author_email,
            "roster_member_for_email": email_to_member.get((author_email or "").strip().lower()),
        }
        if not login:
            row["why"] = (
                "GitHub could not resolve this commit's author email to any account. "
                "Usually a local-only email that was never added to a GitHub profile"
            )
            unattributed.append(row)
        elif login.lower() not in login_to_member:
            row["why"] = (
                f"GitHub attributes this commit to @{login}, who is not on the roster. "
                "That is an account outside the registered team -- or a member who registered "
                "a different handle at check-in"
            )
            unregistered.append(row)

    evidence["commits_compared"] = seen
    evidence["unregistered_login_commits"] = unregistered[:MAX_EVIDENCE_ITEMS]
    evidence["unregistered_login_count"] = len(unregistered)
    evidence["unresolved_author_commits"] = unattributed[:MAX_EVIDENCE_ITEMS]
    evidence["unresolved_author_count"] = len(unattributed)

    if unregistered:
        evidence["interpretation"] = (
            f"{len(unregistered)} commit(s) attributed by GitHub to an account outside the roster. "
            "This is the server plane's view of authorship, independent of any signature"
        )
        return Finding(CHECK_AUTHOR_LOGIN, "server", "flag", evidence, False)

    evidence["note"] = (
        f"every one of {seen} compared commits resolves to a registered GitHub account"
        if seen
        else "no commits were compared"
    )
    if unattributed:
        evidence["note"] += f"; {len(unattributed)} could not be resolved to any account at all"
    return Finding(CHECK_AUTHOR_LOGIN, "server", "info", evidence, True)


def check_force_push(slug: str, db_path: str | None = None) -> Finding:
    evidence: dict = {
        "mechanism": "webhook stream & server event store force-push audit (spec §8.d server check 3)",
        "repo": slug,
        "force_pushes": [],
        "force_push_count": 0,
    }
    db_candidates = [
        db_path,
        os.environ.get("HACKPROOF_DB"),
        "hackproof.db",
        os.path.join(".hackproof", "hackproof.db"),
    ]
    found_db = None
    for cand in db_candidates:
        if cand and os.path.isfile(cand):
            found_db = cand
            break

    if not found_db:
        evidence["note"] = "no webhook database found; start hackproof-server to record real-time push events"
        return Finding(CHECK_FORCE_PUSH, "server", "info", evidence, True)

    try:
        from core.roster_db import RosterDatabase
        db = RosterDatabase(found_db)
        fp_events = db.detect_force_pushes(slug)
        db.close()
    except Exception as exc:
        evidence["note"] = f"could not query event store: {exc}"
        return Finding(CHECK_FORCE_PUSH, "server", "info", evidence, True)

    if fp_events:
        evidence["force_pushes"] = [
            {
                "id": ev.id,
                "before_sha": (ev.before_sha or "")[:12],
                "after_sha": (ev.after_sha or "")[:12],
                "received_at": ev.server_received_at,
            }
            for ev in fp_events[:MAX_EVIDENCE_ITEMS]
        ]
        evidence["force_push_count"] = len(fp_events)
        evidence["interpretation"] = (
            f"FORCE-PUSH DETECTED: {len(fp_events)} forced push event(s) recorded on GitHub. "
            "Commit history was rewritten or dropped during the hackathon!"
        )
        return Finding(CHECK_FORCE_PUSH, "server", "hard_flag", evidence, False)

    evidence["note"] = "no force-pushes recorded by webhook listener"
    return Finding(CHECK_FORCE_PUSH, "server", "info", evidence, True)


def check_push_gap(local_commits: list[dict], slug: str, db_path: str | None = None) -> Finding:
    evidence: dict = {
        "mechanism": "push-event server-timestamp vs commit author-date gap (spec §8.d server check 2)",
        "repo": slug,
        "large_gap_commits": [],
        "large_gap_count": 0,
    }
    db_candidates = [
        db_path,
        os.environ.get("HACKPROOF_DB"),
        "hackproof.db",
        os.path.join(".hackproof", "hackproof.db"),
    ]
    found_db = None
    for cand in db_candidates:
        if cand and os.path.isfile(cand):
            found_db = cand
            break

    if not found_db:
        evidence["note"] = "no webhook database found; start hackproof-server or run hackproof-poll to audit push timing gaps"
        return Finding(CHECK_PUSH_GAP, "server", "info", evidence, True)

    try:
        from core.roster_db import RosterDatabase
        db = RosterDatabase(found_db)
        push_events = db.get_github_events(repo_name=slug, event_type="push", limit=200)
        db.close()
    except Exception as exc:
        evidence["note"] = f"could not query push events: {exc}"
        return Finding(CHECK_PUSH_GAP, "server", "info", evidence, True)

    if not push_events:
        evidence["note"] = "no push events recorded for this repository in the database"
        return Finding(CHECK_PUSH_GAP, "server", "info", evidence, True)

    sha_push_times: dict[str, str] = {}
    for pev in push_events:
        payload = pev.payload or {}
        p_commits = payload.get("commits", [])
        for pc in p_commits:
            c_id = pc.get("id")
            if c_id:
                sha_push_times[c_id] = pev.server_received_at
        if pev.after_sha:
            sha_push_times[pev.after_sha] = pev.server_received_at

    large_gaps = []
    MAX_GAP_SECONDS = 24 * 3600.0  # 24 hours

    for commit in local_commits:
        sha = commit.get("sha")
        push_time_str = sha_push_times.get(sha)
        if not push_time_str:
            continue
        c_dt = _parse_iso(commit.get("author_date"))
        p_dt = _parse_iso(push_time_str)
        if c_dt and p_dt:
            gap_seconds = (p_dt - c_dt).total_seconds()
            if gap_seconds > MAX_GAP_SECONDS:
                large_gaps.append({
                    "sha": sha[:12],
                    "author": f"{commit.get('author_name')} <{commit.get('author_email')}>",
                    "author_date": commit.get("author_date"),
                    "server_pushed_at": push_time_str,
                    "gap_hours": round(gap_seconds / 3600.0, 1),
                })

    evidence["large_gap_commits"] = large_gaps[:MAX_EVIDENCE_ITEMS]
    evidence["large_gap_count"] = len(large_gaps)

    if large_gaps:
        evidence["interpretation"] = (
            f"PUSH TIMING GAP DETECTED: {len(large_gaps)} commit(s) were authored >24h before "
            "being pushed to GitHub. Indicates pre-written code committed locally before the hackathon."
        )
        return Finding(CHECK_PUSH_GAP, "server", "flag", evidence, False)

    evidence["note"] = f"all {len(local_commits)} local commits matched push event timing within expected bounds"
    return Finding(CHECK_PUSH_GAP, "server", "info", evidence, True)


# --- entry point --------------------------------------------------------------


def run(repo_path: str, roster_path: str | None = None, t0: str | None = None) -> list[Finding]:
    """Five server-plane checks. Always returns one Finding each; never raises."""
    resolved = os.path.abspath(os.path.expanduser(str(repo_path)))
    if not os.path.isdir(resolved):
        return _skipped(resolved, "path does not exist or is not a directory")
    if not gpg_check.is_git_repo(resolved):
        return _skipped(resolved, "path is not inside a git working tree")

    slug, how = detect_repo(resolved)
    if not slug:
        return _skipped(resolved, "no GitHub repository to cross-check against", how)

    t0_raw = t0 or os.environ.get("HACKPROOF_T0") or None

    try:
        metadata = fetch_repo_metadata(slug)
        gh_commits = fetch_commits(slug)
    except GitHubError as exc:
        return _skipped(
            resolved,
            "GitHub could not be reached, so every cross-check was skipped rather than failed",
            f"{exc} (repo {slug}, found via {how})",
        )

    local = gpg_check.classify_repo(resolved, roster_path)
    local_commits = local.get("commits") or []
    roster = local.get("roster")
    attribution_enabled = bool(local.get("attribution_enabled"))

    findings: list[Finding] = []
    checks = (
        (CHECK_REPO_METADATA, "server", lambda: check_repo_metadata(slug, metadata, t0_raw)),
        (
            CHECK_CROSSCHECK,
            "server",
            lambda: check_signature_crosscheck(local_commits, gh_commits, attribution_enabled),
        ),
        (CHECK_AUTHOR_LOGIN, "server", lambda: check_author_login(local_commits, gh_commits, roster)),
        (CHECK_FORCE_PUSH, "server", lambda: check_force_push(slug)),
        (CHECK_PUSH_GAP, "server", lambda: check_push_gap(local_commits, slug)),
    )
    for name, plane, fn in checks:
        try:
            finding = fn()
        except Exception as exc:  # never crash the engine
            finding = Finding(
                check_name=name,
                plane=plane,
                severity="info",
                evidence={
                    "repo_path": resolved,
                    "repo": slug,
                    "note": "check raised an unexpected error and was skipped",
                    "error": f"{type(exc).__name__}: {exc}",
                },
                passed=True,
            )
        finding.evidence.setdefault("repo", slug)
        finding.evidence.setdefault("repo_detected_via", how)
        if local.get("error"):
            finding.evidence.setdefault("local_verdict_note", local["error"])
        findings.append(finding)
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cross-check a repo's commits against the GitHub API.")
    parser.add_argument("repo_path")
    parser.add_argument("--roster", default=None)
    parser.add_argument("--t0", default=None, help="event start, ISO 8601 (spec §8.d check 1)")
    parser.add_argument("--format", choices=("table", "json"), default="table")
    args = parser.parse_args(argv)

    findings = run(args.repo_path, roster_path=args.roster, t0=args.t0)
    if args.format == "json":
        import dataclasses

        print(json.dumps([dataclasses.asdict(f) for f in findings], indent=2, default=str))
    else:
        for finding in findings:
            mark = "ok  " if finding.passed else "FAIL"
            headline = finding.evidence.get("interpretation") or finding.evidence.get("note") or ""
            print(f"{mark} {finding.check_name:<32} {finding.severity:<9} {finding.plane:<6}  {headline}")
    return 0 if all(f.passed for f in findings) else 1


if __name__ == "__main__":
    raise SystemExit(main())
