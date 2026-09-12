"""GitHub cross-check tests.

Nothing is mocked here either. The commits are real commits signed by real keys,
and "GitHub" is a real HTTP server on localhost that the analyzer talks to over
the network through its ordinary code path -- ``HACKPROOF_GITHUB_API`` points the
client at it. What each test controls is the *content* GitHub returns, which is
exactly the variable under test: the analyzer's job is to compare two verdicts,
so the tests supply the second one.
"""

from __future__ import annotations

import json
import os
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from analyzers import github_check

try:
    from tests.helpers import out, run
except ModuleNotFoundError:  # pragma: no cover - depends on sys.path shape
    from helpers import out, run

SLUG = "team-07/project"


# --- the stub ------------------------------------------------------------------


class _State:
    """What the fake GitHub will say. Tests mutate this before calling run()."""

    def __init__(self):
        self.repo: dict = {
            "full_name": SLUG,
            "created_at": "2026-09-12T09:00:00Z",
            "pushed_at": "2026-09-12T20:00:00Z",
            "fork": False,
            "private": False,
            "default_branch": "main",
        }
        self.commits: list[dict] = []
        self.repo_status = 200
        self.commits_status = 200
        self.requests: list[str] = []


def _make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence the default stderr spam
            pass

        def _send(self, status: int, payload):
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's interface
            state.requests.append(self.path)
            if self.path == f"/repos/{SLUG}":
                if state.repo_status != 200:
                    return self._send(state.repo_status, {"message": "nope"})
                return self._send(200, state.repo)
            if self.path.startswith(f"/repos/{SLUG}/commits"):
                if state.commits_status != 200:
                    return self._send(state.commits_status, {"message": "nope"})
                query = urllib.parse.urlparse(self.path).query
                page = int(urllib.parse.parse_qs(query).get("page", ["1"])[0])
                return self._send(200, state.commits if page == 1 else [])
            return self._send(404, {"message": "not found"})

    return Handler


@pytest.fixture
def github_api(monkeypatch):
    state = _State()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(state))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("HACKPROOF_GITHUB_API", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("HACKPROOF_T0", "")
    monkeypatch.setenv("GITHUB_TOKEN", "")
    monkeypatch.setenv("GH_TOKEN", "")
    monkeypatch.setenv("HACKPROOF_GITHUB_TOKEN", "")
    monkeypatch.setenv("HACKPROOF_GITHUB_REPO", "")
    try:
        yield state
    finally:
        server.shutdown()
        server.server_close()


# --- a repo with one commit of each interesting local status --------------------


def _git(repo, args, env=None):
    return run(["git", "-C", str(repo), *args], env=env)


@pytest.fixture
def repo_with_statuses(tmp_path, gpg_home):
    """A repo holding one VERIFIED, one UNKNOWN_KEY and one NO_SIGNATURE commit."""
    member_fpr = gpg_home.generate_key("Satoru <satoru@example.test>")
    outsider_fpr = gpg_home.generate_key("Eve <eve@example.test>")

    repo = tmp_path / "repo"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    _git(repo, ["config", "user.name", "Satoru"])
    _git(repo, ["config", "user.email", "satoru@example.test"])
    _git(repo, ["remote", "add", "origin", f"https://github.com/{SLUG}.git"])

    env = dict(gpg_home.env)

    def commit(message, sign_with=None, author_email="satoru@example.test", author_name="Satoru"):
        (repo / "file.py").write_text(f"# {message}\n", encoding="utf-8")
        _git(repo, ["add", "file.py"])
        args = ["commit", "-m", message]
        if sign_with:
            args.insert(1, f"-S{sign_with}")
        else:
            args.append("--no-gpg-sign")
        _git(
            repo,
            args,
            env={**env, "GIT_AUTHOR_EMAIL": author_email, "GIT_AUTHOR_NAME": author_name,
                 "GIT_COMMITTER_EMAIL": author_email, "GIT_COMMITTER_NAME": author_name},
        )
        return out(_git(repo, ["rev-parse", "HEAD"])).strip()

    verified_sha = commit("registered key", sign_with=member_fpr)
    unknown_sha = commit("outsider key, authored as Satoru", sign_with=outsider_fpr)
    unsigned_sha = commit("no signature at all")

    roster = {
        "team_id": "team-07",
        "members": [
            {
                "member_id": "satoru",
                "display_name": "Satoru",
                "github_login": "satorugojo",
                "emails": ["satoru@example.test"],
                "keys": [{"key_id": "satoru-k1", "public_key": gpg_home.export_public(member_fpr)}],
            }
        ],
    }
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(roster), encoding="utf-8")

    return {
        "path": str(repo),
        "roster": str(roster_path),
        "verified": verified_sha,
        "unknown": unknown_sha,
        "unsigned": unsigned_sha,
    }


def gh_commit(sha: str, verified: bool, reason: str, login: str | None = "satorugojo",
              email: str = "satoru@example.test") -> dict:
    return {
        "sha": sha,
        "commit": {
            "author": {"email": email, "name": "Satoru"},
            "verification": {"verified": verified, "reason": reason, "signature": None, "payload": None},
        },
        "author": {"login": login} if login else None,
    }


def by_name(findings):
    return {f.check_name: f for f in findings}


# --- the cross-check ------------------------------------------------------------


def test_both_sources_verify_is_an_agreement(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["verified"], True, "valid")]

    findings = by_name(github_check.run(r["path"], roster_path=r["roster"]))
    check = findings["github.signature_crosscheck"]

    assert check.passed and check.severity == "info"
    assert check.evidence["agreements"] == 1
    assert check.evidence["disagreements"] == 0


def test_roster_verified_but_github_unverified_is_benign_not_a_flag(github_api, repo_with_statuses):
    """The common honest case: key registered with the organizer, never uploaded to GitHub."""
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["verified"], False, "unknown_key")]

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.signature_crosscheck"]

    assert check.passed, "an unuploaded key must never be reported as a flag"
    assert check.severity == "info"
    assert check.evidence["benign_disagreements"] == 1
    assert check.evidence["disagreements"] == 0
    assert check.evidence["rows"][0]["kind"] == "benign_disagreement"


def test_both_sources_reject_the_outsider_key(github_api, repo_with_statuses):
    """The impostor case: neither source can attribute it. Two sources agreeing."""
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["unknown"], False, "unknown_key")]

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.signature_crosscheck"]

    assert check.passed and check.evidence["agreements"] == 1
    assert check.evidence["disagreements"] == 0


def test_github_verifies_a_key_the_roster_never_registered(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["unknown"], True, "valid")]

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.signature_crosscheck"]

    assert not check.passed
    assert check.severity == "flag"
    row = check.evidence["rows"][0]
    assert row["hackproof_status"] == "UNKNOWN_KEY"
    assert row["github_verified"] is True


def test_github_verifying_an_unsigned_commit_is_a_contradiction(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["unsigned"], True, "valid")]

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.signature_crosscheck"]

    assert not check.passed
    assert check.severity == "hard_flag"
    assert check.evidence["rows"][0]["hackproof_status"] == "NO_SIGNATURE"


def test_no_roster_records_github_verdicts_without_comparing(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["unknown"], True, "valid")]

    check = by_name(github_check.run(r["path"], roster_path=None))["github.signature_crosscheck"]

    assert check.passed and check.severity == "info"
    assert "not compared" in check.evidence["note"]


# --- repo metadata (spec §8.d check 1) ------------------------------------------


def test_repo_created_before_t0_is_a_hard_flag(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.repo["created_at"] = "2026-09-01T00:00:00Z"

    check = by_name(
        github_check.run(r["path"], roster_path=r["roster"], t0="2026-09-12T09:00:00Z")
    )["github.repo_metadata"]

    assert not check.passed and check.severity == "hard_flag"
    assert check.evidence["created_before_t0_by_hours"] > 0


def test_repo_created_inside_the_window_passes(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.repo["created_at"] = "2026-09-12T10:00:00Z"

    check = by_name(
        github_check.run(r["path"], roster_path=r["roster"], t0="2026-09-12T09:00:00Z")
    )["github.repo_metadata"]

    assert check.passed and check.severity == "info"


def test_a_fork_is_flagged_even_when_created_inside_the_window(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.repo["created_at"] = "2026-09-12T10:00:00Z"
    github_api.repo["fork"] = True
    github_api.repo["parent"] = {"full_name": "someone-else/original"}

    check = by_name(
        github_check.run(r["path"], roster_path=r["roster"], t0="2026-09-12T09:00:00Z")
    )["github.repo_metadata"]

    assert not check.passed and check.severity == "flag"
    assert check.evidence["fork_parent"] == "someone-else/original"


def test_without_t0_the_window_comparison_is_skipped_not_failed(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.repo["created_at"] = "2020-01-01T00:00:00Z"

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.repo_metadata"]

    assert check.passed and check.severity == "info"
    assert check.evidence["t0"] is None


# --- author login ---------------------------------------------------------------


def test_author_login_outside_the_roster_is_flagged(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["verified"], True, "valid", login="eve-outsider")]

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.author_login_match"]

    assert not check.passed and check.severity == "flag"
    assert check.evidence["unregistered_login_commits"][0]["github_author_login"] == "eve-outsider"


def test_registered_author_login_passes(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["verified"], True, "valid", login="satorugojo")]

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.author_login_match"]

    assert check.passed and check.evidence["unregistered_login_count"] == 0


def test_commit_github_cannot_resolve_is_recorded_but_not_flagged(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.commits = [gh_commit(r["verified"], True, "valid", login=None)]

    check = by_name(github_check.run(r["path"], roster_path=r["roster"]))["github.author_login_match"]

    assert check.passed
    assert check.evidence["unresolved_author_count"] == 1


# --- degradation -----------------------------------------------------------------


def test_unreachable_api_degrades_to_info(monkeypatch, repo_with_statuses):
    """Bad wifi must never look like cheating."""
    r = repo_with_statuses
    # Port 1 with nothing listening: a real connection failure, not a simulated one.
    monkeypatch.setenv("HACKPROOF_GITHUB_API", "http://127.0.0.1:1")
    monkeypatch.setenv("HACKPROOF_GITHUB_REPO", "")

    findings = github_check.run(r["path"], roster_path=r["roster"])

    assert len(findings) == len(github_check.ALL_CHECKS)
    assert all(f.passed and f.severity == "info" for f in findings)
    assert "could not be reached" in findings[0].evidence["note"]


def test_repo_without_a_github_remote_is_skipped(github_api, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    run(["git", "init", "-q", "-b", "main", str(plain)])

    findings = github_check.run(str(plain))

    assert all(f.passed and f.severity == "info" for f in findings)
    assert "no GitHub repository" in findings[0].evidence["note"]


def test_missing_path_is_skipped(github_api, tmp_path):
    findings = github_check.run(str(tmp_path / "nope"))
    assert len(findings) == len(github_check.ALL_CHECKS)
    assert all(f.passed for f in findings)


def test_http_404_degrades_to_info(github_api, repo_with_statuses):
    r = repo_with_statuses
    github_api.repo_status = 404

    findings = github_check.run(r["path"], roster_path=r["roster"])

    assert all(f.passed and f.severity == "info" for f in findings)
    assert "not found" in findings[0].evidence["detail"]


# --- remote parsing ---------------------------------------------------------------


@pytest.mark.parametrize(
    "remote,expected",
    [
        ("https://github.com/team-07/project.git", "team-07/project"),
        ("https://github.com/team-07/project", "team-07/project"),
        ("git@github.com:team-07/project.git", "team-07/project"),
        ("ssh://git@github.com/team-07/project.git", "team-07/project"),
        ("https://gitlab.com/team-07/project.git", None),
    ],
)
def test_remote_url_parsing(tmp_path, remote, expected, monkeypatch):
    monkeypatch.setenv("HACKPROOF_GITHUB_REPO", "")
    repo = tmp_path / "r"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    run(["git", "-C", str(repo), "remote", "add", "origin", remote])

    slug, _ = github_check.detect_repo(str(repo))

    assert slug == expected


def test_env_override_beats_the_remote(tmp_path, monkeypatch):
    repo = tmp_path / "r"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    run(["git", "-C", str(repo), "remote", "add", "origin", "https://github.com/wrong/repo.git"])
    monkeypatch.setenv("HACKPROOF_GITHUB_REPO", "right/repo")

    slug, how = github_check.detect_repo(str(repo))

    assert slug == "right/repo"
    assert "HACKPROOF_GITHUB_REPO" in how


# --- contract -----------------------------------------------------------------------


def test_findings_satisfy_the_engine_contract(github_api, repo_with_statuses):
    from core.engine import validate_finding

    r = repo_with_statuses
    github_api.commits = [gh_commit(r["unknown"], True, "valid")]

    for finding in github_check.run(r["path"], roster_path=r["roster"]):
        assert validate_finding(finding) == [], finding
