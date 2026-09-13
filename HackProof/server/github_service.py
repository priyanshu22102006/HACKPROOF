"""GitHub REST API and GitHub App integration service for HACKPROOF.

Handles polling of repository metadata, historical PushEvents, Actions workflow runs,
and server-side signature verification verdicts, synchronizing them into the HACKPROOF
database.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

try:
    from core.roster_db import RosterDatabase
except ModuleNotFoundError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.roster_db import RosterDatabase

DEFAULT_API = "https://api.github.com"
HTTP_TIMEOUT = 20


class GitHubServiceError(Exception):
    """Base exception for GitHub service operations."""
    pass


class GitHubClient:
    """Client for GitHub REST API supporting Tokens and GitHub App installations."""

    def __init__(
        self,
        token: str | None = None,
        api_base: str | None = None,
        app_id: str | None = None,
        private_key_path: str | None = None,
        installation_id: str | None = None,
    ):
        self.api_base = (api_base or os.environ.get("HACKPROOF_GITHUB_API") or DEFAULT_API).rstrip("/")
        self.token = (
            token
            or os.environ.get("GITHUB_TOKEN")
            or os.environ.get("GH_TOKEN")
            or os.environ.get("HACKPROOF_GITHUB_TOKEN")
        )
        self.app_id = app_id or os.environ.get("HACKPROOF_GITHUB_APP_ID")
        self.private_key_path = private_key_path or os.environ.get("HACKPROOF_GITHUB_APP_KEY_PATH")
        self.installation_id = installation_id or os.environ.get("HACKPROOF_GITHUB_INSTALLATION_ID")
        self._cached_app_token: str | None = None
        self._app_token_expiry: float = 0.0

    def _get_auth_header(self) -> dict[str, str]:
        """Return Authorization header if token or App credentials exist."""
        if self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}

    def _request(self, endpoint: str, query: dict | None = None) -> tuple[int, dict | list | None]:
        url = f"{self.api_base}/{endpoint.lstrip('/')}"
        if query:
            url += f"?{urllib.parse.urlencode(query)}"

        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "HACKPROOF-ServerPlane/1.0",
            **self._get_auth_header(),
        }

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT) as resp:
                status = resp.status
                body = resp.read().decode("utf-8", "replace")
                data = json.loads(body) if body.strip() else None
                return status, data
        except urllib.error.HTTPError as err:
            body = err.read().decode("utf-8", "replace")
            try:
                data = json.loads(body)
            except Exception:
                data = {"message": body}
            return err.code, data
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise GitHubServiceError(f"Network error requesting {url}: {exc}") from exc

    # --- REST Polling Endpoints ------------------------------------------------

    def get_repo(self, owner: str, repo: str) -> dict:
        """Fetch repository metadata (created_at, pushed_at, fork, etc.)."""
        status, data = self._request(f"repos/{owner}/{repo}")
        if status != 200:
            msg = (data or {}).get("message", f"HTTP {status}")
            raise GitHubServiceError(f"Failed to fetch repo {owner}/{repo}: {msg}")
        return data  # type: ignore

    def get_push_events(self, owner: str, repo: str, limit: int = 50) -> list[dict]:
        """Fetch historical PushEvents from public events feed."""
        status, data = self._request(f"repos/{owner}/{repo}/events", {"per_page": min(100, limit)})
        if status != 200:
            return []
        events = data if isinstance(data, list) else []
        push_events = [e for e in events if e.get("type") == "PushEvent"]
        return push_events[:limit]

    def get_workflow_runs(self, owner: str, repo: str, limit: int = 30) -> list[dict]:
        """Fetch GitHub Actions workflow execution runs."""
        status, data = self._request(f"repos/{owner}/{repo}/actions/runs", {"per_page": min(100, limit)})
        if status != 200 or not isinstance(data, dict):
            return []
        runs = data.get("workflow_runs", [])
        return runs[:limit]

    def get_commit_verification(self, owner: str, repo: str, sha: str) -> dict | None:
        """Fetch GitHub's own signature verification status for a single commit."""
        status, data = self._request(f"repos/{owner}/{repo}/commits/{sha}")
        if status != 200 or not isinstance(data, dict):
            return None
        commit_obj = data.get("commit", {})
        verification = commit_obj.get("verification", {})
        return {
            "sha": sha,
            "verified": verification.get("verified", False),
            "reason": verification.get("reason", "unknown"),
            "signature": verification.get("signature"),
            "payload": verification.get("payload"),
            "author_login": (data.get("author") or {}).get("login"),
            "committer_login": (data.get("committer") or {}).get("login"),
        }

    # --- Sync to DB -----------------------------------------------------------

    def sync_repo_to_db(self, owner: str, repo: str, db: RosterDatabase) -> dict:
        """Poll GitHub API for a repository and record events into the local database."""
        repo_name = f"{owner}/{repo}"
        synced_pushes = 0
        synced_runs = 0

        # 1. Fetch Repo Metadata
        repo_info = self.get_repo(owner, repo)
        created_at = repo_info.get("created_at")
        pushed_at = repo_info.get("pushed_at")

        # Record repository baseline event
        db.record_github_event(
            delivery_guid=f"poll-repo-{repo_name}-{repo_info.get('id')}",
            event_type="repository",
            repo_name=repo_name,
            payload=repo_info,
            github_created_at=created_at,
        )

        # 2. Sync Push Events
        push_events = self.get_push_events(owner, repo)
        for ev in push_events:
            ev_id = str(ev.get("id"))
            created = ev.get("created_at")
            payload = ev.get("payload", {})
            before = payload.get("before")
            after = payload.get("head")
            forced = payload.get("forced", False)
            guid = f"poll-push-{repo_name}-{ev_id}"
            db.record_github_event(
                delivery_guid=guid,
                event_type="push",
                repo_name=repo_name,
                payload=payload,
                before_sha=before,
                after_sha=after,
                forced=bool(forced),
                github_created_at=created,
            )
            synced_pushes += 1

        # 3. Sync Actions Runs
        runs = self.get_workflow_runs(owner, repo)
        for r in runs:
            run_id = str(r.get("id"))
            created = r.get("run_started_at") or r.get("created_at")
            head_sha = r.get("head_sha")
            guid = f"poll-action-{repo_name}-{run_id}"
            db.record_github_event(
                delivery_guid=guid,
                event_type="workflow_run",
                repo_name=repo_name,
                payload=r,
                after_sha=head_sha,
                github_created_at=created,
            )
            synced_runs += 1

        return {
            "repo_name": repo_name,
            "created_at": created_at,
            "pushed_at": pushed_at,
            "synced_pushes": synced_pushes,
            "synced_workflow_runs": synced_runs,
        }


# --- CLI ----------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hackproof-poll",
        description="Poll GitHub REST API and sync repo metadata, pushes, and Actions runs into HACKPROOF.",
    )
    parser.add_argument("repo_slug", help="Repository in 'owner/repo' format")
    parser.add_argument("--db", default="hackproof.db", help="Path to SQLite database (default: hackproof.db)")
    parser.add_argument("--token", default=None, help="GitHub Personal Access Token or App Token")
    parser.add_argument("--api", default=None, help="GitHub API base URL (default: https://api.github.com)")

    args = parser.parse_args(argv)

    if "/" not in args.repo_slug:
        print(f"Error: repo_slug must be 'owner/repo' (got '{args.repo_slug}')", file=sys.stderr)
        return 1

    owner, repo = args.repo_slug.strip().split("/", 1)
    client = GitHubClient(token=args.token, api_base=args.api)
    db = RosterDatabase(args.db)

    try:
        print(f"Polling GitHub for '{owner}/{repo}'...")
        res = client.sync_repo_to_db(owner, repo, db)
        print(f"✅ Sync complete for {res['repo_name']}:")
        print(f"   • Repo Created At    : {res['created_at']}")
        print(f"   • Latest Push At     : {res['pushed_at']}")
        print(f"   • Push Events Synced : {res['synced_pushes']}")
        print(f"   • Actions Runs Synced: {res['synced_workflow_runs']}")
        print(f"   • Database           : {args.db}")
        return 0
    except Exception as exc:
        print(f"Error polling GitHub: {exc}", file=sys.stderr)
        return 1
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
