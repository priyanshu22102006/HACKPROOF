"""Tests for HACKPROOF Server Plane (Webhook listener, REST polling, and server-plane analyzers)."""

from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import threading
import time
import urllib.request
import pytest

from core.roster_db import RosterDatabase
from server.webhook_server import run_server, verify_webhook_signature
from server.github_service import GitHubClient
from analyzers.github_check import (
    CHECK_FORCE_PUSH,
    CHECK_PUSH_GAP,
    check_force_push,
    check_push_gap,
)


def _compute_hmac(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


# --- 1. Webhook Signature & Health --------------------------------------------


def test_webhook_signature_verification():
    body = b'{"action": "test"}'
    secret = "super-secret-key-123"

    valid_header = _compute_hmac(body, secret)
    assert verify_webhook_signature(body, secret, valid_header) is True

    # Tampered body or secret
    assert verify_webhook_signature(b'{"action": "tampered"}', secret, valid_header) is False
    assert verify_webhook_signature(body, "wrong-secret", valid_header) is False
    assert verify_webhook_signature(body, secret, "invalid-format") is False
    assert verify_webhook_signature(body, secret, None) is False


def test_webhook_server_endpoints(tmp_path):
    db_path = str(tmp_path / "server_test.db")
    secret = "wh-secret-456"

    # Start server on dynamic port
    server = run_server(host="127.0.0.1", port=0, db_path=db_path, webhook_secret=secret)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # GET /healthz
        req = urllib.request.Request(f"http://127.0.0.1:{port}/healthz")
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "healthy"

        # POST /webhook ping with valid signature
        ping_payload = json.dumps({"zen": "Keep it logically awesome."}).encode("utf-8")
        headers = {
            "Content-Type": "application/json",
            "X-GitHub-Event": "ping",
            "X-GitHub-Delivery": "deliv-ping-001",
            "X-Hub-Signature-256": _compute_hmac(ping_payload, secret),
        }
        req = urllib.request.Request(f"http://127.0.0.1:{port}/webhook", data=ping_payload, headers=headers)
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "pong"

        # POST /webhook with INVALID signature must return HTTP 401
        bad_headers = {
            "Content-Type": "application/json",
            "X-GitHub-Event": "ping",
            "X-Hub-Signature-256": "sha256=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadb",
        }
        bad_req = urllib.request.Request(f"http://127.0.0.1:{port}/webhook", data=ping_payload, headers=bad_headers)
        with pytest.raises(urllib.error.HTTPError) as exc_info:
            urllib.request.urlopen(bad_req)
        assert exc_info.value.code == 401

    finally:
        server.shutdown()
        server.server_close()


# --- 2. Webhook Event Ingestion (Push, Force-Push, Actions) --------------------


def test_webhook_push_and_force_push_ingestion(tmp_path):
    db_path = str(tmp_path / "push_events.db")
    secret = "test-secret"
    server = run_server(host="127.0.0.1", port=0, db_path=db_path, webhook_secret=secret)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        # Standard Push Event
        push_body = json.dumps({
            "repository": {"full_name": "team-07/project", "pushed_at": "2026-09-12T10:00:00Z"},
            "ref": "refs/heads/main",
            "before": "0000000000000000000000000000000000000000",
            "after": "1111111111111111111111111111111111111111",
            "forced": False,
            "head_commit": {
                "id": "1111111111111111111111111111111111111111",
                "timestamp": "2026-09-12T10:00:00+05:30",
            },
            "commits": [
                {
                    "id": "1111111111111111111111111111111111111111",
                    "author": {"name": "Alice", "email": "alice@test.com"},
                    "timestamp": "2026-09-12T10:00:00+05:30",
                }
            ],
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "X-GitHub-Event": "push",
            "X-GitHub-Delivery": "deliv-push-001",
            "X-Hub-Signature-256": _compute_hmac(push_body, secret),
        }
        req = urllib.request.Request(f"http://127.0.0.1:{port}/webhook", data=push_body, headers=headers)
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["status"] == "ingested"
            assert res["event_type"] == "push"
            assert res["forced"] is False

        # Force-Push Event (History Rewrite)
        force_body = json.dumps({
            "repository": {"full_name": "team-07/project"},
            "ref": "refs/heads/main",
            "before": "1111111111111111111111111111111111111111",
            "after": "2222222222222222222222222222222222222222",
            "forced": True,
        }).encode("utf-8")

        headers["X-GitHub-Delivery"] = "deliv-force-002"
        headers["X-Hub-Signature-256"] = _compute_hmac(force_body, secret)
        req = urllib.request.Request(f"http://127.0.0.1:{port}/webhook", data=force_body, headers=headers)
        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            res = json.loads(resp.read().decode("utf-8"))
            assert res["forced"] is True

        # Verify DB directly
        db = RosterDatabase(db_path)
        events = db.get_github_events("team-07/project")
        assert len(events) == 2

        force_pushes = db.detect_force_pushes("team-07/project")
        assert len(force_pushes) == 1
        assert force_pushes[0].forced is True
        assert force_pushes[0].before_sha == "1111111111111111111111111111111111111111"
        db.close()

    finally:
        server.shutdown()
        server.server_close()


# --- 3. REST Polling Client & Sync --------------------------------------------


class _FakeGitHubHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/repos/owner/repo":
            data = {
                "id": 123456,
                "full_name": "owner/repo",
                "created_at": "2026-09-12T08:00:00Z",
                "pushed_at": "2026-09-12T18:00:00Z",
                "fork": False,
            }
        elif self.path.startswith("/repos/owner/repo/events"):
            data = [
                {
                    "id": "ev-100",
                    "type": "PushEvent",
                    "created_at": "2026-09-12T18:00:00Z",
                    "payload": {
                        "before": "000000",
                        "head": "abcdef",
                        "forced": False,
                        "commits": [{"id": "abcdef", "message": "initial"}],
                    },
                }
            ]
        elif self.path.startswith("/repos/owner/repo/actions/runs"):
            data = {
                "workflow_runs": [
                    {
                        "id": 999,
                        "run_started_at": "2026-09-12T18:05:00Z",
                        "head_sha": "abcdef",
                        "conclusion": "success",
                    }
                ]
            }
        elif self.path == "/repos/owner/repo/commits/abcdef":
            data = {
                "sha": "abcdef",
                "commit": {"verification": {"verified": True, "reason": "valid"}},
                "author": {"login": "octocat"},
            }
        else:
            self.send_response(404)
            self.end_headers()
            return

        body = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def test_github_rest_client_and_sync(tmp_path):
    server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeGitHubHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        api_base = f"http://127.0.0.1:{port}"
        client = GitHubClient(token="fake-token", api_base=api_base)

        # Test single endpoints
        repo = client.get_repo("owner", "repo")
        assert repo["full_name"] == "owner/repo"

        pushes = client.get_push_events("owner", "repo")
        assert len(pushes) == 1
        assert pushes[0]["id"] == "ev-100"

        runs = client.get_workflow_runs("owner", "repo")
        assert len(runs) == 1
        assert runs[0]["id"] == 999

        verif = client.get_commit_verification("owner", "repo", "abcdef")
        assert verif["verified"] is True
        assert verif["author_login"] == "octocat"

        # Test full sync to DB
        db_path = str(tmp_path / "sync_test.db")
        db = RosterDatabase(db_path)
        summary = client.sync_repo_to_db("owner", "repo", db)
        assert summary["synced_pushes"] == 1
        assert summary["synced_workflow_runs"] == 1

        events = db.get_github_events("owner/repo")
        assert len(events) == 3  # repository + push + workflow_run
        db.close()

    finally:
        server.shutdown()
        server.server_close()


# --- 4. Server-Plane Analyzers (Force-Push & Push-Gap) ------------------------


def test_analyzer_detects_force_push(tmp_path):
    db_path = str(tmp_path / "fp_analyzer.db")
    db = RosterDatabase(db_path)

    # Clean repo with no force-pushes
    clean_finding = check_force_push("team-07/project", db_path=db_path)
    assert clean_finding.passed is True
    assert clean_finding.severity == "info"

    # Inject a force push event
    db.record_github_event(
        delivery_guid="force-fp-001",
        event_type="push",
        repo_name="team-07/project",
        payload={},
        before_sha="111111",
        after_sha="222222",
        forced=True,
    )
    db.close()

    fp_finding = check_force_push("team-07/project", db_path=db_path)
    assert fp_finding.passed is False
    assert fp_finding.severity == "hard_flag"
    assert "FORCE-PUSH DETECTED" in fp_finding.evidence["interpretation"]


def test_analyzer_detects_push_gap(tmp_path):
    db_path = str(tmp_path / "gap_analyzer.db")
    db = RosterDatabase(db_path)

    # Server received push at 2026-09-13T10:00:00Z
    server_time = "2026-09-13T10:00:00Z"
    db.record_github_event(
        delivery_guid="gap-push-001",
        event_type="push",
        repo_name="team-07/project",
        payload={
            "commits": [{"id": "abc123456789", "timestamp": "2026-09-10T10:00:00Z"}]
        },
        server_received_at=server_time,
    )
    db.close()

    # Commit was authored on 2026-09-10 (3 days BEFORE push)
    local_commits = [
        {
            "sha": "abc123456789",
            "author_name": "Cheater",
            "author_email": "cheater@test.com",
            "author_date": "2026-09-10T10:00:00Z",
        }
    ]

    finding = check_push_gap(local_commits, "team-07/project", db_path=db_path)
    assert finding.passed is False
    assert finding.severity == "flag"
    assert finding.evidence["large_gap_count"] == 1
    assert finding.evidence["large_gap_commits"][0]["gap_hours"] >= 72.0
