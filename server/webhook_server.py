"""Webhook Listener Server for HACKPROOF (Server Plane).

Receives real-time GitHub Webhook deliveries (push, workflow_run, repository),
verifies HMAC-SHA256 signatures, stamps arrivals with HACKPROOF's unforgeable server clock,
and ingests events into the relational database.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import sys
import threading
import time
from typing import Any

try:
    from core.roster_db import RosterDatabase
except ModuleNotFoundError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.roster_db import RosterDatabase


def verify_webhook_signature(payload_bytes: bytes, secret: str, signature_header: str | None) -> bool:
    """Validate X-Hub-Signature-256 HMAC-SHA256 header."""
    if not secret:
        return True  # No secret configured (development mode)
    if not signature_header or not signature_header.startswith("sha256="):
        return False

    expected = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    expected_header = f"sha256={expected}"
    return hmac.compare_digest(expected_header, signature_header)


class WebhookHandler(BaseHTTPRequestHandler):
    """HTTP Request Handler for GitHub Webhook deliveries."""

    server_start_time: float = time.time()
    events_count: int = 0
    _count_lock = threading.Lock()

    def log_message(self, format: str, *args: Any) -> None:
        # Standard clean log output
        sys.stderr.write(f"[{self.log_date_time_string()}] {format % args}\n")

    def _send_json(self, status: int, data: dict) -> None:
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/healthz", "/"):
            uptime = round(time.time() - self.server_start_time, 1)
            self._send_json(
                200,
                {
                    "status": "healthy",
                    "service": "hackproof-webhook-listener",
                    "uptime_seconds": uptime,
                    "events_ingested": self.events_count,
                },
            )
        elif self.path.startswith("/events"):
            db_path = getattr(self.server, "db_path", "hackproof.db")
            db = RosterDatabase(db_path)
            try:
                events = db.get_github_events(limit=50)
                self._send_json(
                    200,
                    {
                        "total_returned": len(events),
                        "events": [
                            {
                                "id": e.id,
                                "delivery_guid": e.delivery_guid,
                                "event_type": e.event_type,
                                "repo_name": e.repo_name,
                                "before_sha": e.before_sha,
                                "after_sha": e.after_sha,
                                "forced": e.forced,
                                "github_created_at": e.github_created_at,
                                "server_received_at": e.server_received_at,
                                "drift_seconds": e.drift_seconds,
                            }
                            for e in events
                        ],
                    },
                )
            finally:
                db.close()
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/webhook":
            return self._send_json(404, {"error": "unknown webhook endpoint; use POST /webhook"})

        # Record exact arrival timestamp using server's independent clock
        server_received_at = datetime.now(timezone.utc).isoformat()

        # Read headers
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length <= 0:
            return self._send_json(400, {"error": "empty request body"})

        body = self.rfile.read(content_length)

        # 1. HMAC Signature Verification
        secret = getattr(self.server, "webhook_secret", "")
        sig_header = self.headers.get("X-Hub-Signature-256")
        if secret and not verify_webhook_signature(body, secret, sig_header):
            return self._send_json(401, {"error": "invalid webhook HMAC signature (X-Hub-Signature-256 mismatch)"})

        # 2. Parse Event Metadata
        event_type = self.headers.get("X-GitHub-Event", "unknown")
        delivery_guid = self.headers.get("X-GitHub-Delivery", f"gen-{int(time.time()*1000)}")

        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception as exc:
            return self._send_json(400, {"error": f"malformed JSON: {exc}"})

        # Ping Event
        if event_type == "ping":
            return self._send_json(200, {"status": "pong", "zen": payload.get("zen")})

        # Extract repo name
        repo_data = payload.get("repository", {})
        repo_name = repo_data.get("full_name") or payload.get("repository_name") or "unknown/unknown"

        # 3. Handle Push Events
        before_sha = None
        after_sha = None
        forced = False
        github_created_at = None

        if event_type == "push":
            before_sha = payload.get("before")
            after_sha = payload.get("after") or payload.get("head_commit", {}).get("id")
            forced = bool(payload.get("forced", False))
            
            # Extract GitHub's claimed time from head_commit or repository.pushed_at
            head_commit = payload.get("head_commit") or {}
            github_created_at = (
                head_commit.get("timestamp")
                or repo_data.get("pushed_at")
                or self.headers.get("Date")
            )

        elif event_type == "workflow_run":
            wf_run = payload.get("workflow_run", {})
            after_sha = wf_run.get("head_sha")
            github_created_at = wf_run.get("run_started_at") or wf_run.get("created_at")

        elif event_type == "repository":
            github_created_at = repo_data.get("created_at")

        # Ingest into SQLite database
        db_path = getattr(self.server, "db_path", "hackproof.db")
        db = RosterDatabase(db_path)
        try:
            event = db.record_github_event(
                delivery_guid=delivery_guid,
                event_type=event_type,
                repo_name=repo_name,
                payload=payload,
                before_sha=before_sha,
                after_sha=after_sha,
                forced=forced,
                github_created_at=github_created_at,
                server_received_at=server_received_at,
            )
            with self._count_lock:
                WebhookHandler.events_count += 1

            self._send_json(
                200,
                {
                    "status": "ingested",
                    "event_id": event.id,
                    "event_type": event.event_type,
                    "repo_name": event.repo_name,
                    "forced": event.forced,
                    "drift_seconds": event.drift_seconds,
                    "server_received_at": event.server_received_at,
                },
            )
        except Exception as exc:
            self._send_json(500, {"error": f"Failed to persist event: {exc}"})
        finally:
            db.close()


def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    db_path: str = "hackproof.db",
    webhook_secret: str = "",
) -> ThreadingHTTPServer:
    """Create and start the webhook listener HTTP server."""
    server = ThreadingHTTPServer((host, port), WebhookHandler)
    server.db_path = db_path  # type: ignore
    server.webhook_secret = webhook_secret  # type: ignore
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="hackproof-server",
        description="HACKPROOF GitHub Webhook Listener Server (Server Plane).",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Binding host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--db", default="hackproof.db", help="Path to SQLite database (default: hackproof.db)")
    parser.add_argument(
        "--secret",
        default=os.environ.get("GITHUB_WEBHOOK_SECRET", ""),
        help="GitHub webhook HMAC secret (default: $GITHUB_WEBHOOK_SECRET)",
    )

    args = parser.parse_args(argv)

    server = run_server(
        host=args.host,
        port=args.port,
        db_path=args.db,
        webhook_secret=args.secret,
    )

    print("=" * 70)
    print(" HACKPROOF SERVER PLANE — WEBHOOK LISTENER")
    print("=" * 70)
    print(f"  • Listening on        : http://{args.host}:{args.port}/webhook")
    print(f"  • Healthcheck endpoint : http://{args.host}:{args.port}/healthz")
    print(f"  • Events feed endpoint : http://{args.host}:{args.port}/events")
    print(f"  • SQLite Event Store   : {args.db}")
    print(f"  • HMAC Secret Configured: {'YES' if args.secret else 'NO (open mode)'}")
    print("=" * 70)
    print("Ready to receive GitHub webhook deliveries. Press Ctrl+C to stop.\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down HACKPROOF Webhook Server...")
    finally:
        server.shutdown()
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
