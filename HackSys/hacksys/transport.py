"""Upload the sealed report to the HackProof server.

Offline-first: a failed upload is spooled to disk and retried by
`hacksys submit --retry`, so a flaky venue network never costs a report.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from .config import Config
from .util import ensure_dir, iso, sha256_text

ENDPOINT = "/api/v1/reports/system"


def _request(url: str, payload: Dict[str, Any], token: str, timeout: float) -> Tuple[int, str]:
    body = json.dumps(payload, default=str).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("User-Agent", "hacksys-agent/1")
    req.add_header("X-HackSys-Report-Sha256", sha256_text(body.decode("utf-8", "replace")))
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")[:2000]
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")[:2000]
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return 0, str(exc)


def submit(cfg: Config, report: Dict[str, Any], markdown: str = "") -> Dict[str, Any]:
    """Send one report. Spools to disk on failure."""
    if not cfg.server_url:
        path = spool(cfg, report, markdown)
        return {"ok": False, "reason": "no server_url configured", "spooled": path}

    url = cfg.server_url.rstrip("/") + ENDPOINT
    payload = {
        "kind": "system_plane_report",
        "submitted_at": iso(),
        "participant_id": cfg.participant_id,
        "team_id": cfg.team_id,
        "event_id": cfg.event_id,
        "submission_repo": cfg.submission_repo,
        "report": report,
        "report_markdown": markdown,
    }

    last: Tuple[int, str] = (0, "")
    for attempt in range(3):
        status, body = _request(url, payload, cfg.server_token, cfg.upload_timeout)
        last = (status, body)
        if 200 <= status < 300:
            return {"ok": True, "status": status, "response": body, "url": url}
        if 400 <= status < 500 and status != 429:
            break  # the server rejected it; retrying will not help
        time.sleep(2 ** attempt)

    path = spool(cfg, report, markdown)
    return {"ok": False, "status": last[0], "response": last[1], "spooled": path, "url": url}


def spool(cfg: Config, report: Dict[str, Any], markdown: str = "") -> str:
    ensure_dir(cfg.spool_dir)
    name = f"report-{report.get('generated_at', iso()).replace(':', '')}.json"
    path = os.path.join(cfg.spool_dir, name)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"report": report, "report_markdown": markdown}, fh, default=str)
    return path


def retry_spool(cfg: Config) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    if not os.path.isdir(cfg.spool_dir):
        return results
    for name in sorted(os.listdir(cfg.spool_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(cfg.spool_dir, name)
        try:
            with open(path, "r", encoding="utf-8") as fh:
                blob = json.load(fh)
        except (OSError, json.JSONDecodeError):
            continue
        res = submit(cfg, blob.get("report", {}), blob.get("report_markdown", ""))
        res["file"] = name
        results.append(res)
        if res.get("ok"):
            try:
                os.remove(path)
            except OSError:
                pass
    return results
