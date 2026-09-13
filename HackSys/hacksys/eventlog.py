"""Append-only, hash-chained event log.

Every event carries the hash of the previous one, so removing, reordering or
editing a line breaks the chain from that point onward and `hacksys verify`
says exactly where. This is what makes the log worth anything to a judge: the
participant controls the machine, so the log has to be tamper-*evident* even
though it cannot be tamper-*proof*.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .models import Event
from .util import canonical_json, ensure_dir, iso, sha256_text

GENESIS = "0" * 64

_CHAIN_FIELDS = ("seq", "ts", "mono", "collector", "kind", "severity", "plane", "summary", "data")


def compute_hash(record: Dict[str, Any], prev_hash: str) -> str:
    payload = {k: record.get(k) for k in _CHAIN_FIELDS}
    return sha256_text(prev_hash + canonical_json(payload))


class EventLog:
    """Thread-safe writer. One instance per daemon process."""

    def __init__(self, path: str, started_mono: Optional[float] = None):
        self.path = path
        ensure_dir(os.path.dirname(path) or ".")
        self._lock = threading.Lock()
        self._started_mono = started_mono if started_mono is not None else time.monotonic()
        self._seq, self._tip = self._resume()

    # -- state ---------------------------------------------------------

    def _resume(self) -> Tuple[int, str]:
        seq, tip = 0, GENESIS
        if not os.path.exists(self.path):
            return seq, tip
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                seq = max(seq, int(rec.get("seq", 0)))
                tip = rec.get("hash", tip)
        return seq, tip

    @property
    def tip(self) -> str:
        return self._tip

    @property
    def count(self) -> int:
        return self._seq

    # -- writing ---------------------------------------------------------

    def append(self, event: Event) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            record = event.to_dict()
            record["seq"] = self._seq
            record["ts"] = iso()
            record["mono"] = round(time.monotonic() - self._started_mono, 3)
            record["prev_hash"] = self._tip
            record["hash"] = compute_hash(record, self._tip)
            self._tip = record["hash"]

            line = json.dumps(record, ensure_ascii=False, default=str)
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            return record

    def emit(self, collector: str, kind: str, summary: str, severity: str = "info",
             **data: Any) -> Dict[str, Any]:
        return self.append(
            Event(kind=kind, collector=collector, summary=summary, severity=severity, data=data)
        )


# --------------------------------------------------------------------------
# reading / verification
# --------------------------------------------------------------------------


def read_events(path: str) -> Iterator[Dict[str, Any]]:
    if not os.path.exists(path):
        return
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                rec = {"_malformed": True, "_lineno": lineno, "_raw": line[:400]}
            rec.setdefault("_lineno", lineno)
            yield rec


def verify_chain(path: str) -> Dict[str, Any]:
    """Walk the log and report the first break, if any."""
    problems: List[Dict[str, Any]] = []
    prev = GENESIS
    expected_seq = 0
    count = 0
    tip = GENESIS

    for rec in read_events(path):
        if rec.get("_malformed"):
            problems.append({"lineno": rec["_lineno"], "issue": "malformed_json"})
            continue
        count += 1
        expected_seq += 1
        if rec.get("seq") != expected_seq:
            problems.append({
                "lineno": rec.get("_lineno"),
                "issue": "sequence_gap",
                "expected": expected_seq,
                "found": rec.get("seq"),
            })
            expected_seq = int(rec.get("seq") or expected_seq)
        if rec.get("prev_hash") != prev:
            problems.append({
                "lineno": rec.get("_lineno"),
                "seq": rec.get("seq"),
                "issue": "prev_hash_mismatch",
            })
        recomputed = compute_hash(rec, rec.get("prev_hash") or GENESIS)
        if recomputed != rec.get("hash"):
            problems.append({
                "lineno": rec.get("_lineno"),
                "seq": rec.get("seq"),
                "issue": "content_modified",
            })
        prev = rec.get("hash") or prev
        tip = prev

    return {
        "ok": not problems,
        "events": count,
        "tip": tip,
        "problems": problems[:50],
        "problem_count": len(problems),
    }
