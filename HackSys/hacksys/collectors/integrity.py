"""Self-integrity collector — "is the watcher still watching?"

The agent runs on a machine its subject controls, so the only defensible
position is to make its own gaps loud. This collector:

  * writes a heartbeat file every few seconds and a heartbeat *event* every
    few minutes, so continuity is provable from the log alone
  * on start, compares the previous heartbeat with now and reports the gap
  * verifies the existing hash chain at start and reports any break
  * cross-checks wall clock against the monotonic clock, so moving the system
    clock (to backdate commits, say) shows up
  * notices if its own launchd job or config file is removed while running
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Dict, Optional

from ..eventlog import verify_chain
from ..models import SEV_CRITICAL, SEV_INFO, SEV_NOTICE, SEV_WARN
from ..util import ensure_dir, human_duration, iso, now_utc, parse_iso, run
from .base import Collector

HEARTBEAT_EVENT_EVERY = 300.0  # seconds between heartbeat events in the log
LAUNCHD_LABEL = "com.hackproof.hacksys"


class IntegrityCollector(Collector):
    name = "integrity"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.interval = ctx.cfg.heartbeat_interval
        self._wall0 = time.time()
        self._mono0 = time.monotonic()
        self._last_event = 0.0
        self._skew_reported = 0.0
        self._hb_lock = threading.Lock()
        self._plist_path = os.path.expanduser(
            f"~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist"
        )
        self._plist_existed = os.path.exists(self._plist_path)

    # -- start-up checks -------------------------------------------------

    def setup(self) -> None:
        ensure_dir(self.cfg.state_dir)
        self._check_previous_run()
        self._check_chain()
        self.emit(
            "daemon.started",
            f"agent started (pid {os.getpid()})",
            pid=os.getpid(),
            python=os.sys.version.split()[0],
            wall_clock=iso(),
            window_start=self.cfg.window_start,
            window_end=self.cfg.window_end,
            launchd_installed=self._plist_existed,
            in_window=self.cfg.in_window(),
        )
        self._write_heartbeat()

    def _check_previous_run(self) -> None:
        hb = self._read_heartbeat()
        if not hb:
            return
        try:
            last = parse_iso(hb["ts"])
        except Exception:
            return
        gap = (now_utc() - last).total_seconds()
        if gap < self.cfg.downtime_tolerance:
            self.emit("daemon.resumed", "agent restarted after a brief pause",
                      gap_seconds=round(gap, 1), previous_heartbeat=hb.get("ts"))
            return
        start, end = self.cfg.window()
        overlaps = last < end and now_utc() > start
        self.emit(
            "integrity.downtime",
            f"agent was not running for {human_duration(gap)} "
            f"(last heartbeat {hb.get('ts')})",
            severity=SEV_CRITICAL if overlaps else SEV_WARN,
            gap_seconds=round(gap, 1),
            last_heartbeat=hb.get("ts"),
            last_seq=hb.get("seq"),
            last_tip=hb.get("tip"),
            inside_window=overlaps,
            reason=hb.get("stop_reason", "unknown — the process did not shut down cleanly"),
        )

    def _check_chain(self) -> None:
        result = verify_chain(self.cfg.log_path)
        if result["events"] == 0:
            return
        self.emit(
            "integrity.chain_checked" if result["ok"] else "integrity.chain_broken",
            f"existing log: {result['events']} event(s), chain "
            + ("intact" if result["ok"] else f"BROKEN ({result['problem_count']} problem(s))"),
            severity=SEV_INFO if result["ok"] else SEV_CRITICAL,
            events=result["events"],
            tip=result["tip"],
            problems=result["problems"],
        )

    # -- loop ---------------------------------------------------------------

    def poll(self) -> None:
        self._check_clock()
        self._check_plist()
        self._write_heartbeat()
        now = time.time()
        if now - self._last_event >= HEARTBEAT_EVENT_EVERY:
            self._last_event = now
            self.emit(
                "daemon.heartbeat",
                f"agent alive, uptime {human_duration(time.monotonic() - self._mono0)}",
                uptime_seconds=round(time.monotonic() - self._mono0, 1),
                events_logged=self.log.count,
                tip=self.log.tip,
                counters=dict(self.ctx.counters),
                in_window=self.cfg.in_window(),
            )

    def _check_clock(self) -> None:
        wall_delta = time.time() - self._wall0
        mono_delta = time.monotonic() - self._mono0
        drift = wall_delta - mono_delta
        if abs(drift) < self.cfg.clock_skew_tolerance:
            return
        if abs(drift - self._skew_reported) < self.cfg.clock_skew_tolerance:
            return
        self._skew_reported = drift
        self.emit(
            "integrity.clock_skew",
            f"system clock moved {drift:+.1f}s relative to the monotonic clock",
            severity=SEV_CRITICAL,
            drift_seconds=round(drift, 2),
            wall_elapsed=round(wall_delta, 2),
            monotonic_elapsed=round(mono_delta, 2),
            note="commit timestamps recorded while the clock was moved cannot be trusted",
        )

    def _check_plist(self) -> None:
        exists = os.path.exists(self._plist_path)
        if self._plist_existed and not exists:
            self._plist_existed = False
            self.emit(
                "integrity.launchd_removed",
                "the agent's launchd job was removed while it was running "
                "— it will not restart after a reboot",
                severity=SEV_CRITICAL, plist=self._plist_path,
            )
        elif not self._plist_existed and exists:
            self._plist_existed = True
            self.emit("integrity.launchd_installed", "launchd job installed",
                      plist=self._plist_path)

    # -- heartbeat file -------------------------------------------------------

    def _write_heartbeat(self, stop_reason: Optional[str] = None) -> None:
        data: Dict[str, Any] = {
            "ts": iso(),
            "mono": round(time.monotonic() - self._mono0, 3),
            "pid": os.getpid(),
            "seq": self.log.count,
            "tip": self.log.tip,
            "in_window": self.cfg.in_window(),
        }
        if stop_reason:
            data["stop_reason"] = stop_reason
        # the poll loop and the shutdown path can both land here at once
        with self._hb_lock:
            tmp = f"{self.cfg.heartbeat_path}.{os.getpid()}.{threading.get_ident()}.tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
                os.replace(tmp, self.cfg.heartbeat_path)
            except OSError as exc:  # pragma: no cover
                try:
                    os.remove(tmp)
                except OSError:
                    pass
                self.error("heartbeat write", exc)

    def _read_heartbeat(self) -> Optional[Dict[str, Any]]:
        try:
            with open(self.cfg.heartbeat_path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            return None

    def mark_stop(self, reason: str) -> None:
        self._write_heartbeat(stop_reason=reason)

    def teardown(self) -> None:
        self._write_heartbeat(stop_reason="clean shutdown")
