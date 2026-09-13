"""Daemon supervisor: owns the event log, starts the collectors, handles signals."""

from __future__ import annotations

import os
import signal
import time
from typing import List, Optional

from .collectors import (
    ClipboardCollector,
    Collector,
    FilesystemCollector,
    GitCollector,
    GpgCollector,
    IntegrityCollector,
    ProcessCollector,
)
from .config import Config
from .context import Context
from .eventlog import EventLog
from .models import SEV_CRITICAL, SEV_NOTICE, SEV_WARN
from .util import ensure_dir, human_duration, iso, now_utc


class Agent:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        ensure_dir(cfg.home)
        ensure_dir(cfg.state_dir)
        ensure_dir(cfg.report_dir)
        ensure_dir(cfg.spool_dir)
        self.log = EventLog(cfg.log_path)
        self.ctx = Context(cfg, self.log)
        self.collectors: List[Collector] = []
        self.integrity: Optional[IntegrityCollector] = None
        self._started = time.monotonic()
        self._stop_reason = "unknown"

    # -- wiring -------------------------------------------------------

    def build(self) -> None:
        cfg = self.cfg
        # integrity first: it records the start event and the previous run's gap
        if cfg.enable_integrity:
            self.integrity = IntegrityCollector(self.ctx)
            self.collectors.append(self.integrity)
        if cfg.enable_filesystem:
            self.collectors.append(FilesystemCollector(self.ctx))
        if cfg.enable_clipboard:
            self.collectors.append(ClipboardCollector(self.ctx))
        if cfg.enable_git:
            self.collectors.append(GitCollector(self.ctx))
        if cfg.enable_gpg:
            self.collectors.append(GpgCollector(self.ctx))
        if cfg.enable_process:
            self.collectors.append(ProcessCollector(self.ctx))

    # -- lifecycle ------------------------------------------------------

    def run(self) -> int:
        self.build()
        self._write_pid()
        self._install_signals()

        self.log.emit(
            "daemon", "daemon.session_open",
            f"monitoring session opened for participant {self.cfg.participant_id}",
            "info",
            participant_id=self.cfg.participant_id,
            team_id=self.cfg.team_id,
            event_id=self.cfg.event_id,
            collectors=[c.name for c in self.collectors],
            project_paths=self.cfg.project_paths,
            watch_roots=self.cfg.watch_roots,
            consent_recorded_at=self.cfg.consent_recorded_at,
        )

        for c in self.collectors:
            c.start()

        try:
            while not self.ctx.stop_event.is_set():
                self.ctx.stop_event.wait(1.0)
                if self.cfg.window_end and not self.cfg.in_window() and now_utc() > self.cfg.window()[1]:
                    self._stop_reason = "hackathon window ended"
                    self.log.emit(
                        "daemon", "daemon.window_ended",
                        "the hackathon window has ended — monitoring stops here",
                        "info", window_end=self.cfg.window_end,
                    )
                    break
        except KeyboardInterrupt:  # pragma: no cover
            self._stop_reason = "interrupted from the terminal"

        self.shutdown()
        return 0

    def shutdown(self) -> None:
        self.ctx.stop_event.set()
        uptime = time.monotonic() - self._started
        if self.integrity:
            self.integrity.mark_stop(self._stop_reason)
        for c in self.collectors:
            c.join(timeout=8)
        self.log.emit(
            "daemon", "daemon.stopped",
            f"agent stopped after {human_duration(uptime)} — {self._stop_reason}",
            "notice" if self._stop_reason in ("hackathon window ended", "stopped for sealing")
            else "warn",
            reason=self._stop_reason,
            uptime_seconds=round(uptime, 1),
            events_logged=self.log.count,
            tip=self.log.tip,
            counters=dict(self.ctx.counters),
            stopped_at=iso(),
        )
        self._clear_pid()

    # -- signals --------------------------------------------------------

    def _install_signals(self) -> None:
        def handler(signum, _frame):
            names = {signal.SIGTERM: "SIGTERM", signal.SIGINT: "SIGINT",
                     signal.SIGHUP: "SIGHUP", signal.SIGQUIT: "SIGQUIT"}
            name = names.get(signum, str(signum))
            # `hacksys seal` drops a marker before stopping us, so an
            # intentional end-of-hackathon stop is not reported as a gap
            expected = os.path.exists(sealing_marker(self.cfg))
            self._stop_reason = "stopped for sealing" if expected else f"received {name}"
            sev = SEV_WARN if self.cfg.in_window() and not expected else SEV_NOTICE
            self.log.emit(
                "daemon", "daemon.signal",
                f"agent asked to stop with {name}"
                + (" as part of sealing the report" if expected else "")
                + (" while the hackathon window was still open"
                   if self.cfg.in_window() and not expected else ""),
                sev, signal=name, in_window=self.cfg.in_window(), pid=os.getpid(),
                expected=expected,
            )
            self.ctx.stop_event.set()

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP, signal.SIGQUIT):
            try:
                signal.signal(sig, handler)
            except (ValueError, OSError):  # pragma: no cover - non-main thread
                pass

    # -- pid file ----------------------------------------------------------

    def _write_pid(self) -> None:
        existing = read_pid(self.cfg)
        if existing and existing != os.getpid():
            self.log.emit(
                "daemon", "daemon.duplicate_instance",
                f"another agent instance appears to be running (pid {existing})",
                SEV_CRITICAL, other_pid=existing,
            )
        with open(self.cfg.pid_path, "w", encoding="utf-8") as fh:
            fh.write(str(os.getpid()))

    def _clear_pid(self) -> None:
        try:
            if read_pid(self.cfg) == os.getpid():
                os.remove(self.cfg.pid_path)
        except OSError:
            pass


def sealing_marker(cfg: Config) -> str:
    return os.path.join(cfg.state_dir, "sealing")


def read_pid(cfg: Config) -> Optional[int]:
    try:
        with open(cfg.pid_path, "r", encoding="utf-8") as fh:
            pid = int(fh.read().strip())
    except (OSError, ValueError):
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None
    except PermissionError:
        return pid
    return pid
