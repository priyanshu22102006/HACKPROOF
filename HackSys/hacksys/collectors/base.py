"""Collector base class: a named background thread with a poll loop."""

from __future__ import annotations

import threading
import traceback
from typing import Any

from ..context import Context


class Collector:
    name = "collector"
    interval = 5.0

    def __init__(self, ctx: Context):
        self.ctx = ctx
        self.cfg = ctx.cfg
        self.log = ctx.log
        self._thread: threading.Thread | None = None
        self._errors = 0

    # -- lifecycle --------------------------------------------------

    def setup(self) -> None:
        """Called once before the loop starts."""

    def poll(self) -> None:
        """Called every `interval` seconds. Override in subclasses."""

    def teardown(self) -> None:
        """Called once after the loop exits."""

    # -- plumbing ----------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name=f"hacksys-{self.name}", daemon=True)
        self._thread.start()

    def join(self, timeout: float = 5.0) -> None:
        if self._thread:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        try:
            self.setup()
        except Exception as exc:
            self.error("setup failed", exc)
            return
        while not self.ctx.stop_event.is_set():
            try:
                self.poll()
            except Exception as exc:
                self.error("poll failed", exc)
            self.ctx.stop_event.wait(self.interval)
        try:
            self.teardown()
        except Exception as exc:  # pragma: no cover - defensive
            self.error("teardown failed", exc)

    # -- emitting ------------------------------------------------------

    def emit(self, kind: str, summary: str, severity: str = "info", **data: Any) -> None:
        self.ctx.bump(kind)
        self.log.emit(self.name, kind, summary, severity, **data)

    def error(self, what: str, exc: BaseException) -> None:
        self._errors += 1
        # Collector failures are themselves evidence — a report from a half-blind
        # agent must say so rather than look clean.
        self.emit(
            "collector.error",
            f"{self.name}: {what}: {exc}",
            severity="warn",
            error=str(exc),
            error_type=type(exc).__name__,
            trace=traceback.format_exc(limit=4),
            error_count=self._errors,
        )
