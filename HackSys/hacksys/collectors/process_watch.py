"""Process and focus collector.

Two cheap, high-context signals:

  * new processes matching a watchlist (git, curl, scp, unzip, AI CLIs, …)
  * which application is in the foreground, sampled on a timer

Neither is evidence of anything on its own. Together they give the report a
timeline — "at 03:12 the browser was foreground, a copy happened, forty
seconds later 600 lines landed in the submission" — which is the sort of thing
a judge can actually read and reason about.

It also watches for tools that could interfere with this agent's view
(screen sharing, remote control, input capture) and reports them.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from ..models import SEV_INFO, SEV_NOTICE, SEV_WARN
from ..util import frontmost_app, run
from .base import Collector

PS_CMD = ["ps", "-axo", "pid=,ppid=,lstart=,comm=,args="]
PS_RE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+[\d:]+\s+\d{4})\s+(\S+)\s*(.*)$")
MAX_ARGS = 400


class ProcessCollector(Collector):
    name = "process"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.interval = min(ctx.cfg.process_interval, ctx.cfg.focus_interval)
        self._known: Set[int] = set()
        self._watch = [re.compile(p, re.IGNORECASE) for p in ctx.cfg.process_watchlist]
        self._observers = [re.compile(p, re.IGNORECASE) for p in ctx.cfg.observer_watchlist]
        self._observed_reported: Set[str] = set()
        self._last_app: Optional[str] = None
        self._focus_started: float = 0.0
        self._ticks = 0

    def setup(self) -> None:
        procs = self._snapshot()
        self._known = {p["pid"] for p in procs}
        watched = [p for p in procs if self._matches(p, self._watch)]
        observers = [p for p in procs if self._matches(p, self._observers)]
        self.emit(
            "process.baseline",
            f"{len(procs)} process(es) running at start; "
            f"{len(watched)} on the watchlist, {len(observers)} screen/remote tool(s)",
            total=len(procs),
            watchlisted=[_slim(p) for p in watched][:40],
            observer_tools=[_slim(p) for p in observers][:20],
            severity_hint="observer tools present" if observers else "",
        )
        for p in observers:
            self._observed_reported.add(p["comm"])

    # -- loop -----------------------------------------------------------

    def poll(self) -> None:
        self._ticks += 1
        if self.cfg.enable_focus:
            self._sample_focus()
        # process scan runs on its own (usually slower) cadence
        every = max(1, int(self.cfg.process_interval / max(0.5, self.interval)))
        if self._ticks % every == 0:
            self._scan_processes()

    def _scan_processes(self) -> None:
        procs = self._snapshot()
        current = {p["pid"] for p in procs}
        new = [p for p in procs if p["pid"] not in self._known]
        self._known = current

        for p in new:
            if self._matches(p, self._observers):
                if p["comm"] not in self._observed_reported:
                    self._observed_reported.add(p["comm"])
                    self.emit(
                        "process.observer_tool",
                        f"screen-sharing / remote-control / capture tool started: {p['comm']}",
                        severity=SEV_WARN, **_slim(p),
                    )
                continue
            if self._matches(p, self._watch):
                sev = SEV_NOTICE if _touches_project(p, self.cfg.project_paths) else SEV_INFO
                self.emit(
                    "process.started",
                    f"{p['comm']} started: {p['args'][:160]}",
                    severity=sev, **_slim(p),
                )

    def _sample_focus(self) -> None:
        app = frontmost_app()
        if not app or app == self._last_app:
            return
        previous = self._last_app
        self._last_app = app
        self.emit(
            "focus.changed",
            f"foreground application is now {app}",
            app=app, previous=previous,
        )

    # -- helpers ---------------------------------------------------------

    def _snapshot(self) -> List[Dict[str, Any]]:
        rc, out, _ = run(PS_CMD, timeout=20)
        if rc != 0:
            return []
        procs: List[Dict[str, Any]] = []
        for line in out.splitlines():
            m = PS_RE.match(line)
            if not m:
                continue
            pid, ppid, started, comm, args = m.groups()
            procs.append({
                "pid": int(pid),
                "ppid": int(ppid),
                "started": started.strip(),
                "comm": comm.rsplit("/", 1)[-1],
                "path": comm,
                "args": args[:MAX_ARGS],
            })
        return procs

    @staticmethod
    def _matches(proc: Dict[str, Any], patterns) -> bool:
        blob = f"{proc['comm']} {proc['args']}"
        return any(p.search(blob) for p in patterns)


def _slim(p: Dict[str, Any]) -> Dict[str, Any]:
    return {"pid": p["pid"], "ppid": p["ppid"], "comm": p["comm"],
            "args": p["args"][:MAX_ARGS], "started": p["started"]}


def _touches_project(p: Dict[str, Any], project_paths: List[str]) -> bool:
    return any(root in p["args"] for root in project_paths)
