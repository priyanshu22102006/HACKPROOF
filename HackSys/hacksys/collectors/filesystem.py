"""Filesystem collector.

Watches the configured roots (the whole home directory by default) and turns
raw file events into meaningful ones:

  * code appearing inside the submission that already exists somewhere else
    on disk  ->  `fs.content_copied_into_project`
  * clipboard content landing inside a project file  ->  `clipboard.paste_landed`
  * a second git clone materialising next to the submission -> `fs.repo_detected`
  * downloaded files, with the URL macOS recorded on them -> `provenance.download`

Everything else is counted and folded into a periodic `fs.rollup`, so that a
full-system watch does not drown the log in noise about browser caches.
"""

from __future__ import annotations

import os
import time
from collections import defaultdict
from queue import Empty, Queue
from typing import Any, Dict, List, Optional, Tuple

from ..models import SEV_CRITICAL, SEV_INFO, SEV_NOTICE, SEV_WARN
from ..util import (
    is_archive,
    is_code_file,
    normalize_code,
    read_text_safe,
    sha256_file,
    xattr_quarantine,
    xattr_where_from,
)
from .base import Collector

try:
    from watchdog.events import FileSystemEventHandler
    from watchdog.observers import Observer
    WATCHDOG = True
except ImportError:  # pragma: no cover
    WATCHDOG = False
    FileSystemEventHandler = object  # type: ignore
    Observer = None  # type: ignore


ROLLUP_INTERVAL = 60.0
MODIFY_DEBOUNCE = 4.0


class _Handler(FileSystemEventHandler):  # type: ignore[misc]
    def __init__(self, queue: "Queue[Tuple[str, str, Optional[str], bool, float]]"):
        self.queue = queue

    def _push(self, kind: str, src: str, dest: Optional[str], is_dir: bool) -> None:
        try:
            self.queue.put_nowait((kind, src, dest, is_dir, time.time()))
        except Exception:
            pass

    def on_created(self, event):
        self._push("create", event.src_path, None, event.is_directory)

    def on_modified(self, event):
        self._push("modify", event.src_path, None, event.is_directory)

    def on_deleted(self, event):
        self._push("delete", event.src_path, None, event.is_directory)

    def on_moved(self, event):
        self._push("move", event.src_path, event.dest_path, event.is_directory)


class FilesystemCollector(Collector):
    name = "filesystem"
    interval = 1.0

    def __init__(self, ctx):
        super().__init__(ctx)
        self.queue: "Queue[Tuple[str, str, Optional[str], bool, float]]" = Queue(maxsize=200_000)
        self.observer = None
        self._last_seen: Dict[str, float] = {}
        self._rollup: Dict[str, int] = defaultdict(int)
        self._rollup_zones: Dict[str, int] = defaultdict(int)
        self._last_rollup = time.time()
        self._known_repos: set[str] = set()

    # -- lifecycle -------------------------------------------------------

    def setup(self) -> None:
        if not WATCHDOG:
            self.emit(
                "collector.unavailable",
                "watchdog is not installed — filesystem monitoring is OFF",
                severity=SEV_CRITICAL,
                remediation="pip install watchdog",
            )
            return

        self._seed_index()

        self.observer = Observer()
        handler = _Handler(self.queue)
        watched: List[str] = []
        for root in self.cfg.watch_roots:
            if not os.path.isdir(root):
                continue
            try:
                self.observer.schedule(handler, root, recursive=True)
                watched.append(root)
            except OSError as exc:
                self.emit(
                    "collector.degraded",
                    f"cannot watch {root}: {exc}",
                    severity=SEV_WARN,
                    root=root,
                    error=str(exc),
                    remediation="grant Full Disk Access to the process running hacksys",
                )
        self.observer.start()
        self.emit(
            "fs.watch_started",
            f"watching {len(watched)} root(s) recursively",
            roots=watched,
            excludes=len(self.cfg.excludes),
            indexed_at_start=len(self.ctx.files),
        )

    def teardown(self) -> None:
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=5)
        self._flush_rollup(force=True)

    # -- baseline --------------------------------------------------------

    def _seed_index(self) -> None:
        """Hash the code already present in the project(s) at start.

        Without a baseline, everything looks new. With one, "this file's bytes
        were already on disk before you started" becomes a statement the report
        can make.
        """
        seeded = 0
        roots = list(self.cfg.project_paths) + list(self.cfg.sensitive_roots)
        # also index what sits *next to* the submission — a reference checkout
        # beside the project is the case this whole collector exists for
        for project in self.cfg.project_paths:
            parent = os.path.dirname(project)
            if parent and parent not in roots and os.path.isdir(parent):
                roots.append(parent)
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                if self.ctx.is_excluded(dirpath + "/"):
                    dirnames[:] = []
                    continue
                if ".git" in dirnames:
                    self._known_repos.add(dirpath)
                dirnames[:] = [d for d in dirnames
                               if not self.ctx.is_excluded(os.path.join(dirpath, d) + "/")]
                for fn in filenames:
                    path = os.path.join(dirpath, fn)
                    if not is_code_file(path) or self.ctx.is_excluded(path):
                        continue
                    try:
                        if os.path.getsize(path) > self.cfg.max_index_file_bytes:
                            continue
                    except OSError:
                        continue
                    digest = sha256_file(path)
                    if digest:
                        self.ctx.files.put(path, digest, {"zone": self.ctx.classify(path),
                                                          "baseline": True})
                        seeded += 1
                    if seeded > self.cfg.file_index_capacity:
                        break
        self.emit(
            "fs.baseline_indexed",
            f"baseline: {seeded} code files hashed before monitoring began",
            files=seeded,
            roots=[r for r in roots if os.path.isdir(r)],
            repos=sorted(self._known_repos),
        )

    # -- main loop --------------------------------------------------------

    def poll(self) -> None:
        batch: Dict[str, Tuple[str, str, Optional[str], bool, float]] = {}
        deadline = time.time() + 0.8
        while time.time() < deadline:
            try:
                kind, src, dest, is_dir, when = self.queue.get(timeout=0.05)
            except Empty:
                break
            key = dest or src
            # Keep the most meaningful event per path in this batch.
            prev = batch.get(key)
            if prev and prev[0] in ("create", "move") and kind == "modify":
                continue
            batch[key] = (kind, src, dest, is_dir, when)

        for kind, src, dest, is_dir, when in batch.values():
            try:
                self._handle(kind, src, dest, is_dir, when)
            except Exception as exc:
                self.error(f"handling {kind} {src}", exc)

        self._flush_rollup()

    # -- per-event handling -------------------------------------------------

    def _handle(self, kind: str, src: str, dest: Optional[str], is_dir: bool, when: float) -> None:
        path = dest or src
        if self.ctx.is_excluded(path) or self.ctx.is_excluded(src):
            return

        zone = self.ctx.classify(path)
        self._rollup[kind] += 1
        self._rollup_zones[zone] += 1

        if is_dir:
            self._handle_dir(kind, src, dest, path, zone)
            return

        base = os.path.basename(path)
        code = is_code_file(path)
        archive = is_archive(path)
        interesting = zone in ("project", "staging") or code or archive or base == ".gitignore"

        if kind == "delete":
            if interesting:
                self.emit(
                    "fs.delete", f"deleted {_display(path)}",
                    severity=SEV_NOTICE if zone == "project" else SEV_INFO,
                    path=path, zone=zone, is_code=code,
                )
            return

        # Debounce repeated modifies of the same path.
        last = self._last_seen.get(path, 0.0)
        if kind == "modify" and when - last < MODIFY_DEBOUNCE:
            return
        self._last_seen[path] = when

        try:
            st = os.stat(path)
        except (OSError, PermissionError):
            return
        size = st.st_size

        digest = None
        if code and size <= self.cfg.max_index_file_bytes:
            digest = sha256_file(path)

        payload: Dict[str, Any] = {
            "path": path,
            "zone": zone,
            "size": size,
            "is_code": code,
            "sha256": digest,
            "mtime": st.st_mtime,
        }
        if dest:
            payload["from"] = src
            payload["from_zone"] = self.ctx.classify(src)

        severity = SEV_INFO
        if interesting:
            self.emit(f"fs.{kind}", f"{kind} {_display(path)}", severity=severity, **payload)

        # -- derived signals ------------------------------------------------

        if kind in ("create", "modify", "move"):
            if digest:
                self._check_duplicate(path, digest, zone, size)
            if zone == "project" and code:
                self._check_paste(path, size)
            if kind in ("create", "move"):
                self._check_provenance(path, zone, archive, code)

        if digest:
            self.ctx.files.put(path, digest, {"zone": zone, "size": size})

    def _handle_dir(self, kind: str, src: str, dest: Optional[str], path: str, zone: str) -> None:
        base = os.path.basename(path)
        if base == ".git" and kind in ("create", "move"):
            repo = os.path.dirname(path)
            if repo in self._known_repos:
                return
            self._known_repos.add(repo)
            near_project = any(
                os.path.dirname(repo) == os.path.dirname(p) or repo.startswith(p)
                for p in self.cfg.project_paths
            )
            self.emit(
                "fs.repo_detected",
                f"new git repository appeared at {_display(repo)}",
                severity=SEV_WARN if near_project else SEV_NOTICE,
                repo=repo,
                zone=self.ctx.classify(repo),
                adjacent_to_submission=near_project,
            )
            try:
                self.ctx.new_repos.append(repo)
            except AttributeError:  # pragma: no cover
                pass

    # -- correlations ---------------------------------------------------------

    def _check_duplicate(self, path: str, digest: str, zone: str, size: int) -> None:
        """Same bytes, two places. The core copy-paste-the-whole-file signal."""
        others = self.ctx.files.paths_with_hash(digest, exclude=path)
        if not others:
            return
        if zone != "project":
            return
        external = [p for p in others if not self.ctx.in_project(p)]
        if not external:
            # Duplicate inside the submission itself: worth noting, not alarming.
            self.emit(
                "fs.internal_duplicate",
                f"{_display(path)} is byte-identical to another file in the submission",
                severity=SEV_INFO, path=path, matches=others[:5], sha256=digest,
            )
            return
        src_zones = sorted({self.ctx.classify(p) for p in external})
        sev = SEV_CRITICAL if "staging" in src_zones else SEV_WARN
        self.emit(
            "fs.content_copied_into_project",
            f"{_display(path)} is byte-identical to {_display(external[0])}"
            + (f" (+{len(external) - 1} more)" if len(external) > 1 else ""),
            severity=sev,
            path=path,
            sources=external[:5],
            source_zones=src_zones,
            sha256=digest,
            size=size,
        )

    def _check_paste(self, path: str, size: int) -> None:
        """Did something that was on the clipboard just land in this file?"""
        if size > self.cfg.max_text_match_bytes:
            return
        text = read_text_safe(path, self.cfg.max_text_match_bytes)
        if not text:
            return
        normalized = normalize_code(text)
        hit = self.ctx.clipboard.find_in_text(normalized, self.cfg.min_paste_chars)
        if not hit:
            return
        if hit.get("_landed_in") == path:
            return  # already reported for this file
        hit["_landed_in"] = path
        age = max(0.0, time.time() - hit.get("_at", time.time()))
        self.emit(
            "clipboard.paste_landed",
            f"clipboard content copied from {hit.get('source_app') or 'an unknown app'} "
            f"now appears in {_display(path)}",
            severity=SEV_WARN if hit.get("source_zone") == "external" else SEV_NOTICE,
            path=path,
            clip_sha256=hit.get("sha256"),
            clip_chars=hit.get("chars"),
            clip_lines=hit.get("lines"),
            clip_language=hit.get("language"),
            source_app=hit.get("source_app"),
            seconds_since_copy=round(age, 1),
        )

    def _check_provenance(self, path: str, zone: str, archive: bool, code: bool) -> None:
        origins = xattr_where_from(path)
        quarantine = xattr_quarantine(path)
        if not origins and not quarantine:
            return
        sev = SEV_CRITICAL if zone == "project" and (code or archive) else SEV_NOTICE
        self.emit(
            "provenance.download",
            f"{_display(path)} came from outside this machine"
            + (f" ({origins[0]})" if origins else ""),
            severity=sev,
            path=path,
            zone=zone,
            origins=origins[:4],
            quarantine=quarantine,
            is_archive=archive,
            is_code=code,
        )

    # -- rollup -------------------------------------------------------------

    def _flush_rollup(self, force: bool = False) -> None:
        now = time.time()
        if not force and now - self._last_rollup < ROLLUP_INTERVAL:
            return
        if not self._rollup:
            self._last_rollup = now
            return
        self.emit(
            "fs.rollup",
            "filesystem activity summary for the last "
            f"{int(now - self._last_rollup)}s: {sum(self._rollup.values())} events",
            by_kind=dict(self._rollup),
            by_zone=dict(self._rollup_zones),
            window_seconds=round(now - self._last_rollup, 1),
            index_size=len(self.ctx.files),
        )
        self._rollup.clear()
        self._rollup_zones.clear()
        self._last_rollup = now


def _display(path: str) -> str:
    home = os.path.expanduser("~")
    return path.replace(home, "~", 1) if path.startswith(home) else path
