"""Shared runtime state handed to every collector.

The interesting signals in this system are *correlations* — a clipboard copy
that later shows up inside a project file, a file in the project whose bytes
match something in Downloads. Those correlations need shared indexes, so they
live here rather than inside any one collector.
"""

from __future__ import annotations

import fnmatch
import os
import threading
from collections import OrderedDict, deque
from typing import Any, Deque, Dict, List, Optional, Tuple

from .config import Config
from .eventlog import EventLog
from .util import normalize_code, sha256_text


class ClipboardIndex:
    """Recent clipboard contents, stored as hashes + shape, never raw text."""

    def __init__(self, capacity: int = 200):
        self._lock = threading.Lock()
        self._items: Deque[Dict[str, Any]] = deque(maxlen=capacity)

    def add(self, entry: Dict[str, Any]) -> None:
        with self._lock:
            self._items.append(entry)

    def snapshot(self) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._items)

    def find_in_text(self, normalized_text: str, min_chars: int) -> Optional[Dict[str, Any]]:
        """Most recent clipboard entry whose normalized body occurs in `text`."""
        for entry in reversed(self.snapshot()):
            body = entry.get("_normalized")
            if not body or len(body) < min_chars:
                continue
            if body in normalized_text:
                return entry
        return None


class FileHashIndex:
    """path -> content hash, plus a reverse hash -> paths map.

    Used to spot the same bytes appearing in two places: a reference clone and
    the submission, or Downloads and the submission.
    """

    def __init__(self, capacity: int = 120_000):
        self._lock = threading.Lock()
        self._capacity = capacity
        self._by_path: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
        self._by_hash: Dict[str, List[str]] = {}

    def put(self, path: str, digest: str, meta: Optional[Dict[str, Any]] = None) -> None:
        with self._lock:
            old = self._by_path.get(path)
            if old and old["hash"] == digest:
                self._by_path.move_to_end(path)
                return
            if old:
                self._drop_hash(old["hash"], path)
            self._by_path[path] = {"hash": digest, **(meta or {})}
            self._by_path.move_to_end(path)
            self._by_hash.setdefault(digest, [])
            if path not in self._by_hash[digest]:
                self._by_hash[digest].append(path)
            while len(self._by_path) > self._capacity:
                evicted_path, evicted = self._by_path.popitem(last=False)
                self._drop_hash(evicted["hash"], evicted_path)

    def _drop_hash(self, digest: str, path: str) -> None:
        paths = self._by_hash.get(digest)
        if not paths:
            return
        if path in paths:
            paths.remove(path)
        if not paths:
            self._by_hash.pop(digest, None)

    def paths_with_hash(self, digest: str, exclude: Optional[str] = None) -> List[str]:
        with self._lock:
            return [p for p in self._by_hash.get(digest, []) if p != exclude]

    def get(self, path: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._by_path.get(path)

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_path)


class Context:
    def __init__(self, cfg: Config, log: EventLog):
        self.cfg = cfg
        self.log = log
        self.clipboard = ClipboardIndex(cfg.clipboard_history)
        self.files = FileHashIndex(cfg.file_index_capacity)
        # repos the filesystem collector notices appearing, drained by the git collector
        self.new_repos: Deque[str] = deque(maxlen=64)
        self.stop_event = threading.Event()
        self.counters: Dict[str, int] = {}
        self._counter_lock = threading.Lock()

    # -- counters ------------------------------------------------------

    def bump(self, key: str, n: int = 1) -> None:
        with self._counter_lock:
            self.counters[key] = self.counters.get(key, 0) + n

    # -- path classification --------------------------------------------

    def is_excluded(self, path: str) -> bool:
        for pattern in self.cfg.excludes:
            if fnmatch.fnmatch(path, pattern):
                return True
        return False

    def in_project(self, path: str) -> bool:
        return any(_under(path, root) for root in self.cfg.project_paths)

    def in_sensitive(self, path: str) -> bool:
        return any(_under(path, root) for root in self.cfg.sensitive_roots)

    def classify(self, path: str) -> str:
        if self.in_project(path):
            return "project"
        if self.in_sensitive(path):
            return "staging"
        return "elsewhere"

    def project_of(self, path: str) -> Optional[str]:
        for root in self.cfg.project_paths:
            if _under(path, root):
                return root
        return None

    # -- helpers ----------------------------------------------------------

    @staticmethod
    def fingerprint_text(text: str) -> Tuple[str, str]:
        normalized = normalize_code(text)
        return sha256_text(normalized), normalized


def _under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(path), os.path.abspath(root)]) == os.path.abspath(root)
    except ValueError:
        return False
