"""Clipboard collector.

Records *that* a copy happened, its shape, and where it came from — never the
text itself unless the organiser explicitly sets `clipboard_preview_chars`.
A sha256 of the whitespace-normalised body is enough for the filesystem
collector to recognise the same content landing in a project file later.

It also tries to name the origin: when a copied blob is found verbatim in a
file outside the submission (a second clone, a download, a reference folder),
that file is named in the event. That is the "copying from the cloned repo
into the real project" case, caught at the copy end rather than inferred.
"""

from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

from ..models import SEV_INFO, SEV_NOTICE, SEV_WARN
from ..util import (
    count_lines,
    frontmost_app,
    guess_language,
    is_code_file,
    looks_like_code,
    normalize_code,
    read_text_safe,
    redact,
    run,
    sha256_text,
)
from .base import Collector

BROWSERS = {"safari", "google chrome", "chrome", "firefox", "arc", "brave browser",
            "microsoft edge", "opera", "vivaldi", "zen browser"}
AI_CHAT = {"claude", "chatgpt", "gemini", "copilot", "perplexity", "poe", "ollama"}
EDITORS = {"code", "visual studio code", "cursor", "pycharm", "intellij idea", "webstorm",
           "xcode", "sublime text", "zed", "neovim", "vim", "emacs", "android studio",
           "windsurf", "antigravity"}
TERMINALS = {"terminal", "iterm2", "iterm", "warp", "alacritty", "kitty", "hyper", "ghostty"}
MESSAGING = {"slack", "discord", "telegram", "whatsapp", "messages", "microsoft teams", "zoom"}

CANDIDATE_REFRESH = 60.0
MAX_ORIGIN_CANDIDATES = 250
MAX_ORIGIN_BYTES = 4 * 1024 * 1024


def app_category(app: Optional[str]) -> str:
    if not app:
        return "unknown"
    a = app.strip().lower()
    if a in BROWSERS:
        return "browser"
    if a in AI_CHAT:
        return "ai_assistant"
    if a in EDITORS:
        return "editor"
    if a in TERMINALS:
        return "terminal"
    if a in MESSAGING:
        return "messaging"
    return "other"


class ClipboardCollector(Collector):
    name = "clipboard"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.interval = ctx.cfg.clipboard_interval
        self._last_hash: Optional[str] = None
        self._candidates: List[str] = []
        self._candidates_at = 0.0
        self._changes = 0

    def setup(self) -> None:
        rc, _, _ = run(["pbpaste"], timeout=5)
        if rc != 0:
            self.emit(
                "collector.unavailable",
                "pbpaste is unavailable — clipboard monitoring is OFF",
                severity=SEV_WARN,
            )

    def poll(self) -> None:
        rc, text, _ = run(["pbpaste"], timeout=5)
        if rc != 0 or not text:
            return
        digest_raw = sha256_text(text)
        if digest_raw == self._last_hash:
            return
        self._last_hash = digest_raw
        self._changes += 1

        normalized = normalize_code(text)
        if len(normalized) < self.cfg.min_paste_chars:
            return  # ignore trivial clipboard traffic

        app = frontmost_app() if self.cfg.enable_focus else None
        category = app_category(app)
        language = guess_language(text)
        code_like = looks_like_code(text)

        entry: Dict[str, Any] = {
            "sha256": sha256_text(normalized),
            "raw_sha256": digest_raw,
            "chars": len(text),
            "lines": count_lines(text),
            "language": language,
            "code_like": code_like,
            "source_app": app,
            "source_category": category,
            "source_zone": "external" if category in ("browser", "ai_assistant", "messaging")
                            else "local",
            "_normalized": normalized,
            "_at": time.time(),
        }
        if self.cfg.clipboard_preview_chars > 0:
            entry["preview"] = redact(text, self.cfg.clipboard_preview_chars)

        origin = self._find_origin(normalized) if code_like else None
        if origin:
            entry["origin_path"] = origin

        self.ctx.clipboard.add(entry)

        severity = SEV_INFO
        if code_like and entry["source_zone"] == "external":
            severity = SEV_NOTICE
        if origin and not self.ctx.in_project(origin):
            severity = SEV_WARN

        summary = (
            f"copied {entry['lines']} line(s) of "
            f"{language if language != 'unknown' else 'text'}"
            f" from {app or 'an unidentified app'}"
        )
        if origin:
            summary += f" — matches {_display(origin)}"

        payload = {k: v for k, v in entry.items() if not k.startswith("_")}
        self.emit("clipboard.copy", summary, severity=severity, **payload)

    # -- origin search ---------------------------------------------------

    def _refresh_candidates(self) -> None:
        """Recently-touched code files outside the submission."""
        now = time.time()
        if now - self._candidates_at < CANDIDATE_REFRESH and self._candidates:
            return
        self._candidates_at = now

        roots: List[str] = list(self.cfg.sensitive_roots)
        for p in self.cfg.project_paths:
            parent = os.path.dirname(p)
            if parent and parent not in roots:
                roots.append(parent)

        found: List[tuple[float, str]] = []
        for root in roots:
            if not os.path.isdir(root):
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                if self.ctx.is_excluded(dirpath + "/"):
                    dirnames[:] = []
                    continue
                dirnames[:] = [d for d in dirnames
                               if not self.ctx.is_excluded(os.path.join(dirpath, d) + "/")]
                if len(found) > MAX_ORIGIN_CANDIDATES * 4:
                    break
                for fn in filenames:
                    path = os.path.join(dirpath, fn)
                    if self.ctx.in_project(path) or not is_code_file(path):
                        continue
                    try:
                        st = os.stat(path)
                    except OSError:
                        continue
                    if st.st_size > self.cfg.max_text_match_bytes:
                        continue
                    found.append((st.st_mtime, path))
        found.sort(reverse=True)
        self._candidates = [p for _, p in found[:MAX_ORIGIN_CANDIDATES]]

    def _find_origin(self, normalized: str) -> Optional[str]:
        self._refresh_candidates()
        budget = MAX_ORIGIN_BYTES
        for path in self._candidates:
            if budget <= 0:
                break
            text = read_text_safe(path, self.cfg.max_text_match_bytes)
            if not text:
                continue
            budget -= len(text)
            if normalized in normalize_code(text):
                return path
        return None

    def teardown(self) -> None:
        self.emit(
            "clipboard.summary",
            f"{self._changes} clipboard change(s) observed",
            changes=self._changes,
        )


def _display(path: str) -> str:
    home = os.path.expanduser("~")
    return path.replace(home, "~", 1) if path.startswith(home) else path
