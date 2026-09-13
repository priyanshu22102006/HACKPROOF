"""Small helpers: hashing, time, subprocess, macOS metadata."""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# time
# --------------------------------------------------------------------------


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime] = None) -> str:
    return (dt or now_utc()).astimezone(timezone.utc).isoformat(timespec="milliseconds")


def parse_iso(s: str) -> datetime:
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def human_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h}h {m}m"
    if m:
        return f"{m}m {s}s"
    return f"{s}s"


# --------------------------------------------------------------------------
# hashing
# --------------------------------------------------------------------------


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_file(path: str, chunk: int = 1 << 20) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            while True:
                block = fh.read(chunk)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def short(h: Optional[str], n: int = 12) -> str:
    return (h or "")[:n]


# --------------------------------------------------------------------------
# subprocess
# --------------------------------------------------------------------------


def run(cmd: List[str], cwd: Optional[str] = None, timeout: int = 20,
        env: Optional[Dict[str, str]] = None) -> Tuple[int, str, str]:
    """Run a command, never raise. Returns (rc, stdout, stderr)."""
    try:
        p = subprocess.run(
            cmd, cwd=cwd, timeout=timeout, capture_output=True, text=True,
            errors="replace", env=env,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"not found: {cmd[0]}"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as exc:  # pragma: no cover - defensive
        return 1, "", str(exc)


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


# --------------------------------------------------------------------------
# text / code heuristics
# --------------------------------------------------------------------------

CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".kt", ".c", ".h", ".cc", ".cpp",
    ".hpp", ".cs", ".go", ".rs", ".rb", ".php", ".swift", ".m", ".mm", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".sql", ".r", ".jl", ".dart", ".lua", ".vue",
    ".svelte", ".html", ".css", ".scss", ".sass", ".less", ".json", ".yaml", ".yml",
    ".toml", ".ipynb", ".proto", ".graphql", ".tf", ".dockerfile", ".md",
}

ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar"}

_TEXT_HINT = re.compile(rb"[\x00]")


def is_code_file(path: str) -> bool:
    base = os.path.basename(path).lower()
    if base in {"dockerfile", "makefile", "rakefile", "gemfile", "procfile"}:
        return True
    _, ext = os.path.splitext(base)
    return ext in CODE_EXTENSIONS


def is_archive(path: str) -> bool:
    _, ext = os.path.splitext(path.lower())
    return ext in ARCHIVE_EXTENSIONS


def read_text_safe(path: str, max_bytes: int) -> Optional[str]:
    """Read a file as text if it is small enough and looks like text."""
    try:
        size = os.path.getsize(path)
        if size == 0 or size > max_bytes:
            return None
        with open(path, "rb") as fh:
            raw = fh.read(max_bytes)
        if _TEXT_HINT.search(raw[:4096]):
            return None
        return raw.decode("utf-8", "replace")
    except (OSError, PermissionError):
        return None


def normalize_code(text: str) -> str:
    """Whitespace-insensitive normalisation used for paste/copy matching.

    Collapses runs of whitespace so that an auto-formatted paste still
    matches the clipboard content it came from.
    """
    return re.sub(r"\s+", " ", text).strip()


def count_lines(text: str) -> int:
    return text.count("\n") + (1 if text and not text.endswith("\n") else 0)


def guess_language(text: str) -> str:
    t = text.lstrip()[:2000]
    checks = [
        ("python", (r"^\s*(def |class |import |from \w+ import)", )),
        ("javascript", (r"\b(const|let|var)\s+\w+\s*=", r"=>", r"\bfunction\b")),
        ("typescript", (r":\s*(string|number|boolean)\b", r"\binterface\b")),
        ("java", (r"\bpublic\s+(static\s+)?(class|void)\b",)),
        ("go", (r"\bfunc\s+\w+\(", r"\bpackage\s+\w+")),
        ("rust", (r"\bfn\s+\w+\(", r"\blet\s+mut\b")),
        ("sql", (r"\bSELECT\b.*\bFROM\b",)),
        ("html", (r"<\s*(html|div|span|body)\b",)),
        ("shell", (r"^#!/(bin|usr)", r"\becho\b")),
    ]
    for lang, patterns in checks:
        for pat in patterns:
            if re.search(pat, t, re.IGNORECASE | re.MULTILINE):
                return lang
    return "unknown"


def looks_like_code(text: str) -> bool:
    if len(text) < 40:
        return False
    if guess_language(text) != "unknown":
        return True
    symbols = sum(text.count(c) for c in "{};()=<>[]")
    return symbols / max(1, len(text)) > 0.02


def redact(text: str, limit: int) -> str:
    """A bounded, single-line preview. Never the whole clipboard."""
    flat = " ".join(text.split())
    if len(flat) <= limit:
        return flat
    return flat[:limit] + f"… (+{len(flat) - limit} chars)"


# --------------------------------------------------------------------------
# macOS metadata
# --------------------------------------------------------------------------


def xattr_where_from(path: str) -> List[str]:
    """Origin URLs macOS records on downloaded files."""
    rc, out, _ = run(["xattr", "-p", "com.apple.metadata:kMDItemWhereFroms", path], timeout=5)
    if rc != 0 or not out.strip():
        return []
    # xattr prints a hex dump; re-read as raw bytes via python's os.getxattr when possible
    try:
        raw = os.getxattr(path, "com.apple.metadata:kMDItemWhereFroms")  # type: ignore[attr-defined]
        val = plistlib.loads(raw)
        if isinstance(val, list):
            return [str(v) for v in val if v]
        return [str(val)]
    except Exception:
        # Fall back to parsing the hex dump.
        hexstr = re.sub(r"[^0-9a-fA-F]", "", out)
        try:
            val = plistlib.loads(bytes.fromhex(hexstr))
            if isinstance(val, list):
                return [str(v) for v in val if v]
        except Exception:
            pass
    return []


def xattr_quarantine(path: str) -> Optional[str]:
    try:
        raw = os.getxattr(path, "com.apple.quarantine")  # type: ignore[attr-defined]
        return raw.decode("utf-8", "replace")
    except Exception:
        return None


_FRONTMOST_SCRIPT = (
    'tell application "System Events" to get name of first application process '
    "whose frontmost is true"
)


def frontmost_app(timeout: int = 3) -> Optional[str]:
    """Name of the focused application. Requires Accessibility permission.

    Returns None when unavailable — this is optional signal, never fatal.
    """
    rc, out, _ = run(["osascript", "-e", _FRONTMOST_SCRIPT], timeout=timeout)
    if rc == 0 and out.strip():
        return out.strip()
    return None


# --------------------------------------------------------------------------
# misc
# --------------------------------------------------------------------------


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path


def monotonic() -> float:
    return time.monotonic()


def expand(path: str) -> str:
    return os.path.abspath(os.path.expanduser(os.path.expandvars(path)))
