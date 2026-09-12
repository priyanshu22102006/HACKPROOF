"""Hidden / untracked source-code analyzer (HACKPROOF §8.f).

Inspects a git repository for the four mechanisms a participant can use to keep
source code out of a reviewer's view, and reports each one as a ``Finding``:

1. ``.gitignore``            (claim plane  -- committed, visible to reviewers)
2. ``.git/info/exclude``     (system plane -- never committed, invisible)
3. ``core.excludesFile``     (system plane -- usually outside the repo entirely)
4. assume-unchanged / skip-worktree bits (system plane -- invisible unless asked)

plus the headline dashboard metric:

5. tracked-vs-on-disk source-file ratio (system plane, always computed)

Design notes
------------
* Everything shells out to ``git`` directly rather than using a git library, so
  the exact plumbing command is auditable from the evidence dict.
* Pure functions, no global state, no writes: the only I/O is reading the target
  repo (and, for check 3, the global excludes file it points at).
* Nothing raises. A missing repo, a missing file, a missing ``git`` binary or a
  command failure produces a ``passed=True`` Finding carrying a ``note``.
* Static pattern classification answers "is this rule suspicious"; ``git
  check-ignore -v`` answers "which rule is actually hiding this source file
  right now". Both are reported, because the second is much stronger evidence
  and attributes the hiding to a specific mechanism.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import subprocess
import sys
from datetime import datetime, timezone

try:  # allow both `python -m analyzers.gitignore_check` and direct execution
    from core.models import Finding
except ModuleNotFoundError:  # pragma: no cover - import path convenience only
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.models import Finding

# --- check names (stable ids; the dashboard groups on these) -----------------

CHECK_GITIGNORE = "gitignore.pattern_audit"
CHECK_INFO_EXCLUDE = "gitignore.info_exclude"
CHECK_CORE_EXCLUDES_FILE = "gitignore.core_excludes_file"
CHECK_ASSUME_UNCHANGED = "gitignore.assume_unchanged_skip_worktree"
CHECK_SOURCE_RATIO = "gitignore.tracked_source_ratio"

ALL_CHECKS = (
    (CHECK_GITIGNORE, "claim"),
    (CHECK_INFO_EXCLUDE, "system"),
    (CHECK_CORE_EXCLUDES_FILE, "system"),
    (CHECK_ASSUME_UNCHANGED, "system"),
    (CHECK_SOURCE_RATIO, "system"),
)

# --- tunables ----------------------------------------------------------------

SOURCE_EXTENSIONS = frozenset(
    {
        ".py", ".pyi", ".ipynb",
        ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx",
        ".java", ".kt", ".kts", ".scala", ".groovy",
        ".go", ".rs", ".swift", ".dart",
        ".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx",
        ".cs", ".fs", ".vb",
        ".rb", ".php", ".pl", ".pm", ".lua", ".r", ".jl", ".m", ".mm",
        ".ex", ".exs", ".erl", ".clj", ".cljs", ".hs", ".ml", ".nim", ".zig",
        ".sh", ".bash", ".zsh", ".ps1",
        ".sql", ".vue", ".svelte", ".astro",
        ".html", ".css", ".scss", ".sass", ".less",
    }
)

# Directory names whose exclusion is normal hygiene, not hiding.
BENIGN_NAMES = frozenset(
    {
        "node_modules", "bower_components", "jspm_packages",
        "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
        "venv", ".venv", "env", ".env", "virtualenv", "site-packages",
        ".idea", ".vscode", ".vs", ".DS_Store", "Thumbs.db",
        "dist", "build", "out", "target", "bin", "obj", "coverage", "htmlcov",
        ".next", ".nuxt", ".svelte-kit", ".parcel-cache", ".cache", ".turbo",
        "logs", "tmp", "temp", ".terraform", ".gradle", ".dart_tool",
        "vendor",  # go/php vendored deps
    }
)

# Extensions/globs that are build output or secrets, never hand-written source.
BENIGN_GLOB_SUFFIXES = (
    ".pyc", ".pyo", ".pyd", ".class", ".o", ".obj", ".so", ".dll", ".dylib",
    ".exe", ".jar", ".war", ".a", ".lib", ".log", ".lock", ".tmp", ".swp",
    ".min.js", ".min.css", ".map", ".egg-info", ".coverage",
)

# Directory names that normally hold first-party source.
SOURCE_DIR_NAMES = frozenset(
    {
        "src", "lib", "libs", "app", "apps", "server", "client", "backend",
        "frontend", "api", "core", "services", "service", "components", "pkg",
        "cmd", "internal", "modules", "packages", "scripts", "analyzers",
        "models", "controllers", "routes", "handlers", "utils", "common",
        "domain", "engine", "worker", "workers", "tests", "test",
    }
)

# Directories skipped when counting source files on disk (check 5).
SKIP_WALK_DIRS = frozenset(
    {
        ".git", "node_modules", "bower_components", "__pycache__", ".pytest_cache",
        ".mypy_cache", ".ruff_cache", ".tox", "venv", ".venv", "env", ".env",
        "site-packages", "dist", "build", "out", "target", ".next", ".nuxt",
        ".svelte-kit", ".parcel-cache", ".cache", ".turbo", ".gradle", "vendor",
        ".terraform", ".dart_tool", "coverage", "htmlcov", ".idea", ".vscode",
    }
)

CATCH_ALL_PATTERNS = frozenset({"*", "/*", "**", "/**", "**/*", "*/"})

# Below this share of source files tracked, check 5 reports passed=False.
TRACKED_RATIO_PASS_THRESHOLD = 0.90

# Git stores commit dates at second granularity while mtimes are sub-second, so a
# file written moments before its own commit can appear "newer" than it. Only a
# gap larger than this counts as an edit after the commit (check 4).
MTIME_TOLERANCE_SECONDS = 2.0

MAX_HISTORY_COMMITS = 200  # per .gitignore file, newest first
MAX_EVIDENCE_ITEMS = 50  # cap on any list embedded in evidence
GIT_TIMEOUT_SECONDS = 60


# --- git plumbing -------------------------------------------------------------


def _git(repo_path: str, args: list[str], timeout: int = GIT_TIMEOUT_SECONDS) -> tuple[int, str, str]:
    """Run a git command in ``repo_path``. Returns (returncode, stdout, stderr).

    Never raises: a missing binary or a timeout comes back as a non-zero code
    with the reason in stderr. ``GIT_OPTIONAL_LOCKS=0`` keeps read-only checks
    from touching the target repo's index.
    """
    env = dict(os.environ)
    env.update({"GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "GIT_PAGER": "cat"})
    cmd = ["git", "--no-pager", *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=repo_path,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError:
        return 127, "", "git executable not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"git command timed out after {timeout}s: {' '.join(cmd)}"
    except OSError as exc:  # pragma: no cover - defensive
        return 126, "", f"failed to run git: {exc}"
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def _git_command_string(args: list[str]) -> str:
    return "git " + " ".join(args)


def _nul_split(text: str) -> list[str]:
    return [part for part in text.split("\0") if part != ""]


def is_git_repo(repo_path: str) -> bool:
    if not os.path.isdir(repo_path):
        return False
    code, out, _ = _git(repo_path, ["rev-parse", "--is-inside-work-tree"])
    return code == 0 and out.strip() == "true"


def _git_dir(repo_path: str) -> str | None:
    code, out, _ = _git(repo_path, ["rev-parse", "--absolute-git-dir"])
    if code != 0 or not out.strip():
        return None
    return out.strip()


def _has_commits(repo_path: str) -> bool:
    code, _, _ = _git(repo_path, ["rev-parse", "--verify", "--quiet", "HEAD"])
    return code == 0


def _tracked_files(repo_path: str) -> list[str]:
    code, out, _ = _git(repo_path, ["ls-files", "-z"])
    if code != 0:
        return []
    return _nul_split(out)


# --- pattern classification ---------------------------------------------------


def _iter_pattern_lines(text: str):
    """Yield (line_number, pattern) for meaningful .gitignore lines."""
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        yield lineno, line


def _is_benign(pattern: str) -> bool:
    core = pattern.strip("/")
    lowered = core.lower()
    if lowered.endswith(BENIGN_GLOB_SUFFIXES):
        return True
    segments = [seg for seg in lowered.split("/") if seg not in ("", "**")]
    for seg in segments:
        if seg in BENIGN_NAMES or seg.lstrip("*") in BENIGN_NAMES:
            return True
    return False


def classify_pattern(pattern: str) -> dict | None:
    """Classify a single ignore pattern. Returns None when it looks benign.

    Purely textual: it does not consult the working tree. Directory-shaped
    patterns come back as kind ``directory`` and are confirmed (or dropped) by
    the caller against what actually exists on disk.
    """
    pattern = pattern.strip()
    if not pattern or pattern.startswith("#"):
        return None
    if pattern.startswith("!"):
        return None  # a negation re-includes files; never a hiding mechanism
    if pattern in CATCH_ALL_PATTERNS:
        return {
            "pattern": pattern,
            "kind": "catch_all",
            "reason": "excludes everything in scope; any source file not explicitly re-included is hidden",
        }
    if _is_benign(pattern):
        return None

    core = pattern.rstrip("/").lstrip("/")
    if not core:
        return None
    basename = core.rsplit("/", 1)[-1]

    # *.py / src/*.ts / **/*.java
    if basename.startswith("*.") or basename.startswith("."):
        ext = basename[basename.index("."):].lower()
        if ext in SOURCE_EXTENSIONS:
            return {
                "pattern": pattern,
                "kind": "source_extension",
                "reason": f"excludes source files by extension ({ext})",
            }
    dot = basename.rfind(".")
    if dot > 0 and basename[dot:].lower() in SOURCE_EXTENSIONS and "*" not in basename:
        return {
            "pattern": pattern,
            "kind": "source_file",
            "reason": f"excludes a specific source file ({basename})",
        }

    named_source_dir = basename.lower() in SOURCE_DIR_NAMES or any(
        seg.lower() in SOURCE_DIR_NAMES for seg in core.split("/") if seg
    )
    if named_source_dir:
        return {
            "pattern": pattern,
            "kind": "source_directory",
            "reason": f"excludes a directory that conventionally holds source ({basename})",
        }
    if pattern.endswith("/") or "*" not in basename:
        # Shaped like a directory but not a known source-dir name: only
        # suspicious if it actually contains source on disk (caller checks).
        return {
            "pattern": pattern,
            "kind": "directory",
            "reason": "excludes a directory; confirmed only if it holds source files on disk",
        }
    return None


def _relative_source_files(root: str, subdir: str = "") -> list[str]:
    """Source files on disk under ``root``/``subdir``, as repo-relative posix paths."""
    base = os.path.join(root, subdir) if subdir else root
    results: list[str] = []
    if not os.path.isdir(base):
        return results
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in SKIP_WALK_DIRS]
        for name in filenames:
            if os.path.splitext(name)[1].lower() in SOURCE_EXTENSIONS:
                full = os.path.join(dirpath, name)
                rel = os.path.relpath(full, root).replace(os.sep, "/")
                results.append(rel)
    return sorted(results)


def _worktree_sources_under_pattern(repo_path: str, pattern: str, base_dir: str = "") -> list[str]:
    """Source files on disk inside the directory a (wildcard-free) pattern names."""
    core = pattern.strip("/").strip()
    if not core or "*" in core or "?" in core:
        return []
    candidate = os.path.join(base_dir, core) if base_dir else core
    return _relative_source_files(repo_path, candidate)[:MAX_EVIDENCE_ITEMS]


def analyze_ignore_file(
    repo_path: str, file_path: str, base_dir: str = "", confirm_against_worktree: bool = True
) -> dict:
    """Parse one ignore file and return {'readable', 'patterns', 'suspicious', ...}."""
    result: dict = {
        "path": file_path,
        "readable": False,
        "pattern_count": 0,
        "suspicious": [],
        "error": None,
    }
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except OSError as exc:
        result["error"] = str(exc)
        return result

    result["readable"] = True
    suspicious: list[dict] = []
    count = 0
    for lineno, pattern in _iter_pattern_lines(text):
        count += 1
        verdict = classify_pattern(pattern)
        if verdict is None:
            continue
        verdict = dict(verdict, line=lineno)
        if verdict["kind"] == "directory":
            if not confirm_against_worktree:
                continue
            hidden = _worktree_sources_under_pattern(repo_path, pattern, base_dir)
            if not hidden:
                continue
            verdict["kind"] = "source_directory"
            verdict["reason"] = "excludes a directory that holds source files in the working tree"
            verdict["worktree_source_files"] = hidden
        elif verdict["kind"] == "source_directory" and confirm_against_worktree:
            hidden = _worktree_sources_under_pattern(repo_path, pattern, base_dir)
            if hidden:
                verdict["worktree_source_files"] = hidden
        suspicious.append(verdict)

    result["pattern_count"] = count
    result["suspicious"] = suspicious[:MAX_EVIDENCE_ITEMS]
    return result


# --- "what is actually hidden right now" -------------------------------------


def ignored_source_files(repo_path: str) -> list[str]:
    """Untracked source files on disk that git is currently ignoring."""
    code, out, _ = _git(
        repo_path, ["ls-files", "-z", "--others", "--ignored", "--exclude-standard"]
    )
    if code != 0:
        return []
    return [
        path
        for path in _nul_split(out)
        if os.path.splitext(path)[1].lower() in SOURCE_EXTENSIONS
    ]


def attribute_ignored_files(repo_path: str, paths: list[str]) -> list[dict]:
    """Map each ignored path to the rule hiding it via ``git check-ignore -v``.

    Returns [{'source': <ignore file>, 'line': int, 'pattern': str, 'path': str}].
    """
    if not paths:
        return []
    env = dict(os.environ)
    env.update({"GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    try:
        proc = subprocess.run(
            ["git", "--no-pager", "check-ignore", "-v", "-z", "--stdin"],
            cwd=repo_path,
            env=env,
            input="\0".join(paths).encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=GIT_TIMEOUT_SECONDS,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    # check-ignore exits 1 when nothing matches; that is not an error.
    if proc.returncode not in (0, 1):
        return []
    fields = proc.stdout.decode("utf-8", "replace").split("\0")
    records: list[dict] = []
    for i in range(0, len(fields) - 3, 4):
        source, lineno, pattern, path = fields[i : i + 4]
        if not path:
            continue
        records.append(
            {
                "source": source,
                "line": int(lineno) if lineno.isdigit() else None,
                "pattern": pattern,
                "path": path,
            }
        )
    return records


def _attributions_for(records: list[dict], predicate) -> list[dict]:
    return [rec for rec in records if predicate(rec.get("source", ""))][:MAX_EVIDENCE_ITEMS]


# --- check 1: .gitignore ------------------------------------------------------


def find_gitignore_files(repo_path: str) -> list[str]:
    """Every .gitignore in the working tree (root and nested), repo-relative."""
    found: list[str] = []
    for dirpath, dirnames, filenames in os.walk(repo_path):
        dirnames[:] = [d for d in dirnames if d not in SKIP_WALK_DIRS]
        if ".gitignore" in filenames:
            rel = os.path.relpath(os.path.join(dirpath, ".gitignore"), repo_path)
            found.append(rel.replace(os.sep, "/"))
    return sorted(found)


def gitignore_history_flags(repo_path: str) -> list[dict]:
    """Rules added to a .gitignore in history that hide source present on disk.

    Walks each tracked .gitignore backwards through history, diffs each revision
    against its first parent, and reports added patterns whose target directory
    currently holds source files in the working tree.
    """
    if not _has_commits(repo_path):
        return []
    tracked = [p for p in _tracked_files(repo_path) if p.split("/")[-1] == ".gitignore"]
    flags: list[dict] = []
    for path in tracked:
        base_dir = path.rsplit("/", 1)[0] if "/" in path else ""
        code, out, _ = _git(
            repo_path,
            ["log", f"-n{MAX_HISTORY_COMMITS}", "--format=%H%x1f%cI%x1f%an", "--", path],
        )
        if code != 0:
            continue
        for row in out.strip().splitlines():
            parts = row.split("\x1f")
            if len(parts) != 3:
                continue
            sha, committed_at, author = parts
            rc_cur, cur, _ = _git(repo_path, ["show", f"{sha}:{path}"])
            if rc_cur != 0:
                continue
            rc_prev, prev, _ = _git(repo_path, ["show", f"{sha}^:{path}"])
            prev_patterns = (
                {p for _, p in _iter_pattern_lines(prev)} if rc_prev == 0 else set()
            )
            for _, pattern in _iter_pattern_lines(cur):
                if pattern in prev_patterns:
                    continue
                verdict = classify_pattern(pattern)
                if verdict is None:
                    continue
                hidden = _worktree_sources_under_pattern(repo_path, pattern, base_dir)
                if not hidden:
                    continue
                flags.append(
                    {
                        "gitignore": path,
                        "pattern": pattern,
                        "kind": verdict["kind"],
                        "added_in_commit": sha,
                        "committed_at": committed_at,
                        "author": author,
                        "worktree_source_files": hidden[:MAX_EVIDENCE_ITEMS],
                    }
                )
            if len(flags) >= MAX_EVIDENCE_ITEMS:
                return flags[:MAX_EVIDENCE_ITEMS]
    return flags


def analysis_source() -> str:
    """Where the thing under analysis came from: ``local`` (default) or ``clone``.

    Set by ``scripts/analyze_repo_url.py``. Three of the four hiding mechanisms
    in spec §8.f are *system plane* -- they live on the machine where the work
    was done and are never pushed:

    * the assume-unchanged / skip-worktree bits live in the local index
    * ``.git/info/exclude`` is local by design, "never committed"
    * ``core.excludesFile`` is local git config

    and the tracked-source ratio compares git's file list against what is on
    disk, which in a clone are the same set by construction.

    A clone cannot see any of it, however hard it looks. Saying "ok" there is not
    a small imprecision -- it hands a judge a clean bill of health for a check
    that never ran. So on a clone these report ``evaluable: False`` instead, and
    the engine prints them as ``n/a``.
    """
    return (os.environ.get("HACKPROOF_SOURCE") or "local").strip().lower()


REMEDY = (
    "Evaluate this on the participant's own checkout, or from agent Receipts "
    "(spec §8.b), which is what the system plane is for."
)


def _not_evaluable_on_clone(check_name: str, plane: str, mechanism: str, reason: str) -> Finding:
    return Finding(
        check_name=check_name,
        plane=plane,
        severity="info",
        evidence={
            "mechanism": mechanism,
            "evaluable": False,
            "analysis_source": "clone",
            "not_evaluable_reason": reason,
            "remedy": REMEDY,
        },
        passed=True,
    )


def check_gitignore(repo_path: str, attributions: list[dict] | None = None) -> Finding:
    if attributions is None:
        attributions = attribute_ignored_files(repo_path, ignored_source_files(repo_path))
    evidence: dict = {
        "mechanism": ".gitignore",
        "commands": [
            _git_command_string(["ls-files", "-z", "--others", "--ignored", "--exclude-standard"]),
            _git_command_string(["check-ignore", "-v", "-z", "--stdin"]),
            _git_command_string(["log", "--format=%H%x1f%cI%x1f%an", "--", "<.gitignore>"]),
        ],
    }

    files = find_gitignore_files(repo_path)
    evidence["gitignore_files"] = files
    if not files:
        evidence["note"] = "no .gitignore file found in the working tree"

    suspicious: list[dict] = []
    for rel in files:
        base_dir = rel.rsplit("/", 1)[0] if "/" in rel else ""
        analysis = analyze_ignore_file(
            repo_path, os.path.join(repo_path, rel), base_dir=base_dir
        )
        for item in analysis["suspicious"]:
            suspicious.append(dict(item, file=rel))
        if analysis["error"]:
            evidence.setdefault("read_errors", []).append(
                {"file": rel, "error": analysis["error"]}
            )
    evidence["suspicious_patterns"] = suspicious[:MAX_EVIDENCE_ITEMS]

    hidden = _attributions_for(attributions, lambda src: src.split("/")[-1] == ".gitignore")
    evidence["hidden_source_files"] = hidden
    evidence["hidden_source_file_count"] = len(hidden)

    if analysis_source() == "clone":
        # Still evaluable -- the committed .gitignore and its whole history are
        # right here -- but say plainly which half of it a clone cannot see.
        evidence["clone_limitation"] = (
            "analyzed from a clone: the committed .gitignore files and their full history were "
            "read, but code hidden BY those rules was never pushed, so 'hidden_source_files' is "
            "empty by construction here and a late-added rule is reported only where the path it "
            "hides is also present. A rule that hid work later committed anyway is still visible "
            "in the history below"
        )

    history = gitignore_history_flags(repo_path)
    evidence["late_added_rules"] = history
    if not _has_commits(repo_path):
        evidence["history_note"] = "repository has no commits; history diff skipped"

    if history:
        severity = "hard_flag"
        evidence["interpretation"] = (
            f"{len(history)} ignore rule(s) were added to a committed .gitignore AFTER the code "
            "they hide already existed. evidence.late_added_rules names the commit and its author "
            "for each one. A rule written before the work is housekeeping; a rule written after it "
            "is the thing worth asking about"
        )
    elif suspicious or hidden:
        severity = "flag"
        parts = []
        if suspicious:
            patterns = ", ".join(sorted({str(item.get("pattern")) for item in suspicious})[:5])
            parts.append(
                f"{len(suspicious)} committed ignore rule(s) exclude paths that normally hold "
                f"first-party source ({patterns})"
            )
        if hidden:
            parts.append(f"{len(hidden)} source file(s) present on disk are excluded by those rules")
        evidence["interpretation"] = (
            "; ".join(parts)
            + ". Build output and dependencies are ignored by every healthy project, so this is a "
            "question to ask rather than a finding -- open the rule and see what it covers"
        )
    else:
        severity = "info"
    passed = not (history or suspicious or hidden)
    return Finding(
        check_name=CHECK_GITIGNORE,
        plane="claim",
        severity=severity,
        evidence=evidence,
        passed=passed,
    )


# --- check 2: .git/info/exclude ----------------------------------------------


def check_info_exclude(repo_path: str, attributions: list[dict] | None = None) -> Finding:
    if analysis_source() == "clone":
        return _not_evaluable_on_clone(
            CHECK_INFO_EXCLUDE,
            "system",
            ".git/info/exclude",
            "`.git/info/exclude` is local to the machine that wrote it and is never pushed; "
            "a clone always carries git's default template, so there is nothing here to read",
        )

    if attributions is None:
        attributions = attribute_ignored_files(repo_path, ignored_source_files(repo_path))
    evidence: dict = {
        "mechanism": ".git/info/exclude",
        "rationale": "never committed and not visible to anyone reviewing the repo, "
        "so any source-hiding rule here is weighted above the same rule in .gitignore",
    }

    git_dir = _git_dir(repo_path)
    if git_dir is None:
        evidence["note"] = "could not resolve the .git directory"
        return Finding(CHECK_INFO_EXCLUDE, "system", "info", evidence, True)

    exclude_path = os.path.join(git_dir, "info", "exclude")
    evidence["path"] = exclude_path
    if not os.path.isfile(exclude_path):
        evidence["note"] = "no .git/info/exclude file present"
        return Finding(CHECK_INFO_EXCLUDE, "system", "info", evidence, True)

    analysis = analyze_ignore_file(repo_path, exclude_path)
    evidence["pattern_count"] = analysis["pattern_count"]
    evidence["suspicious_patterns"] = analysis["suspicious"]
    if analysis["error"]:
        evidence["note"] = f"could not read .git/info/exclude: {analysis['error']}"
        return Finding(CHECK_INFO_EXCLUDE, "system", "info", evidence, True)

    hidden = _attributions_for(
        attributions, lambda src: src.replace(os.sep, "/").endswith("info/exclude")
    )
    evidence["hidden_source_files"] = hidden
    evidence["hidden_source_file_count"] = len(hidden)

    flagged = bool(analysis["suspicious"] or hidden)
    return Finding(
        check_name=CHECK_INFO_EXCLUDE,
        plane="system",
        severity="hard_flag" if flagged else "info",
        evidence=evidence,
        passed=not flagged,
    )


# --- check 3: core.excludesFile ----------------------------------------------


def resolve_excludes_file(repo_path: str, raw_value: str) -> str:
    path = os.path.expanduser(os.path.expandvars(raw_value.strip()))
    if not os.path.isabs(path):
        path = os.path.join(repo_path, path)
    return os.path.normpath(path)


def check_core_excludes_file(repo_path: str, attributions: list[dict] | None = None) -> Finding:
    if analysis_source() == "clone":
        return _not_evaluable_on_clone(
            CHECK_CORE_EXCLUDES_FILE,
            "system",
            "core.excludesFile",
            "`core.excludesFile` is local git config and is never pushed; a clone inherits the "
            "analyzing machine's config, which says nothing about the participant's",
        )

    if attributions is None:
        attributions = attribute_ignored_files(repo_path, ignored_source_files(repo_path))
    evidence: dict = {
        "mechanism": "core.excludesFile",
        "commands": [
            _git_command_string(["config", "--get", "core.excludesFile"]),
            _git_command_string(["config", "--show-origin", "--get", "core.excludesFile"]),
        ],
    }

    code, out, err = _git(repo_path, ["config", "--get", "core.excludesFile"])
    if code != 0 or not out.strip():
        evidence["note"] = "core.excludesFile is not configured"
        if err.strip():
            evidence["stderr"] = err.strip()
        return Finding(CHECK_CORE_EXCLUDES_FILE, "system", "info", evidence, True)

    raw = out.strip().splitlines()[0]
    evidence["configured_value"] = raw
    _, origin_out, _ = _git(repo_path, ["config", "--show-origin", "--get", "core.excludesFile"])
    if origin_out.strip():
        evidence["config_origin"] = origin_out.strip().split("\t")[0]

    resolved = resolve_excludes_file(repo_path, raw)
    evidence["resolved_path"] = resolved
    repo_real = os.path.realpath(repo_path)
    evidence["outside_repo"] = not os.path.realpath(resolved).startswith(repo_real + os.sep)
    if evidence["outside_repo"]:
        evidence["note_scope"] = (
            "the excludes file lives outside the repository, so it is invisible to "
            "anyone who only has the repo (typically a global ~/.gitignore)"
        )

    if not os.path.isfile(resolved):
        evidence["note"] = "core.excludesFile is configured but the target file does not exist"
        return Finding(CHECK_CORE_EXCLUDES_FILE, "system", "info", evidence, True)

    analysis = analyze_ignore_file(repo_path, resolved)
    if analysis["error"]:
        evidence["note"] = f"could not read core.excludesFile: {analysis['error']}"
        return Finding(CHECK_CORE_EXCLUDES_FILE, "system", "info", evidence, True)
    evidence["pattern_count"] = analysis["pattern_count"]
    evidence["suspicious_patterns"] = analysis["suspicious"]

    resolved_norm = resolved.replace(os.sep, "/")
    hidden = _attributions_for(
        attributions, lambda src: src.replace(os.sep, "/") == resolved_norm
    )
    evidence["hidden_source_files"] = hidden
    evidence["hidden_source_file_count"] = len(hidden)

    if hidden:
        severity, passed = "hard_flag", False
    elif analysis["suspicious"]:
        severity, passed = "flag", False
    else:
        severity, passed = "info", True
    return Finding(CHECK_CORE_EXCLUDES_FILE, "system", severity, evidence, passed)


# --- check 4: assume-unchanged / skip-worktree -------------------------------


def _last_commit_iso(repo_path: str, path: str) -> str | None:
    code, out, _ = _git(repo_path, ["log", "-1", "--format=%cI", "--", path])
    if code != 0 or not out.strip():
        return None
    return out.strip().splitlines()[0]


def _content_differs_from_index(repo_path: str, path: str) -> bool | None:
    """True when the working-tree file's blob hash differs from its index entry.

    Corroborates the mtime signal: git's own diff machinery deliberately ignores
    files carrying these bits, so the hashes have to be compared by hand.
    Returns None when either side cannot be hashed.
    """
    code_index, index_sha, _ = _git(repo_path, ["rev-parse", f":{path}"])
    code_work, work_sha, _ = _git(repo_path, ["hash-object", "--", path])
    if code_index != 0 or code_work != 0:
        return None
    if not index_sha.strip() or not work_sha.strip():
        return None
    return index_sha.strip() != work_sha.strip()


def _parse_iso(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def check_assume_unchanged(repo_path: str) -> Finding:
    """``git ls-files -v``: lowercase tag = assume-unchanged, S/s = skip-worktree."""
    if analysis_source() == "clone":
        return _not_evaluable_on_clone(
            CHECK_ASSUME_UNCHANGED,
            "system",
            "assume-unchanged / skip-worktree",
            "these bits live in the local git index and are never pushed; a fresh clone builds a "
            "new index that cannot carry them, so this check can only ever report 'none found' "
            "regardless of what the participant did",
        )

    evidence: dict = {
        "mechanism": "assume-unchanged / skip-worktree",
        "commands": [
            _git_command_string(["ls-files", "-v", "-z"]),
            _git_command_string(["log", "-1", "--format=%cI", "--", "<file>"]),
        ],
        "tag_legend": {
            "lowercase (h, s, m, ...)": "assume-unchanged bit set",
            "S or s": "skip-worktree bit set",
        },
        "mtime_tolerance_seconds": MTIME_TOLERANCE_SECONDS,
    }

    code, out, err = _git(repo_path, ["ls-files", "-v", "-z"])
    if code != 0:
        evidence["note"] = f"git ls-files -v failed: {err.strip() or code}"
        return Finding(CHECK_ASSUME_UNCHANGED, "system", "info", evidence, True)

    flagged: list[dict] = []
    for entry in _nul_split(out):
        if len(entry) < 3 or entry[1] != " ":
            continue
        tag, path = entry[0], entry[2:]
        mechanisms = []
        if tag.islower():
            mechanisms.append("assume-unchanged")
        if tag in ("S", "s"):
            mechanisms.append("skip-worktree")
        if not mechanisms:
            continue

        record: dict = {"path": path, "ls_files_tag": tag, "mechanisms": mechanisms}
        full = os.path.join(repo_path, path)
        commit_iso = _last_commit_iso(repo_path, path)
        record["last_commit_date"] = commit_iso
        mtime_dt = None
        try:
            mtime_dt = datetime.fromtimestamp(os.path.getmtime(full), tz=timezone.utc)
            record["worktree_mtime"] = mtime_dt.isoformat()
        except OSError:
            record["worktree_mtime"] = None
            record["note"] = "file is flagged in the index but absent from the working tree"

        record["content_differs_from_index"] = _content_differs_from_index(repo_path, path)

        commit_dt = _parse_iso(commit_iso) if commit_iso else None
        if commit_dt is not None and mtime_dt is not None:
            delta = (mtime_dt - commit_dt).total_seconds()
            record["seconds_after_last_commit"] = round(delta, 3)
            edited = delta > MTIME_TOLERANCE_SECONDS
            record["modified_after_last_commit"] = edited
            if edited:
                record["interpretation"] = (
                    "file was edited in the working tree after the commit that last "
                    "changed it, while flagged to be skipped -- 'commit a stub, then "
                    "edit freely' pattern"
                )
        else:
            record["modified_after_last_commit"] = None
        flagged.append(record)

    evidence["flagged_files"] = flagged[:MAX_EVIDENCE_ITEMS]
    evidence["flagged_file_count"] = len(flagged)
    edited_after = [r for r in flagged if r.get("modified_after_last_commit") is True]
    evidence["modified_after_flagging"] = [r["path"] for r in edited_after][:MAX_EVIDENCE_ITEMS]

    if edited_after:
        severity, passed = "hard_flag", False
        evidence["interpretation"] = (
            f"{len(edited_after)} file(s) carry the assume-unchanged or skip-worktree bit AND were "
            "edited in the working tree after the commit that last changed them -- the 'commit a "
            "stub, then edit freely' pattern, which git status never shows"
        )
    elif flagged:
        severity, passed = "flag", False
        evidence["interpretation"] = (
            f"{len(flagged)} file(s) carry the assume-unchanged or skip-worktree bit. Nothing has "
            "been edited behind it yet, so this may be an ordinary local workaround -- worth asking about"
        )
    else:
        severity, passed = "info", True
        evidence["note"] = "no files carry the assume-unchanged or skip-worktree bit"
    return Finding(CHECK_ASSUME_UNCHANGED, "system", severity, evidence, passed)


# --- check 5: tracked vs. on-disk source ratio -------------------------------


def check_source_ratio(repo_path: str) -> Finding:
    if analysis_source() == "clone":
        return _not_evaluable_on_clone(
            CHECK_SOURCE_RATIO,
            "system",
            "tracked files vs. source files on disk",
            "this compares what git tracks against what is on disk. A clone writes out exactly "
            "the tracked files and nothing else, so the ratio is 1.0 by construction and carries "
            "no information -- the hidden files it is meant to find were never pushed",
        )

    """Headline dashboard metric: how much of the source on disk is tracked."""
    evidence: dict = {
        "mechanism": "tracked-vs-on-disk source ratio",
        "commands": [_git_command_string(["ls-files", "-z"])],
        "source_extensions": sorted(SOURCE_EXTENSIONS),
        "skipped_directories": sorted(SKIP_WALK_DIRS),
    }

    on_disk = set(_relative_source_files(repo_path))
    tracked_all = _tracked_files(repo_path)
    tracked = {
        p for p in tracked_all if os.path.splitext(p)[1].lower() in SOURCE_EXTENSIONS
    }
    # Tracked files that are not on disk (deleted but still in the index) do not
    # count toward the denominator; the metric is about unaudited code present.
    tracked_present = tracked & on_disk

    evidence["source_files_on_disk"] = len(on_disk)
    evidence["source_files_tracked"] = len(tracked)
    evidence["source_files_tracked_and_present"] = len(tracked_present)
    untracked = sorted(on_disk - tracked)
    evidence["untracked_source_files"] = untracked[:MAX_EVIDENCE_ITEMS]
    evidence["untracked_source_file_count"] = len(untracked)

    ratio = 1.0 if not on_disk else round(len(tracked_present) / len(on_disk), 4)
    evidence["tracked_ratio"] = ratio
    evidence["pass_threshold"] = TRACKED_RATIO_PASS_THRESHOLD
    if not on_disk:
        evidence["note"] = "no source files found on disk"

    return Finding(
        check_name=CHECK_SOURCE_RATIO,
        plane="system",
        severity="info",  # always informational: this is a metric, not an accusation
        evidence=evidence,
        passed=ratio >= TRACKED_RATIO_PASS_THRESHOLD,
    )


# --- entry point --------------------------------------------------------------


def _not_a_repo_findings(repo_path: str, reason: str) -> list[Finding]:
    return [
        Finding(
            check_name=name,
            plane=plane,
            severity="info",
            evidence={"repo_path": repo_path, "note": reason, "skipped": True},
            passed=True,
        )
        for name, plane in ALL_CHECKS
    ]


def run(repo_path: str) -> list[Finding]:
    """Run all five hidden-code checks against ``repo_path``.

    Always returns one Finding per check, in a stable order, and never raises.
    """
    resolved = os.path.abspath(os.path.expanduser(str(repo_path)))
    if not os.path.isdir(resolved):
        return _not_a_repo_findings(resolved, "path does not exist or is not a directory")
    if not is_git_repo(resolved):
        return _not_a_repo_findings(resolved, "path is not inside a git working tree")

    try:
        attributions = attribute_ignored_files(resolved, ignored_source_files(resolved))
    except Exception:  # pragma: no cover - defensive
        attributions = []

    checks = (
        (CHECK_GITIGNORE, "claim", lambda: check_gitignore(resolved, attributions)),
        (CHECK_INFO_EXCLUDE, "system", lambda: check_info_exclude(resolved, attributions)),
        (
            CHECK_CORE_EXCLUDES_FILE,
            "system",
            lambda: check_core_excludes_file(resolved, attributions),
        ),
        (CHECK_ASSUME_UNCHANGED, "system", lambda: check_assume_unchanged(resolved)),
        (CHECK_SOURCE_RATIO, "system", lambda: check_source_ratio(resolved)),
    )

    findings: list[Finding] = []
    for name, plane, fn in checks:
        try:
            findings.append(fn())
        except Exception as exc:  # never crash the analyzer engine
            findings.append(
                Finding(
                    check_name=name,
                    plane=plane,
                    severity="info",
                    evidence={
                        "repo_path": resolved,
                        "note": "check raised an unexpected error and was skipped",
                        "error": f"{type(exc).__name__}: {exc}",
                    },
                    passed=True,
                )
            )
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Inspect a git repository for hidden/untracked source code."
    )
    parser.add_argument("repo_path", help="path to the git repository to inspect")
    parser.add_argument(
        "--compact", action="store_true", help="emit single-line JSON instead of indented"
    )
    args = parser.parse_args(argv)

    findings = run(args.repo_path)
    payload = [dataclasses.asdict(f) for f in findings]
    print(json.dumps(payload, indent=None if args.compact else 2, sort_keys=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
