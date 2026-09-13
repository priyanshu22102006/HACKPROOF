"""Configuration loading for the HackSys agent.

The config is a TOML file (Python 3.11+ reads it with the stdlib `tomllib`).
`hacksys init` writes one; everything else reads it.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any, Dict, List, Optional

from .util import expand, now_utc, parse_iso

try:  # Python 3.11+
    import tomllib  # type: ignore
except ModuleNotFoundError:  # pragma: no cover
    try:
        import tomli as tomllib  # type: ignore
    except ModuleNotFoundError:
        tomllib = None  # type: ignore


def _parse_simple_toml(text: str) -> Dict[str, Any]:
    """Fallback reader for the config shape this agent writes.

    Participants' machines are not a controlled environment; refusing to start
    because the interpreter predates `tomllib` would be a silly way to lose a
    whole event's monitoring. Handles exactly what `render_template` emits:
    [sections], strings, booleans, numbers and single-line string arrays.
    """
    out: Dict[str, Any] = {}
    section: Dict[str, Any] = out
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = out.setdefault(line[1:-1].strip(), {})
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key, value = key.strip(), value.split(" #")[0].strip()
        parsed: Any
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1].strip()
            parsed = [v.strip().strip('"\'') for v in inner.split(",") if v.strip()]
        elif value.lower() in ("true", "false"):
            parsed = value.lower() == "true"
        elif value.startswith(('"', "'")):
            parsed = value.strip("\"'")
        else:
            try:
                parsed = float(value) if "." in value else int(value)
            except ValueError:
                parsed = value
        section[key] = parsed
    return out


DEFAULT_HOME = os.path.expanduser("~/.hacksys")

# Directories that are never worth watching: huge, noisy, and irrelevant to
# whether a person wrote their hackathon code themselves. Excluding them is
# what makes a full-home watch survivable on a laptop.
DEFAULT_EXCLUDES: List[str] = [
    "**/Library/**",
    "**/.Trash/**",
    "**/.hacksys/**",
    "**/node_modules/**",
    # git's own internals are read directly by the git collector; watching them
    # as files produces nothing but index.lock churn
    "**/.git/**",
    "**/.venv/**",
    "**/venv/**",
    "**/env/**",
    "**/__pycache__/**",
    "**/.mypy_cache/**",
    "**/.pytest_cache/**",
    "**/.ruff_cache/**",
    "**/.next/**",
    "**/.nuxt/**",
    "**/dist/**",
    "**/build/**",
    "**/target/**",
    "**/.gradle/**",
    "**/.cargo/**",
    "**/.rustup/**",
    "**/.npm/**",
    "**/.cache/**",
    "**/.conda/**",
    "**/anaconda3/**",
    "**/miniconda3/**",
    "**/site-packages/**",
    "**/Photos Library.photoslibrary/**",
    "**/*.photoslibrary/**",
    "**/.DS_Store",
    "**/*.swp",
    "**/*.tmp",
    "**/*.part",
    "**/*.crdownload",
    "**/.idea/**",
    "**/.vscode/extensions/**",
]

# Processes worth noting in the timeline. Presence is *context*, never proof.
DEFAULT_PROCESS_WATCHLIST: List[str] = [
    r"\bgit\b",
    r"\bgh\b",
    r"\bcurl\b",
    r"\bwget\b",
    r"\bscp\b",
    r"\brsync\b",
    r"\bunzip\b",
    r"\btar\b",
    r"\bditto\b",
    r"\bcodesign\b",
    r"\bgpg2?\b",
    r"\bollama\b",
    r"\bclaude\b",
    r"\bcursor\b",
    r"\bcopilot\b",
    r"\bcontinue\b",
    r"\baider\b",
    r"\bcodex\b",
    r"\bgemini\b",
]

# Tools that could interfere with, or shadow, this agent's observations.
DEFAULT_OBSERVER_WATCHLIST: List[str] = [
    r"screencapture",
    r"QuickTime Player",
    r"OBS",
    r"AnyDesk",
    r"TeamViewer",
    r"parsec",
    r"RustDesk",
    r"ScreenSharing",
    r"VNC",
    r"Karabiner",
    r"Keylogger",
]


@dataclass
class Config:
    # --- identity -------------------------------------------------------
    participant_id: str = "unknown"
    participant_name: str = ""
    team_id: str = ""
    event_id: str = ""
    submission_repo: str = ""

    # --- hackathon window ------------------------------------------------
    window_start: str = ""     # ISO-8601
    window_end: str = ""       # ISO-8601

    # --- paths ------------------------------------------------------------
    home: str = DEFAULT_HOME
    project_paths: List[str] = field(default_factory=list)
    watch_roots: List[str] = field(default_factory=lambda: [os.path.expanduser("~")])
    sensitive_roots: List[str] = field(
        default_factory=lambda: [
            os.path.expanduser("~/Downloads"),
            os.path.expanduser("~/Desktop"),
            "/tmp",
            "/private/tmp",
        ]
    )
    excludes: List[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))

    # --- collector toggles / tuning ---------------------------------------
    enable_filesystem: bool = True
    enable_clipboard: bool = True
    enable_git: bool = True
    enable_gpg: bool = True
    enable_process: bool = True
    enable_focus: bool = True          # frontmost-app sampling (needs Accessibility)
    enable_integrity: bool = True

    clipboard_interval: float = 1.5
    git_interval: float = 20.0
    gpg_interval: float = 60.0
    process_interval: float = 10.0
    focus_interval: float = 5.0
    heartbeat_interval: float = 15.0

    # --- content handling --------------------------------------------------
    max_index_file_bytes: int = 512 * 1024     # files larger than this are hash-only
    max_text_match_bytes: int = 256 * 1024     # paste-correlation read cap
    clipboard_preview_chars: int = 0           # 0 = store no raw preview at all
    clipboard_history: int = 200
    file_index_capacity: int = 120_000
    min_paste_chars: int = 60                  # ignore trivial clipboard traffic

    # --- thresholds ---------------------------------------------------------
    bulk_commit_lines: int = 600
    bulk_commit_files: int = 30
    clock_skew_tolerance: float = 5.0
    downtime_tolerance: float = 120.0          # seconds of silence before it is a gap

    # --- watchlists ----------------------------------------------------------
    process_watchlist: List[str] = field(default_factory=lambda: list(DEFAULT_PROCESS_WATCHLIST))
    observer_watchlist: List[str] = field(default_factory=lambda: list(DEFAULT_OBSERVER_WATCHLIST))

    # --- commit signing expectations -------------------------------------------
    registered_gpg_fingerprint: str = ""
    require_signed_commits: bool = True

    # --- server ------------------------------------------------------------------
    server_url: str = ""
    server_token: str = ""
    upload_timeout: float = 30.0

    # --- consent -------------------------------------------------------------------
    consent_recorded_at: str = ""

    # ---------------------------------------------------------------------------

    # derived paths
    @property
    def log_path(self) -> str:
        return os.path.join(self.home, "events.jsonl")

    @property
    def state_dir(self) -> str:
        return os.path.join(self.home, "state")

    @property
    def report_dir(self) -> str:
        return os.path.join(self.home, "reports")

    @property
    def spool_dir(self) -> str:
        return os.path.join(self.home, "spool")

    @property
    def config_path(self) -> str:
        return os.path.join(self.home, "config.toml")

    @property
    def pid_path(self) -> str:
        return os.path.join(self.state_dir, "hacksys.pid")

    @property
    def heartbeat_path(self) -> str:
        return os.path.join(self.state_dir, "heartbeat.json")

    def window(self):
        start = parse_iso(self.window_start) if self.window_start else now_utc()
        end = parse_iso(self.window_end) if self.window_end else start + timedelta(hours=36)
        return start, end

    def in_window(self, when=None) -> bool:
        start, end = self.window()
        when = when or now_utc()
        return start <= when <= end

    def normalise(self) -> "Config":
        self.home = expand(self.home)
        self.project_paths = [expand(p) for p in self.project_paths]
        self.watch_roots = [expand(p) for p in self.watch_roots]
        self.sensitive_roots = [expand(p) for p in self.sensitive_roots]
        return self

    def to_dict(self) -> Dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        d.pop("server_token", None)  # never serialise the token into reports
        return d


# --------------------------------------------------------------------------


def load_config(path: Optional[str] = None) -> Config:
    path = expand(path or os.path.join(DEFAULT_HOME, "config.toml"))
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"No HackSys config at {path}. Run `hacksys init` first."
        )
    if tomllib is not None:
        with open(path, "rb") as fh:
            raw = tomllib.load(fh)
    else:
        with open(path, "r", encoding="utf-8") as fh:
            raw = _parse_simple_toml(fh.read())

    flat: Dict[str, Any] = {}
    for section in raw.values():
        if isinstance(section, dict):
            flat.update(section)
    flat.update({k: v for k, v in raw.items() if not isinstance(v, dict)})

    known = {f for f in Config().__dict__}
    cfg = Config(**{k: v for k, v in flat.items() if k in known})
    cfg.home = expand(os.path.dirname(path))
    return cfg.normalise()


TEMPLATE = """# HackSys agent configuration
# Generated by `hacksys init`. Everything here is visible to the participant
# by design — the agent must be auditable by the person it observes.

[identity]
participant_id   = "{participant_id}"
participant_name = "{participant_name}"
team_id          = "{team_id}"
event_id         = "{event_id}"
submission_repo  = "{submission_repo}"

[window]
window_start = "{window_start}"
window_end   = "{window_end}"

[paths]
# Directories treated as "the submission" — copies landing here are the
# interesting signal.
project_paths = [{project_paths}]
# Full-system watch. Narrow this if you want a lighter footprint.
watch_roots = [{watch_roots}]
# Folders that code arriving from outside tends to pass through.
sensitive_roots = [{sensitive_roots}]

[collectors]
enable_filesystem = true
enable_clipboard  = true
enable_git        = true
enable_gpg        = true
enable_process    = true
enable_focus      = true
enable_integrity  = true

clipboard_interval = 1.5
git_interval       = 20.0
gpg_interval       = 60.0
process_interval   = 10.0
focus_interval     = 5.0
heartbeat_interval = 15.0

[content]
# 0 means: never store any raw clipboard text, only hashes and shape.
clipboard_preview_chars = 0
min_paste_chars         = 60
max_index_file_bytes    = 524288

[signing]
registered_gpg_fingerprint = "{registered_gpg_fingerprint}"
require_signed_commits     = true

[thresholds]
bulk_commit_lines  = 600
bulk_commit_files  = 30
downtime_tolerance = 120.0

[server]
server_url   = "{server_url}"
server_token = "{server_token}"

[consent]
consent_recorded_at = "{consent_recorded_at}"
"""


def render_template(cfg: Config) -> str:
    def arr(items: List[str]) -> str:
        return ", ".join(f'"{i}"' for i in items)

    return TEMPLATE.format(
        participant_id=cfg.participant_id,
        participant_name=cfg.participant_name,
        team_id=cfg.team_id,
        event_id=cfg.event_id,
        submission_repo=cfg.submission_repo,
        window_start=cfg.window_start,
        window_end=cfg.window_end,
        project_paths=arr(cfg.project_paths),
        watch_roots=arr(cfg.watch_roots),
        sensitive_roots=arr(cfg.sensitive_roots),
        registered_gpg_fingerprint=cfg.registered_gpg_fingerprint,
        server_url=cfg.server_url,
        server_token=cfg.server_token,
        consent_recorded_at=cfg.consent_recorded_at,
    )
