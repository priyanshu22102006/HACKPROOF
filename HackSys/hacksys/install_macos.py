"""launchd integration.

A LaunchAgent (not a LaunchDaemon): it runs as the participant, in their login
session, which is what it needs to see their clipboard, their foreground app
and their files. It deliberately does not ask for root.
"""

from __future__ import annotations

import os
import sys
from typing import Dict, Tuple

from .config import Config
from .util import ensure_dir, run

LABEL = "com.hackproof.hacksys"

PLIST = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>

    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>-m</string>
        <string>hacksys</string>
        <string>--config</string>
        <string>{config}</string>
        <string>start</string>
    </array>

    <key>WorkingDirectory</key>
    <string>{home}</string>

    <key>EnvironmentVariables</key>
    <dict>
        <key>PYTHONPATH</key>
        <string>{pythonpath}</string>
        <key>PATH</key>
        <string>/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
        <key>PYTHONUNBUFFERED</key>
        <string>1</string>
    </dict>

    <key>RunAtLoad</key>
    <true/>

    <!-- Restart if it crashes or is killed, but not when it exits cleanly:
         a clean exit means the window closed or the report was sealed. -->
    <key>KeepAlive</key>
    <dict>
        <key>SuccessfulExit</key>
        <false/>
    </dict>

    <key>StandardOutPath</key>
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>

    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"""


def plist_path() -> str:
    return os.path.expanduser(f"~/Library/LaunchAgents/{LABEL}.plist")


def render_plist(cfg: Config) -> str:
    package_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return PLIST.format(
        label=LABEL,
        python=sys.executable,
        config=cfg.config_path,
        home=cfg.home,
        pythonpath=package_root,
        stdout=os.path.join(cfg.state_dir, "stdout.log"),
        stderr=os.path.join(cfg.state_dir, "stderr.log"),
    )


def install(cfg: Config) -> Tuple[bool, str]:
    path = plist_path()
    ensure_dir(os.path.dirname(path))
    ensure_dir(cfg.state_dir)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(render_plist(cfg))

    uid = os.getuid()
    run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"], timeout=15)
    rc, out, err = run(["launchctl", "bootstrap", f"gui/{uid}", path], timeout=20)
    if rc != 0:
        # older macOS
        rc, out, err = run(["launchctl", "load", "-w", path], timeout=20)
    if rc != 0:
        return False, f"launchctl failed: {err or out}"
    run(["launchctl", "enable", f"gui/{uid}/{LABEL}"], timeout=15)
    run(["launchctl", "kickstart", "-k", f"gui/{uid}/{LABEL}"], timeout=20)
    return True, path


def uninstall() -> Tuple[bool, str]:
    path = plist_path()
    uid = os.getuid()
    run(["launchctl", "bootout", f"gui/{uid}/{LABEL}"], timeout=15)
    run(["launchctl", "unload", "-w", path], timeout=15)
    if os.path.exists(path):
        try:
            os.remove(path)
        except OSError as exc:
            return False, str(exc)
    return True, path


def status() -> Dict[str, object]:
    uid = os.getuid()
    rc, out, _ = run(["launchctl", "print", f"gui/{uid}/{LABEL}"], timeout=15)
    loaded = rc == 0
    state = ""
    pid = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("state = "):
            state = line.split("=", 1)[1].strip()
        if line.startswith("pid = "):
            try:
                pid = int(line.split("=", 1)[1].strip())
            except ValueError:
                pass
    return {
        "plist": plist_path(),
        "plist_exists": os.path.exists(plist_path()),
        "loaded": loaded,
        "state": state,
        "pid": pid,
    }
