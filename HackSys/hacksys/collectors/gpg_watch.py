"""GPG collector.

Takes a snapshot of the signing material at start and re-checks it on a timer.
The question it answers is narrow and honest: *did the signing key that this
machine can use change during the event, and does it match the key the
participant registered?*

A key change is not misconduct. Keys expire, laptops get re-imaged, people
generate a key mid-event because the rules told them to. The report records
the change and the times; a human decides what it means.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from ..models import SEV_CRITICAL, SEV_INFO, SEV_NOTICE, SEV_WARN
from ..util import have, run, sha256_text
from .base import Collector


class GpgCollector(Collector):
    name = "gpg"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.interval = ctx.cfg.gpg_interval
        self._snapshot_hash: Optional[str] = None
        self._binary: Optional[str] = None
        self._agent_seen = False

    def setup(self) -> None:
        for candidate in ("gpg", "gpg2"):
            if have(candidate):
                self._binary = candidate
                break
        if not self._binary:
            self.emit(
                "gpg.unavailable",
                "no gpg binary on PATH — commit signatures cannot be verified locally",
                severity=SEV_WARN if self.cfg.require_signed_commits else SEV_INFO,
            )

    # -- snapshotting -----------------------------------------------------

    def _parse_colons(self, text: str, want: str) -> List[Dict[str, Any]]:
        """Parse `--with-colons` output into key records."""
        keys: List[Dict[str, Any]] = []
        current: Optional[Dict[str, Any]] = None
        for line in text.splitlines():
            fields = line.split(":")
            rec = fields[0]
            if rec == want:
                current = {
                    "validity": fields[1] if len(fields) > 1 else "",
                    "length": fields[2] if len(fields) > 2 else "",
                    "algo": fields[3] if len(fields) > 3 else "",
                    "keyid": fields[4] if len(fields) > 4 else "",
                    "created": fields[5] if len(fields) > 5 else "",
                    "expires": fields[6] if len(fields) > 6 else "",
                    "capabilities": fields[11] if len(fields) > 11 else "",
                    "uids": [],
                    "fingerprint": "",
                }
                keys.append(current)
            elif rec == "fpr" and current is not None and not current["fingerprint"]:
                current["fingerprint"] = fields[9] if len(fields) > 9 else ""
            elif rec == "uid" and current is not None:
                uid = fields[9] if len(fields) > 9 else ""
                if uid:
                    current["uids"].append(uid)
        return keys

    def _collect(self) -> Dict[str, Any]:
        secret: List[Dict[str, Any]] = []
        public: List[Dict[str, Any]] = []
        if self._binary:
            rc, out, _ = run([self._binary, "--list-secret-keys", "--with-colons"], timeout=20)
            if rc == 0:
                secret = self._parse_colons(out, "sec")
            rc, out, _ = run([self._binary, "--list-keys", "--with-colons"], timeout=20)
            if rc == 0:
                public = self._parse_colons(out, "pub")

        git_cfg: Dict[str, str] = {}
        for key in ("user.signingkey", "commit.gpgsign", "tag.gpgsign", "gpg.format",
                    "gpg.program", "gpg.ssh.allowedSignersFile"):
            rc, out, _ = run(["git", "config", "--global", "--get", key], timeout=8)
            git_cfg[key] = out.strip() if rc == 0 else ""

        ssh_keys: List[str] = []
        ssh_dir = os.path.expanduser("~/.ssh")
        if os.path.isdir(ssh_dir):
            try:
                ssh_keys = sorted(f for f in os.listdir(ssh_dir) if f.endswith(".pub"))
            except OSError:
                pass

        return {
            "secret_keys": [_public_fields(k) for k in secret],
            "public_keys": [_public_fields(k) for k in public],
            "git_config": git_cfg,
            "ssh_public_key_files": ssh_keys,
        }

    # -- loop ----------------------------------------------------------------

    def poll(self) -> None:
        snap = self._collect()
        digest = sha256_text(repr(snap))

        if self._snapshot_hash is None:
            self._snapshot_hash = digest
            fps = [k["fingerprint"] for k in snap["secret_keys"] if k["fingerprint"]]
            registered = self.cfg.registered_gpg_fingerprint.replace(" ", "").upper()
            matches = [f for f in fps if registered and f.upper() == registered]
            severity = SEV_INFO
            note = ""
            if registered and not matches:
                severity = SEV_WARN
                note = " — none of them is the fingerprint registered with the organiser"
            elif not fps and self.cfg.require_signed_commits:
                severity = SEV_WARN
                note = " — no secret key available, commits cannot be signed on this machine"
            self.emit(
                "gpg.baseline",
                f"{len(fps)} secret signing key(s) available at start{note}",
                severity=severity,
                snapshot=snap,
                fingerprints=fps,
                registered_fingerprint=registered,
                registered_key_present=bool(matches),
                snapshot_sha256=digest,
            )
            return

        if digest != self._snapshot_hash:
            previous = self._snapshot_hash
            self._snapshot_hash = digest
            fps = [k["fingerprint"] for k in snap["secret_keys"] if k["fingerprint"]]
            self.emit(
                "gpg.changed",
                "signing material changed during the event "
                f"({len(fps)} secret key(s) now present)",
                severity=SEV_CRITICAL,
                snapshot=snap,
                fingerprints=fps,
                snapshot_sha256=digest,
                previous_sha256=previous,
            )


def _public_fields(key: Dict[str, Any]) -> Dict[str, Any]:
    """Fingerprints, ids and validity only — never key material."""
    return {
        "keyid": key.get("keyid", ""),
        "fingerprint": key.get("fingerprint", ""),
        "algo": key.get("algo", ""),
        "length": key.get("length", ""),
        "created": key.get("created", ""),
        "expires": key.get("expires", ""),
        "capabilities": key.get("capabilities", ""),
        "uids": key.get("uids", [])[:3],
        "validity": key.get("validity", ""),
    }
