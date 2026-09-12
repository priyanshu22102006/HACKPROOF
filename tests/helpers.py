"""Test helpers: subprocess wrappers and a throwaway GPG keyring.

Kept out of conftest.py so the test modules can import them without pytest
loading conftest twice under two module names.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess

FPR_RE = re.compile(r"^fpr:::::::::([0-9A-F]{40}):", re.MULTILINE)


def run(cmd: list[str], cwd: str | None = None, env: dict | None = None, input_text: str | None = None):
    """Run a command, returning CompletedProcess. Raises with full output on failure."""
    full_env = dict(os.environ)
    full_env["LC_ALL"] = "C"
    if env:
        full_env.update(env)
    proc = subprocess.run(
        cmd,
        cwd=cwd,
        env=full_env,
        input=input_text.encode() if input_text is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
    )
    if proc.returncode != 0:
        raise AssertionError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"stdout: {proc.stdout.decode('utf-8', 'replace')}\n"
            f"stderr: {proc.stderr.decode('utf-8', 'replace')}"
        )
    return proc


def out(proc) -> str:
    return proc.stdout.decode("utf-8", "replace")


class GpgHome:
    """A throwaway GNUPGHOME that can mint keys and export them."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(self.path, mode=0o700, exist_ok=True)

    @property
    def env(self) -> dict:
        return {"GNUPGHOME": self.path, "HOME": self.path}

    def _gpg(self, args: list[str], input_text: str | None = None):
        return run(
            [
                "gpg",
                "--batch",
                "--no-tty",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                *args,
            ],
            env=self.env,
            input_text=input_text,
        )

    def generate_key(self, uid: str, expire: str = "0") -> str:
        """Create an ed25519 signing key for ``uid``; returns its fingerprint.

        ``expire`` uses gpg's own syntax: "0" never expires, "seconds=5" is what
        the expired-key test uses so it can wait out a real expiry.
        """
        self._gpg(["--quick-generate-key", uid, "ed25519", "sign", expire])
        listing = out(self._gpg(["--with-colons", "--fingerprint", uid]))
        fingerprints = FPR_RE.findall(listing)
        assert fingerprints, f"no fingerprint found for {uid}:\n{listing}"
        return fingerprints[0]  # primary key of the first (only) match

    def export_public(self, fingerprint: str) -> str:
        return out(self._gpg(["--armor", "--export", fingerprint]))

    def export_secret(self, fingerprint: str) -> str:
        return out(self._gpg(["--armor", "--export-secret-keys", fingerprint]))

    def close(self) -> None:
        subprocess.run(
            ["gpgconf", "--kill", "gpg-agent"],
            env={**os.environ, **self.env},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        )
        shutil.rmtree(self.path, ignore_errors=True)


class SshHome:
    """A helper for generating throwaway SSH keys and signing git commits."""

    def __init__(self, path: str):
        self.path = path
        os.makedirs(self.path, exist_ok=True)

    def generate_key(self, name: str = "id_ed25519", comment: str = "test@example.test") -> tuple[str, str, str]:
        """Returns (private_key_path, public_key_text, fingerprint)."""
        priv_path = os.path.join(self.path, name)
        subprocess.run(
            ["ssh-keygen", "-t", "ed25519", "-N", "", "-f", priv_path, "-C", comment],
            check=True,
            capture_output=True,
        )
        pub_path = priv_path + ".pub"
        with open(pub_path, "r", encoding="utf-8") as f:
            pub_text = f.read().strip()
        res = subprocess.run(["ssh-keygen", "-l", "-f", pub_path], check=True, capture_output=True, text=True)
        fpr = res.stdout.strip().split()[1]
        return priv_path, pub_text, fpr

    def close(self) -> None:
        shutil.rmtree(self.path, ignore_errors=True)
