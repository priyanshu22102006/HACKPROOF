#!/usr/bin/env python3
"""hackproof enroll -- what one participant runs on their own machine.

Spec §8.a/§8.b: the participant generates (or adopts) a signing key locally,
registers only the *public* half, and has git configured to actually sign. That
last part is the one people skip, and without it "most commits arrive unsigned
regardless of registration, and the identity checks in §8.e have nothing to
verify against."

So this does four things, in this order, and refuses to claim success on a
partial run:

  1. Mint or adopt a signing key -- OpenPGP or SSH.
  2. Configure git in the target repo to sign every commit with it.
  3. **Prove signing works** by making a real signed commit in a scratch repo and
     reading ``git log --format=%G?`` back. This is the step that catches a
     broken macOS pinentry at check-in rather than at hour 30.
  4. Write an enrollment card holding the public key only, which the participant
     sends to the organizer. ``scripts/build_roster.py`` merges the cards.

The private key never leaves the machine and is never read into this process.
Every blob on its way out is scanned for private key material first; finding any
is a hard error, not a warning.

    python3 scripts/hackproof_enroll.py \
        --member-id satoru --name "Satoru" --email satoru@example.com \
        --github-login satorugojo --method gpg --repo ~/code/team-repo

    python3 scripts/hackproof_enroll.py --member-id priyanshu ... --method ssh

Adopt an existing key instead of minting one:

    --use-key 4673FBA5...            # gpg: fingerprint, key id, or uid
    --use-key ~/.ssh/id_ed25519.pub  # ssh: path to the PUBLIC half
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

SCHEMA = "hackproof.enrollment-card/1"

# Anything that looks like private key material must never reach a card.
PRIVATE_KEY_MARKERS = (
    "PRIVATE KEY BLOCK",
    "OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
)

SSH_KEY_PREFIXES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)

FPR_RE = re.compile(r"^fpr:::::::::([0-9A-F]{40}):", re.MULTILINE)
TIMEOUT = 120


class EnrollError(RuntimeError):
    """Anything that should stop enrollment with a readable message."""


def sh(cmd: list[str], cwd: str | None = None, env: dict | None = None, check: bool = True):
    full_env = dict(os.environ)
    full_env["LC_ALL"] = "C"
    if env:
        full_env.update(env)
    proc = subprocess.run(
        cmd, cwd=cwd, env=full_env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=TIMEOUT
    )
    if check and proc.returncode != 0:
        raise EnrollError(
            f"command failed ({proc.returncode}): {' '.join(cmd)}\n"
            f"{proc.stdout.decode('utf-8', 'replace')}\n{proc.stderr.decode('utf-8', 'replace')}"
        )
    return proc


def out(proc) -> str:
    return proc.stdout.decode("utf-8", "replace")


def have(binary: str) -> bool:
    return shutil.which(binary) is not None


def assert_public_only(blob: str, what: str) -> None:
    """The one rule that must never be relaxed: no private key material leaves here."""
    upper = blob.upper()
    for marker in PRIVATE_KEY_MARKERS:
        if marker in upper:
            raise EnrollError(
                f"refusing to write {what}: it contains private key material ({marker}). "
                "Only the public half is ever registered -- see spec §8.a."
            )


# --- OpenPGP ------------------------------------------------------------------


def gpg(args: list[str], check: bool = True):
    return sh(["gpg", "--batch", "--no-tty", "--yes", *args], check=check)


def gpg_fingerprint(query: str) -> str:
    listing = out(gpg(["--with-colons", "--fingerprint", query]))
    matches = FPR_RE.findall(listing)
    if not matches:
        raise EnrollError(f"no OpenPGP key found matching {query!r}")
    return matches[0]


def gpg_has_secret(fingerprint: str) -> bool:
    proc = gpg(["--with-colons", "--list-secret-keys", fingerprint], check=False)
    return proc.returncode == 0 and "sec:" in out(proc)


def gpg_generate(uid: str) -> str:
    """Mint a passphrase-less ed25519 signing key.

    Passphrase-less on purpose: a participant signing 80 commits over 48 hours
    behind a passphrase prompt turns signing off within the hour, and an unsigned
    commit is worth nothing to §8.e. The key is scoped to one event and the
    organizer's retention policy (spec §11) deletes the roster after judging.
    """
    gpg(["--pinentry-mode", "loopback", "--passphrase", "", "--quick-generate-key", uid, "ed25519", "sign", "0"])
    return gpg_fingerprint(uid)


def gpg_export_public(fingerprint: str) -> str:
    blob = out(gpg(["--armor", "--export", fingerprint])).strip()
    if not blob:
        raise EnrollError(f"gpg exported nothing for {fingerprint}")
    assert_public_only(blob, "the OpenPGP public key")
    return blob


# --- SSH ----------------------------------------------------------------------


def ssh_fingerprint(public_key_path: str) -> str:
    listing = out(sh(["ssh-keygen", "-l", "-f", public_key_path]))
    parts = listing.strip().split()
    if len(parts) < 2 or not parts[1].startswith("SHA256:"):
        raise EnrollError(f"could not read an SSH fingerprint from {public_key_path}: {listing!r}")
    return parts[1]


def ssh_generate(private_path: str, comment: str) -> str:
    if os.path.exists(private_path):
        raise EnrollError(
            f"{private_path} already exists. Pass --use-key {private_path}.pub to adopt it, "
            "or --key-path to choose another location."
        )
    os.makedirs(os.path.dirname(private_path), mode=0o700, exist_ok=True)
    sh(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", comment, "-f", private_path])
    return private_path + ".pub"


def ssh_read_public(public_key_path: str) -> str:
    with open(public_key_path, "r", encoding="utf-8") as handle:
        blob = handle.read().strip()
    assert_public_only(blob, "the SSH public key")
    if not blob.startswith(SSH_KEY_PREFIXES):
        raise EnrollError(
            f"{public_key_path} does not look like an SSH public key. "
            "Point --use-key at the .pub half, not the private key."
        )
    return blob


# --- git configuration --------------------------------------------------------


def configure_git(repo: str, method: str, signing_key: str, scope: str) -> list[str]:
    """Turn on signing. Returns the settings applied, for the report."""
    where = ["--global"] if scope == "global" else []
    applied = []
    settings = [
        ("gpg.format", "openpgp" if method == "gpg" else "ssh"),
        ("user.signingkey", signing_key),
        ("commit.gpgsign", "true"),
        ("tag.gpgsign", "true"),
    ]
    for key, value in settings:
        sh(["git", "config", *where, key, value], cwd=repo)
        applied.append(f"{key}={value}")
    return applied


def verify_signing(method: str, signing_key: str, name: str, email: str, public_key: str) -> dict:
    """Make a real signed commit in a scratch repo and read the verdict back.

    This is the whole point of running enrollment rather than just mailing a
    public key: a key that is registered but cannot sign is worse than useless,
    because the team believes they are covered.
    """
    scratch = tempfile.mkdtemp(prefix="hackproof-enroll-check-")
    try:
        env = {
            "GIT_CONFIG_GLOBAL": os.path.join(scratch, "gitconfig"),
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_AUTHOR_NAME": name,
            "GIT_AUTHOR_EMAIL": email,
            "GIT_COMMITTER_NAME": name,
            "GIT_COMMITTER_EMAIL": email,
        }
        sh(["git", "init", "-q", "-b", "main", scratch], env=env)
        config = [
            ("gpg.format", "openpgp" if method == "gpg" else "ssh"),
            ("user.signingkey", signing_key),
            ("user.name", name),
            ("user.email", email),
        ]
        if method == "ssh":
            allowed = os.path.join(scratch, "allowed_signers")
            with open(allowed, "w", encoding="utf-8") as handle:
                handle.write(f"{email} {public_key}\n")
            config.append(("gpg.ssh.allowedSignersFile", allowed))
        for key, value in config:
            sh(["git", "config", key, value], cwd=scratch, env=env)

        proc = sh(
            ["git", "commit", "-S", "--allow-empty", "-m", "hackproof enrollment signing check"],
            cwd=scratch,
            env=env,
            check=False,
        )
        if proc.returncode != 0:
            return {
                "ok": False,
                "code": None,
                "detail": (out(proc) + proc.stderr.decode("utf-8", "replace")).strip()[:2000],
            }
        code = out(sh(["git", "log", "-1", "--format=%G?"], cwd=scratch, env=env)).strip()
        signer = out(sh(["git", "log", "-1", "--format=%GS"], cwd=scratch, env=env)).strip()
        return {"ok": code in ("G", "U"), "code": code, "signer": signer, "detail": ""}
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


# --- card ---------------------------------------------------------------------


def build_card(args, key_type: str, fingerprint: str, public_key: str, signing_check: dict) -> dict:
    assert_public_only(public_key, "the enrollment card")
    now = datetime.now(timezone.utc).isoformat()
    emails = [e.strip().lower() for e in args.email if e.strip()]
    return {
        "schema": SCHEMA,
        "member_id": args.member_id,
        "display_name": args.name or args.member_id,
        "github_login": (args.github_login or "").strip(),
        "emails": emails,
        "declared_non_coding_role": args.non_coding_role,
        "key": {
            "key_id": args.key_id or f"{args.member_id}-{key_type}-1",
            "key_type": key_type,
            "fingerprint": fingerprint,
            "public_key": public_key,
            "status": "active",
            "revoked_at": None,
            "expires_at": None,
            "registered_at": now,
        },
        "enrolled": {
            "at": now,
            "hostname": socket.gethostname(),
            "platform": f"{platform.system()} {platform.release()}",
            "signing_check": signing_check,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Register one participant's signing key and turn on commit signing.",
    )
    parser.add_argument("--member-id", required=True, help="stable id used across the roster, e.g. 'satoru'")
    parser.add_argument("--name", default=None, help="display name")
    parser.add_argument("--email", action="append", required=True, help="git author email; repeatable")
    parser.add_argument("--github-login", default=None, help="GitHub username (for the API cross-check)")
    parser.add_argument("--method", choices=("gpg", "ssh"), required=True)
    parser.add_argument("--repo", default=None, help="repo to configure for signing (default: no repo config)")
    parser.add_argument(
        "--scope",
        choices=("repo", "global"),
        default="repo",
        help="write git config into the repo (default) or the user's global config",
    )
    parser.add_argument("--use-key", default=None, help="adopt an existing key instead of minting one")
    parser.add_argument(
        "--key-path",
        default=None,
        help="ssh only: where to write the new private key (default ~/.ssh/id_hackproof_ed25519)",
    )
    parser.add_argument("--key-id", default=None, help="label for this key in the roster")
    parser.add_argument("--non-coding-role", default=None, help="declare a non-coding role (spec §8.g)")
    parser.add_argument("--out", default=None, help="where to write the enrollment card")
    parser.add_argument(
        "--skip-signing-check",
        action="store_true",
        help="do not make a test signed commit (not recommended: this is the check that catches a broken setup)",
    )
    args = parser.parse_args(argv)

    try:
        if args.method == "gpg":
            if not have("gpg"):
                raise EnrollError("gpg is not on PATH. macOS: brew install gnupg pinentry-mac")
            if args.use_key:
                fingerprint = gpg_fingerprint(args.use_key)
                if not gpg_has_secret(fingerprint):
                    raise EnrollError(
                        f"{args.use_key} resolves to {fingerprint}, but no secret key for it is on this "
                        "machine -- you cannot sign with it."
                    )
                print(f"==> adopting existing OpenPGP key {fingerprint}")
            else:
                uid = f"{args.name or args.member_id} <{args.email[0]}>"
                print(f"==> generating an OpenPGP signing key for {uid}")
                fingerprint = gpg_generate(uid)
                print(f"    {fingerprint}")
            public_key = gpg_export_public(fingerprint)
            signing_key = fingerprint
        else:
            if not have("ssh-keygen"):
                raise EnrollError("ssh-keygen is not on PATH")
            if args.use_key:
                public_path = os.path.abspath(os.path.expanduser(args.use_key))
                if not public_path.endswith(".pub"):
                    raise EnrollError(f"--use-key must point at the public half (.pub), got {public_path}")
                print(f"==> adopting existing SSH key {public_path}")
            else:
                private_path = os.path.abspath(
                    os.path.expanduser(args.key_path or "~/.ssh/id_hackproof_ed25519")
                )
                print(f"==> generating an SSH signing key at {private_path}")
                public_path = ssh_generate(private_path, comment=f"hackproof:{args.member_id}")
            public_key = ssh_read_public(public_path)
            fingerprint = ssh_fingerprint(public_path)
            print(f"    {fingerprint}")
            signing_key = public_path

        signing_check = {"skipped": True}
        if not args.skip_signing_check:
            print("==> proving the key can actually sign a commit")
            signing_check = verify_signing(
                args.method, signing_key, args.name or args.member_id, args.email[0], public_key
            )
            if signing_check["ok"]:
                print(f"    git reports signature code {signing_check['code']!r} -- signing works")
            else:
                print("    !! could not produce a verifiable signed commit", file=sys.stderr)
                if signing_check.get("detail"):
                    print(f"    {signing_check['detail']}", file=sys.stderr)
                if args.method == "gpg":
                    print(
                        "    macOS hint: add `export GPG_TTY=$(tty)` to your shell profile, "
                        "and `brew install pinentry-mac`.",
                        file=sys.stderr,
                    )
                return 2

        if args.repo:
            repo = os.path.abspath(os.path.expanduser(args.repo))
            if not os.path.isdir(os.path.join(repo, ".git")):
                raise EnrollError(f"{repo} is not a git repository")
            applied = configure_git(repo, args.method, signing_key, args.scope)
            print(f"==> configured signing in {repo} ({args.scope})")
            for line in applied:
                print(f"    {line}")

        card = build_card(args, args.method, fingerprint, public_key, signing_check)
        out_path = os.path.abspath(
            os.path.expanduser(args.out or f"enrollment-{args.member_id}-{args.method}.json")
        )
        with open(out_path, "w", encoding="utf-8") as handle:
            json.dump(card, handle, indent=2)
            handle.write("\n")
        print(f"==> enrollment card written to {out_path}")
        print("    Send this file to the organizer. It holds your PUBLIC key only.")
        return 0
    except EnrollError as exc:
        print(f"enrollment failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
