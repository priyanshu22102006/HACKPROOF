"""GPG commit-signature verification analyzer (HACKPROOF §8.e, identity checks 1-5).

Answers one question per commit: **was this commit signed by a key the organizer
registered to the member who claims to have authored it?** Every commit lands in
exactly one of seven statuses:

    VERIFIED            signature good, key on the roster, signer == author
    NO_SIGNATURE        no gpgsig header at all (zero provenance, not cheating)
    INVALID_SIGNATURE   signature present but does not match the commit object
    UNKNOWN_KEY         signed by a key that is not on the roster
    EXPIRED_KEY         good signature, but the key (or signature) had expired
    REVOKED_KEY         good signature, but the key was revoked
    IDENTITY_MISMATCH   roster key signed a commit authored by a *different* member

Design notes
------------
* Verification runs against **HACKPROOF's own roster keyring**, never the
  developer's keyring and never GitHub's "Verified" badge (§8.e check 1). The
  roster is imported into a throwaway ``GNUPGHOME`` that is deleted on the way
  out, so running the analyzer cannot alter the host's keyring, and the host's
  keys cannot leak into a verdict.
* Private keys are never accepted. A roster entry carrying a private key block is
  refused with ``PRIVATE_KEY_SUBMITTED``, the blob is not imported, and the
  roster-integrity check hard-flags it.
* Everything shells out to ``git`` and ``gpg`` directly, so the exact command is
  auditable from the evidence dict.
* Nothing raises. A missing repo, a missing roster, a missing ``gpg`` binary or a
  command failure produces ``passed=True`` Findings carrying a ``note``.
* **Degradation is deliberate.** With no roster (or a roster from which no key
  could be imported) the analyzer cannot attribute anything, so every
  attribution check returns ``passed=True`` with a note and only the coverage
  metric reports real numbers. An unverifiable commit must never be rendered as
  a flagged one.
* Interpretation limit, repeated here because it belongs next to the code: a
  signature proves **control of a key**, not that a particular human typed the
  code (spec §11). Device binding (§8.e checks 6-8) is what narrows that, and it
  lives outside this module. No status produced here means "cheating".

Roster format (JSON) -- see docs/GPG-VERIFICATION.md
---------------------------------------------------
```json
{
  "team_id": "team-07",
  "baseline_commit": "<sha of the organizer template commit, excluded from scoring>",
  "members": [
    {
      "member_id": "m1",
      "display_name": "Satoru",
      "github_login": "satorugojo",
      "emails": ["satoru@example.com"],
      "keys": [
        {
          "fingerprint": "<declared, optional -- cross-checked against the blob>",
          "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK----- ...",
          "status": "active",
          "revoked_at": null,
          "expires_at": null
        }
      ]
    }
  ]
}
```
``public_key_path`` may be used instead of inline ``public_key``.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone

try:  # allow both `python -m analyzers.gpg_check` and direct execution
    from core.models import Finding
except ModuleNotFoundError:  # pragma: no cover - import path convenience only
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from core.models import Finding

# --- check names (stable ids; the dashboard groups on these) -----------------

CHECK_ROSTER = "gpg.roster_integrity"
CHECK_SIGNATURES = "gpg.signature_verification"
CHECK_UNREGISTERED = "gpg.unregistered_key"
CHECK_IDENTITY = "gpg.identity_match"
CHECK_KEY_VALIDITY = "gpg.key_validity"
CHECK_COVERAGE = "gpg.signature_coverage"

ALL_CHECKS = (
    (CHECK_ROSTER, "server"),  # HACKPROOF's own registration records
    (CHECK_SIGNATURES, "claim"),
    (CHECK_UNREGISTERED, "claim"),
    (CHECK_IDENTITY, "claim"),
    (CHECK_KEY_VALIDITY, "claim"),
    (CHECK_COVERAGE, "claim"),
)

# --- per-commit statuses ------------------------------------------------------

STATUS_VERIFIED = "VERIFIED"
STATUS_NO_SIGNATURE = "NO_SIGNATURE"
STATUS_INVALID_SIGNATURE = "INVALID_SIGNATURE"
STATUS_UNKNOWN_KEY = "UNKNOWN_KEY"
STATUS_EXPIRED_KEY = "EXPIRED_KEY"
STATUS_REVOKED_KEY = "REVOKED_KEY"
STATUS_IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
STATUS_PLATFORM_KEY = "PLATFORM_KEY"

ALL_STATUSES = (
    STATUS_VERIFIED,
    STATUS_NO_SIGNATURE,
    STATUS_INVALID_SIGNATURE,
    STATUS_UNKNOWN_KEY,
    STATUS_EXPIRED_KEY,
    STATUS_REVOKED_KEY,
    STATUS_IDENTITY_MISMATCH,
    STATUS_PLATFORM_KEY,
)

# --- platform keys ------------------------------------------------------------
#
# The git host signs some commits itself: GitHub's "Merge pull request" and
# "Squash and merge" buttons, and any edit made in its web UI, are signed with
# GitHub's own key rather than with anything a participant holds. A team using
# pull requests -- the ordinary GitHub workflow -- accumulates several of these.
#
# Treating them as UNKNOWN_KEY hard-flags an honest team for using GitHub
# normally, which is the single most likely false positive on a real repository.
# They get their own status instead: verified as the platform's, never counted as
# a participant's work, never flagged.
#
# This is not a hole. A participant cannot sign into this bucket without GitHub's
# private key, which they do not have. Contrast a roster key, where the whole
# limitation is that possession is all a signature proves.

PLATFORM_KEY_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "platform_keys")

# Bundled so verification stays offline. Labels are what a judge reads.
KNOWN_PLATFORM_FINGERPRINTS = {
    "5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23": "GitHub (web-flow commit signing)",
    "968479A1AFF927E37D1A566BB5690EEEBB952194": "GitHub",
}

# Roster-rejection reasons (roster integrity, not per-commit).
REJECT_PRIVATE_KEY = "PRIVATE_KEY_SUBMITTED"
REJECT_UNREADABLE = "PUBLIC_KEY_UNREADABLE"
REJECT_IMPORT_FAILED = "PUBLIC_KEY_IMPORT_FAILED"
REJECT_FINGERPRINT_MISMATCH = "DECLARED_FINGERPRINT_MISMATCH"
REJECT_NO_KEY_MATERIAL = "NO_KEY_MATERIAL"

# Identity verdicts, mirroring the three-way result the judge dashboard shows.
IDENTITY_MATCH = "MATCH"
IDENTITY_MISMATCH = "MISMATCH"
IDENTITY_UNKNOWN = "UNKNOWN"  # author identity is not on the roster at all
IDENTITY_NA = "NOT_APPLICABLE"  # unsigned or unattributable commit

# git's %G? codes -> our status. See `man git-log` ("Placeholders").
#   G good | U good, unknown validity | B bad | X good but signature expired
#   Y good but key expired | R good but key revoked | E cannot check | N none
GOOD_CODES = frozenset({"G", "U"})

# --- tunables ----------------------------------------------------------------

# Roster discovery order, relative to the repo, after $HACKPROOF_ROSTER.
ROSTER_CANDIDATES = (
    os.path.join(".hackproof", "roster.json"),
    "hackproof-roster.json",
    os.path.join(".chronicle", "roster.json"),
    "chronicle-roster.json",
)

# Below this share of commits VERIFIED, the coverage check reports passed=False.
VERIFIED_RATIO_PASS_THRESHOLD = 0.90

MAX_COMMITS = 2000  # newest first
MAX_EVIDENCE_ITEMS = 50  # cap on any list embedded in evidence
MAX_RAW_VERIFY = 25  # per-commit `git verify-commit --raw` calls
GIT_TIMEOUT_SECONDS = 60
GPG_TIMEOUT_SECONDS = 30

# `<digits>+login@users.noreply.github.com` or `login@users.noreply.github.com`
NOREPLY_RE = re.compile(r"^(?:\d+\+)?([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)@users\.noreply\.github\.com$")

SSH_KEY_PREFIXES = (
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com",
    "sk-ecdsa-sha2-nistp256@openssh.com",
)

_RECORD_SEP = "\x1e"
_FIELD_SEP = "\x1f"

# %H %an %ae %aI %cI %cn %ce %G? %GK %GF %GP %GS %GT
_LOG_FORMAT = _RECORD_SEP + _FIELD_SEP.join(
    ["%H", "%an", "%ae", "%aI", "%cI", "%cn", "%ce", "%G?", "%GK", "%GF", "%GP", "%GS", "%GT"]
)
_LOG_FIELDS = (
    "sha",
    "author_name",
    "author_email",
    "author_date",
    "committer_date",
    "committer_name",
    "committer_email",
    "git_signature_code",
    "signing_key_id",
    "signing_fingerprint",
    "signing_primary_fingerprint",
    "signer_name",
    "trust_level",
)


# --- subprocess plumbing ------------------------------------------------------


def _run(
    cmd: list[str],
    cwd: str | None = None,
    env_extra: dict | None = None,
    input_bytes: bytes | None = None,
    timeout: int = GIT_TIMEOUT_SECONDS,
) -> tuple[int, str, str]:
    """Run a command. Returns (returncode, stdout, stderr) and never raises."""
    env = dict(os.environ)
    env.update({"LC_ALL": "C", "GIT_PAGER": "cat", "GIT_OPTIONAL_LOCKS": "0"})
    if env_extra:
        env.update(env_extra)
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except FileNotFoundError:
        return 127, "", f"{cmd[0]} executable not found on PATH"
    except subprocess.TimeoutExpired:
        return 124, "", f"command timed out after {timeout}s: {' '.join(cmd)}"
    except OSError as exc:  # pragma: no cover - defensive
        return 126, "", f"failed to run {cmd[0]}: {exc}"
    return (
        proc.returncode,
        proc.stdout.decode("utf-8", "replace"),
        proc.stderr.decode("utf-8", "replace"),
    )


def _git(
    repo_path: str, args: list[str], gnupghome: str | None = None, timeout: int = GIT_TIMEOUT_SECONDS
) -> tuple[int, str, str]:
    env_extra = {}
    extra_git_args = []
    if gnupghome:
        # Point git's gpg at the roster keyring only. HOME is redirected too so a
        # stray ~/.gnupg can never be consulted.
        env_extra.update({"GNUPGHOME": gnupghome, "HOME": gnupghome})
        allowed_signers = os.path.join(gnupghome, "allowed_signers")
        if os.path.isfile(allowed_signers):
            extra_git_args = ["-c", f"gpg.ssh.allowedSignersFile={allowed_signers}"]
    return _run(["git", *extra_git_args, "--no-pager", *args], cwd=repo_path, env_extra=env_extra, timeout=timeout)


def _gpg(
    gnupghome: str, args: list[str], input_bytes: bytes | None = None
) -> tuple[int, str, str]:
    cmd = ["gpg", "--batch", "--no-tty", "--yes", "--with-colons", *args]
    return _run(
        cmd,
        env_extra={"GNUPGHOME": gnupghome, "HOME": gnupghome},
        input_bytes=input_bytes,
        timeout=GPG_TIMEOUT_SECONDS,
    )


def _git_command_string(args: list[str]) -> str:
    return "git " + " ".join(args)


def gpg_available() -> bool:
    code, _, _ = _run(["gpg", "--version"], timeout=GPG_TIMEOUT_SECONDS)
    return code == 0


def is_git_repo(repo_path: str) -> bool:
    if not os.path.isdir(repo_path):
        return False
    code, out, _ = _git(repo_path, ["rev-parse", "--is-inside-work-tree"])
    return code == 0 and out.strip() == "true"


def _has_commits(repo_path: str) -> bool:
    code, _, _ = _git(repo_path, ["rev-parse", "--verify", "--quiet", "HEAD"])
    return code == 0


# --- helpers ------------------------------------------------------------------


def compute_ssh_fingerprint(public_key: str) -> str | None:
    """Compute standard OpenSSH SHA256 fingerprint (e.g. 'SHA256:...')."""
    parts = public_key.strip().split()
    if len(parts) < 2:
        return None
    try:
        blob = base64.b64decode(parts[1])
        digest = hashlib.sha256(blob).digest()
        b64_digest = base64.b64encode(digest).decode("ascii").rstrip("=")
        return f"SHA256:{b64_digest}"
    except Exception:
        pass
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            f.write(public_key.strip() + "\n")
            tmp_name = f.name
        try:
            proc = subprocess.run(
                ["ssh-keygen", "-l", "-f", tmp_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=5,
            )
            if proc.returncode == 0 and proc.stdout:
                bits = proc.stdout.strip().split()
                if len(bits) >= 2 and bits[1].startswith("SHA256:"):
                    return bits[1]
        finally:
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
    except Exception:
        pass
    return None


def normalize_fingerprint(value: str | None) -> str:
    """Normalize GPG hex fingerprint or OpenSSH SHA256 fingerprint."""
    if not value:
        return ""
    raw = str(value).strip()
    if raw.startswith("SHA256:"):
        return raw
    cleaned = re.sub(r"[\s:]", "", raw).upper()
    if cleaned.startswith("0X"):
        cleaned = cleaned[2:]
    return cleaned if re.fullmatch(r"[0-9A-F]{8,40}", cleaned) else ""


def _clean_field(value: str) -> str:
    """Blank out a placeholder git did not understand (e.g. '%GT' on old git)."""
    if len(value) == 3 and value.startswith("%"):
        return ""
    return value


def github_login_from_email(email: str) -> str | None:
    match = NOREPLY_RE.match((email or "").strip())
    return match.group(1) if match else None


def _parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _truncate(items: list, limit: int = MAX_EVIDENCE_ITEMS) -> list:
    return items[:limit]


# --- roster loading -----------------------------------------------------------


def discover_roster_path(repo_path: str) -> str | None:
    """$HACKPROOF_ROSTER (or $CHRONICLE_ROSTER), else a well-known path inside the repo, else None."""
    env_path = os.environ.get("HACKPROOF_ROSTER", "").strip() or os.environ.get("CHRONICLE_ROSTER", "").strip()
    if env_path:
        expanded = os.path.abspath(os.path.expanduser(env_path))
        return expanded if os.path.isfile(expanded) else None
    for candidate in ROSTER_CANDIDATES:
        full = os.path.join(repo_path, candidate)
        if os.path.isfile(full):
            return full
    return None


def load_roster(path: str) -> dict:
    """Parse and normalize a roster file. Collects errors instead of raising."""
    roster: dict = {
        "path": path,
        "team_id": None,
        "baseline_commit": None,
        "members": [],
        "errors": [],
    }
    try:
        with open(path, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        roster["errors"].append({"reason": "ROSTER_UNREADABLE", "detail": str(exc)})
        return roster

    if not isinstance(raw, dict):
        roster["errors"].append({"reason": "ROSTER_MALFORMED", "detail": "top level is not an object"})
        return roster

    roster["team_id"] = raw.get("team_id")
    baseline = raw.get("baseline_commit")
    roster["baseline_commit"] = str(baseline).strip().lower() if baseline else None

    members = raw.get("members")
    if not isinstance(members, list):
        roster["errors"].append({"reason": "ROSTER_MALFORMED", "detail": "'members' is missing or not a list"})
        return roster

    for index, entry in enumerate(members):
        if not isinstance(entry, dict):
            roster["errors"].append(
                {"reason": "ROSTER_MALFORMED", "detail": f"members[{index}] is not an object"}
            )
            continue
        member = {
            "member_id": str(entry.get("member_id") or entry.get("id") or f"member-{index}"),
            "display_name": entry.get("display_name") or entry.get("name") or "",
            "github_login": (entry.get("github_login") or "").strip(),
            "emails": [
                str(e).strip().lower()
                for e in (entry.get("emails") or ([entry["email"]] if entry.get("email") else []))
                if str(e).strip()
            ],
            "declared_non_coding_role": entry.get("declared_non_coding_role") or None,
            "keys": [],
        }
        keys = entry.get("keys")
        if isinstance(keys, dict):
            keys = [keys]
        if not isinstance(keys, list):
            keys = []
        for key_index, key in enumerate(keys):
            if not isinstance(key, dict):
                roster["errors"].append(
                    {
                        "reason": "ROSTER_MALFORMED",
                        "detail": f"members[{index}].keys[{key_index}] is not an object",
                    }
                )
                continue
            member["keys"].append(
                {
                    "key_id": str(key.get("key_id") or key.get("id") or f"{member['member_id']}-k{key_index}"),
                    "declared_fingerprint": normalize_fingerprint(key.get("fingerprint")),
                    "public_key": key.get("public_key") or key.get("armored") or None,
                    "public_key_path": key.get("public_key_path") or None,
                    "status": str(key.get("status") or "active").lower(),
                    "revoked_at": key.get("revoked_at"),
                    "expires_at": key.get("expires_at"),
                    "registered_at": key.get("registered_at"),
                }
            )
        roster["members"].append(member)
    return roster


def _read_key_material(key: dict) -> tuple[str | None, str | None]:
    """Return (armored_text, error). Inline material wins over a path."""
    if key.get("public_key"):
        return str(key["public_key"]), None
    path = key.get("public_key_path")
    if not path:
        return None, "no 'public_key' or 'public_key_path' given"
    full = os.path.abspath(os.path.expanduser(str(path)))
    try:
        with open(full, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(), None
    except OSError as exc:
        return None, str(exc)


def _parse_colons_keys(colons_output: str) -> dict:
    """Pull primary/sub fingerprints and key ids out of gpg --with-colons output."""
    primary: list[str] = []
    all_fprs: list[str] = []
    key_ids: list[str] = []
    has_secret = False
    current_is_primary = False
    awaiting_primary_fpr = False
    for line in colons_output.splitlines():
        fields = line.split(":")
        if not fields:
            continue
        record = fields[0]
        if record in ("pub", "sec"):
            has_secret = has_secret or record == "sec"
            current_is_primary = True
            awaiting_primary_fpr = True
            if len(fields) > 4 and fields[4]:
                key_ids.append(fields[4].upper())
        elif record in ("sub", "ssb"):
            current_is_primary = False
            if len(fields) > 4 and fields[4]:
                key_ids.append(fields[4].upper())
        elif record == "fpr" and len(fields) > 9:
            fpr = normalize_fingerprint(fields[9])
            if not fpr:
                continue
            all_fprs.append(fpr)
            if current_is_primary and awaiting_primary_fpr:
                primary.append(fpr)
                awaiting_primary_fpr = False
    return {
        "primary_fingerprints": primary,
        "fingerprints": all_fprs,
        "key_ids": key_ids,
        "has_secret": has_secret,
    }


def build_keyring(gnupghome: str, roster: dict) -> dict:
    """Import every roster public key into ``gnupghome``.

    Returns {'imported': [...], 'rejected': [...], 'index': {fpr-or-keyid: (member, key)}}.
    Private key material is refused and never imported.
    """
    result: dict = {"imported": [], "rejected": [], "index": {}, "platform_index": {}}
    try:
        result["platform_index"] = import_platform_keys(gnupghome)
    except Exception:  # never let a bundled key take down verification
        result["platform_index"] = dict(KNOWN_PLATFORM_FINGERPRINTS)
    for member in roster["members"]:
        if not member["keys"]:
            result["rejected"].append(
                {
                    "member_id": member["member_id"],
                    "key_id": None,
                    "reason": REJECT_NO_KEY_MATERIAL,
                    "detail": "member has no registered key",
                }
            )
            continue
        for key in member["keys"]:
            armored, error = _read_key_material(key)
            if armored is None:
                result["rejected"].append(
                    {
                        "member_id": member["member_id"],
                        "key_id": key["key_id"],
                        "reason": REJECT_UNREADABLE,
                        "detail": error,
                    }
                )
                continue

            upper_armored = armored.upper()
            # Guard against private key material (GPG or OpenSSH)
            if any(
                p in upper_armored
                for p in (
                    "PRIVATE KEY BLOCK",
                    "SECRET KEY BLOCK",
                    "OPENSSH PRIVATE KEY",
                    "PRIVATE KEY-----",
                )
            ):
                result["rejected"].append(
                    {
                        "member_id": member["member_id"],
                        "key_id": key["key_id"],
                        "reason": REJECT_PRIVATE_KEY,
                        "detail": "key contains private key material; refused and not imported",
                    }
                )
                continue

            stripped = armored.strip()
            # Handle SSH public key
            if any(stripped.startswith(prefix) for prefix in SSH_KEY_PREFIXES):
                ssh_fpr = compute_ssh_fingerprint(stripped)
                if not ssh_fpr:
                    result["rejected"].append(
                        {
                            "member_id": member["member_id"],
                            "key_id": key["key_id"],
                            "reason": REJECT_UNREADABLE,
                            "detail": "could not parse SSH public key",
                        }
                    )
                    continue

                declared = normalize_fingerprint(key.get("declared_fingerprint") or key.get("fingerprint"))
                if declared and declared != ssh_fpr and not ssh_fpr.endswith(declared):
                    result["rejected"].append(
                        {
                            "member_id": member["member_id"],
                            "key_id": key["key_id"],
                            "reason": REJECT_FINGERPRINT_MISMATCH,
                            "detail": "declared fingerprint does not match the submitted SSH key",
                            "declared_fingerprint": declared,
                            "derived_fingerprint": ssh_fpr,
                        }
                    )
                    continue

                allowed_path = os.path.join(gnupghome, "allowed_signers")
                clean_key = " ".join(stripped.split()[:2])
                with open(allowed_path, "a", encoding="utf-8") as f:
                    for email in member.get("emails", []):
                        f.write(f'{email} namespaces="git" {clean_key}\n')
                    if member.get("github_login"):
                        f.write(f'{member["github_login"]} namespaces="git" {clean_key}\n')
                    f.write(f'* namespaces="git" {clean_key}\n')

                record = {
                    "member_id": member["member_id"],
                    "key_id": key["key_id"],
                    "key_type": "ssh",
                    "primary_fingerprint": ssh_fpr,
                    "fingerprints": [ssh_fpr],
                    "gpg_key_ids": [],
                    "status": key["status"],
                    "revoked_at": key["revoked_at"],
                    "expires_at": key["expires_at"],
                }
                result["imported"].append(record)
                result["index"][ssh_fpr] = (member, key, record)
                if ssh_fpr.startswith("SHA256:"):
                    result["index"][ssh_fpr[7:]] = (member, key, record)
                continue

            # Otherwise, handle GPG public key
            blob = armored.encode("utf-8", "replace")
            code, out, err = _gpg(gnupghome, ["--import-options", "show-only", "--import"], blob)
            parsed = _parse_colons_keys(out)
            if parsed["has_secret"]:
                result["rejected"].append(
                    {
                        "member_id": member["member_id"],
                        "key_id": key["key_id"],
                        "reason": REJECT_PRIVATE_KEY,
                        "detail": "gpg reports secret key material in the submitted blob; refused",
                    }
                )
                continue
            if code != 0 or not parsed["fingerprints"]:
                result["rejected"].append(
                    {
                        "member_id": member["member_id"],
                        "key_id": key["key_id"],
                        "reason": REJECT_UNREADABLE,
                        "detail": (err.strip() or "gpg could not read any key from the blob")[:500],
                    }
                )
                continue

            derived_primary = parsed["primary_fingerprints"][0] if parsed["primary_fingerprints"] else ""
            declared = key["declared_fingerprint"]
            fingerprint_mismatch = bool(
                declared
                and derived_primary
                and not derived_primary.endswith(declared)
                and declared not in parsed["fingerprints"]
            )
            if fingerprint_mismatch:
                result["rejected"].append(
                    {
                        "member_id": member["member_id"],
                        "key_id": key["key_id"],
                        "reason": REJECT_FINGERPRINT_MISMATCH,
                        "detail": "declared fingerprint does not match the submitted key",
                        "declared_fingerprint": declared,
                        "derived_fingerprint": derived_primary,
                    }
                )
                continue

            import_code, _, import_err = _gpg(gnupghome, ["--import"], blob)
            if import_code != 0:
                result["rejected"].append(
                    {
                        "member_id": member["member_id"],
                        "key_id": key["key_id"],
                        "reason": REJECT_IMPORT_FAILED,
                        "detail": (import_err.strip() or f"gpg --import exited {import_code}")[:500],
                    }
                )
                continue

            record = {
                "member_id": member["member_id"],
                "key_id": key["key_id"],
                "key_type": "gpg",
                "primary_fingerprint": derived_primary,
                "fingerprints": parsed["fingerprints"],
                "gpg_key_ids": parsed["key_ids"],
                "status": key["status"],
                "revoked_at": key["revoked_at"],
                "expires_at": key["expires_at"],
            }
            result["imported"].append(record)
            # Index every handle a commit might present: primary fpr, subkey
            # fprs and short/long key ids all resolve to the same roster key.
            for handle in [*parsed["fingerprints"], *parsed["key_ids"]]:
                result["index"][handle] = (member, key, record)
    return result


def platform_key_files() -> list[str]:
    """Bundled platform keys, plus any the organizer adds for another host.

    ``$HACKPROOF_PLATFORM_KEYS`` takes os.pathsep-separated paths, for GitLab,
    Gitea or a self-hosted host that signs its own merges.
    ``$HACKPROOF_NO_PLATFORM_KEYS=1`` turns the whole mechanism off for an
    organizer who would rather see every non-roster signature as UNKNOWN_KEY.
    """
    if (os.environ.get("HACKPROOF_NO_PLATFORM_KEYS") or "").strip().lower() in ("1", "true", "yes"):
        return []
    files = []
    if os.path.isdir(PLATFORM_KEY_DIR):
        files.extend(
            os.path.join(PLATFORM_KEY_DIR, name)
            for name in sorted(os.listdir(PLATFORM_KEY_DIR))
            if name.endswith((".asc", ".gpg", ".pub"))
        )
    extra = (os.environ.get("HACKPROOF_PLATFORM_KEYS") or "").strip()
    if extra:
        files.extend(p for p in extra.split(os.pathsep) if p.strip())
    return files


def import_platform_keys(gnupghome: str) -> dict:
    """Import host keys into the throwaway keyring. Returns {handle: label}.

    Failure is never fatal: a missing or unreadable bundle simply means those
    commits fall through to UNKNOWN_KEY, which is the old behaviour.
    """
    index: dict = {}
    for path in platform_key_files():
        try:
            with open(path, "rb") as handle:
                blob = handle.read()
        except OSError:
            continue
        code, _, _ = _gpg(gnupghome, ["--import"], input_bytes=blob)
        if code != 0:
            continue
        _, out, _ = _gpg(gnupghome, ["--list-keys", "--with-fingerprint"])
        parsed = _parse_colons_keys(out)
        for handle in [*parsed["fingerprints"], *parsed["key_ids"]]:
            label = KNOWN_PLATFORM_FINGERPRINTS.get(handle)
            if label is None:
                # An organizer-supplied key: label it by where it came from.
                label = f"platform key from {os.path.basename(path)}"
            index.setdefault(handle, label)
    # Always recognise the known fingerprints, even if the bundle failed to load.
    for fingerprint, label in KNOWN_PLATFORM_FINGERPRINTS.items():
        index.setdefault(fingerprint, label)
    return index


def _build_identity_indexes(roster: dict) -> tuple[dict, dict]:
    email_index: dict = {}
    login_index: dict = {}
    for member in roster["members"]:
        for email in member["emails"]:
            email_index.setdefault(email, member)
        if member["github_login"]:
            login_index.setdefault(member["github_login"].lower(), member)
    return email_index, login_index


def resolve_author(email_index: dict, login_index: dict, author_email: str) -> tuple[dict | None, str | None]:
    """Map a commit's author email to a roster member. (member, how) or (None, None)."""
    email = (author_email or "").strip().lower()
    if email in email_index:
        return email_index[email], "email"
    login = github_login_from_email(email)
    if login and login.lower() in login_index:
        return login_index[login.lower()], "github_noreply_login"
    return None, None


# --- commit collection --------------------------------------------------------


def collect_commits(repo_path: str, gnupghome: str | None) -> tuple[list[dict], str | None]:
    """One `git log` pass, verifying every commit against ``gnupghome``.

    Returns (records, error). git performs the signature check itself, so this is
    a single subprocess for the whole history rather than one per commit.
    """
    args = ["log", f"--max-count={MAX_COMMITS}", f"--format={_LOG_FORMAT}"]
    code, out, err = _git(repo_path, args, gnupghome=gnupghome, timeout=GIT_TIMEOUT_SECONDS * 3)
    if code != 0:
        return [], (err.strip() or f"git log exited {code}")

    records: list[dict] = []
    for chunk in out.split(_RECORD_SEP):
        if not chunk.strip():
            continue
        parts = chunk.split(_FIELD_SEP)
        if len(parts) < len(_LOG_FIELDS):
            parts += [""] * (len(_LOG_FIELDS) - len(parts))
        record = {name: _clean_field(parts[i].strip()) for i, name in enumerate(_LOG_FIELDS)}
        if not record["sha"]:
            continue
        record["signing_fingerprint"] = normalize_fingerprint(record["signing_fingerprint"])
        record["signing_primary_fingerprint"] = normalize_fingerprint(
            record["signing_primary_fingerprint"]
        )
        record["signing_key_id"] = normalize_fingerprint(record["signing_key_id"])
        records.append(record)
    return records, None


def raw_verify(repo_path: str, sha: str, gnupghome: str | None) -> list[str]:
    """`git verify-commit --raw`: gpg/ssh status lines, kept verbatim as evidence."""
    _, _, err = _git(repo_path, ["verify-commit", "--raw", sha], gnupghome=gnupghome)
    return [
        line.strip()
        for line in err.splitlines()
        if (
            line.startswith("[GNUPG:]")
            or "gpg:" in line
            or "Good \"git\" signature" in line
            or "BAD signature" in line
            or "No signature" in line
            or "signature" in line.lower()
        )
    ][:20]


# --- status resolution --------------------------------------------------------


def _roster_key_for(record: dict, index: dict):
    for handle in (
        record.get("signing_primary_fingerprint"),
        record.get("signing_fingerprint"),
        record.get("signing_key_id"),
    ):
        if handle and handle in index:
            return index[handle]
    # A commit may present a 16-hex key id while the roster indexed a 40-hex
    # fingerprint (or the reverse). Fall back to suffix matching.
    candidates = [
        h for h in (
            record.get("signing_primary_fingerprint"),
            record.get("signing_fingerprint"),
            record.get("signing_key_id"),
        ) if h
    ]
    for handle in candidates:
        for indexed, value in index.items():
            if indexed.endswith(handle) or handle.endswith(indexed):
                return value
    return None


def _platform_label_for(record: dict, platform_index: dict | None) -> str | None:
    if not platform_index:
        return None
    for handle in (
        record.get("signing_primary_fingerprint"),
        record.get("signing_fingerprint"),
        record.get("signing_key_id"),
    ):
        if not handle:
            continue
        if handle in platform_index:
            return platform_index[handle]
        for indexed, label in platform_index.items():
            if indexed.endswith(handle) or handle.endswith(indexed):
                return label
    return None


def classify_commit(
    record: dict,
    index: dict,
    email_index: dict,
    login_index: dict,
    attribution_enabled: bool,
    platform_index: dict | None = None,
) -> dict:
    """Resolve one commit to a status plus the evidence behind it."""
    code = record["git_signature_code"]
    result = dict(record)
    result["identity_match"] = IDENTITY_NA
    result["platform_label"] = None
    result["roster_member_id"] = None
    result["roster_key_id"] = None
    result["author_roster_member_id"] = None
    result["notes"] = []

    if code == "N" or not code:
        result["status"] = STATUS_NO_SIGNATURE
        result["has_signature"] = False
        return result

    result["has_signature"] = True

    if code == "B":
        result["status"] = STATUS_INVALID_SIGNATURE
        result["notes"].append("signature does not match the commit object; the object was altered after signing")
        return result

    if not attribution_enabled:
        # No usable roster: record what git said and stop. Deliberately NOT
        # UNKNOWN_KEY -- we have nothing to compare against.
        result["status"] = None
        result["notes"].append("no roster keyring available; signature recorded but not attributed")
        return result

    if code == "R":
        result["status"] = STATUS_REVOKED_KEY
        result["notes"].append("the signing key carries a revocation certificate")
        return result
    if code == "Y":
        result["status"] = STATUS_EXPIRED_KEY
        result["notes"].append("good signature made by a key that had already expired")
        return result
    if code == "X":
        result["status"] = STATUS_EXPIRED_KEY
        result["notes"].append("good signature, but the signature itself has expired")
        return result
    if code == "E":
        platform = _platform_label_for(record, platform_index)
        if platform:
            result["status"] = STATUS_PLATFORM_KEY
            result["platform_label"] = platform
            result["notes"].append(
                f"signed by {platform}, not by a participant; the key could not be imported "
                "but its fingerprint is recognised"
            )
            return result
        result["status"] = STATUS_UNKNOWN_KEY
        result["notes"].append("git could not check the signature; the signing key is not on the roster")
        return result
    if code not in GOOD_CODES:
        result["status"] = STATUS_UNKNOWN_KEY
        result["notes"].append(f"unrecognized git signature code {code!r}; treated as unattributable")
        return result

    # --- good signature: attribute it -----------------------------------------
    match = _roster_key_for(record, index)
    if match is None:
        platform = _platform_label_for(record, platform_index)
        if platform:
            # The host signed this, not a person. Real, verifiable, and not the
            # team's work -- so it is neither attributed nor flagged.
            result["status"] = STATUS_PLATFORM_KEY
            result["platform_label"] = platform
            result["notes"].append(
                f"good signature from {platform} -- created by the git host (a web merge or "
                "web edit), so it is not attributable to a team member and is not counted as one"
            )
            return result
        result["status"] = STATUS_UNKNOWN_KEY
        result["notes"].append("good signature from a key that is not on the roster (outside contributor)")
        return result

    member, key, key_record = match
    result["roster_member_id"] = member["member_id"]
    result["roster_key_id"] = key_record["key_id"]

    author_member, how = resolve_author(email_index, login_index, record["author_email"])
    if author_member is None:
        result["identity_match"] = IDENTITY_UNKNOWN
        result["notes"].append("commit author identity is not on the roster")
    else:
        result["author_roster_member_id"] = author_member["member_id"]
        result["author_matched_by"] = how
        result["identity_match"] = (
            IDENTITY_MATCH if author_member["member_id"] == member["member_id"] else IDENTITY_MISMATCH
        )

    # Administrative revocation, recorded by the organizer rather than by gpg.
    if key_record["status"] == "revoked":
        revoked_at = _parse_iso(key_record.get("revoked_at"))
        committed_at = _parse_iso(record.get("committer_date"))
        if revoked_at and committed_at and committed_at < revoked_at:
            result["notes"].append(
                f"key was revoked at {key_record['revoked_at']}, after this commit; signature still counts"
            )
        else:
            result["status"] = STATUS_REVOKED_KEY
            result["notes"].append(
                "key is marked revoked on the roster"
                + (f" (revoked_at={key_record['revoked_at']})" if key_record.get("revoked_at") else "")
            )
            return result

    roster_expiry = _parse_iso(key_record.get("expires_at"))
    committed_at = _parse_iso(record.get("committer_date"))
    if roster_expiry and committed_at and committed_at > roster_expiry:
        result["status"] = STATUS_EXPIRED_KEY
        result["notes"].append(f"roster records this key as expiring at {key_record['expires_at']}")
        return result

    if result["identity_match"] == IDENTITY_MISMATCH:
        result["status"] = STATUS_IDENTITY_MISMATCH
        result["notes"].append(
            "signed by "
            f"{member['member_id']}'s registered key but authored as {record['author_email']}"
            f" ({result['author_roster_member_id']})"
        )
        return result

    result["status"] = STATUS_VERIFIED
    return result


def _commit_summary(record: dict) -> dict:
    """The compact per-commit shape embedded in evidence."""
    keep = (
        "sha",
        "author_name",
        "author_email",
        "author_date",
        "committer_date",
        "status",
        "git_signature_code",
        "signing_key_id",
        "signing_fingerprint",
        "signing_primary_fingerprint",
        "signer_name",
        "roster_member_id",
        "roster_key_id",
        "author_roster_member_id",
        "identity_match",
        "notes",
    )
    return {k: record.get(k) for k in keep if record.get(k) not in (None, "", [])}


# --- checks -------------------------------------------------------------------


def check_roster_integrity(roster: dict | None, keyring: dict | None, roster_path: str | None) -> Finding:
    evidence: dict = {
        "mechanism": "organizer-controlled roster of registered public keys",
        "commands": [
            "gpg --with-colons --import-options show-only --import  (fingerprint derivation, no import)",
            "gpg --import  (public keys only)",
        ],
        "policy": "private key material is refused and never imported; only public keys are registered (spec §8.a)",
    }
    if roster is None:
        evidence["note"] = "no roster file found; signature attribution is disabled"
        evidence["searched"] = ["$HACKPROOF_ROSTER", "$CHRONICLE_ROSTER", *ROSTER_CANDIDATES]
        return Finding(CHECK_ROSTER, "server", "info", evidence, True)

    evidence["roster_path"] = roster_path
    evidence["team_id"] = roster.get("team_id")
    evidence["member_count"] = len(roster["members"])
    evidence["parse_errors"] = _truncate(roster["errors"])

    if keyring is None:
        evidence["note"] = "gpg is unavailable, so no key could be imported"
        return Finding(CHECK_ROSTER, "server", "info", evidence, True)

    evidence["imported_keys"] = _truncate(
        [
            {
                "member_id": rec["member_id"],
                "key_id": rec["key_id"],
                "primary_fingerprint": rec["primary_fingerprint"],
                "status": rec["status"],
            }
            for rec in keyring["imported"]
        ]
    )
    evidence["imported_key_count"] = len(keyring["imported"])
    evidence["rejected_keys"] = _truncate(keyring["rejected"])
    evidence["rejected_key_count"] = len(keyring["rejected"])
    evidence["note"] = (
        f"{len(keyring['imported'])} key(s) imported from {len(roster['members'])} member(s), "
        f"{len(keyring['rejected'])} rejected"
    )

    reasons = {r["reason"] for r in keyring["rejected"]}
    if REJECT_PRIVATE_KEY in reasons:
        severity, passed = "hard_flag", False
        evidence["interpretation"] = (
            "a participant submitted private key material; the key was not imported and must be "
            "rotated before it can be trusted, since HACKPROOF may have seen it"
        )
    elif reasons & {REJECT_FINGERPRINT_MISMATCH, REJECT_IMPORT_FAILED} or roster["errors"]:
        severity, passed = "flag", False
    elif REJECT_UNREADABLE in reasons or REJECT_NO_KEY_MATERIAL in reasons:
        severity, passed = "info", True
        evidence["note"] = "some members have no usable registered key; their commits cannot be attributed"
    else:
        severity, passed = "info", True
    return Finding(CHECK_ROSTER, "server", severity, evidence, passed)


def _by_status(commits: list[dict], status: str) -> list[dict]:
    return [c for c in commits if c.get("status") == status]


def check_signature_verification(
    repo_path: str, commits: list[dict], attribution_enabled: bool, raw_budget: int
) -> Finding:
    evidence: dict = {
        "mechanism": "per-commit GPG signature verification against the roster keyring",
        "commands": [
            _git_command_string(["log", "--format=%H %ae %G? %GK %GF %GP"]),
            _git_command_string(["verify-commit", "--raw", "<sha>"]),
        ],
        "git_code_legend": {
            "G/U": "good signature",
            "B": "bad signature",
            "X": "good signature, expired signature",
            "Y": "good signature, expired key",
            "R": "good signature, revoked key",
            "E": "signature could not be checked (key not on the roster)",
            "N": "no signature",
        },
        "statuses": {status: len(_by_status(commits, status)) for status in ALL_STATUSES},
        "commit_count": len(commits),
    }
    if not attribution_enabled:
        evidence["note"] = "no roster keyring; only the presence of a signature was recorded"
        evidence["signed_commits"] = sum(1 for c in commits if c.get("has_signature"))

    invalid = _by_status(commits, STATUS_INVALID_SIGNATURE)
    evidence["invalid_signature_commits"] = _truncate([_commit_summary(c) for c in invalid])

    # Raw gpg status lines for anything that is not a clean pass, capped.
    interesting = [c for c in commits if c.get("status") not in (STATUS_VERIFIED, STATUS_NO_SIGNATURE)]
    raw: list[dict] = []
    for commit in interesting[:raw_budget]:
        lines = raw_verify(repo_path, commit["sha"], commit.get("_gnupghome"))
        if lines:
            raw.append({"sha": commit["sha"], "gpg_status": lines})
    if raw:
        evidence["raw_gpg_status"] = raw

    evidence["commits"] = _truncate([_commit_summary(c) for c in commits])
    if len(commits) > MAX_EVIDENCE_ITEMS:
        evidence["commits_truncated"] = True

    if attribution_enabled:
        breakdown = ", ".join(
            f"{count} {status}" for status, count in evidence["statuses"].items() if count
        )
        evidence["note"] = f"{len(commits)} commits: {breakdown or 'nothing to verify'}"

    if invalid:
        return Finding(CHECK_SIGNATURES, "claim", "hard_flag", evidence, False)
    return Finding(CHECK_SIGNATURES, "claim", "info", evidence, True)


def check_unregistered_key(commits: list[dict], attribution_enabled: bool) -> Finding:
    evidence: dict = {
        "mechanism": "signing key not present on the organizer's roster (spec §8.e check 4)",
        "interpretation": (
            "a key HACKPROOF never registered signed code in this repo. That points at a "
            "contributor outside the team -- but it is also what an unregistered second "
            "machine or a forgotten `git config user.signingkey` looks like, so it is "
            "evidence to put to the team, not a finding of cheating"
        ),
    }
    if not attribution_enabled:
        evidence["note"] = "no roster keyring available; attribution skipped"
        return Finding(CHECK_UNREGISTERED, "claim", "info", evidence, True)

    platform = _by_status(commits, STATUS_PLATFORM_KEY)
    if platform:
        evidence["platform_signed_commits"] = _truncate(
            [
                dict(_commit_summary(c), platform_label=c.get("platform_label"))
                for c in platform
            ]
        )
        evidence["platform_signed_commit_count"] = len(platform)
        evidence["platform_note"] = (
            f"{len(platform)} commit(s) were signed by the git host itself (a web merge or web "
            "edit), not by any participant's key. They are verifiable and they are not the "
            "team's work, so they are neither attributed to a member nor flagged"
        )

    unknown = _by_status(commits, STATUS_UNKNOWN_KEY)
    evidence["unregistered_key_commits"] = _truncate([_commit_summary(c) for c in unknown])
    evidence["unregistered_key_commit_count"] = len(unknown)
    evidence["distinct_unregistered_keys"] = sorted(
        {c.get("signing_primary_fingerprint") or c.get("signing_key_id") or "unknown" for c in unknown}
    )[:MAX_EVIDENCE_ITEMS]
    if unknown:
        return Finding(CHECK_UNREGISTERED, "claim", "hard_flag", evidence, False)
    evidence["note"] = "every signed commit was signed by a registered key"
    return Finding(CHECK_UNREGISTERED, "claim", "info", evidence, True)


def check_identity_match(commits: list[dict], attribution_enabled: bool) -> Finding:
    evidence: dict = {
        "mechanism": "registered key vs. commit author identity (spec §8.e check 3)",
        "matching": "commit author email against the member's registered emails, plus GitHub noreply logins",
        "verdict_legend": {
            IDENTITY_MATCH: "signing key and author resolve to the same registered member",
            IDENTITY_MISMATCH: "one member's key signed a commit authored as another member",
            IDENTITY_UNKNOWN: "the author identity is not on the roster at all",
            IDENTITY_NA: "unsigned or unattributable commit",
        },
    }
    if not attribution_enabled:
        evidence["note"] = "no roster keyring available; attribution skipped"
        return Finding(CHECK_IDENTITY, "claim", "info", evidence, True)

    mismatches = [c for c in commits if c.get("identity_match") == IDENTITY_MISMATCH]
    unknown_authors = [c for c in commits if c.get("identity_match") == IDENTITY_UNKNOWN]
    evidence["identity_mismatch_commits"] = _truncate([_commit_summary(c) for c in mismatches])
    evidence["identity_mismatch_count"] = len(mismatches)
    evidence["unknown_author_commits"] = _truncate([_commit_summary(c) for c in unknown_authors])
    evidence["unknown_author_count"] = len(unknown_authors)
    evidence["match_count"] = sum(1 for c in commits if c.get("identity_match") == IDENTITY_MATCH)

    if mismatches:
        evidence["interpretation"] = (
            "someone committed under a teammate's identity while signing with their own key "
            "(or registered their key against the wrong handle at check-in). Ask before flagging"
        )
        return Finding(CHECK_IDENTITY, "claim", "flag", evidence, False)
    if unknown_authors:
        evidence["note"] = (
            f"{len(unknown_authors)} signed commits have an author email that is not on the roster"
        )
    elif evidence["match_count"]:
        evidence["note"] = (
            f"all {evidence['match_count']} attributed commits were signed by their own author's key"
        )
    else:
        evidence["note"] = "no attributable signed commits to match"
    return Finding(CHECK_IDENTITY, "claim", "info", evidence, True)


def check_key_validity(commits: list[dict], attribution_enabled: bool) -> Finding:
    evidence: dict = {
        "mechanism": "expired / revoked signing keys",
        "sources": {
            "cryptographic": "gpg reports the key's own expiry or revocation certificate (git codes Y, X, R)",
            "administrative": "the roster marks the key revoked or expired, with a timestamp",
        },
        "rule": "a commit made before a key's revocation timestamp still counts as verified",
    }
    if not attribution_enabled:
        evidence["note"] = "no roster keyring available; key validity not evaluated"
        return Finding(CHECK_KEY_VALIDITY, "claim", "info", evidence, True)

    revoked = _by_status(commits, STATUS_REVOKED_KEY)
    expired = _by_status(commits, STATUS_EXPIRED_KEY)
    evidence["revoked_key_commits"] = _truncate([_commit_summary(c) for c in revoked])
    evidence["revoked_key_commit_count"] = len(revoked)
    evidence["expired_key_commits"] = _truncate([_commit_summary(c) for c in expired])
    evidence["expired_key_commit_count"] = len(expired)

    if revoked:
        return Finding(CHECK_KEY_VALIDITY, "claim", "hard_flag", evidence, False)
    if expired:
        evidence["interpretation"] = (
            "an expired key still identifies its holder; this is usually hygiene, not deception. "
            "Weigh it well below an unregistered key"
        )
        return Finding(CHECK_KEY_VALIDITY, "claim", "flag", evidence, False)
    evidence["note"] = "no commit was signed by an expired or revoked key"
    return Finding(CHECK_KEY_VALIDITY, "claim", "info", evidence, True)


def check_signature_coverage(
    commits: list[dict], attribution_enabled: bool, baseline_commit: str | None
) -> Finding:
    """Headline dashboard metric: how much of the history is cryptographically attributed."""
    evidence: dict = {
        "mechanism": "verified-signature coverage",
        "commands": [_git_command_string(["log", "--format=%H %G?"])],
        "pass_threshold": VERIFIED_RATIO_PASS_THRESHOLD,
        "framing": (
            "a coverage number, not an accusation: unsigned commits are unattributed, "
            "not evidence of cheating (spec §8.e check 5)"
        ),
    }

    scored = commits
    if baseline_commit:
        excluded = [c for c in commits if c["sha"].lower().startswith(baseline_commit.lower())]
        if excluded:
            scored = [c for c in commits if c not in excluded]
            evidence["baseline_commit_excluded"] = [c["sha"] for c in excluded]

    platform_commits = [c for c in scored if c.get("status") == STATUS_PLATFORM_KEY]
    if platform_commits:
        # A merge GitHub performed is not code anyone typed, so counting it in the
        # denominator would penalise a team for opening pull requests.
        scored = [c for c in scored if c.get("status") != STATUS_PLATFORM_KEY]
        evidence["platform_commits_excluded"] = _truncate(
            [c["sha"] for c in platform_commits]
        )
        evidence["platform_commits_excluded_count"] = len(platform_commits)

    total = len(scored)
    evidence["commit_count"] = total
    signed = sum(1 for c in scored if c.get("has_signature"))
    evidence["signed_commit_count"] = signed
    evidence["unsigned_commit_count"] = total - signed
    evidence["signed_ratio"] = round(signed / total, 4) if total else 1.0
    evidence["unsigned_commits"] = _truncate(
        [_commit_summary(c) for c in scored if not c.get("has_signature")]
    )

    if not attribution_enabled:
        evidence["note"] = (
            "no roster keyring available: signature presence is reported, verified coverage is not"
        )
        evidence["verified_ratio"] = None
        return Finding(CHECK_COVERAGE, "claim", "info", evidence, True)

    verified = len(_by_status(scored, STATUS_VERIFIED))
    evidence["verified_commit_count"] = verified
    ratio = round(verified / total, 4) if total else 1.0
    evidence["verified_ratio"] = ratio
    evidence["status_breakdown"] = {s: len(_by_status(scored, s)) for s in ALL_STATUSES}
    if not total:
        evidence["note"] = "repository has no commits"
    return Finding(
        CHECK_COVERAGE,
        "claim",
        "info",  # always informational: this is a metric, not an accusation
        evidence,
        ratio >= VERIFIED_RATIO_PASS_THRESHOLD,
    )


# --- entry point --------------------------------------------------------------


def _skipped_findings(repo_path: str, reason: str) -> list[Finding]:
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


def classify_repo(repo_path: str, roster_path: str | None = None) -> dict:
    """One repo's commits, classified against the roster -- the shared local verdict.

    ``run()`` below and ``analyzers.github_check`` both need the same answer to
    "what does HACKPROOF itself think of each commit". A cross-check against
    GitHub is only meaningful if both sides are comparing against an identical
    local verdict, so that verdict is produced in exactly one place: here.

    Returns a dict instead of raising. ``error`` is set when nothing could be
    classified at all; ``commits`` is then empty rather than wrong.
    """
    resolved = os.path.abspath(os.path.expanduser(str(repo_path)))
    result: dict = {
        "repo_path": resolved,
        "roster_path": None,
        "roster": None,
        "keyring": None,
        "commits": [],
        "attribution_enabled": False,
        "error": None,
    }
    if not os.path.isdir(resolved):
        result["error"] = "path does not exist or is not a directory"
        return result
    if not is_git_repo(resolved):
        result["error"] = "path is not inside a git working tree"
        return result
    if not gpg_available():
        result["error"] = "gpg executable not found on PATH"
        return result

    found_roster_path = roster_path or discover_roster_path(resolved)
    result["roster_path"] = found_roster_path
    roster = load_roster(found_roster_path) if found_roster_path else None
    result["roster"] = roster

    temp_home = None
    try:
        keyring = None
        if roster is not None:
            temp_home = tempfile.mkdtemp(prefix="hackproof-keyring-")
            os.chmod(temp_home, 0o700)
            try:
                keyring = build_keyring(temp_home, roster)
            except Exception as exc:  # pragma: no cover - defensive
                keyring = {
                    "imported": [],
                    "rejected": [
                        {"reason": REJECT_IMPORT_FAILED, "detail": f"{type(exc).__name__}: {exc}"}
                    ],
                    "index": {},
                }
        result["keyring"] = keyring
        attribution_enabled = bool(keyring and keyring["imported"])
        result["attribution_enabled"] = attribution_enabled

        gnupghome = temp_home
        if gnupghome is None:
            # Never fall back to the host keyring: an empty GNUPGHOME is the
            # honest state when there is no roster.
            temp_home = tempfile.mkdtemp(prefix="hackproof-keyring-")
            os.chmod(temp_home, 0o700)
            gnupghome = temp_home

        if not _has_commits(resolved):
            return result

        commits, log_error = collect_commits(resolved, gnupghome)
        if log_error:
            result["error"] = f"git log failed: {log_error}"
            return result

        index = keyring["index"] if keyring else {}
        platform_index = keyring.get("platform_index") if keyring else {}
        email_index, login_index = _build_identity_indexes(roster) if roster else ({}, {})
        result["commits"] = [
            classify_commit(
                record, index, email_index, login_index, attribution_enabled, platform_index
            )
            for record in commits
        ]
        return result
    finally:
        if temp_home:
            _run(
                ["gpgconf", "--kill", "gpg-agent"],
                env_extra={"GNUPGHOME": temp_home, "HOME": temp_home},
            )
            shutil.rmtree(temp_home, ignore_errors=True)


def run(repo_path: str, roster_path: str | None = None) -> list[Finding]:
    """Run all six signature checks against ``repo_path``.

    Always returns one Finding per check, in a stable order, and never raises.
    ``roster_path`` defaults to ``$HACKPROOF_ROSTER`` or a well-known path in the
    repo, which keeps the engine's ``run(repo_path)`` contract intact.
    """
    resolved = os.path.abspath(os.path.expanduser(str(repo_path)))
    if not os.path.isdir(resolved):
        return _skipped_findings(resolved, "path does not exist or is not a directory")
    if not is_git_repo(resolved):
        return _skipped_findings(resolved, "path is not inside a git working tree")
    if not gpg_available():
        return _skipped_findings(resolved, "gpg executable not found on PATH; signature checks skipped")

    found_roster_path = roster_path or discover_roster_path(resolved)
    roster = load_roster(found_roster_path) if found_roster_path else None

    gnupghome = None
    keyring = None
    temp_home = None
    try:
        if roster is not None:
            temp_home = tempfile.mkdtemp(prefix="hackproof-keyring-")
            os.chmod(temp_home, 0o700)  # gpg refuses a world-readable home
            gnupghome = temp_home
            try:
                keyring = build_keyring(gnupghome, roster)
            except Exception as exc:  # pragma: no cover - defensive
                keyring = {
                    "imported": [],
                    "rejected": [{"reason": REJECT_IMPORT_FAILED, "detail": f"{type(exc).__name__}: {exc}"}],
                    "index": {},
                }

        attribution_enabled = bool(keyring and keyring["imported"])
        if not attribution_enabled:
            # Never verify against the host's own keyring: an empty GNUPGHOME is
            # the honest state when we have no roster keys.
            if gnupghome is None:
                temp_home = tempfile.mkdtemp(prefix="hackproof-keyring-")
                os.chmod(temp_home, 0o700)
                gnupghome = temp_home

        if not _has_commits(resolved):
            findings = [
                check_roster_integrity(roster, keyring, found_roster_path),
                *[
                    Finding(
                        name,
                        plane,
                        "info",
                        {"repo_path": resolved, "note": "repository has no commits", "commit_count": 0},
                        True,
                    )
                    for name, plane in ALL_CHECKS
                    if name != CHECK_ROSTER
                ],
            ]
            return findings

        commits, log_error = collect_commits(resolved, gnupghome)
        if log_error:
            return _skipped_findings(resolved, f"git log failed: {log_error}")

        index = keyring["index"] if keyring else {}
        platform_index = keyring.get("platform_index") if keyring else {}
        email_index, login_index = _build_identity_indexes(roster) if roster else ({}, {})
        classified = [
            classify_commit(
                record, index, email_index, login_index, attribution_enabled, platform_index
            )
            for record in commits
        ]
        for record in classified:
            record["_gnupghome"] = gnupghome

        baseline = roster.get("baseline_commit") if roster else None

        checks = (
            (CHECK_ROSTER, "server", lambda: check_roster_integrity(roster, keyring, found_roster_path)),
            (
                CHECK_SIGNATURES,
                "claim",
                lambda: check_signature_verification(resolved, classified, attribution_enabled, MAX_RAW_VERIFY),
            ),
            (CHECK_UNREGISTERED, "claim", lambda: check_unregistered_key(classified, attribution_enabled)),
            (CHECK_IDENTITY, "claim", lambda: check_identity_match(classified, attribution_enabled)),
            (CHECK_KEY_VALIDITY, "claim", lambda: check_key_validity(classified, attribution_enabled)),
            (
                CHECK_COVERAGE,
                "claim",
                lambda: check_signature_coverage(classified, attribution_enabled, baseline),
            ),
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
    finally:
        if temp_home:
            # gpg-agent can hold a socket in here; ignore whatever refuses to go.
            _run(["gpgconf", "--kill", "gpg-agent"], env_extra={"GNUPGHOME": temp_home, "HOME": temp_home})
            shutil.rmtree(temp_home, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify commit signatures in a git repository against a HACKPROOF roster."
    )
    parser.add_argument("repo_path", help="path to the git repository to inspect")
    parser.add_argument(
        "--roster",
        default=None,
        help="path to the roster JSON (default: $HACKPROOF_ROSTER, then .hackproof/roster.json)",
    )
    parser.add_argument(
        "--compact", action="store_true", help="emit single-line JSON instead of indented"
    )
    args = parser.parse_args(argv)

    findings = run(args.repo_path, roster_path=args.roster)
    payload = [dataclasses.asdict(f) for f in findings]
    print(json.dumps(payload, indent=None if args.compact else 2, sort_keys=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
