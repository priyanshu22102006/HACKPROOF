#!/usr/bin/env python3
"""build_roster -- the organizer side of enrollment.

Collects the enrollment cards participants produced with
``scripts/hackproof_enroll.py`` and merges them into the ``roster.json`` that
``analyzers/gpg_check.py`` verifies against.

    python3 scripts/build_roster.py --team-id team-07 --out roster.json \
        enrollment-satoru-gpg.json enrollment-priyanshu-ssh.json

Three things it refuses to produce, because each one silently corrupts a verdict
later:

* **A roster carrying private key material.** Checked again here even though
  enrollment already checked: the file travelled over chat or email in between,
  and this is the last point before it becomes the thing verdicts are built on.
  Per spec §8.a only the public half is ever registered.
* **The same fingerprint under two members.** ``gpg_check`` resolves a key
  through one index, so whichever member is indexed first wins the attribution
  and the other silently becomes unattributable. The GPG design note calls this
  out as first-write-wins and says to reject it at enrollment instead of guessing
  at analysis time -- so it is rejected here.
* **A card that does not parse back.** The finished roster is loaded through
  ``gpg_check.load_roster`` before it is written, so a roster that the analyzer
  would reject never reaches the judging machine.

One member may hold several keys: pass several cards with the same
``member_id`` and they merge. That is how key rotation and a
GPG-plus-SSH participant both work.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from analyzers.gpg_check import load_roster  # noqa: E402

SCHEMA = "hackproof.enrollment-card/1"

PRIVATE_KEY_MARKERS = (
    "PRIVATE KEY BLOCK",
    "OPENSSH PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN EC PRIVATE KEY",
    "BEGIN DSA PRIVATE KEY",
    "BEGIN PRIVATE KEY",
    "BEGIN ENCRYPTED PRIVATE KEY",
)


class RosterError(RuntimeError):
    pass


def contains_private_key(blob: str) -> str | None:
    upper = (blob or "").upper()
    for marker in PRIVATE_KEY_MARKERS:
        if marker in upper:
            return marker
    return None


def read_card(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            card = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RosterError(f"{path}: cannot read enrollment card ({exc})") from exc
    if not isinstance(card, dict):
        raise RosterError(f"{path}: top level is not an object")
    if card.get("schema") != SCHEMA:
        raise RosterError(f"{path}: unexpected schema {card.get('schema')!r}, expected {SCHEMA!r}")
    for field in ("member_id", "emails", "key"):
        if not card.get(field):
            raise RosterError(f"{path}: missing required field {field!r}")
    key = card["key"]
    if not isinstance(key, dict) or not key.get("public_key") or not key.get("fingerprint"):
        raise RosterError(f"{path}: 'key' must carry both 'public_key' and 'fingerprint'")
    marker = contains_private_key(key["public_key"])
    if marker:
        raise RosterError(
            f"{path}: card contains private key material ({marker}). "
            "That key must be rotated -- treat it as compromised, since it has now been shared."
        )
    return card


def merge(cards: list[tuple[str, dict]], team_id: str, baseline_commit: str | None) -> dict:
    members: dict[str, dict] = {}
    fingerprint_owner: dict[str, tuple[str, str]] = {}  # fingerprint -> (member_id, card path)
    key_ids: set[tuple[str, str]] = set()

    for path, card in cards:
        member_id = str(card["member_id"]).strip()
        key = card["key"]
        fingerprint = str(key["fingerprint"]).strip()

        owner = fingerprint_owner.get(fingerprint)
        if owner and owner[0] != member_id:
            raise RosterError(
                f"fingerprint {fingerprint} appears under two members: "
                f"{owner[0]} ({owner[1]}) and {member_id} ({path}). "
                "Two people cannot share one key -- attribution would be a coin flip. "
                "Re-enroll one of them with their own key."
            )
        fingerprint_owner[fingerprint] = (member_id, path)

        member = members.setdefault(
            member_id,
            {
                "member_id": member_id,
                "display_name": card.get("display_name") or member_id,
                "github_login": (card.get("github_login") or "").strip(),
                "emails": [],
                "declared_non_coding_role": card.get("declared_non_coding_role"),
                "keys": [],
            },
        )
        for email in card.get("emails") or []:
            email = str(email).strip().lower()
            if email and email not in member["emails"]:
                member["emails"].append(email)
        if card.get("github_login") and not member["github_login"]:
            member["github_login"] = str(card["github_login"]).strip()

        key_id = str(key.get("key_id") or f"{member_id}-k{len(member['keys']) + 1}")
        while (member_id, key_id) in key_ids:
            key_id = f"{key_id}-dup"
        key_ids.add((member_id, key_id))

        if any(existing["fingerprint"] == fingerprint for existing in member["keys"]):
            continue  # same card submitted twice; harmless

        member["keys"].append(
            {
                "key_id": key_id,
                "key_type": key.get("key_type"),
                "fingerprint": fingerprint,
                "public_key": key["public_key"],
                "status": key.get("status") or "active",
                "revoked_at": key.get("revoked_at"),
                "expires_at": key.get("expires_at"),
                "registered_at": key.get("registered_at"),
            }
        )

    return {
        "team_id": team_id,
        "baseline_commit": baseline_commit,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "members": list(members.values()),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Merge enrollment cards into a HACKPROOF roster.")
    parser.add_argument("cards", nargs="+", help="enrollment card JSON files")
    parser.add_argument("--team-id", required=True)
    parser.add_argument(
        "--baseline-commit",
        default=None,
        help="the organizer template commit, excluded from coverage (spec §7 phase 0)",
    )
    parser.add_argument("--out", default="roster.json")
    args = parser.parse_args(argv)

    try:
        cards = [(path, read_card(path)) for path in args.cards]
        roster = merge(cards, args.team_id, args.baseline_commit)
    except RosterError as exc:
        print(f"roster build failed: {exc}", file=sys.stderr)
        return 1

    out_path = os.path.abspath(os.path.expanduser(args.out))
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(roster, handle, indent=2)
        handle.write("\n")

    # Load it back through the analyzer's own parser, so a roster this script is
    # happy with but gpg_check would reject can never reach a judging machine.
    parsed = load_roster(out_path)
    if parsed["errors"]:
        print(f"roster written to {out_path}, but gpg_check rejects it:", file=sys.stderr)
        for error in parsed["errors"]:
            print(f"  {error.get('reason')}: {error.get('detail')}", file=sys.stderr)
        return 1

    print(f"==> roster written to {out_path}")
    print(f"    team_id         {roster['team_id']}")
    print(f"    baseline_commit {roster['baseline_commit'] or '(none)'}")
    for member in parsed["members"]:
        keys = ", ".join(f"{k['key_id']}" for k in member["keys"])
        login = f" @{member['github_login']}" if member["github_login"] else ""
        print(f"    {member['member_id']:<12}{login:<16} {', '.join(member['emails'])}  [{keys}]")
    print()
    print("    The roster carries participants' emails and public keys -- personal data")
    print("    under the retention policy in spec §11. Keep it out of git; delete it after judging.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
