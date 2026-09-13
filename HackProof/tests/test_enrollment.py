"""Enrollment and roster-building tests.

The end-to-end test at the bottom is the one that matters: two people enroll on
two "machines" with two different signing methods, the organizer merges their
cards, and a real signed commit verifies against the result. If that passes, the
path a live test actually walks is known to work.
"""

from __future__ import annotations

import importlib.util
import json
import os

import pytest

from analyzers import gpg_check

try:
    from tests.helpers import out, run
except ModuleNotFoundError:  # pragma: no cover - depends on sys.path shape
    from helpers import out, run

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")


def _load(name: str):
    """scripts/ is not a package; load the module straight off its path."""
    spec = importlib.util.spec_from_file_location(name, os.path.join(SCRIPTS, f"{name}.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


enroll = _load("hackproof_enroll")
build_roster = _load("build_roster")


# --- the rule that must never bend --------------------------------------------


@pytest.mark.parametrize(
    "blob",
    [
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nx\n-----END PGP PRIVATE KEY BLOCK-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nx\n-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----\nx\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_enrollment_refuses_private_key_material(blob):
    with pytest.raises(enroll.EnrollError) as excinfo:
        enroll.assert_public_only(blob, "a test blob")
    assert "private key material" in str(excinfo.value)


def test_a_real_public_key_passes_the_private_key_check(gpg_home):
    fingerprint = gpg_home.generate_key("Satoru <satoru@example.test>")
    enroll.assert_public_only(gpg_home.export_public(fingerprint), "public key")  # must not raise


def test_roster_builder_refuses_a_card_carrying_a_private_key(tmp_path, gpg_home):
    fingerprint = gpg_home.generate_key("Satoru <satoru@example.test>")
    card = {
        "schema": build_roster.SCHEMA,
        "member_id": "satoru",
        "emails": ["satoru@example.test"],
        "key": {"fingerprint": fingerprint, "public_key": gpg_home.export_secret(fingerprint)},
    }
    path = tmp_path / "card.json"
    path.write_text(json.dumps(card), encoding="utf-8")

    with pytest.raises(build_roster.RosterError) as excinfo:
        build_roster.read_card(str(path))
    assert "private key material" in str(excinfo.value)
    assert "rotated" in str(excinfo.value)


# --- roster merging ------------------------------------------------------------


def _card(member_id, email, fingerprint, public_key, login=None, key_id=None):
    return {
        "schema": build_roster.SCHEMA,
        "member_id": member_id,
        "display_name": member_id.title(),
        "github_login": login or f"{member_id}-gh",
        "emails": [email],
        "key": {
            "key_id": key_id or f"{member_id}-k1",
            "key_type": "gpg",
            "fingerprint": fingerprint,
            "public_key": public_key,
            "status": "active",
        },
    }


def _write(tmp_path, name, card):
    path = tmp_path / name
    path.write_text(json.dumps(card), encoding="utf-8")
    return str(path)


def test_two_cards_become_two_members(tmp_path, gpg_home):
    a = gpg_home.generate_key("A <a@example.test>")
    b = gpg_home.generate_key("B <b@example.test>")
    cards = [
        (p, build_roster.read_card(p))
        for p in [
            _write(tmp_path, "a.json", _card("alice", "a@example.test", a, gpg_home.export_public(a))),
            _write(tmp_path, "b.json", _card("bob", "b@example.test", b, gpg_home.export_public(b))),
        ]
    ]

    roster = build_roster.merge(cards, "team-07", None)

    assert [m["member_id"] for m in roster["members"]] == ["alice", "bob"]
    assert all(len(m["keys"]) == 1 for m in roster["members"])


def test_one_member_can_hold_two_keys(tmp_path, gpg_home):
    """Key rotation, and the GPG-plus-SSH participant, are the same shape."""
    first = gpg_home.generate_key("A <a@example.test>")
    second = gpg_home.generate_key("A2 <a@example.test>")
    cards = [
        (p, build_roster.read_card(p))
        for p in [
            _write(tmp_path, "a1.json", _card("alice", "a@example.test", first, gpg_home.export_public(first), key_id="k1")),
            _write(tmp_path, "a2.json", _card("alice", "a@example.test", second, gpg_home.export_public(second), key_id="k2")),
        ]
    ]

    roster = build_roster.merge(cards, "team-07", None)

    assert len(roster["members"]) == 1
    assert {k["key_id"] for k in roster["members"][0]["keys"]} == {"k1", "k2"}


def test_the_same_fingerprint_under_two_members_is_rejected(tmp_path, gpg_home):
    """Attribution would be a coin flip, so this is refused at enrollment."""
    shared = gpg_home.generate_key("Shared <shared@example.test>")
    public = gpg_home.export_public(shared)
    cards = [
        (p, build_roster.read_card(p))
        for p in [
            _write(tmp_path, "a.json", _card("alice", "a@example.test", shared, public)),
            _write(tmp_path, "b.json", _card("bob", "b@example.test", shared, public)),
        ]
    ]

    with pytest.raises(build_roster.RosterError) as excinfo:
        build_roster.merge(cards, "team-07", None)
    assert "two members" in str(excinfo.value)


def test_resubmitting_the_same_card_is_harmless(tmp_path, gpg_home):
    a = gpg_home.generate_key("A <a@example.test>")
    card = _card("alice", "a@example.test", a, gpg_home.export_public(a))
    cards = [
        (p, build_roster.read_card(p))
        for p in [_write(tmp_path, "a.json", card), _write(tmp_path, "a-again.json", card)]
    ]

    roster = build_roster.merge(cards, "team-07", None)

    assert len(roster["members"]) == 1
    assert len(roster["members"][0]["keys"]) == 1


def test_a_card_with_the_wrong_schema_is_rejected(tmp_path):
    path = _write(tmp_path, "bad.json", {"schema": "something-else", "member_id": "x"})
    with pytest.raises(build_roster.RosterError) as excinfo:
        build_roster.read_card(path)
    assert "schema" in str(excinfo.value)


def test_baseline_commit_is_carried_into_the_roster(tmp_path, gpg_home):
    a = gpg_home.generate_key("A <a@example.test>")
    cards = [
        (p, build_roster.read_card(p))
        for p in [_write(tmp_path, "a.json", _card("alice", "a@example.test", a, gpg_home.export_public(a)))]
    ]

    roster = build_roster.merge(cards, "team-07", "abc123")

    assert roster["baseline_commit"] == "abc123"


# --- the path a live test actually walks ----------------------------------------


def test_enroll_two_methods_build_a_roster_and_verify_a_real_commit(tmp_path, gpg_home, monkeypatch):
    """GPG member + SSH member -> roster -> a real signed commit verifies."""
    gpg_fpr = gpg_home.generate_key("Satoru <satoru@example.test>")

    ssh_dir = tmp_path / "ssh"
    ssh_dir.mkdir()
    priv = str(ssh_dir / "id_hackproof")
    run(["ssh-keygen", "-t", "ed25519", "-N", "", "-C", "hackproof:priyanshu", "-f", priv])
    ssh_pub_path = priv + ".pub"
    ssh_pub = open(ssh_pub_path, encoding="utf-8").read().strip()
    ssh_fpr = enroll.ssh_fingerprint(ssh_pub_path)

    cards = [
        (
            p,
            build_roster.read_card(p),
        )
        for p in [
            _write(
                tmp_path,
                "satoru.json",
                _card("satoru", "satoru@example.test", gpg_fpr, gpg_home.export_public(gpg_fpr), login="satorugojo"),
            ),
            _write(
                tmp_path,
                "priyanshu.json",
                {
                    "schema": build_roster.SCHEMA,
                    "member_id": "priyanshu",
                    "display_name": "Priyanshu",
                    "github_login": "priyanshu-dev",
                    "emails": ["priyanshu@example.test"],
                    "key": {
                        "key_id": "priyanshu-ssh-1",
                        "key_type": "ssh",
                        "fingerprint": ssh_fpr,
                        "public_key": ssh_pub,
                        "status": "active",
                    },
                },
            ),
        ]
    ]
    roster = build_roster.merge(cards, "team-07", None)
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(roster), encoding="utf-8")

    # gpg_check's own loader must accept what the builder produced.
    parsed = gpg_check.load_roster(str(roster_path))
    assert parsed["errors"] == []
    assert len(parsed["members"]) == 2

    repo = tmp_path / "repo"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    run(["git", "-C", str(repo), "config", "user.name", "Satoru"])
    run(["git", "-C", str(repo), "config", "user.email", "satoru@example.test"])
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "a.py"])
    run(
        ["git", "-C", str(repo), "commit", f"-S{gpg_fpr}", "-m", "gpg signed"],
        env={**gpg_home.env, "GIT_AUTHOR_EMAIL": "satoru@example.test", "GIT_COMMITTER_EMAIL": "satoru@example.test",
             "GIT_AUTHOR_NAME": "Satoru", "GIT_COMMITTER_NAME": "Satoru"},
    )
    (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "b.py"])
    run(
        [
            "git", "-C", str(repo),
            "-c", "gpg.format=ssh", "-c", f"user.signingkey={ssh_pub_path}",
            "commit", "-S", "-m", "ssh signed",
        ],
        env={"GIT_AUTHOR_EMAIL": "priyanshu@example.test", "GIT_COMMITTER_EMAIL": "priyanshu@example.test",
             "GIT_AUTHOR_NAME": "Priyanshu", "GIT_COMMITTER_NAME": "Priyanshu"},
    )

    findings = {f.check_name: f for f in gpg_check.run(str(repo), roster_path=str(roster_path))}

    assert findings["gpg.roster_integrity"].passed
    assert findings["gpg.unregistered_key"].passed, findings["gpg.unregistered_key"].evidence
    assert findings["gpg.identity_match"].passed
    assert findings["gpg.signature_coverage"].evidence["verified_ratio"] == 1.0


def test_a_repo_whose_signing_key_is_off_the_roster_is_caught(tmp_path, gpg_home):
    """The impostor, reduced to its essentials: unregistered key, spoofed author."""
    member = gpg_home.generate_key("Satoru <satoru@example.test>")
    outsider = gpg_home.generate_key("Eve <eve@example.test>")

    roster = {
        "team_id": "team-07",
        "members": [
            {
                "member_id": "satoru",
                "emails": ["satoru@example.test"],
                "keys": [{"key_id": "k1", "public_key": gpg_home.export_public(member)}],
            }
        ],
    }
    roster_path = tmp_path / "roster.json"
    roster_path.write_text(json.dumps(roster), encoding="utf-8")

    repo = tmp_path / "repo"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    run(["git", "-C", str(repo), "add", "a.py"])
    # Eve's key, Satoru's name on the commit.
    run(
        ["git", "-C", str(repo), "commit", f"-S{outsider}", "-m", "not mine"],
        env={**gpg_home.env, "GIT_AUTHOR_EMAIL": "satoru@example.test", "GIT_COMMITTER_EMAIL": "satoru@example.test",
             "GIT_AUTHOR_NAME": "Satoru", "GIT_COMMITTER_NAME": "Satoru"},
    )

    findings = {f.check_name: f for f in gpg_check.run(str(repo), roster_path=str(roster_path))}

    unregistered = findings["gpg.unregistered_key"]
    assert not unregistered.passed
    assert unregistered.severity == "hard_flag"
    # The author field was spoofed, but it is the KEY that raises the flag.
    assert findings["gpg.identity_match"].passed
