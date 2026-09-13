"""Unit tests for the HACKPROOF multi-team roster database (core.roster_db)."""

from __future__ import annotations

import json
import os
import sqlite3
import pytest

from core.roster_db import (
    RosterDatabase,
    RosterDBError,
    Team,
    Member,
    Key,
    Device,
    main as cli_main,
)
from analyzers.gpg_check import load_roster

SAMPLE_PGP_PUBKEY = (
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\n"
    "mDMEaqV3ghYJKwYBBAHaRw8BAQdAoYaPVmeA42NuBcg/tN1xuI03diTiqW7/Bp+A\n"
    "nJmIw2S0KFByaXRpbSBNb25kYWwgPG1vbmRhbHByaXRpbTE0QGdtYWlsLmNvbT6I\n"
    "rwQTFgoAVxYhBLIlhW5mihX7dxPIjOvAc4a2L9EtBQJqpXeCGxSAAAAAAAQADm1h\n"
    "-----END PGP PUBLIC KEY BLOCK-----"
)

SAMPLE_SSH_PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGf68a5Q+zB3x0v/x+test member@example.com"


def test_schema_init_and_foreign_keys(tmp_path):
    db_path = str(tmp_path / "roster.db")
    db = RosterDatabase(db_path)
    assert os.path.exists(db_path)
    
    # Adding member to nonexistent team must raise RosterDBError
    with pytest.raises(RosterDBError, match="Team 'nonexistent' does not exist"):
        db.add_member("m1", "nonexistent", "Name", "test@test.com")
    db.close()


def test_team_crud(tmp_path):
    db = RosterDatabase(str(tmp_path / "roster.db"))
    team = db.add_team("team-01", "Alpha Team", project_name="HACKPROOF", repo_url="https://github.com/a/b")
    assert team.team_id == "team-01"
    assert team.name == "Alpha Team"

    # Duplicate team_id rejected
    with pytest.raises(RosterDBError, match="already exists"):
        db.add_team("team-01", "Duplicate")

    fetched = db.get_team("team-01")
    assert fetched is not None
    assert fetched.project_name == "HACKPROOF"

    teams = db.list_teams()
    assert len(teams) == 1
    assert teams[0].team_id == "team-01"

    assert db.delete_team("team-01") is True
    assert db.get_team("team-01") is None
    db.close()


def test_member_and_key_management():
    db = RosterDatabase(":memory:")
    db.add_team("team-42", "Galaxy Team")
    
    m1 = db.add_member(
        member_id="mem-1",
        team_id="team-42",
        display_name="Alice",
        email="alice@galaxy.test",
        github_login="alice42",
    )
    assert m1.member_id == "mem-1"

    # Add OpenPGP key
    k1 = db.add_key(
        key_id="k-1",
        member_id="mem-1",
        key_type="openpgp",
        fingerprint="B225856E668A15FB7713C88CEBC07386B62FD12D",
        public_key=SAMPLE_PGP_PUBKEY,
    )
    assert k1.fingerprint == "B225856E668A15FB7713C88CEBC07386B62FD12D"

    # Verify keys query
    keys = db.get_keys("mem-1")
    assert len(keys) == 1
    assert keys[0].key_id == "k-1"

    # Resolve key owner
    owner = db.resolve_key_owner("B225856E668A15FB7713C88CEBC07386B62FD12D")
    assert owner is not None
    member, team = owner
    assert member.member_id == "mem-1"
    assert team.team_id == "team-42"
    db.close()


def test_reject_private_key_material():
    db = RosterDatabase(":memory:")
    db.add_team("t1", "Team 1")
    db.add_member("m1", "t1", "Bob", "bob@test.com")

    fake_privkey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsecret\n-----END PGP PRIVATE KEY BLOCK-----"
    with pytest.raises(RosterDBError, match="private key material"):
        db.add_key("k1", "m1", "openpgp", "1234567890ABCDEF1234567890ABCDEF12345678", fake_privkey)


def test_prevent_duplicate_key_across_members_and_teams():
    db = RosterDatabase(":memory:")
    db.add_team("t1", "Team 1")
    db.add_team("t2", "Team 2")

    db.add_member("m1", "t1", "Alice", "alice@test.com")
    db.add_member("m2", "t2", "Bob", "bob@test.com")

    fp = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    db.add_key("k1", "m1", "openpgp", fp, SAMPLE_PGP_PUBKEY)

    # Bob attempts to register the exact same key fingerprint
    with pytest.raises(RosterDBError, match="already registered to member 'm1' in team 't1'"):
        db.add_key("k2", "m2", "openpgp", fp, SAMPLE_PGP_PUBKEY)


def test_device_registration_and_lookup():
    db = RosterDatabase(":memory:")
    db.add_team("t1", "Team 1")
    db.add_member("m1", "t1", "Charlie", "charlie@test.com")

    dfp = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    d = db.add_device("d1", "m1", dfp, hostname="macbook-pro", platform="Darwin")
    assert d.hostname == "macbook-pro"

    devices = db.get_devices("m1")
    assert len(devices) == 1
    assert devices[0].device_fingerprint == dfp

    owners = db.resolve_device_owner(dfp)
    assert len(owners) == 1
    mem, team = owners[0]
    assert mem.member_id == "m1"
    assert team.team_id == "t1"


def test_cascade_delete():
    db = RosterDatabase(":memory:")
    db.add_team("t1", "Team 1")
    db.add_member("m1", "t1", "Alice", "alice@test.com")
    db.add_key("k1", "m1", "openpgp", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB", SAMPLE_PGP_PUBKEY)
    db.add_device("d1", "m1", "devicehash123")

    # Deleting team cascades to members, keys, and devices
    db.delete_team("t1")
    assert db.get_member("m1") is None
    assert len(db.get_keys("m1")) == 0
    assert len(db.get_devices("m1")) == 0


def test_import_and_export_roster(tmp_path):
    db_path = str(tmp_path / "test.db")
    db = RosterDatabase(db_path)

    sample_roster = {
        "team_id": "team-pritim",
        "team_name": "Pritim Team",
        "members": [
            {
                "member_id": "pritim",
                "name": "Pritim Mondal",
                "email": "mondalpritim14@gmail.com",
                "keys": [
                    {
                        "key_id": "pritim-k1",
                        "type": "openpgp",
                        "fingerprint": "B225856E668A15FB7713C88CEBC07386B62FD12D",
                        "public_key": SAMPLE_PGP_PUBKEY,
                    }
                ],
                "devices": [
                    {
                        "device_id": "pritim-d1",
                        "device_fingerprint": "dfp1234567890",
                        "hostname": "pritims-macbook",
                        "platform": "Darwin",
                    }
                ]
            }
        ]
    }

    team = db.import_team_roster(sample_roster)
    assert team.team_id == "team-pritim"

    exported = db.export_team_roster("team-pritim")
    assert exported["team_id"] == "team-pritim"
    assert len(exported["members"]) == 1
    assert exported["members"][0]["name"] == "Pritim Mondal"
    assert exported["members"][0]["keys"][0]["fingerprint"] == "B225856E668A15FB7713C88CEBC07386B62FD12D"
    assert exported["members"][0]["devices"][0]["device_fingerprint"] == "dfp1234567890"

    # Export all
    out_dir = str(tmp_path / "exported_rosters")
    files = db.export_all(out_dir)
    assert len(files) == 1
    assert os.path.exists(files[0])
    db.close()


def test_gpg_check_loads_directly_from_sqlite(tmp_path):
    db_path = str(tmp_path / "teams.db")
    db = RosterDatabase(db_path)

    db.add_team("team-a", "Team Alpha")
    db.add_member("m1", "team-a", "Pritim", "mondalpritim14@gmail.com")
    db.add_key("k1", "m1", "openpgp", "B225856E668A15FB7713C88CEBC07386B62FD12D", SAMPLE_PGP_PUBKEY)
    db.close()

    # load_roster directly against SQLite DB
    loaded = load_roster(db_path)
    assert not loaded["errors"]
    assert loaded["team_id"] == "team-a"
    assert len(loaded["members"]) == 1
    assert loaded["members"][0]["display_name"] == "Pritim"
    assert loaded["members"][0]["keys"][0]["declared_fingerprint"] == "B225856E668A15FB7713C88CEBC07386B62FD12D"


def test_gpg_check_sqlite_multiple_teams(tmp_path):
    db_path = str(tmp_path / "teams_multi.db")
    db = RosterDatabase(db_path)

    db.add_team("team-1", "First Team")
    db.add_member("m1", "team-1", "User 1", "u1@test.com")
    db.add_key("k1", "m1", "openpgp", "1111111111111111111111111111111111111111", SAMPLE_PGP_PUBKEY)

    db.add_team("team-2", "Second Team")
    db.add_member("m2", "team-2", "User 2", "u2@test.com")
    db.add_key("k2", "m2", "ssh", "SHA256:abcd1234efgh5678", SAMPLE_SSH_PUBKEY)
    db.close()

    # Without team_id specified, errors out with MULTIPLE_TEAMS_IN_DB
    ambiguous = load_roster(db_path)
    assert any(err["reason"] == "MULTIPLE_TEAMS_IN_DB" for err in ambiguous["errors"])

    # With team_id specified, loads cleanly
    loaded_t2 = load_roster(db_path, team_id="team-2")
    assert not loaded_t2["errors"]
    assert loaded_t2["team_id"] == "team-2"
    assert loaded_t2["members"][0]["display_name"] == "User 2"


def test_cli_execution(tmp_path, capsys):
    db_path = str(tmp_path / "cli_test.db")
    
    # init
    ret = cli_main(["--db", db_path, "init"])
    assert ret == 0

    # team add
    ret = cli_main(["--db", db_path, "team", "add", "team-hack", "--name", "Hackers", "--project", "HACKPROOF"])
    assert ret == 0

    # member add
    ret = cli_main(["--db", db_path, "member", "add", "team-hack", "user-1", "--name", "John Doe", "--email", "john@test.com"])
    assert ret == 0

    # key add
    ret = cli_main(["--db", db_path, "key", "add", "user-1", "--type", "openpgp", "--fingerprint", "9999999999999999999999999999999999999999", "--key-text", SAMPLE_PGP_PUBKEY])
    assert ret == 0

    # device add
    ret = cli_main(["--db", db_path, "device", "add", "user-1", "devicehash999", "--hostname", "john-laptop", "--platform", "Linux"])
    assert ret == 0

    # list
    ret = cli_main(["--db", db_path, "list"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Hackers" in captured.out
    assert "John Doe" in captured.out
    assert "john-laptop" in captured.out
