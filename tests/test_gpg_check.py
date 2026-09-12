"""Tests for analyzers.gpg_check against real signed commits.

Every test mints a real GPG key and makes a real ``git commit -S``, so the
analyzer is exercised against actual gpg and git behaviour rather than mocks.
Keys live in a throwaway GNUPGHOME (see conftest.py) and never touch the
developer's keyring.
"""

from __future__ import annotations

import json
import os
import time

import pytest

from analyzers.gpg_check import (
    CHECK_COVERAGE,
    CHECK_IDENTITY,
    CHECK_KEY_VALIDITY,
    CHECK_ROSTER,
    CHECK_SIGNATURES,
    CHECK_UNREGISTERED,
    IDENTITY_MATCH,
    IDENTITY_MISMATCH,
    IDENTITY_UNKNOWN,
    REJECT_FINGERPRINT_MISMATCH,
    REJECT_PRIVATE_KEY,
    STATUS_EXPIRED_KEY,
    STATUS_IDENTITY_MISMATCH,
    STATUS_INVALID_SIGNATURE,
    STATUS_NO_SIGNATURE,
    STATUS_REVOKED_KEY,
    STATUS_UNKNOWN_KEY,
    STATUS_VERIFIED,
    run,
)
try:
    from tests.helpers import SshHome, out, run as sh
except ModuleNotFoundError:  # pragma: no cover - depends on sys.path shape
    from helpers import SshHome, out, run as sh

ALL_CHECK_NAMES = (
    CHECK_ROSTER,
    CHECK_SIGNATURES,
    CHECK_UNREGISTERED,
    CHECK_IDENTITY,
    CHECK_KEY_VALIDITY,
    CHECK_COVERAGE,
)


# --- helpers ------------------------------------------------------------------


def make_repo(tmp_path, name: str = "repo") -> str:
    repo = tmp_path / name
    repo.mkdir()
    sh(["git", "init", "-q", "-b", "main"], cwd=str(repo))
    sh(["git", "config", "user.name", "Fixture Author"], cwd=str(repo))
    sh(["git", "config", "user.email", "author@example.test"], cwd=str(repo))
    sh(["git", "config", "commit.gpgsign", "false"], cwd=str(repo))
    sh(["git", "config", "gpg.program", "gpg"], cwd=str(repo))
    return str(repo)


def commit(
    repo: str,
    message: str,
    gpg_home=None,
    signing_key: str | None = None,
    ssh_key: str | None = None,
    author_email: str | None = None,
    author_name: str = "Fixture Author",
    filename: str | None = None,
    body: str | None = None,
) -> str:
    """Write a file and commit it, signed when ``signing_key`` or ``ssh_key`` is given."""
    target = os.path.join(repo, filename or f"{abs(hash(message)) % 10**8}.py")
    with open(target, "w", encoding="utf-8") as handle:
        handle.write(body if body is not None else f"# {message}\nvalue = 1\n")
    sh(["git", "add", "-A"], cwd=repo)

    env = {}
    if author_email:
        env.update({"GIT_AUTHOR_EMAIL": author_email, "GIT_COMMITTER_EMAIL": author_email})
    if author_name:
        env.update({"GIT_AUTHOR_NAME": author_name, "GIT_COMMITTER_NAME": author_name})

    cmd = ["git"]
    if signing_key:
        assert gpg_home is not None, "signing requires a gpg_home"
        env.update(gpg_home.env)
        cmd += ["-c", f"user.signingkey={signing_key}", "-c", "commit.gpgsign=true"]
        cmd += ["commit", "-S", "-q", "-m", message]
    elif ssh_key:
        cmd += [
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={ssh_key}",
            "-c",
            "commit.gpgsign=true",
        ]
        cmd += ["commit", "-S", "-q", "-m", message]
    else:
        cmd += ["commit", "--no-gpg-sign", "-q", "-m", message]
    sh(cmd, cwd=repo, env=env)
    return out(sh(["git", "rev-parse", "HEAD"], cwd=repo)).strip()


def write_roster(tmp_path, members: list[dict], team_id: str = "team-test", baseline: str | None = None) -> str:
    payload: dict = {"team_id": team_id, "members": members}
    if baseline:
        payload["baseline_commit"] = baseline
    path = tmp_path / "roster.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return str(path)


def member(member_id: str, email: str, public_key: str, **key_overrides) -> dict:
    key = {"key_id": f"{member_id}-key", "public_key": public_key, "status": "active"}
    key.update(key_overrides)
    return {
        "member_id": member_id,
        "display_name": member_id.title(),
        "emails": [email],
        "keys": [key],
    }


def by_name(findings) -> dict:
    return {finding.check_name: finding for finding in findings}


def commits_of(finding) -> list[dict]:
    return finding.evidence.get("commits", [])


def status_of(finding, sha: str) -> str | None:
    for record in commits_of(finding):
        if record["sha"] == sha:
            return record.get("status")
    raise AssertionError(f"commit {sha} not present in evidence")


# --- the happy path -----------------------------------------------------------


def test_verified_commit_passes_every_check(tmp_path, gpg_home):
    fpr = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(repo, "signed work", gpg_home, fpr, author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(fpr))])

    findings = by_name(run(repo, roster_path=roster))

    assert set(findings) == set(ALL_CHECK_NAMES)
    assert all(f.passed for f in findings.values()), {
        name: f.evidence for name, f in findings.items() if not f.passed
    }
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_VERIFIED
    assert findings[CHECK_COVERAGE].evidence["verified_ratio"] == 1.0
    assert findings[CHECK_IDENTITY].evidence["match_count"] == 1
    assert findings[CHECK_ROSTER].evidence["imported_key_count"] == 1
    assert findings[CHECK_ROSTER].evidence["rejected_key_count"] == 0


def test_key_rotation_both_keys_verify(tmp_path, gpg_home):
    """A member who rotates keys mid-event keeps both commits attributed."""
    old = gpg_home.generate_key("Satoru Old <satoru@example.test>")
    new = gpg_home.generate_key("Satoru New <satoru@example.test>")
    repo = make_repo(tmp_path)
    first = commit(repo, "before rotation", gpg_home, old, author_email="satoru@example.test")
    second = commit(repo, "after rotation", gpg_home, new, author_email="satoru@example.test")

    roster = write_roster(
        tmp_path,
        [
            {
                "member_id": "m1",
                "display_name": "Satoru",
                "emails": ["satoru@example.test"],
                "keys": [
                    {"key_id": "old", "public_key": gpg_home.export_public(old), "status": "active"},
                    {"key_id": "new", "public_key": gpg_home.export_public(new), "status": "active"},
                ],
            }
        ],
    )

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], first) == STATUS_VERIFIED
    assert status_of(findings[CHECK_SIGNATURES], second) == STATUS_VERIFIED
    assert findings[CHECK_COVERAGE].evidence["verified_ratio"] == 1.0


# --- the seven statuses -------------------------------------------------------


def test_unsigned_commit_is_no_signature_and_not_a_flag(tmp_path, gpg_home):
    """Unsigned code is unattributed, never an accusation (spec §8.e check 5)."""
    fpr = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    signed = commit(repo, "signed", gpg_home, fpr, author_email="satoru@example.test")
    unsigned = commit(repo, "unsigned", author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(fpr))])

    findings = by_name(run(repo, roster_path=roster))

    assert status_of(findings[CHECK_SIGNATURES], unsigned) == STATUS_NO_SIGNATURE
    assert status_of(findings[CHECK_SIGNATURES], signed) == STATUS_VERIFIED
    # No hard flag anywhere: nothing here is evidence of wrongdoing.
    assert findings[CHECK_SIGNATURES].severity == "info"
    assert findings[CHECK_UNREGISTERED].passed
    assert findings[CHECK_KEY_VALIDITY].passed
    # But coverage drops below threshold and says so.
    coverage = findings[CHECK_COVERAGE]
    assert coverage.evidence["verified_ratio"] == 0.5
    assert coverage.evidence["unsigned_commit_count"] == 1
    assert coverage.severity == "info"
    assert not coverage.passed


def test_unregistered_key_is_hard_flagged(tmp_path, gpg_home):
    registered = gpg_home.generate_key("Satoru <satoru@example.test>")
    outsider = gpg_home.generate_key("Outsider <outsider@example.test>")
    repo = make_repo(tmp_path)
    good = commit(repo, "team work", gpg_home, registered, author_email="satoru@example.test")
    foreign = commit(repo, "outside work", gpg_home, outsider, author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(registered))])

    findings = by_name(run(repo, roster_path=roster))

    assert status_of(findings[CHECK_SIGNATURES], foreign) == STATUS_UNKNOWN_KEY
    assert status_of(findings[CHECK_SIGNATURES], good) == STATUS_VERIFIED
    unregistered = findings[CHECK_UNREGISTERED]
    assert unregistered.severity == "hard_flag"
    assert not unregistered.passed
    assert unregistered.evidence["unregistered_key_commit_count"] == 1
    assert [c["sha"] for c in unregistered.evidence["unregistered_key_commits"]] == [foreign]
    # The signature itself was good, so the matrix check stays clean.
    assert findings[CHECK_SIGNATURES].passed


def test_identity_mismatch_when_key_signs_for_another_member(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    # Satoru's registered key signs a commit authored as Priyanshu.
    sha = commit(repo, "committed as a teammate", gpg_home, key, author_email="priyanshu@example.test")
    roster = write_roster(
        tmp_path,
        [
            member("m1", "satoru@example.test", gpg_home.export_public(key)),
            {"member_id": "m2", "display_name": "Priyanshu", "emails": ["priyanshu@example.test"], "keys": []},
        ],
    )

    findings = by_name(run(repo, roster_path=roster))

    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_IDENTITY_MISMATCH
    identity = findings[CHECK_IDENTITY]
    assert identity.severity == "flag"  # flag, not hard_flag -- spec §8.e check 3
    assert identity.evidence["identity_mismatch_count"] == 1
    record = identity.evidence["identity_mismatch_commits"][0]
    assert record["roster_member_id"] == "m1"
    assert record["author_roster_member_id"] == "m2"
    assert record["identity_match"] == IDENTITY_MISMATCH


def test_author_outside_the_roster_is_unknown_not_mismatch(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(repo, "unknown author", gpg_home, key, author_email="nobody@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(key))])

    findings = by_name(run(repo, roster_path=roster))
    identity = findings[CHECK_IDENTITY]
    assert identity.evidence["unknown_author_count"] == 1
    assert identity.evidence["identity_mismatch_count"] == 0
    assert identity.passed  # recorded, not flagged
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_VERIFIED
    assert identity.evidence["unknown_author_commits"][0]["identity_match"] == IDENTITY_UNKNOWN


def test_github_noreply_email_matches_a_registered_login(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(
        repo,
        "committed via the github web editor",
        gpg_home,
        key,
        author_email="12345+satorugojo@users.noreply.github.com",
    )
    roster = write_roster(
        tmp_path,
        [
            {
                "member_id": "m1",
                "display_name": "Satoru",
                "github_login": "satorugojo",
                "emails": ["satoru@example.test"],
                "keys": [{"key_id": "k", "public_key": gpg_home.export_public(key), "status": "active"}],
            }
        ],
    )

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_VERIFIED
    assert findings[CHECK_IDENTITY].evidence["match_count"] == 1


def test_forged_commit_object_is_invalid_signature(tmp_path, gpg_home):
    """Rewrite a signed commit's message but keep its gpgsig header.

    This is the case the friend's Node suite noted is unreachable through the
    GitHub API -- GitHub never serves you a commit whose signature it has
    already rejected, so it has to be built by hand.
    """
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    commit(repo, "honest base", gpg_home, key, author_email="satoru@example.test")
    original = commit(repo, "SIGNED-MESSAGE", gpg_home, key, author_email="satoru@example.test")

    raw = out(sh(["git", "cat-file", "commit", original], cwd=repo))
    assert "gpgsig" in raw and "SIGNED-MESSAGE" in raw
    tampered = raw.replace("SIGNED-MESSAGE", "TAMPERED-MESSAGE")
    forged = out(
        sh(["git", "hash-object", "-t", "commit", "-w", "--stdin"], cwd=repo, input_text=tampered)
    ).strip()
    sh(["git", "update-ref", "refs/heads/main", forged], cwd=repo)

    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(key))])
    findings = by_name(run(repo, roster_path=roster))

    assert status_of(findings[CHECK_SIGNATURES], forged) == STATUS_INVALID_SIGNATURE
    signatures = findings[CHECK_SIGNATURES]
    assert signatures.severity == "hard_flag"
    assert not signatures.passed
    assert signatures.evidence["invalid_signature_commits"][0]["sha"] == forged
    # Raw gpg status lines are kept verbatim so a judge can audit the claim.
    assert signatures.evidence["raw_gpg_status"]


def test_administratively_revoked_key_is_hard_flagged(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(repo, "signed with a key later revoked", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(
        tmp_path,
        [member("m1", "satoru@example.test", gpg_home.export_public(key), status="revoked")],
    )

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_REVOKED_KEY
    validity = findings[CHECK_KEY_VALIDITY]
    assert validity.severity == "hard_flag"
    assert validity.evidence["revoked_key_commit_count"] == 1


def test_commit_made_before_revocation_still_verifies(tmp_path, gpg_home):
    """Revocation is not retroactive: work signed before it still counts."""
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(repo, "honest work", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(
        tmp_path,
        [
            member(
                "m1",
                "satoru@example.test",
                gpg_home.export_public(key),
                status="revoked",
                revoked_at="2099-01-01T00:00:00+00:00",
            )
        ],
    )

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_VERIFIED
    assert findings[CHECK_KEY_VALIDITY].passed
    note = " ".join(commits_of(findings[CHECK_SIGNATURES])[0]["notes"])
    assert "after this commit" in note


@pytest.mark.slow
def test_expired_key_is_flagged_not_hard_flagged(tmp_path, gpg_home):
    """gpg reports a good signature made by a key that has since expired."""
    key = gpg_home.generate_key("Shortlived <short@example.test>", expire="seconds=5")
    repo = make_repo(tmp_path)
    sha = commit(repo, "signed just before expiry", gpg_home, key, author_email="short@example.test")
    time.sleep(7)  # let the key expire for real rather than faking a clock

    roster = write_roster(tmp_path, [member("m1", "short@example.test", gpg_home.export_public(key))])
    findings = by_name(run(repo, roster_path=roster))

    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_EXPIRED_KEY
    validity = findings[CHECK_KEY_VALIDITY]
    assert validity.severity == "flag"  # hygiene, not deception
    assert validity.evidence["expired_key_commit_count"] == 1


def test_roster_expiry_marks_later_commits_expired(tmp_path, gpg_home):
    """Administrative expiry, without waiting for gpg's own clock."""
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(repo, "after the roster expiry", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(
        tmp_path,
        [
            member(
                "m1",
                "satoru@example.test",
                gpg_home.export_public(key),
                expires_at="2000-01-01T00:00:00+00:00",
            )
        ],
    )

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_EXPIRED_KEY
    assert findings[CHECK_KEY_VALIDITY].severity == "flag"


# --- roster integrity ---------------------------------------------------------


def test_private_key_is_refused_and_never_imported(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    commit(repo, "signed", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_secret(key))])

    findings = by_name(run(repo, roster_path=roster))
    integrity = findings[CHECK_ROSTER]

    assert integrity.severity == "hard_flag"
    assert not integrity.passed
    assert integrity.evidence["imported_key_count"] == 0
    assert integrity.evidence["rejected_keys"][0]["reason"] == REJECT_PRIVATE_KEY
    # With nothing imported, attribution must degrade rather than accuse.
    assert findings[CHECK_UNREGISTERED].passed
    assert findings[CHECK_UNREGISTERED].severity == "info"
    assert findings[CHECK_COVERAGE].evidence["verified_ratio"] is None


def test_declared_fingerprint_mismatch_is_flagged(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    commit(repo, "signed", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(
        tmp_path,
        [
            member(
                "m1",
                "satoru@example.test",
                gpg_home.export_public(key),
                fingerprint="DEADBEEF" * 5,  # 40 hex chars, wrong key
            )
        ],
    )

    findings = by_name(run(repo, roster_path=roster))
    integrity = findings[CHECK_ROSTER]
    assert integrity.severity == "flag"
    assert integrity.evidence["rejected_keys"][0]["reason"] == REJECT_FINGERPRINT_MISMATCH
    assert integrity.evidence["imported_key_count"] == 0


def test_malformed_roster_is_reported_not_raised(tmp_path, gpg_home):
    repo = make_repo(tmp_path)
    commit(repo, "unsigned")
    bad = tmp_path / "roster.json"
    bad.write_text("{not json", encoding="utf-8")

    findings = by_name(run(repo, roster_path=str(bad)))
    assert set(findings) == set(ALL_CHECK_NAMES)
    integrity = findings[CHECK_ROSTER]
    assert integrity.evidence["parse_errors"][0]["reason"] == "ROSTER_UNREADABLE"
    assert not integrity.passed


# --- degradation --------------------------------------------------------------


def test_no_roster_reports_presence_only_and_flags_nothing(tmp_path, gpg_home):
    """Without a roster the analyzer must not turn 'unverifiable' into 'flagged'."""
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    commit(repo, "signed", gpg_home, key, author_email="satoru@example.test")
    commit(repo, "unsigned", author_email="satoru@example.test")

    findings = by_name(run(repo))  # no roster anywhere

    assert all(f.passed for f in findings.values())
    assert all(f.severity == "info" for f in findings.values())
    coverage = findings[CHECK_COVERAGE]
    assert coverage.evidence["signed_commit_count"] == 1
    assert coverage.evidence["unsigned_commit_count"] == 1
    assert coverage.evidence["verified_ratio"] is None
    assert "no roster" in findings[CHECK_UNREGISTERED].evidence["note"]
    assert findings[CHECK_ROSTER].evidence["searched"]


def test_roster_discovered_inside_the_repo(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(repo, "signed", gpg_home, key, author_email="satoru@example.test")
    hackproof_dir = os.path.join(repo, ".hackproof")
    os.makedirs(hackproof_dir)
    with open(os.path.join(hackproof_dir, "roster.json"), "w", encoding="utf-8") as handle:
        json.dump(
            {"team_id": "t", "members": [member("m1", "satoru@example.test", gpg_home.export_public(key))]},
            handle,
        )

    findings = by_name(run(repo))  # discovery, not an explicit path
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_VERIFIED


def test_env_roster_is_used_when_no_path_is_passed(tmp_path, gpg_home, monkeypatch):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    sha = commit(repo, "signed", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(key))])
    monkeypatch.setenv("HACKPROOF_ROSTER", roster)

    findings = by_name(run(repo))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_VERIFIED


def test_baseline_commit_is_excluded_from_coverage(tmp_path, gpg_home):
    """The organizer's template commit is declared prior work (spec §7 phase 0)."""
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    baseline = commit(repo, "organizer template", author_email="organizer@example.test")
    commit(repo, "team work", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(
        tmp_path,
        [member("m1", "satoru@example.test", gpg_home.export_public(key))],
        baseline=baseline,
    )

    findings = by_name(run(repo, roster_path=roster))
    coverage = findings[CHECK_COVERAGE]
    assert coverage.evidence["baseline_commit_excluded"] == [baseline]
    assert coverage.evidence["commit_count"] == 1
    assert coverage.evidence["verified_ratio"] == 1.0
    assert coverage.passed


@pytest.mark.parametrize("kind", ["missing", "not_a_repo"])
def test_bad_paths_return_findings_not_tracebacks(tmp_path, kind):
    target = str(tmp_path / "nope") if kind == "missing" else str(tmp_path)
    findings = run(target)
    assert [f.check_name for f in findings] == list(ALL_CHECK_NAMES)
    assert all(f.passed and f.severity == "info" for f in findings)
    assert all(f.evidence.get("skipped") for f in findings)


def test_repo_without_commits_returns_every_check(tmp_path, gpg_home):
    repo = make_repo(tmp_path)
    roster = write_roster(
        tmp_path,
        [member("m1", "satoru@example.test", gpg_home.export_public(gpg_home.generate_key("S <satoru@example.test>")))],
    )
    findings = by_name(run(repo, roster_path=roster))
    assert set(findings) == set(ALL_CHECK_NAMES)
    assert all(f.passed for f in findings.values())
    assert findings[CHECK_COVERAGE].evidence["commit_count"] == 0


def test_analyzer_never_touches_the_host_keyring(tmp_path, gpg_home):
    """The roster keyring is built in a temp GNUPGHOME and removed afterwards."""
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    commit(repo, "signed", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(key))])

    before = set(os.listdir("/tmp"))
    run(repo, roster_path=roster)
    leftover = {d for d in set(os.listdir("/tmp")) - before if d.startswith(("hackproof-keyring-", "chronicle-keyring-"))}
    assert not leftover, f"analyzer left keyrings behind: {leftover}"


# --- contract -----------------------------------------------------------------


def test_findings_honour_the_shared_contract(tmp_path, gpg_home):
    key = gpg_home.generate_key("Satoru <satoru@example.test>")
    repo = make_repo(tmp_path)
    commit(repo, "signed", gpg_home, key, author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", gpg_home.export_public(key))])

    findings = run(repo, roster_path=roster)
    assert [f.check_name for f in findings] == list(ALL_CHECK_NAMES)  # stable order
    for finding in findings:
        assert finding.plane in ("claim", "system", "server")
        assert finding.severity in ("info", "flag", "hard_flag")
        assert isinstance(finding.evidence, dict)
        assert isinstance(finding.passed, bool)
        # Evidence must survive a JSON round trip: the dashboard serializes it.
        json.loads(json.dumps(finding.evidence, default=str))
        # Internal plumbing must not leak into a report.
        assert "_gnupghome" not in json.dumps(finding.evidence, default=str)


# --- SSH signature verification tests -----------------------------------------


@pytest.fixture
def ssh_home(tmp_path):
    home = SshHome(str(tmp_path / "ssh-home"))
    try:
        yield home
    finally:
        home.close()


def test_verified_ssh_commit_passes_every_check(tmp_path, ssh_home):
    priv, pub, fpr = ssh_home.generate_key("id_ed25519", "satoru@example.test")
    repo = make_repo(tmp_path)
    sha = commit(repo, "ssh-signed", ssh_key=priv, author_email="satoru@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", pub, fingerprint=fpr)])

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_VERIFIED
    assert findings[CHECK_ROSTER].passed is True
    assert findings[CHECK_SIGNATURES].passed is True
    assert findings[CHECK_UNREGISTERED].passed is True
    assert findings[CHECK_IDENTITY].passed is True
    assert findings[CHECK_COVERAGE].evidence["verified_commit_count"] == 1
    assert findings[CHECK_COVERAGE].evidence["verified_ratio"] == 1.0


def test_unregistered_ssh_key_is_hard_flagged(tmp_path, ssh_home):
    priv, pub, fpr = ssh_home.generate_key("id_reg", "satoru@example.test")
    priv_unreg, _, _ = ssh_home.generate_key("id_unreg", "outsider@example.test")
    repo = make_repo(tmp_path)
    sha = commit(repo, "outsider commit", ssh_key=priv_unreg, author_email="outsider@example.test")
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", pub, fingerprint=fpr)])

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_UNKNOWN_KEY
    assert findings[CHECK_UNREGISTERED].passed is False
    assert findings[CHECK_UNREGISTERED].severity == "hard_flag"


def test_ssh_identity_mismatch_when_key_signs_for_another_member(tmp_path, ssh_home):
    priv_satoru, pub_satoru, fpr_satoru = ssh_home.generate_key("id_satoru", "satoru@example.test")
    _, pub_priyanshu, fpr_priyanshu = ssh_home.generate_key("id_priyanshu", "priyanshu@example.test")
    repo = make_repo(tmp_path)
    sha = commit(repo, "teammate impersonation", ssh_key=priv_satoru, author_email="priyanshu@example.test")
    roster = write_roster(
        tmp_path,
        [
            member("m1", "satoru@example.test", pub_satoru, fingerprint=fpr_satoru),
            member("m2", "priyanshu@example.test", pub_priyanshu, fingerprint=fpr_priyanshu),
        ],
    )

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha) == STATUS_IDENTITY_MISMATCH
    assert findings[CHECK_IDENTITY].passed is False
    assert findings[CHECK_IDENTITY].severity == "flag"


def test_ssh_private_key_is_refused_and_never_imported(tmp_path, ssh_home):
    priv, pub, fpr = ssh_home.generate_key("id_ed25519", "satoru@example.test")
    with open(priv, "r", encoding="utf-8") as f:
        priv_text = f.read()
    repo = make_repo(tmp_path)
    roster = write_roster(tmp_path, [member("m1", "satoru@example.test", priv_text)])

    findings = by_name(run(repo, roster_path=roster))
    assert findings[CHECK_ROSTER].passed is False
    assert findings[CHECK_ROSTER].severity == "hard_flag"
    assert any(r["reason"] == REJECT_PRIVATE_KEY for r in findings[CHECK_ROSTER].evidence["rejected_keys"])


def test_mixed_gpg_and_ssh_commits_both_verify(tmp_path, gpg_home, ssh_home):
    gpg_key = gpg_home.generate_key("GPG User <gpguser@example.test>")
    gpg_pub = gpg_home.export_public(gpg_key)
    ssh_priv, ssh_pub, ssh_fpr = ssh_home.generate_key("id_ssh", "sshuser@example.test")

    repo = make_repo(tmp_path)
    sha1 = commit(repo, "gpg-commit", gpg_home=gpg_home, signing_key=gpg_key, author_email="gpguser@example.test")
    sha2 = commit(repo, "ssh-commit", ssh_key=ssh_priv, author_email="sshuser@example.test")

    roster = write_roster(
        tmp_path,
        [
            member("m1", "gpguser@example.test", gpg_pub, fingerprint=gpg_key),
            member("m2", "sshuser@example.test", ssh_pub, fingerprint=ssh_fpr),
        ],
    )

    findings = by_name(run(repo, roster_path=roster))
    assert status_of(findings[CHECK_SIGNATURES], sha1) == STATUS_VERIFIED
    assert status_of(findings[CHECK_SIGNATURES], sha2) == STATUS_VERIFIED
    assert findings[CHECK_ROSTER].passed is True
    assert findings[CHECK_COVERAGE].evidence["verified_commit_count"] == 2
    assert findings[CHECK_COVERAGE].evidence["verified_ratio"] == 1.0

