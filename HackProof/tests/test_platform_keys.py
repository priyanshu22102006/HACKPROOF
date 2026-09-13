"""Real-world key shapes: host-signed merges, and RSA keys with signing subkeys.

Both of these are things a synthetic fixture repo never produces and a real
repository produces immediately. They are the two cases most likely to turn an
honest team's report red for no reason.
"""

from __future__ import annotations

import json
import os
import tempfile

import pytest

from analyzers import gpg_check

try:
    from tests.helpers import out, run
except ModuleNotFoundError:  # pragma: no cover - depends on sys.path shape
    from helpers import out, run


def _git(repo, args, env=None):
    return run(["git", "-C", str(repo), *args], env=env)


def _roster(tmp_path, gpg_home, fingerprint, member_id="satoru", email="satoru@example.test"):
    path = tmp_path / "roster.json"
    path.write_text(
        json.dumps(
            {
                "team_id": "team-07",
                "members": [
                    {
                        "member_id": member_id,
                        "emails": [email],
                        "keys": [{"key_id": "k1", "public_key": gpg_home.export_public(fingerprint)}],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return str(path)


def by_name(findings):
    return {f.check_name: f for f in findings}


# --- the bundled GitHub keys ----------------------------------------------------


def test_githubs_real_web_flow_fingerprints_are_recognised():
    """The bundled key file must actually cover the keys GitHub signs with."""
    home = tempfile.mkdtemp(prefix="hackproof-keyring-", dir="/tmp")
    os.chmod(home, 0o700)
    try:
        index = gpg_check.import_platform_keys(home)
    finally:
        gpg_check._run(["gpgconf", "--kill", "gpg-agent"], env_extra={"GNUPGHOME": home, "HOME": home})
        __import__("shutil").rmtree(home, ignore_errors=True)

    assert "5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23" in index
    assert "968479A1AFF927E37D1A566BB5690EEEBB952194" in index
    assert "GitHub" in index["5DE3E0509C47EA3CF04A42D34AEE18F83AFDEB23"]


def test_the_bundled_key_file_exists_and_is_importable():
    files = gpg_check.platform_key_files()
    assert any(f.endswith("github-web-flow.asc") for f in files), files


def test_strict_mode_loads_no_platform_keys(monkeypatch):
    monkeypatch.setenv("HACKPROOF_NO_PLATFORM_KEYS", "1")
    assert gpg_check.platform_key_files() == []


# --- a host-signed merge --------------------------------------------------------


@pytest.fixture
def repo_with_host_merge(tmp_path, gpg_home, monkeypatch):
    """A member's signed work, merged by a 'host' key that is not on the roster.

    The host key is minted here and registered through
    ``$HACKPROOF_PLATFORM_KEYS``, because GitHub's private key is not available
    to sign a fixture with. The mechanism under test -- import, recognise, do not
    flag -- is identical.
    """
    member = gpg_home.generate_key("Satoru <satoru@example.test>")
    host = gpg_home.generate_key("GitHub <noreply@github.com>")

    host_key_file = tmp_path / "host.asc"
    host_key_file.write_text(gpg_home.export_public(host), encoding="utf-8")
    monkeypatch.setenv("HACKPROOF_PLATFORM_KEYS", str(host_key_file))

    repo = tmp_path / "repo"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    _git(repo, ["config", "user.name", "Satoru"])
    _git(repo, ["config", "user.email", "satoru@example.test"])

    env = {**gpg_home.env, "GIT_AUTHOR_NAME": "Satoru", "GIT_AUTHOR_EMAIL": "satoru@example.test",
           "GIT_COMMITTER_NAME": "Satoru", "GIT_COMMITTER_EMAIL": "satoru@example.test"}

    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, ["add", "a.py"])
    _git(repo, ["commit", f"-S{member}", "-m", "base"], env=env)

    _git(repo, ["checkout", "-q", "-b", "feature"])
    (repo / "b.py").write_text("y = 2\n", encoding="utf-8")
    _git(repo, ["add", "b.py"])
    _git(repo, ["commit", f"-S{member}", "-m", "feature work"], env=env)
    _git(repo, ["checkout", "-q", "main"])

    host_env = {**gpg_home.env, "GIT_AUTHOR_NAME": "GitHub", "GIT_AUTHOR_EMAIL": "noreply@github.com",
                "GIT_COMMITTER_NAME": "GitHub", "GIT_COMMITTER_EMAIL": "noreply@github.com"}
    _git(
        repo,
        ["merge", "--no-ff", "-q", f"-S{host}", "-m", "Merge pull request #1 from team/feature", "feature"],
        env=host_env,
    )

    return {"path": str(repo), "roster": _roster(tmp_path, gpg_home, member), "host": host}


def test_a_host_signed_merge_is_not_flagged(repo_with_host_merge):
    """Using GitHub's merge button must not read as an outside contributor."""
    r = repo_with_host_merge
    findings = by_name(gpg_check.run(r["path"], roster_path=r["roster"]))

    unregistered = findings["gpg.unregistered_key"]
    assert unregistered.passed, unregistered.evidence
    assert unregistered.severity == "info"
    assert unregistered.evidence["platform_signed_commit_count"] == 1
    label = unregistered.evidence["platform_signed_commits"][0]["platform_label"]
    assert "host.asc" in label, label  # organizer-supplied keys are labelled by source


def test_host_commits_do_not_drag_down_coverage(repo_with_host_merge):
    """A merge GitHub performed is not code anyone typed, so it is not scored."""
    r = repo_with_host_merge
    coverage = by_name(gpg_check.run(r["path"], roster_path=r["roster"]))["gpg.signature_coverage"]

    assert coverage.evidence["platform_commits_excluded_count"] == 1
    assert coverage.evidence["verified_ratio"] == 1.0
    assert coverage.passed


def test_strict_mode_puts_the_merge_back_in_the_flagged_bucket(repo_with_host_merge, monkeypatch):
    """An organizer who wants every non-roster signature flagged can have that."""
    monkeypatch.setenv("HACKPROOF_NO_PLATFORM_KEYS", "1")
    r = repo_with_host_merge

    unregistered = by_name(gpg_check.run(r["path"], roster_path=r["roster"]))["gpg.unregistered_key"]

    assert not unregistered.passed
    assert unregistered.severity == "hard_flag"


def test_the_platform_bucket_does_not_swallow_a_real_outsider(tmp_path, gpg_home, monkeypatch):
    """The whole point is still to catch Eve. Loading host keys must not help her."""
    member = gpg_home.generate_key("Satoru <satoru@example.test>")
    host = gpg_home.generate_key("GitHub <noreply@github.com>")
    outsider = gpg_home.generate_key("Eve <eve@example.test>")

    host_key_file = tmp_path / "host.asc"
    host_key_file.write_text(gpg_home.export_public(host), encoding="utf-8")
    monkeypatch.setenv("HACKPROOF_PLATFORM_KEYS", str(host_key_file))

    repo = tmp_path / "repo"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, ["add", "a.py"])
    # Eve signs, and even claims the host's own author identity to try to hide.
    _git(
        repo,
        ["commit", f"-S{outsider}", "-m", "Merge pull request #2 from team/feature"],
        env={**gpg_home.env, "GIT_AUTHOR_NAME": "GitHub", "GIT_AUTHOR_EMAIL": "noreply@github.com",
             "GIT_COMMITTER_NAME": "GitHub", "GIT_COMMITTER_EMAIL": "noreply@github.com"},
    )

    unregistered = by_name(
        gpg_check.run(str(repo), roster_path=_roster(tmp_path, gpg_home, member))
    )["gpg.unregistered_key"]

    assert not unregistered.passed, "an outsider key must still be caught"
    assert unregistered.severity == "hard_flag"
    assert unregistered.evidence["unregistered_key_commit_count"] == 1


# --- RSA primary with a separate signing subkey ---------------------------------


def test_rsa_primary_with_a_signing_subkey_verifies(tmp_path, gpg_home):
    """The common real-world key shape: cert-only primary, separate signing subkey.

    The participant registers the primary's exported public key -- that export
    carries the subkey too -- and commits are signed by the subkey. Both
    fingerprints must resolve to the same roster entry, or every commit from
    anyone holding an ordinary RSA key reads as UNKNOWN_KEY.
    """
    gpg_home._gpg(["--quick-generate-key", "Satoru <satoru@example.test>", "rsa4096", "cert", "0"])
    listing = out(gpg_home._gpg(["--with-colons", "--fingerprint", "satoru@example.test"]))
    primary = [line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:")][0]
    gpg_home._gpg(["--quick-add-key", primary, "rsa4096", "sign", "0"])

    repo = tmp_path / "repo"
    repo.mkdir()
    run(["git", "init", "-q", "-b", "main", str(repo)])
    (repo / "a.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, ["add", "a.py"])
    _git(
        repo,
        ["commit", f"-S{primary}", "-m", "signed by the subkey"],
        env={**gpg_home.env, "GIT_AUTHOR_NAME": "Satoru", "GIT_AUTHOR_EMAIL": "satoru@example.test",
             "GIT_COMMITTER_NAME": "Satoru", "GIT_COMMITTER_EMAIL": "satoru@example.test"},
    )

    subkey_fpr = out(_git(repo, ["log", "-1", "--format=%GF"], env=gpg_home.env)).strip()
    primary_fpr = out(_git(repo, ["log", "-1", "--format=%GP"], env=gpg_home.env)).strip()
    assert subkey_fpr and subkey_fpr != primary_fpr, "fixture should sign with a distinct subkey"

    findings = by_name(gpg_check.run(str(repo), roster_path=_roster(tmp_path, gpg_home, primary)))

    assert findings["gpg.unregistered_key"].passed, findings["gpg.unregistered_key"].evidence
    assert findings["gpg.signature_coverage"].evidence["verified_ratio"] == 1.0
    assert findings["gpg.identity_match"].passed
