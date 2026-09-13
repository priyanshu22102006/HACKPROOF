"""Shared fixtures: isolated git config and throwaway GPG keyrings.

Two isolation rules apply to every test in this suite:

* The developer's real git config can never influence a fixture repo
  (``GIT_CONFIG_GLOBAL`` / ``GIT_CONFIG_SYSTEM`` are redirected).
* The developer's real keyring can never influence a verdict, and no test key
  ever lands in it. Keys are generated inside a throwaway ``GNUPGHOME`` that is
  deleted -- along with its ``gpg-agent`` -- when the test ends.

``GNUPGHOME`` is created under ``/tmp`` rather than pytest's ``tmp_path`` on
purpose: gpg-agent's socket path has a ~104-byte limit, and pytest's nested
temp paths blow through it.
"""

from __future__ import annotations

import os
import shutil
import tempfile

import pytest

try:
    from tests.helpers import GpgHome
except ModuleNotFoundError:  # pragma: no cover - depends on sys.path shape
    from helpers import GpgHome


@pytest.fixture
def gpg_home():
    path = tempfile.mkdtemp(prefix="chg-", dir="/tmp")
    os.chmod(path, 0o700)
    home = GpgHome(path)
    try:
        yield home
    finally:
        home.close()


@pytest.fixture(autouse=True)
def isolated_git_env(tmp_path, monkeypatch):
    """Keep the developer's real global/system git config out of the fixtures."""
    home = tmp_path / "fake-home"
    home.mkdir(exist_ok=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(home / "gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("GIT_AUTHOR_NAME", "Fixture Author")
    monkeypatch.setenv("GIT_AUTHOR_EMAIL", "author@example.test")
    monkeypatch.setenv("GIT_COMMITTER_NAME", "Fixture Author")
    monkeypatch.setenv("GIT_COMMITTER_EMAIL", "author@example.test")
    # A roster left over in the environment would silently change every result.
    # setenv (not delenv) so that a test which sets it directly -- core.engine
    # exports it -- is still reverted when the test ends.
    monkeypatch.setenv("HACKPROOF_ROSTER", "")
    monkeypatch.setenv("CHRONICLE_ROSTER", "")


@pytest.fixture(autouse=True)
def _no_leaked_keyrings():
    """Fail loudly if an analyzer forgets to clean up its temp keyring."""
    prefixes = ("hackproof-keyring-", "chronicle-keyring-")
    before = {d for d in os.listdir("/tmp") if d.startswith(prefixes)}
    yield
    leftover = {d for d in os.listdir("/tmp") if d.startswith(prefixes)} - before
    for name in leftover:
        shutil.rmtree(os.path.join("/tmp", name), ignore_errors=True)
    assert not leftover, f"analyzer left temporary keyrings behind: {sorted(leftover)}"
