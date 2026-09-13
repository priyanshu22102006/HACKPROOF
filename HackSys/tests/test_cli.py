"""Argument-parsing regression tests.

The launchd job invokes `hacksys --config <path> start`. An earlier version
accepted `--config` only before the subcommand, which meant the generated
plist launched a process that exited instantly and launchd throttled it —
the agent looked "loaded" but recorded nothing. Both orders must parse.
"""

import plistlib

import pytest

from hacksys.cli import build_parser
from hacksys.config import Config
from hacksys.install_macos import render_plist


@pytest.mark.parametrize("argv", [
    ["--config", "/tmp/c.toml", "start"],
    ["start", "--config", "/tmp/c.toml"],
    ["--config", "/tmp/c.toml", "seal", "--submit"],
    ["seal", "--config", "/tmp/c.toml", "--submit"],
    ["--config", "/tmp/c.toml", "status"],
    ["events", "--config", "/tmp/c.toml", "--tail", "5"],
])
def test_config_parses_on_either_side_of_the_subcommand(argv):
    args = build_parser().parse_args(argv)
    assert args.config == "/tmp/c.toml"


def test_config_defaults_to_none():
    assert build_parser().parse_args(["status"]).config is None


def test_generated_plist_is_valid_and_its_command_parses(tmp_path):
    cfg = Config(home=str(tmp_path), project_paths=[str(tmp_path)]).normalise()
    plist = plistlib.loads(render_plist(cfg).encode())

    argv = plist["ProgramArguments"]
    assert argv[1:3] == ["-m", "hacksys"]

    # the exact command launchd will run must be accepted by the parser
    args = build_parser().parse_args(argv[3:])
    assert args.command == "start"
    assert args.config == cfg.config_path

    # a clean exit must not be restarted forever
    assert plist["KeepAlive"] == {"SuccessfulExit": False}
    assert plist["RunAtLoad"] is True


def test_init_refuses_to_clobber_a_live_window(tmp_path, monkeypatch, capsys):
    """Re-running init mid-event must not silently replace the setup."""
    from datetime import timedelta

    from hacksys.cli import main
    from hacksys.config import render_template
    from hacksys.util import iso, now_utc

    home = tmp_path / "agent"
    project = tmp_path / "submission"
    home.mkdir()
    project.mkdir()

    live = Config(
        home=str(home),
        participant_id="satoru",
        project_paths=[str(project)],
        window_start=iso(now_utc() - timedelta(minutes=5)),
        window_end=iso(now_utc() + timedelta(hours=5)),
    )
    (home / "config.toml").write_text(render_template(live))

    argv = ["init", "--participant", "someone-else",
            "--project", str(project), "--home", str(home), "--yes"]

    assert main(argv) == 2
    assert "already configured" in capsys.readouterr().err
    # the original config is untouched
    assert "satoru" in (home / "config.toml").read_text()

    # --force replaces it, and says so in the log
    assert main(argv + ["--force"]) == 0
    assert "someone-else" in (home / "config.toml").read_text()

    from hacksys.eventlog import read_events
    kinds = [e.get("kind") for e in read_events(str(home / "events.jsonl"))]
    assert "config.replaced" in kinds


def test_token_falls_back_to_the_environment(tmp_path, monkeypatch):
    from hacksys.cli import main
    from hacksys.config import load_config

    home = tmp_path / "agent"
    project = tmp_path / "submission"
    project.mkdir()
    monkeypatch.setenv("HACKPROOF_TOKEN", "tok-from-env")

    assert main(["init", "--participant", "satoru", "--project", str(project),
                 "--home", str(home), "--yes"]) == 0
    assert load_config(str(home / "config.toml")).server_token == "tok-from-env"
