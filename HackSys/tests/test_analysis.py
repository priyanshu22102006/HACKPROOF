from datetime import timedelta

from hacksys.analysis import build_report
from hacksys.config import Config
from hacksys.eventlog import EventLog
from hacksys.models import Event
from hacksys.report import render_markdown
from hacksys.util import iso, now_utc


def make_cfg(tmp_path, **kw) -> Config:
    start = now_utc() - timedelta(seconds=30)
    cfg = Config(
        home=str(tmp_path),
        participant_id="satoru",
        project_paths=[str(tmp_path / "submission")],
        window_start=iso(start),
        window_end=iso(start + timedelta(hours=6)),
        **kw,
    ).normalise()
    (tmp_path / "submission").mkdir(exist_ok=True)
    return cfg


def seed(cfg, events):
    log = EventLog(cfg.log_path)
    for e in events:
        log.append(e)
    return log


def test_clean_log_passes_the_evidence_checks(tmp_path):
    cfg = make_cfg(tmp_path)
    seed(cfg, [
        Event(kind="daemon.started", collector="integrity", summary="started"),
        Event(kind="daemon.heartbeat", collector="integrity", summary="alive"),
    ])
    report = build_report(cfg)
    names = {f["check_name"]: f for f in report["findings"]}

    assert names["log_chain_integrity"]["passed"]
    assert names["external_code_ingestion"]["passed"]
    assert names["clipboard_code_movement"]["passed"]
    assert report["summary"]["max_severity"] in ("info", "notice", "warn")


def test_copy_into_project_is_reported(tmp_path):
    cfg = make_cfg(tmp_path)
    seed(cfg, [
        Event(kind="daemon.started", collector="integrity", summary="started"),
        Event(
            kind="fs.content_copied_into_project",
            collector="filesystem",
            severity="critical",
            summary="solution.py matches ~/Downloads/solution.py",
            data={
                "path": str(tmp_path / "submission" / "solution.py"),
                "sources": [str(tmp_path / "Downloads" / "solution.py")],
                "source_zones": ["staging"],
                "sha256": "abc123",
            },
        ),
    ])
    report = build_report(cfg)
    finding = next(f for f in report["findings"]
                   if f["check_name"] == "external_code_ingestion")

    assert not finding["passed"]
    assert finding["severity"] == "critical"
    assert finding["evidence"]["files"][0]["path"].endswith("solution.py")
    assert report["summary"]["attention"] == "significant_questions"


def test_unsigned_commit_is_reported(tmp_path):
    cfg = make_cfg(tmp_path, require_signed_commits=True)
    seed(cfg, [
        Event(kind="daemon.started", collector="integrity", summary="started"),
        Event(
            kind="git.commit", collector="git", severity="warn",
            summary="commit abc",
            data={
                "short": "abc1234", "subject": "add feature", "author_name": "S",
                "author_email": "s@example.com", "signature_state": "N",
                "signature_meaning": "no signature", "insertions": 12, "deletions": 0,
                "files_changed": 1, "notes": ["unsigned"], "historical": False,
                "commit_date": iso(now_utc()), "author_date": iso(now_utc()),
            },
        ),
    ])
    report = build_report(cfg)
    finding = next(f for f in report["findings"] if f["check_name"] == "commit_signing")
    assert not finding["passed"]
    assert finding["evidence"]["commits_observed"] == 1


def test_downtime_shows_up_as_a_coverage_gap(tmp_path):
    start = now_utc() - timedelta(hours=4)
    cfg = Config(
        home=str(tmp_path),
        participant_id="satoru",
        project_paths=[str(tmp_path)],
        window_start=iso(start),
        window_end=iso(start + timedelta(hours=8)),
    ).normalise()

    log = EventLog(cfg.log_path)
    log.append(Event(kind="daemon.started", collector="integrity", summary="started"))

    report = build_report(cfg)
    cov = report["coverage"]
    assert cov["gap_count"] >= 1
    assert cov["coverage_pct"] < 100
    finding = next(f for f in report["findings"] if f["check_name"] == "monitoring_coverage")
    assert not finding["passed"]


def test_markdown_renders(tmp_path):
    cfg = make_cfg(tmp_path)
    seed(cfg, [Event(kind="daemon.started", collector="integrity", summary="started")])
    md = render_markdown(build_report(cfg))
    assert "# HackSys system-activity report" in md
    assert "## Checks" in md
    assert "## Monitoring coverage" in md


def test_pre_existing_git_history_is_summarised_not_replayed(tmp_path):
    """A repo's prior reflog must not flood the log or read as live activity."""
    import subprocess

    from hacksys.collectors.git_activity import HISTORY_BASELINE_DETAIL, GitCollector
    from hacksys.context import Context

    repo = tmp_path / "submission"
    repo.mkdir()

    def sh(*cmd):
        subprocess.run(["git", "-C", str(repo), *cmd], capture_output=True, check=False)

    subprocess.run(["git", "init", "-q", str(repo)], capture_output=True, check=False)
    sh("config", "user.email", "t@example.com")
    sh("config", "user.name", "T")
    for i in range(HISTORY_BASELINE_DETAIL + 15):
        (repo / "f.txt").write_text(str(i))
        sh("add", "-A")
        sh("commit", "-q", "-m", f"commit {i}")

    cfg = make_cfg(tmp_path)
    log = EventLog(cfg.log_path)
    ctx = Context(cfg, log)
    collector = GitCollector(ctx)
    collector.setup()
    collector.poll()

    events = list(read_log(cfg))
    baseline = [e for e in events if e["kind"] == "git.history_baseline"]
    commits = [e for e in events if e["kind"] == "git.commit"]

    assert len(baseline) == 1
    assert baseline[0]["data"]["entries"] == HISTORY_BASELINE_DETAIL + 15
    # only the tail is kept as individual events
    assert len(commits) <= HISTORY_BASELINE_DETAIL
    # and every one of them reads as historical in the timeline itself
    assert all(c["summary"].startswith("[pre-existing]") for c in commits)
    assert all(c["data"]["historical"] for c in commits)
    # pre-existing history must not fail the live checks
    report = build_report(cfg)
    assert next(f for f in report["findings"]
                if f["check_name"] == "history_rewriting")["passed"]


def read_log(cfg):
    from hacksys.eventlog import read_events
    return read_events(cfg.log_path)
