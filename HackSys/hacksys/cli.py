"""`hacksys` command line."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import timedelta
from typing import List, Optional

from . import __version__
from .analysis import build_report
from .config import Config, load_config, render_template
from .daemon import Agent, read_pid, sealing_marker
from .eventlog import EventLog, verify_chain
from .models import Event
from .report import render_markdown, write_reports
from .util import ensure_dir, expand, have, human_duration, iso, now_utc, parse_iso, run

CONSENT_TEXT = """
HackSys records, on this machine, for the duration of the hackathon window only:

  · file creations, changes, moves and deletions under the watched folders,
    with the SHA-256 of source files (file *contents* are not stored or sent)
  · that a clipboard copy happened, its size, shape and which app was focused
    — the clipboard text itself is NOT stored or sent
  · git activity in your project: commits, their signatures, diffstats,
    amends, rebases, resets, pushes, and .gitignore changes
  · the fingerprints of GPG keys available for signing (never key material)
  · launches of processes on a published watchlist, and which app is in front
  · its own uptime, so gaps in monitoring are visible to a judge

It does NOT record keystrokes, screenshots, audio, browsing history, page
contents, passwords, or anything outside the watched folders.

The full event log stays on this machine at ~/.hacksys/events.jsonl in plain
text. You can read it at any time. Only the sealed report is sent to the
organiser, and `hacksys seal` prints it for you before it is sent.
"""


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _resolve_config(args) -> Config:
    return load_config(getattr(args, "config", None))


def _print_header(title: str) -> None:
    print(f"\n{title}\n" + "-" * len(title))


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_init(args) -> int:
    home = expand(args.home)
    ensure_dir(home)

    # Re-running init against a live window would silently replace the window,
    # the project paths and the recorded consent — which is exactly the kind of
    # quiet change a judge should never have to wonder about.
    existing_path = os.path.join(home, "config.toml")
    if os.path.exists(existing_path) and not args.force:
        try:
            previous = load_config(existing_path)
        except Exception:
            previous = None
        if previous and previous.in_window():
            print(f"error: monitoring is already configured at {existing_path} and its "
                  f"window is still open\n"
                  f"       ({previous.window_start} → {previous.window_end})\n"
                  f"       Seal it first with `hacksys seal`, or pass --force to replace it.",
                  file=sys.stderr)
            return 2

    cfg = Config(home=home)

    cfg.participant_id = args.participant or os.environ.get("USER", "participant")
    cfg.participant_name = args.name or ""
    cfg.team_id = args.team or ""
    cfg.event_id = args.event or ""
    cfg.submission_repo = args.repo or ""
    cfg.registered_gpg_fingerprint = (args.gpg_fingerprint or "").replace(" ", "").upper()
    cfg.server_url = args.server or os.environ.get("HACKPROOF_SERVER", "")
    cfg.server_token = args.token or os.environ.get("HACKPROOF_TOKEN", "")

    projects = [expand(p) for p in (args.project or [])]
    if not projects:
        print("error: at least one --project path is required", file=sys.stderr)
        return 2
    missing = [p for p in projects if not os.path.isdir(p)]
    if missing:
        print(f"error: not a directory: {', '.join(missing)}", file=sys.stderr)
        return 2
    cfg.project_paths = projects

    if args.watch_root:
        cfg.watch_roots = [expand(p) for p in args.watch_root]

    start = parse_iso(args.start) if args.start else now_utc()
    if args.end:
        end = parse_iso(args.end)
    else:
        end = start + timedelta(hours=float(args.hours))
    cfg.window_start = iso(start)
    cfg.window_end = iso(end)

    print(CONSENT_TEXT)
    print(f"Watched folders : {', '.join(cfg.watch_roots)}")
    print(f"Submission      : {', '.join(cfg.project_paths)}")
    print(f"Window          : {cfg.window_start}  →  {cfg.window_end}"
          f"  ({human_duration((end - start).total_seconds())})")
    print()

    if not args.yes:
        answer = input("Type 'I agree' to enable monitoring: ").strip().lower()
        if answer not in ("i agree", "agree", "yes"):
            print("Not enabled. Nothing was written.")
            return 1
    cfg.consent_recorded_at = iso()

    with open(cfg.config_path, "w", encoding="utf-8") as fh:
        fh.write(render_template(cfg))

    ensure_dir(cfg.state_dir)
    ensure_dir(cfg.report_dir)
    ensure_dir(cfg.spool_dir)

    log = EventLog(cfg.log_path)
    if os.path.exists(existing_path) and args.force:
        # the log is append-only, so a replacement is recorded rather than hidden
        log.append(Event(
            kind="config.replaced",
            collector="cli",
            summary="monitoring was reconfigured with --force, replacing the previous setup",
            severity="warn",
            data={"new_window_start": cfg.window_start, "new_window_end": cfg.window_end,
                  "new_project_paths": cfg.project_paths},
        ))

    log.append(Event(
        kind="consent.recorded",
        collector="cli",
        summary=f"{cfg.participant_id} enabled monitoring for the window "
                f"{cfg.window_start} → {cfg.window_end}",
        severity="info",
        data={
            "participant_id": cfg.participant_id,
            "team_id": cfg.team_id,
            "event_id": cfg.event_id,
            "window_start": cfg.window_start,
            "window_end": cfg.window_end,
            "project_paths": cfg.project_paths,
            "watch_roots": cfg.watch_roots,
            "consent_text_sha256": __import__("hashlib").sha256(
                CONSENT_TEXT.encode()).hexdigest(),
            "agent_version": __version__,
        },
    ))

    print(f"\nWritten: {cfg.config_path}")
    print(f"Log:     {cfg.log_path}")
    print("\nNext:  hacksys install     (run it in the background via launchd)")
    print("  or:  hacksys start       (run it in this terminal)")
    return 0


def cmd_start(args) -> int:
    cfg = _resolve_config(args)
    existing = read_pid(cfg)
    if existing:
        print(f"already running (pid {existing})", file=sys.stderr)
        return 1
    print(f"hacksys {__version__} — monitoring for {cfg.participant_id}")
    print(f"  window : {cfg.window_start} → {cfg.window_end}")
    print(f"  log    : {cfg.log_path}")
    print("  stop with Ctrl-C (the stop is recorded in the log)\n")
    return Agent(cfg).run()


def cmd_install(args) -> int:
    from . import install_macos
    cfg = _resolve_config(args)
    ok, detail = install_macos.install(cfg)
    if not ok:
        print(f"install failed: {detail}", file=sys.stderr)
        return 1
    print(f"launchd job installed: {detail}")
    print("It starts now and restarts automatically at login.")
    print("Check it with:  hacksys status")
    return 0


def cmd_uninstall(args) -> int:
    from . import install_macos
    ok, detail = install_macos.uninstall()
    print("launchd job removed" if ok else f"uninstall failed: {detail}")
    return 0 if ok else 1


def cmd_status(args) -> int:
    from . import install_macos
    cfg = _resolve_config(args)
    pid = read_pid(cfg)
    chain = verify_chain(cfg.log_path)
    launchd = install_macos.status()

    hb = {}
    try:
        with open(cfg.heartbeat_path, "r", encoding="utf-8") as fh:
            hb = json.load(fh)
    except (OSError, json.JSONDecodeError):
        pass

    _print_header("hacksys status")
    print(f"participant : {cfg.participant_id}"
          + (f" (team {cfg.team_id})" if cfg.team_id else ""))
    print(f"window      : {cfg.window_start} → {cfg.window_end}"
          f"  [{'OPEN' if cfg.in_window() else 'closed'}]")
    print(f"process     : {'running, pid ' + str(pid) if pid else 'NOT RUNNING'}")
    print(f"launchd     : {'loaded' if launchd['loaded'] else 'not loaded'}"
          f"  ({launchd['state'] or 'n/a'})")
    print(f"log         : {cfg.log_path}")
    print(f"events      : {chain['events']}   chain: "
          f"{'intact' if chain['ok'] else 'BROKEN — ' + str(chain['problem_count']) + ' problem(s)'}")
    if hb:
        print(f"heartbeat   : {hb.get('ts')}  (seq {hb.get('seq')})")
        if hb.get("stop_reason"):
            print(f"last stop   : {hb['stop_reason']}")

    # "loaded but not running" is the confusing state — say why, don't make
    # the user go hunting for the log
    if not pid and launchd["loaded"]:
        stderr_path = os.path.join(cfg.state_dir, "stderr.log")
        tail = _tail(stderr_path, 12)
        print()
        print("launchd has the job loaded but nothing is running. Last output from it:")
        print(f"  ({stderr_path})")
        for line in tail or ["  <empty — try `hacksys start` in this terminal to see the error>"]:
            print(f"  {line}")
    print()
    return 0 if (pid and chain["ok"]) else 1


def _tail(path: str, n: int) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [ln.rstrip() for ln in fh.readlines()[-n:] if ln.strip()]
    except OSError:
        return []


def cmd_verify(args) -> int:
    cfg = None
    log_path = args.log
    if not log_path:
        cfg = _resolve_config(args)
        log_path = cfg.log_path
    result = verify_chain(log_path)
    _print_header("hacksys verify")
    print(f"log    : {log_path}")
    print(f"events : {result['events']}")
    print(f"tip    : {result['tip']}")
    print(f"chain  : {'INTACT' if result['ok'] else 'BROKEN'}")
    for p in result["problems"]:
        print(f"  line {p.get('lineno')}: {p['issue']}"
              + (f" (seq {p.get('seq')})" if p.get("seq") else ""))
    print()
    return 0 if result["ok"] else 1


def cmd_seal(args) -> int:
    cfg = _resolve_config(args)

    pid = read_pid(cfg)
    if pid and not args.keep_running:
        print(f"stopping the agent (pid {pid})…")
        marker = sealing_marker(cfg)
        ensure_dir(cfg.state_dir)
        with open(marker, "w", encoding="utf-8") as fh:
            fh.write(iso())
        try:
            os.kill(pid, 15)
        except OSError as exc:
            print(f"  could not stop it: {exc}", file=sys.stderr)
        import time
        for _ in range(20):
            if not read_pid(cfg):
                break
            time.sleep(0.5)
        try:
            os.remove(marker)
        except OSError:
            pass

    log = EventLog(cfg.log_path)
    log.append(Event(
        kind="report.sealed",
        collector="cli",
        summary="report sealed — the log is closed for this session",
        data={"events_before_seal": log.count, "sealed_at": iso(),
              "agent_version": __version__},
    ))

    report = build_report(cfg)
    paths = write_reports(cfg, report)

    _print_header("hacksys seal")
    s = report["summary"]
    print(f"events     : {report['log']['events']}")
    print(f"coverage   : {report['coverage']['coverage_pct']}% of the window")
    print(f"checks     : {s['checks_run'] - s['checks_failed']}/{s['checks_run']} passed")
    if s["failed_checks"]:
        print(f"attention  : {', '.join(s['failed_checks'])}")
    print(f"report     : {paths['markdown']}")
    print(f"json       : {paths['json']}")

    if args.print_report:
        print()
        print(render_markdown(report))

    if args.submit:
        from .transport import submit
        with open(paths["markdown"], "r", encoding="utf-8") as fh:
            md = fh.read()
        result = submit(cfg, report, md)
        if result.get("ok"):
            print(f"\nuploaded to {result['url']} ({result['status']})")
        else:
            print(f"\nupload failed: {result.get('reason') or result.get('response')}")
            print(f"spooled to {result.get('spooled')} — retry with `hacksys submit --retry`")
            return 1
    else:
        print("\nNot uploaded. Send it with:  hacksys seal --submit   "
              "(or `hacksys submit`)")
    return 0


def cmd_submit(args) -> int:
    cfg = _resolve_config(args)
    from .transport import retry_spool, submit

    if args.retry:
        results = retry_spool(cfg)
        if not results:
            print("nothing spooled")
            return 0
        for r in results:
            print(f"{r['file']}: {'sent' if r.get('ok') else 'failed — ' + str(r.get('response'))[:120]}")
        return 0 if all(r.get("ok") for r in results) else 1

    report = build_report(cfg)
    md = render_markdown(report)
    result = submit(cfg, report, md)
    if result.get("ok"):
        print(f"uploaded to {result['url']} ({result['status']})")
        return 0
    print(f"upload failed: {result.get('reason') or result.get('response')}")
    print(f"spooled to {result.get('spooled')}")
    return 1


def cmd_report(args) -> int:
    cfg = _resolve_config(args)
    report = build_report(cfg)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(render_markdown(report))
    return 0


def cmd_events(args) -> int:
    cfg = _resolve_config(args)
    from .eventlog import read_events
    rows = list(read_events(cfg.log_path))
    if args.kind:
        rows = [r for r in rows if str(r.get("kind", "")).startswith(args.kind)]
    if args.severity:
        from .models import severity_rank
        floor = severity_rank(args.severity)
        rows = [r for r in rows if severity_rank(r.get("severity", "info")) >= floor]
    for r in rows[-args.tail:]:
        print(f"{r.get('seq'):>6} {r.get('ts')} {r.get('severity','info'):<8} "
              f"{r.get('kind',''):<32} {r.get('summary','')}")
    return 0


def cmd_doctor(args) -> int:
    _print_header("hacksys doctor")
    ok = True

    def check(label: str, passed: bool, detail: str = "", fatal: bool = True) -> None:
        nonlocal ok
        mark = "ok  " if passed else ("FAIL" if fatal else "warn")
        print(f"[{mark}] {label}" + (f" — {detail}" if detail else ""))
        if not passed and fatal:
            ok = False

    check("python 3.11+", sys.version_info >= (3, 11), sys.version.split()[0])

    try:
        import watchdog  # noqa: F401
        check("watchdog installed", True)
    except ImportError:
        check("watchdog installed", False, "pip install watchdog")

    check("git available", have("git"), fatal=True)
    check("gpg available", have("gpg") or have("gpg2"),
          "signature verification needs it", fatal=False)
    check("pbpaste available", have("pbpaste"), "clipboard monitoring needs it", fatal=False)

    from .util import frontmost_app
    app = frontmost_app()
    check("Accessibility permission (foreground app)", app is not None,
          f"detected: {app}" if app
          else "System Settings → Privacy & Security → Accessibility → add your terminal/python",
          fatal=False)

    tcc = os.path.expanduser("~/Library/Application Support/com.apple.TCC/TCC.db")
    fda = os.access(tcc, os.R_OK)
    check("Full Disk Access", fda,
          "without it, parts of the home folder cannot be watched — "
          "System Settings → Privacy & Security → Full Disk Access",
          fatal=False)

    try:
        cfg = _resolve_config(args)
        check("config readable", True, cfg.config_path)
        check("project path(s) exist",
              all(os.path.isdir(p) for p in cfg.project_paths),
              ", ".join(cfg.project_paths))
        check("consent recorded", bool(cfg.consent_recorded_at), cfg.consent_recorded_at)
        chain = verify_chain(cfg.log_path)
        check("event log chain", chain["ok"], f"{chain['events']} events")
    except FileNotFoundError as exc:
        check("config readable", False, str(exc))

    print()
    return 0 if ok else 1


# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hacksys",
        description="HackProof system-plane agent: records what happened on this "
                    "machine during a hackathon, and seals it into a report.",
    )
    p.add_argument("--version", action="version", version=f"hacksys {__version__}")
    p.add_argument("--config", help="path to config.toml (default ~/.hacksys/config.toml)")

    # --config must work on either side of the subcommand: launchd, shell history
    # and muscle memory all produce both orders. SUPPRESS keeps the subparser
    # copy from clobbering a value given before the subcommand.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", default=argparse.SUPPRESS,
                        help="path to config.toml (default ~/.hacksys/config.toml)")

    sub = p.add_subparsers(dest="command", required=True, parser_class=argparse.ArgumentParser)

    def add(name: str, **kw):
        return sub.add_parser(name, parents=[common], **kw)

    i = add("init", help="set up monitoring and record consent")
    i.add_argument("--participant", help="participant id")
    i.add_argument("--name", help="participant display name")
    i.add_argument("--team", help="team id")
    i.add_argument("--event", help="hackathon/event id")
    i.add_argument("--repo", help="submission repository URL")
    i.add_argument("--project", action="append", required=True,
                   help="submission directory (repeatable)")
    i.add_argument("--watch-root", action="append",
                   help="directory to watch (repeatable, default: your home folder)")
    i.add_argument("--start", help="window start, ISO-8601 (default: now)")
    i.add_argument("--end", help="window end, ISO-8601")
    i.add_argument("--hours", default=36, help="window length if --end is omitted")
    i.add_argument("--gpg-fingerprint", help="fingerprint registered with the organiser")
    i.add_argument("--server", help="HackProof server base URL (or $HACKPROOF_SERVER)")
    i.add_argument("--token", help="upload token (or $HACKPROOF_TOKEN)")
    i.add_argument("--home", default="~/.hacksys", help="agent data directory")
    i.add_argument("--yes", action="store_true", help="accept the consent notice non-interactively")
    i.add_argument("--force", action="store_true",
                   help="replace an existing setup whose window is still open")
    i.set_defaults(func=cmd_init)

    s = add("start", help="run the agent in the foreground")
    s.set_defaults(func=cmd_start)

    ins = add("install", help="install and start the launchd job")
    ins.set_defaults(func=cmd_install)

    un = add("uninstall", help="stop and remove the launchd job")
    un.set_defaults(func=cmd_uninstall)

    st = add("status", help="is it running, and is the log intact")
    st.set_defaults(func=cmd_status)

    v = add("verify", help="verify the event log hash chain")
    v.add_argument("--log", help="log file to verify (default: the configured one)")
    v.set_defaults(func=cmd_verify)

    se = add("seal", help="stop monitoring and produce the final report")
    se.add_argument("--submit", action="store_true", help="upload the report to the server")
    se.add_argument("--keep-running", action="store_true",
                    help="produce an interim report without stopping the agent")
    se.add_argument("--print-report", action="store_true", help="print the report to stdout")
    se.set_defaults(func=cmd_seal)

    sb = add("submit", help="upload a report to the server")
    sb.add_argument("--retry", action="store_true", help="retry everything in the spool")
    sb.set_defaults(func=cmd_submit)

    r = add("report", help="render the report without sealing")
    r.add_argument("--json", action="store_true")
    r.set_defaults(func=cmd_report)

    e = add("events", help="read the event log")
    e.add_argument("--tail", type=int, default=40)
    e.add_argument("--kind", help="filter by event kind prefix, e.g. git.")
    e.add_argument("--severity", help="minimum severity: info|notice|warn|critical")
    e.set_defaults(func=cmd_events)

    d = add("doctor", help="check permissions and dependencies")
    d.set_defaults(func=cmd_doctor)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130
