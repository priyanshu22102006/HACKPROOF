"""Render the sealed report: a Markdown document a human reads, and the JSON
the dashboard and the LLM comparator consume.

The Markdown is the primary artifact. A judge with five minutes should be able
to read the top third and know what happened.
"""

from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from .config import Config
from .util import ensure_dir, human_duration, iso, short

ATTENTION_LABEL = {
    "clear": "Clear — nothing needing review",
    "notes_for_the_judge": "Notes — normal activity worth being aware of",
    "needs_human_review": "Review — specific items a judge should ask about",
    "significant_questions": "Significant questions — several items need an explanation",
}

SEV_LABEL = {"info": "ok", "notice": "note", "warn": "review", "critical": "question"}
SEV_MARK = {"info": "·", "notice": "•", "warn": "!", "critical": "!!"}


def render_markdown(report: Dict[str, Any]) -> str:
    p = report["participant"]
    w = report["window"]
    cov = report["coverage"]
    s = report["summary"]
    log = report["log"]

    out: List[str] = []
    add = out.append

    add(f"# HackSys system-activity report")
    add("")
    add(f"**{p.get('participant_name') or p.get('participant_id')}**"
        + (f" · team `{p['team_id']}`" if p.get("team_id") else "")
        + (f" · event `{p['event_id']}`" if p.get("event_id") else ""))
    add("")
    add(f"- Hackathon window: `{w['start']}` → `{w['end']}`")
    if p.get("submission_repo"):
        add(f"- Submission repo: {p['submission_repo']}")
    add(f"- Report generated: `{report['generated_at']}`")
    add(f"- Events recorded: **{log['events']}** · log sha256 `{short(log['sha256'], 16)}…`")
    add("")

    # ---------------------------------------------------------------- verdict
    add("## What this report says")
    add("")
    add(f"> **{ATTENTION_LABEL.get(s['attention'], s['attention'])}**  ")
    add(f"> {s['checks_run'] - s['checks_failed']} of {s['checks_run']} checks passed."
        + (f" Needing attention: {', '.join('`' + c + '`' for c in s['failed_checks'])}."
           if s["failed_checks"] else ""))
    add("")
    add(s["disclaimer"])
    add("")

    # --------------------------------------------------------------- coverage
    add("## Monitoring coverage")
    add("")
    add(f"The agent observed **{cov['coverage_pct']}%** of the window "
        f"({human_duration(cov['covered_seconds'])} of {human_duration(cov['window_seconds'])}).")
    add("")
    if cov["gaps"]:
        add("| Gap from | to | duration | why |")
        add("|---|---|---|---|")
        for g in cov["gaps"][:15]:
            add(f"| `{g['from']}` | `{g['to']}` | {human_duration(g['seconds'])} | {g['reason']} |")
        add("")
        add("*Activity during a gap was not observed. Everything below covers monitored time only.*")
    else:
        add("No gaps. The agent was running continuously for the whole window.")
    add("")

    # --------------------------------------------------------------- findings
    add("## Checks")
    add("")
    add("| | Check | Result | Severity |")
    add("|---|---|---|---|")
    for f in report["findings"]:
        mark = SEV_MARK.get(f["severity"], "·")
        result = "pass" if f["passed"] else SEV_LABEL.get(f["severity"], "review")
        add(f"| {mark} | `{f['check_name']}` | {result} | {f['severity']} |")
    add("")

    for f in report["findings"]:
        title = f.get("title") or f["check_name"]
        status = "PASS" if f["passed"] else f["severity"].upper()
        add(f"### {SEV_MARK.get(f['severity'], '·')} {title}")
        add("")
        add(f"`{f['check_name']}` — **{status}**")
        add("")
        if f.get("explanation"):
            add(f["explanation"])
            add("")
        rendered = _render_evidence(f)
        if rendered:
            out.extend(rendered)
            add("")

    # ---------------------------------------------------------------- timeline
    notable = report.get("notable_events", [])
    add("## Timeline of notable events")
    add("")
    if not notable:
        add("Nothing above routine activity was recorded.")
    else:
        add(f"{len(notable)} event(s) above routine level"
            + (" (first 120 shown)" if len(notable) > 120 else "") + ".")
        add("")
        add("| # | time | severity | what happened |")
        add("|---|---|---|---|")
        for e in notable[:120]:
            add(f"| {e['seq']} | `{e['ts']}` | {e['severity']} | {_esc(e['summary'])} |")
    add("")

    # ------------------------------------------------------------ event volume
    add("## Event volume")
    add("")
    add("| event kind | count |")
    add("|---|---|")
    for kind, n in list(report["counts_by_kind"].items())[:30]:
        add(f"| `{kind}` | {n} |")
    add("")

    # ---------------------------------------------------------------- verify
    add("## How to verify this report")
    add("")
    add("The event log is hash-chained: every entry commits to the one before it, so any "
        "deletion, edit or reordering breaks the chain at that point.")
    add("")
    add("```")
    add(f"hacksys verify --log {log['path']}")
    add(f"shasum -a 256 {log['path']}   # expect {log['sha256']}")
    add("```")
    add("")
    add(f"- Chain tip: `{log['chain_tip']}`")
    add(f"- Consent recorded: `{p.get('consent_recorded_at') or 'not recorded'}`")
    add("")
    add("---")
    add("")
    add("*Generated by the HackSys system-plane agent. This is one of two inputs to the "
        "HackProof review: the other is the repository analysis of the submitted GitHub "
        "repo. Neither is a judgement on its own.*")

    return "\n".join(out) + "\n"


# --------------------------------------------------------------------------


def _render_evidence(finding: Dict[str, Any]) -> List[str]:
    ev = finding.get("evidence") or {}
    name = finding["check_name"]
    out: List[str] = []

    def table(rows: List[Dict[str, Any]], cols: List[tuple]) -> None:
        if not rows:
            return
        out.append("| " + " | ".join(c[0] for c in cols) + " |")
        out.append("|" + "|".join("---" for _ in cols) + "|")
        for r in rows:
            cells = []
            for _, key in cols:
                val = r.get(key, "")
                if isinstance(val, list):
                    val = ", ".join(str(v) for v in val[:3])
                cells.append(_esc(str(val)))
            out.append("| " + " | ".join(cells) + " |")
        out.append("")

    if name == "external_code_ingestion":
        table(ev.get("files", []), [("file", "path"), ("identical to", "sources"),
                                    ("where from", "source_zones"), ("event", "seq")])
    elif name == "clipboard_code_movement":
        table(ev.get("pastes", []), [("time", "ts"), ("landed in", "path"),
                                     ("copied from", "source_app"), ("lines", "lines"),
                                     ("delay", "seconds_since_copy")])
        if ev.get("copy_origins"):
            out.append("Copies matched to a specific file on disk:")
            out.append("")
            table(ev["copy_origins"], [("time", "ts"), ("origin file", "origin_path"),
                                       ("app", "source_app"), ("lines", "lines")])
    elif name == "reference_repository_copying":
        table(ev.get("repositories", []), [("repo", "repo"),
                                           ("next to submission", "adjacent"), ("event", "seq")])
        table(ev.get("copied_files", []), [("submission file", "path"), ("matches", "sources")])
    elif name == "downloaded_code_provenance":
        table(ev.get("into_submission", []), [("time", "ts"), ("file", "path"),
                                              ("origin URL", "origins")])
    elif name in ("commit_signing", "commit_timeline"):
        rows = (ev.get("commits") or ev.get("unsigned") or [])[:40]
        table(rows, [("sha", "sha"), ("subject", "subject"), ("author", "author"),
                     ("committed", "commit_date"), ("signature", "signature"),
                     ("+/-", "insertions"), ("notes", "notes")])
    elif name == "history_rewriting":
        table(ev.get("force_pushes", []), [("time", "ts"), ("ref", "ref"),
                                           ("old", "old"), ("new", "new")])
        table(ev.get("amended_commits", []), [("sha", "sha"), ("subject", "subject"),
                                              ("committed", "commit_date")])
        table(ev.get("resets", []), [("time", "ts"), ("reflog", "reflog"),
                                     ("rewrites history", "rewrites_history")])
    elif name == "gitignore_hidden_code":
        table(ev.get("changes", []), [("time", "ts"), ("repo", "repo"),
                                      ("newly hidden source files", "newly_ignored_code")])
    elif name == "signing_key_stability":
        table(ev.get("changes", []), [("time", "ts"), ("fingerprints now", "fingerprints")])
    elif name == "monitoring_environment":
        table(ev.get("started_during_event", []), [("time", "ts"), ("tool", "comm")])
    elif name == "monitoring_coverage":
        table(ev.get("stop_signals", []), [("time", "ts"), ("signal", "signal")])
    elif name == "log_chain_integrity" and ev.get("problems"):
        table(ev["problems"], [("line", "lineno"), ("event", "seq"), ("problem", "issue")])

    if not out:
        # fall back to a compact JSON block so nothing is silently dropped
        trimmed = {k: v for k, v in ev.items() if k != "events"}
        if trimmed:
            out.append("<details><summary>evidence</summary>")
            out.append("")
            out.append("```json")
            out.append(json.dumps(trimmed, indent=2, default=str)[:4000])
            out.append("```")
            out.append("")
            out.append("</details>")
    return out


def _esc(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


# --------------------------------------------------------------------------


def write_reports(cfg: Config, report: Dict[str, Any]) -> Dict[str, str]:
    ensure_dir(cfg.report_dir)
    stamp = report["generated_at"].replace(":", "").replace("-", "")[:15]
    base = f"hacksys-{cfg.participant_id or 'participant'}-{stamp}"

    json_path = os.path.join(cfg.report_dir, base + ".json")
    md_path = os.path.join(cfg.report_dir, base + ".md")

    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, default=str)
    with open(md_path, "w", encoding="utf-8") as fh:
        fh.write(render_markdown(report))

    latest_json = os.path.join(cfg.report_dir, "latest.json")
    latest_md = os.path.join(cfg.report_dir, "latest.md")
    for src, dst in ((json_path, latest_json), (md_path, latest_md)):
        try:
            if os.path.lexists(dst):
                os.remove(dst)
            os.symlink(src, dst)
        except OSError:
            pass

    return {"json": json_path, "markdown": md_path}
