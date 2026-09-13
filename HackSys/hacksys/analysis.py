"""Turn the raw event log into Findings.

Rules this module follows, deliberately:

  * every Finding cites the events it came from, by sequence number
  * nothing is ever labelled "cheating" — checks describe what happened
  * absence of evidence is reported as absence of *coverage*, not as a pass:
    a log with a four-hour hole says so loudly rather than looking clean
"""

from __future__ import annotations

import os
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .config import Config
from .eventlog import read_events, verify_chain
from .models import (
    PLANE_SYSTEM,
    SEV_CRITICAL,
    SEV_INFO,
    SEV_NOTICE,
    SEV_WARN,
    Finding,
    severity_rank,
)
from .util import human_duration, iso, now_utc, parse_iso, sha256_file

GAP_THRESHOLD = 600.0  # heartbeats are every 300s; 600s of silence is a real gap


# --------------------------------------------------------------------------


class Analysis:
    def __init__(self, cfg: Config, events: List[Dict[str, Any]]):
        self.cfg = cfg
        self.events = [e for e in events if not e.get("_malformed")]
        self.by_kind: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for e in self.events:
            self.by_kind[e.get("kind", "?")].append(e)

    # -- helpers -----------------------------------------------------

    def k(self, *kinds: str) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for kind in kinds:
            out.extend(self.by_kind.get(kind, []))
        return sorted(out, key=lambda e: e.get("seq", 0))

    @staticmethod
    def refs(events: Iterable[Dict[str, Any]], limit: int = 25) -> List[int]:
        return [e.get("seq") for e in list(events)[:limit]]

    @staticmethod
    def when(event: Dict[str, Any]) -> Optional[Any]:
        try:
            return parse_iso(event["ts"])
        except Exception:
            return None

    # ==================================================================
    # coverage
    # ==================================================================

    def coverage(self) -> Dict[str, Any]:
        start, end = self.cfg.window()
        now = now_utc()
        horizon = min(end, now)
        total = max(1.0, (horizon - start).total_seconds())

        stamps = [t for t in (self.when(e) for e in self.events) if t]
        stamps = sorted(t for t in stamps if start <= t <= horizon)

        gaps: List[Dict[str, Any]] = []
        if not stamps:
            gaps.append({"from": iso(start), "to": iso(horizon),
                         "seconds": total, "reason": "no events recorded inside the window"})
        else:
            lead = (stamps[0] - start).total_seconds()
            if lead > GAP_THRESHOLD:
                gaps.append({"from": iso(start), "to": iso(stamps[0]), "seconds": lead,
                             "reason": "agent was not running when the window opened"})
            for a, b in zip(stamps, stamps[1:]):
                delta = (b - a).total_seconds()
                if delta > GAP_THRESHOLD:
                    gaps.append({"from": iso(a), "to": iso(b), "seconds": delta,
                                 "reason": "no events recorded"})
            trail = (horizon - stamps[-1]).total_seconds()
            if trail > GAP_THRESHOLD:
                gaps.append({"from": iso(stamps[-1]), "to": iso(horizon), "seconds": trail,
                             "reason": "agent stopped before the window closed"})

        # explicit downtime events carry the authoritative reason
        for e in self.k("integrity.downtime"):
            for g in gaps:
                if abs(g["seconds"] - float(e.get("data", {}).get("gap_seconds", -1))) < 90:
                    g["reason"] = e.get("data", {}).get("reason", g["reason"])

        missing = sum(g["seconds"] for g in gaps)
        covered = max(0.0, total - missing)
        return {
            "window_start": iso(start),
            "window_end": iso(end),
            "evaluated_until": iso(horizon),
            "window_seconds": total,
            "covered_seconds": covered,
            "coverage_pct": round(100.0 * covered / total, 2),
            "gaps": gaps,
            "gap_count": len(gaps),
            "first_event": iso(stamps[0]) if stamps else None,
            "last_event": iso(stamps[-1]) if stamps else None,
        }

    # ==================================================================
    # checks
    # ==================================================================

    def run(self) -> Tuple[List[Finding], Dict[str, Any]]:
        cov = self.coverage()
        findings = [
            self.check_chain(),
            self.check_coverage(cov),
            self.check_clock(),
            self.check_collector_health(),
            self.check_external_code(),
            self.check_clipboard(),
            self.check_reference_clone(),
            self.check_downloads(),
            self.check_signing(),
            self.check_history_rewrite(),
            self.check_commit_timeline(),
            self.check_gitignore(),
            self.check_gpg_material(),
            self.check_observer_tools(),
            self.check_assistant_context(),
        ]
        return [f for f in findings if f], cov

    # -- integrity of the record itself -----------------------------------

    def check_chain(self) -> Finding:
        result = verify_chain(self.cfg.log_path)
        broken = self.k("integrity.chain_broken")
        ok = result["ok"] and not broken
        return Finding(
            check_name="log_chain_integrity",
            plane=PLANE_SYSTEM,
            severity=SEV_INFO if ok else SEV_CRITICAL,
            passed=ok,
            title="Event log is tamper-evident and intact",
            explanation=(
                f"Every one of the {result['events']} events hashes over its predecessor. "
                "Deleting, editing or reordering any line would break the chain."
                if ok else
                "The hash chain does not verify. Some part of the log was altered or "
                "truncated after it was written; the events after the first break cannot "
                "be relied on."
            ),
            evidence={
                "events": result["events"],
                "chain_tip": result["tip"],
                "problems": result["problems"],
                "log_sha256": sha256_file(self.cfg.log_path),
            },
        )

    def check_coverage(self, cov: Dict[str, Any]) -> Finding:
        pct = cov["coverage_pct"]
        stops = self.k("daemon.signal")
        # a stop the participant asked for by running `hacksys seal` is not a gap
        in_window_stops = [e for e in stops
                           if e.get("data", {}).get("in_window")
                           and not e.get("data", {}).get("expected")]
        passed = pct >= 98.0 and not in_window_stops
        sev = SEV_INFO
        if pct < 98.0 or in_window_stops:
            sev = SEV_WARN
        if pct < 85.0:
            sev = SEV_CRITICAL
        biggest = max((g["seconds"] for g in cov["gaps"]), default=0)
        return Finding(
            check_name="monitoring_coverage",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=passed,
            title="Agent ran for the whole window",
            explanation=(
                f"The agent was running for {pct}% of the window."
                + (f" Longest gap: {human_duration(biggest)}." if biggest else "")
                + (f" It was asked to stop {len(in_window_stops)} time(s) while the window "
                   "was still open." if in_window_stops else "")
                + (" Activity during a gap was not observed at all — treat the rest of this "
                   "report as covering only the monitored time."
                   if cov["gaps"] else "")
            ),
            evidence={
                "coverage_pct": pct,
                "gaps": cov["gaps"][:20],
                "longest_gap_seconds": biggest,
                "stop_signals": [
                    {"seq": e.get("seq"), "ts": e.get("ts"),
                     "signal": e.get("data", {}).get("signal")}
                    for e in stops[:10]
                ],
            },
        )

    def check_clock(self) -> Finding:
        skews = self.k("integrity.clock_skew")
        return Finding(
            check_name="system_clock_integrity",
            plane=PLANE_SYSTEM,
            severity=SEV_INFO if not skews else SEV_CRITICAL,
            passed=not skews,
            title="System clock was stable",
            explanation=(
                "Wall clock and monotonic clock stayed in step, so timestamps in this "
                "report — including git commit times — were taken from a clock that was "
                "not moved."
                if not skews else
                f"The system clock jumped {len(skews)} time(s) during the event. Commit "
                "timestamps and file mtimes recorded around those jumps are not reliable "
                "evidence of when work happened."
            ),
            evidence={
                "events": self.refs(skews),
                "jumps": [e.get("data", {}).get("drift_seconds") for e in skews][:10],
            },
        )

    def check_collector_health(self) -> Finding:
        bad = self.k("collector.error", "collector.unavailable", "collector.degraded")
        blind = self.k("collector.unavailable")
        sev = SEV_INFO
        if bad:
            sev = SEV_NOTICE
        if blind:
            sev = SEV_WARN
        counts = Counter(e.get("data", {}).get("error_type", e.get("kind")) for e in bad)
        return Finding(
            check_name="collector_health",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not blind,
            title="All collectors were operational",
            explanation=(
                "Every collector started and ran without failure."
                if not bad else
                f"{len(bad)} collector problem(s) were recorded"
                + (f", including {len(blind)} collector(s) that could not run at all. "
                   "Whatever those collectors would have seen is simply missing."
                   if blind else ". Individual polls failed and were retried.")
            ),
            evidence={"events": self.refs(bad), "by_type": dict(counts),
                      "unavailable": [e.get("summary") for e in blind][:10]},
        )

    # -- code provenance -------------------------------------------------------

    def check_external_code(self) -> Finding:
        copies = self.k("fs.content_copied_into_project")
        critical = [e for e in copies if e.get("severity") == SEV_CRITICAL]
        sev = SEV_INFO
        if copies:
            sev = SEV_WARN
        if critical:
            sev = SEV_CRITICAL
        return Finding(
            check_name="external_code_ingestion",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not copies,
            title="No pre-existing files were copied into the submission",
            explanation=(
                "No file in the submission matched, byte for byte, a file that already "
                "existed elsewhere on this machine."
                if not copies else
                f"{len(copies)} file(s) in the submission are byte-identical to files that "
                "existed elsewhere on this machine — "
                + ("including files in Downloads, Desktop or /tmp. "
                   if critical else "")
                + "This detects whole-file copying, not authorship: vendored libraries, "
                  "scaffolding output and the participant's own earlier work all look the "
                  "same to it."
            ),
            evidence={
                "events": self.refs(copies),
                "files": [
                    {
                        "seq": e.get("seq"),
                        "ts": e.get("ts"),
                        "path": e.get("data", {}).get("path"),
                        "sources": e.get("data", {}).get("sources", [])[:3],
                        "source_zones": e.get("data", {}).get("source_zones"),
                        "sha256": e.get("data", {}).get("sha256"),
                    }
                    for e in copies[:40]
                ],
            },
        )

    def check_clipboard(self) -> Finding:
        landed = self.k("clipboard.paste_landed")
        copies = self.k("clipboard.copy")
        external = [e for e in copies if e.get("data", {}).get("source_zone") == "external"
                    and e.get("data", {}).get("code_like")]
        from_other_file = [e for e in copies if e.get("data", {}).get("origin_path")]
        sev = SEV_INFO
        if landed:
            sev = SEV_NOTICE
        if [e for e in landed if e.get("severity") in (SEV_WARN, SEV_CRITICAL)]:
            sev = SEV_WARN
        return Finding(
            check_name="clipboard_code_movement",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not landed,
            title="No clipboard content was traced into the submission",
            explanation=(
                f"{len(copies)} clipboard change(s) were observed; none of the copied "
                "content was found in a submission file afterwards."
                if not landed else
                f"{len(landed)} time(s), content that had been on the clipboard was found "
                f"verbatim inside a submission file. {len(external)} of the "
                f"{len(copies)} copies came from a browser, chat or assistant window, and "
                f"{len(from_other_file)} were matched to a specific file elsewhere on disk. "
                "Copying is normal developer behaviour — the value here is the timeline, "
                "not the count."
            ),
            evidence={
                "events": self.refs(landed),
                "clipboard_changes": len(copies),
                "code_like_copies_from_external_apps": len(external),
                "pastes": [
                    {
                        "seq": e.get("seq"),
                        "ts": e.get("ts"),
                        "path": e.get("data", {}).get("path"),
                        "source_app": e.get("data", {}).get("source_app"),
                        "lines": e.get("data", {}).get("clip_lines"),
                        "language": e.get("data", {}).get("clip_language"),
                        "seconds_since_copy": e.get("data", {}).get("seconds_since_copy"),
                    }
                    for e in landed[:40]
                ],
                "copy_origins": [
                    {"seq": e.get("seq"), "ts": e.get("ts"),
                     "origin_path": e.get("data", {}).get("origin_path"),
                     "source_app": e.get("data", {}).get("source_app"),
                     "lines": e.get("data", {}).get("lines")}
                    for e in from_other_file[:25]
                ],
            },
        )

    def check_reference_clone(self) -> Finding:
        repos = self.k("fs.repo_detected")
        adjacent = [e for e in repos if e.get("data", {}).get("adjacent_to_submission")]
        # cloning the submission repo itself, before the window, is not a signal
        clones = [e for e in self.k("git.clone") if not e.get("data", {}).get("historical")]
        # copies whose source sits inside one of those repos
        copy_events = self.k("fs.content_copied_into_project")
        repo_paths = [e.get("data", {}).get("repo", "") for e in repos]
        # repos that already existed when the agent started are in the baseline
        for e in self.k("fs.baseline_indexed"):
            repo_paths.extend(e.get("data", {}).get("repos", []))
        repo_paths = [r for r in dict.fromkeys(repo_paths)
                      if r and not any(r.startswith(p) for p in self.cfg.project_paths)]
        from_repo = [
            e for e in copy_events
            if any(src.startswith(rp + os.sep)
                   for src in e.get("data", {}).get("sources", [])
                   for rp in repo_paths)
        ]
        sev = SEV_INFO
        if adjacent or clones:
            sev = SEV_NOTICE
        if from_repo:
            sev = SEV_CRITICAL
        return Finding(
            check_name="reference_repository_copying",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not from_repo,
            title="No code was copied from a second repository on this machine",
            explanation=(
                "No second git repository was seen being used as a source for submission "
                "files."
                if not from_repo else
                f"{len(from_repo)} submission file(s) match files inside another git "
                "repository present on this machine. This is the pattern of building in a "
                "reference checkout and copying the result into the submission."
            ) + (
                f" {len(repos)} additional repository/repositories appeared during the "
                f"event ({len(adjacent)} next to the submission)." if repos else ""
            ),
            evidence={
                "events": self.refs(repos + from_repo),
                "repositories": [
                    {"seq": e.get("seq"), "ts": e.get("ts"),
                     "repo": e.get("data", {}).get("repo"),
                     "adjacent": e.get("data", {}).get("adjacent_to_submission")}
                    for e in repos[:20]
                ],
                "clones": [{"seq": e.get("seq"), "reflog": e.get("data", {}).get("reflog")}
                           for e in clones[:10]],
                "copied_files": [
                    {"seq": e.get("seq"), "path": e.get("data", {}).get("path"),
                     "sources": e.get("data", {}).get("sources", [])[:2]}
                    for e in from_repo[:25]
                ],
            },
        )

    def check_downloads(self) -> Finding:
        downloads = self.k("provenance.download")
        into_project = [e for e in downloads if e.get("data", {}).get("zone") == "project"]
        archives = [e for e in downloads if e.get("data", {}).get("is_archive")]
        sev = SEV_INFO
        if downloads:
            sev = SEV_NOTICE
        if into_project:
            sev = SEV_CRITICAL
        return Finding(
            check_name="downloaded_code_provenance",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not into_project,
            title="No downloaded files landed directly in the submission",
            explanation=(
                (f"{len(downloads)} downloaded file(s) were seen on this machine"
                 + (f", {len(archives)} of them archives" if archives else "")
                 + ". None of them was written into the submission directory."
                 if downloads else
                 "No files carrying a download origin were observed.")
                if not into_project else
                f"{len(into_project)} file(s) that macOS recorded as downloaded from the "
                "internet were written into the submission directory. The origin URLs are "
                "listed below; they are recorded by the operating system, not inferred."
            ),
            evidence={
                "events": self.refs(downloads),
                "into_submission": [
                    {"seq": e.get("seq"), "ts": e.get("ts"),
                     "path": e.get("data", {}).get("path"),
                     "origins": e.get("data", {}).get("origins", [])}
                    for e in into_project[:25]
                ],
                "all_downloads": [
                    {"seq": e.get("seq"), "path": e.get("data", {}).get("path"),
                     "origins": e.get("data", {}).get("origins", [])[:2]}
                    for e in downloads[:40]
                ],
            },
        )

    # -- git ----------------------------------------------------------------

    def _commits(self) -> List[Dict[str, Any]]:
        return [e for e in self.k("git.commit") if not e.get("data", {}).get("historical")]

    def check_signing(self) -> Finding:
        commits = self._commits()
        if not commits:
            return Finding(
                check_name="commit_signing",
                plane=PLANE_SYSTEM,
                severity=SEV_WARN if self.cfg.require_signed_commits else SEV_INFO,
                passed=False,
                title="Commits were signed with the registered key",
                explanation="No commits were observed during the monitored window, so "
                            "signing could not be assessed on the system plane.",
                evidence={"commits_observed": 0},
            )
        unsigned = [c for c in commits if c["data"].get("signature_state") in ("N", "")]
        bad = [c for c in commits if c["data"].get("signature_state") in ("B", "R", "E")]
        mismatch = [c for c in commits
                    if "signed by a key other than the registered one"
                    in c["data"].get("notes", [])]
        keys = Counter(c["data"].get("signing_key") for c in commits
                       if c["data"].get("signing_key"))
        passed = not bad and not mismatch and (not unsigned or not self.cfg.require_signed_commits)
        sev = SEV_INFO
        if unsigned and self.cfg.require_signed_commits:
            sev = SEV_WARN
        if bad or mismatch:
            sev = SEV_CRITICAL
        return Finding(
            check_name="commit_signing",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=passed,
            title="Commits were signed with the registered key",
            explanation=(
                f"All {len(commits)} commit(s) observed carried a good signature"
                + (f" from {list(keys)[0]}." if len(keys) == 1 else ".")
                if passed else
                f"Of {len(commits)} commit(s) observed: {len(unsigned)} unsigned, "
                f"{len(bad)} with a bad/revoked/uncheckable signature, {len(mismatch)} "
                "signed by a key other than the one registered with the organiser. "
                "A signature proves control of a key at commit time — it does not prove "
                "who wrote the code, and an anomaly here is a question, not a verdict."
            ),
            evidence={
                "commits_observed": len(commits),
                "unsigned": [_commit_ref(c) for c in unsigned[:25]],
                "bad_signature": [_commit_ref(c) for c in bad[:25]],
                "key_mismatch": [_commit_ref(c) for c in mismatch[:25]],
                "signing_keys_used": dict(keys),
                "registered_fingerprint": self.cfg.registered_gpg_fingerprint,
            },
        )

    def check_history_rewrite(self) -> Finding:
        amends = [c for c in self._commits() if c["data"].get("amended")]
        resets = [e for e in self.k("git.reset") if not e["data"].get("historical")]
        rebases = [e for e in self.k("git.rebase") if not e["data"].get("historical")]
        forced = [e for e in self.k("git.force_push") if not e["data"].get("historical")]
        total = len(amends) + len(resets) + len(rebases) + len(forced)
        sev = SEV_INFO
        if total:
            sev = SEV_NOTICE
        if forced or len(amends) > 5:
            sev = SEV_WARN
        return Finding(
            check_name="history_rewriting",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not forced,
            title="Git history was not rewritten",
            explanation=(
                "No amends, resets, rebases or force pushes were observed during the window."
                if not total else
                f"{len(amends)} amend(s), {len(resets)} reset(s), {len(rebases)} rebase(s) "
                f"and {len(forced)} force push(es) were observed. Rewriting is ordinary "
                "practice, but it means the published history is not the history that was "
                "actually created — the reflog entries below are what the submitted repo "
                "will no longer show."
            ),
            evidence={
                "amended_commits": [_commit_ref(c) for c in amends[:25]],
                "resets": [{"seq": e["seq"], "ts": e["ts"],
                            "reflog": e["data"].get("reflog"),
                            "rewrites_history": e["data"].get("rewrites_history")}
                           for e in resets[:25]],
                "rebases": [{"seq": e["seq"], "ts": e["ts"], "reflog": e["data"].get("reflog")}
                            for e in rebases[:25]],
                "force_pushes": [{"seq": e["seq"], "ts": e["ts"], "ref": e["data"].get("ref"),
                                  "old": e["data"].get("old"), "new": e["data"].get("new")}
                                 for e in forced[:25]],
            },
        )

    def check_commit_timeline(self) -> Finding:
        commits = self._commits()
        outside = [c for c in commits if c["data"].get("outside_window")]
        bulk = [c for c in commits if c["data"].get("bulk")]
        skewed = [c for c in commits
                  if abs(c["data"].get("author_commit_skew_seconds") or 0) > 3600]
        total_ins = sum(c["data"].get("insertions", 0) for c in commits)
        sev = SEV_INFO
        if bulk or skewed:
            sev = SEV_NOTICE
        if outside:
            sev = SEV_WARN
        return Finding(
            check_name="commit_timeline",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not outside,
            title="Commits fall inside the hackathon window",
            explanation=(
                f"{len(commits)} commit(s), {total_ins} line(s) added, all inside the window."
                if not outside else
                f"{len(outside)} of {len(commits)} commit(s) carry a commit date outside the "
                "hackathon window."
            ) + (
                f" {len(bulk)} commit(s) were unusually large (over "
                f"{self.cfg.bulk_commit_lines} lines or {self.cfg.bulk_commit_files} files); "
                "large commits are common when scaffolding or adding dependencies."
                if bulk else ""
            ) + (
                f" {len(skewed)} commit(s) have an author date more than an hour from the "
                "commit date, which is what rebasing and patch-applying produce."
                if skewed else ""
            ),
            evidence={
                "commits": [_commit_ref(c) for c in commits[:60]],
                "outside_window": [_commit_ref(c) for c in outside[:25]],
                "bulk_commits": [_commit_ref(c) for c in bulk[:25]],
                "date_skewed": [_commit_ref(c) for c in skewed[:25]],
                "total_insertions": total_ins,
                "total_deletions": sum(c["data"].get("deletions", 0) for c in commits),
            },
        )

    def check_gitignore(self) -> Finding:
        changes = self.k("git.gitignore_changed")
        hiding = [e for e in changes if e["data"].get("newly_ignored_code")]
        baseline = self.k("git.gitignore_baseline")
        baseline_ignored = sum(len(e["data"].get("ignored_code_files", [])) for e in baseline)
        sev = SEV_INFO
        if changes:
            sev = SEV_NOTICE
        if hiding:
            sev = SEV_WARN
        return Finding(
            check_name="gitignore_hidden_code",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not hiding,
            title="No source files were hidden from git mid-event",
            explanation=(
                f".gitignore changed {len(changes)} time(s); no source files became hidden "
                "as a result." if changes else ".gitignore was not modified during the window."
            ) if not hiding else (
                f"{len(hiding)} .gitignore change(s) newly excluded source files from the "
                "repository. Files excluded this way exist on the participant's disk but "
                "never reach the submitted repo, so the repo-plane analysis cannot see them. "
                "Build output and secrets are the ordinary reason; the file list is below."
            ),
            evidence={
                "changes": [
                    {"seq": e["seq"], "ts": e["ts"], "repo": e["data"].get("repo"),
                     "newly_ignored_code": e["data"].get("newly_ignored_code", [])[:30]}
                    for e in changes[:20]
                ],
                "ignored_code_files_at_start": baseline_ignored,
            },
        )

    def check_gpg_material(self) -> Finding:
        changes = self.k("gpg.changed")
        baseline = self.k("gpg.baseline")
        registered_present = any(e["data"].get("registered_key_present") for e in baseline)
        sev = SEV_INFO
        if changes:
            sev = SEV_CRITICAL
        elif baseline and self.cfg.registered_gpg_fingerprint and not registered_present:
            sev = SEV_WARN
        return Finding(
            check_name="signing_key_stability",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not changes,
            title="Signing key material was unchanged during the event",
            explanation=(
                "The set of secret keys and the git signing configuration were identical "
                "from start to finish."
                if not changes else
                f"Signing material changed {len(changes)} time(s) during the event. Keys "
                "legitimately get created, imported or rotated mid-event; what matters to a "
                "judge is whether commits before and after the change are signed by "
                "different keys, which the commit list above shows."
            ) + ("" if registered_present or not self.cfg.registered_gpg_fingerprint else
                 " The fingerprint registered with the organiser was not present in the "
                 "local keyring at start."),
            evidence={
                "changes": [{"seq": e["seq"], "ts": e["ts"],
                             "fingerprints": e["data"].get("fingerprints", [])}
                            for e in changes[:10]],
                "baseline_fingerprints": (baseline[0]["data"].get("fingerprints")
                                          if baseline else []),
                "registered_fingerprint": self.cfg.registered_gpg_fingerprint,
                "registered_key_present_at_start": registered_present,
            },
        )

    # -- environment ------------------------------------------------------------

    def check_observer_tools(self) -> Finding:
        tools = self.k("process.observer_tool")
        baseline = self.k("process.baseline")
        at_start = baseline[0]["data"].get("observer_tools", []) if baseline else []
        dup = self.k("daemon.duplicate_instance")
        launchd = self.k("integrity.launchd_removed")
        sev = SEV_INFO
        if tools or at_start:
            sev = SEV_NOTICE
        if launchd or dup:
            sev = SEV_CRITICAL
        return Finding(
            check_name="monitoring_environment",
            plane=PLANE_SYSTEM,
            severity=sev,
            passed=not (launchd or dup),
            title="Nothing interfered with the agent",
            explanation=(
                "The agent's launchd job stayed installed, only one instance ran, and no "
                "screen-sharing or remote-control tool was started."
                if sev == SEV_INFO else
                "; ".join(filter(None, [
                    f"{len(tools)} screen-sharing/remote-control/capture tool(s) started "
                    "during the event" if tools else "",
                    f"{len(at_start)} such tool(s) were already running at start" if at_start else "",
                    "the agent's launchd job was removed while it ran" if launchd else "",
                    "more than one agent instance was detected" if dup else "",
                ])) + ". Remote-control software means work could have been done by someone "
                "not at this keyboard; it is context, not an accusation."
            ),
            evidence={
                "started_during_event": [{"seq": e["seq"], "ts": e["ts"],
                                          "comm": e["data"].get("comm")} for e in tools[:20]],
                "running_at_start": at_start[:20],
                "launchd_removed": self.refs(launchd),
                "duplicate_instances": self.refs(dup),
            },
        )

    def check_assistant_context(self) -> Finding:
        """Informational only — never a pass/fail signal."""
        procs = [e for e in self.k("process.started")
                 if any(t in (e["data"].get("comm", "") + e["data"].get("args", "")).lower()
                        for t in ("claude", "copilot", "cursor", "ollama", "aider",
                                  "codex", "gemini", "continue"))]
        focus = [e for e in self.k("focus.changed")
                 if (e["data"].get("app") or "").lower() in
                 ("claude", "chatgpt", "gemini", "copilot", "perplexity", "cursor")]
        clips = [e for e in self.k("clipboard.copy")
                 if e["data"].get("source_category") == "ai_assistant"]
        return Finding(
            check_name="assistant_tooling_context",
            plane=PLANE_SYSTEM,
            severity=SEV_INFO,
            passed=True,
            title="AI assistant usage (context only)",
            explanation=(
                "No AI assistant processes, windows or clipboard sources were observed."
                if not (procs or focus or clips) else
                f"AI tooling was present: {len(procs)} assistant process launch(es), "
                f"{len(focus)} period(s) with an assistant window in the foreground, "
                f"{len(clips)} clipboard copy/copies sourced from one. "
                "Most hackathons permit AI assistance; this check never fails and exists so "
                "the organiser's own rules can be applied to real data instead of guesses."
            ),
            evidence={
                "assistant_processes": [{"seq": e["seq"], "comm": e["data"].get("comm")}
                                        for e in procs[:20]],
                "foreground_periods": len(focus),
                "clipboard_copies_from_assistants": len(clips),
            },
        )


def _commit_ref(c: Dict[str, Any]) -> Dict[str, Any]:
    d = c.get("data", {})
    return {
        "seq": c.get("seq"),
        "observed_at": c.get("ts"),
        "sha": d.get("short"),
        "subject": d.get("subject"),
        "author": f"{d.get('author_name')} <{d.get('author_email')}>",
        "author_date": d.get("author_date"),
        "commit_date": d.get("commit_date"),
        "signature": d.get("signature_meaning"),
        "signing_key": d.get("signing_key"),
        "insertions": d.get("insertions"),
        "deletions": d.get("deletions"),
        "files_changed": d.get("files_changed"),
        "notes": d.get("notes", []),
    }


# --------------------------------------------------------------------------


def build_report(cfg: Config) -> Dict[str, Any]:
    events = list(read_events(cfg.log_path))
    analysis = Analysis(cfg, events)
    findings, coverage = analysis.run()

    counts = Counter(e.get("kind") for e in analysis.events)
    severities = Counter(e.get("severity") for e in analysis.events)
    worst = SEV_INFO
    for f in findings:
        if severity_rank(f.severity) > severity_rank(worst):
            worst = f.severity

    failed = [f for f in findings if not f.passed]
    attention = {
        SEV_INFO: "clear",
        SEV_NOTICE: "notes_for_the_judge",
        SEV_WARN: "needs_human_review",
        SEV_CRITICAL: "significant_questions",
    }[worst]

    notable = [
        {"seq": e.get("seq"), "ts": e.get("ts"), "kind": e.get("kind"),
         "severity": e.get("severity"), "summary": e.get("summary")}
        for e in analysis.events
        if severity_rank(e.get("severity", SEV_INFO)) >= severity_rank(SEV_NOTICE)
    ]

    return {
        "schema": "hacksys.system-report/1",
        "plane": PLANE_SYSTEM,
        "generated_at": iso(),
        "agent": {"name": "hacksys", "version": _version()},
        "participant": {
            "participant_id": cfg.participant_id,
            "participant_name": cfg.participant_name,
            "team_id": cfg.team_id,
            "event_id": cfg.event_id,
            "submission_repo": cfg.submission_repo,
            "consent_recorded_at": cfg.consent_recorded_at,
        },
        "window": {"start": cfg.window_start, "end": cfg.window_end},
        "log": {
            "path": cfg.log_path,
            "events": len(analysis.events),
            "sha256": sha256_file(cfg.log_path),
            "chain_tip": (analysis.events[-1].get("hash") if analysis.events else None),
        },
        "coverage": coverage,
        "counts_by_kind": dict(counts.most_common()),
        "counts_by_severity": dict(severities),
        "findings": [f.to_dict() for f in findings],
        "notable_events": notable[:400],
        "summary": {
            "attention": attention,
            "max_severity": worst,
            "checks_run": len(findings),
            "checks_failed": len(failed),
            "failed_checks": [f.check_name for f in failed],
            "disclaimer": (
                "This report describes observed system activity during the hackathon "
                "window. It is evidence for a human reviewer, not a verdict. No item here "
                "establishes that work was copied, delegated or misattributed; each one "
                "raises a question that the participant can answer."
            ),
        },
    }


def _version() -> str:
    try:
        from . import __version__
        return __version__
    except Exception:  # pragma: no cover
        return "0"
