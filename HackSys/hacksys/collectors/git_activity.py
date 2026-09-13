"""Git collector.

Reads git's own reflogs rather than polling `git log`, so history rewrites are
visible as *events* (a reset, an amend, a force push) instead of being silently
absorbed into the new history. For every commit it records author/committer
identity, both dates, the signature state, and the diffstat.

Nothing here decides that anyone cheated. An amended commit is an amended
commit; the report says so and shows the reflog line it came from.
"""

from __future__ import annotations

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..models import SEV_CRITICAL, SEV_INFO, SEV_NOTICE, SEV_WARN
from ..util import is_code_file, parse_iso, run, sha256_text
from .base import Collector

REFLOG_RE = re.compile(
    r"^(?P<old>[0-9a-f]{40})\s+(?P<new>[0-9a-f]{40})\s+(?P<who>.*?)\s+"
    r"(?P<ts>\d{9,})\s+(?P<tz>[+-]\d{4})\t(?P<msg>.*)$"
)

SIG_MEANING = {
    "G": "good signature",
    "B": "BAD signature",
    "U": "good signature, untrusted key",
    "X": "good signature that has expired",
    "Y": "good signature made by an expired key",
    "R": "good signature made by a revoked key",
    "E": "signature could not be checked",
    "N": "no signature",
}

HISTORY_BASELINE_DETAIL = 25  # historical reflog entries kept as individual events

COMMIT_FMT = "%H%x1f%an%x1f%ae%x1f%cn%x1f%ce%x1f%aI%x1f%cI%x1f%G?%x1f%GK%x1f%GS%x1f%P%x1f%s"


class RepoState:
    def __init__(self, path: str):
        self.path = path
        self.head_reflog_lines = 0
        self.remote_reflog_lines: Dict[str, int] = {}
        self.gitignore_hash: Optional[str] = None
        self.config_hash: Optional[str] = None
        self.fetch_head_mtime: float = 0.0
        self.seen_commits: set[str] = set()
        self.ignored_code: set[str] = set()
        self.bootstrapped = False


class GitCollector(Collector):
    name = "git"

    def __init__(self, ctx):
        super().__init__(ctx)
        self.interval = ctx.cfg.git_interval
        self.repos: Dict[str, RepoState] = {}

    # -- discovery ---------------------------------------------------

    def setup(self) -> None:
        for path in self.cfg.project_paths:
            repo = self._repo_root(path)
            if repo:
                self._register(repo, primary=True)
        if not self.repos:
            self.emit(
                "git.no_repo",
                "no git repository found under the configured project path(s)",
                severity=SEV_WARN,
                project_paths=self.cfg.project_paths,
            )

    def _repo_root(self, path: str) -> Optional[str]:
        if not os.path.isdir(path):
            return None
        rc, out, _ = run(["git", "-C", path, "rev-parse", "--show-toplevel"], timeout=10)
        return out.strip() if rc == 0 and out.strip() else None

    def _register(self, repo: str, primary: bool = False) -> None:
        if repo in self.repos:
            return
        state = RepoState(repo)
        self.repos[repo] = state
        rc, out, _ = run(["git", "-C", repo, "remote", "-v"], timeout=10)
        remotes = sorted({line.split()[1] for line in out.splitlines() if len(line.split()) > 1})
        rc2, head, _ = run(["git", "-C", repo, "rev-parse", "--short", "HEAD"], timeout=10)
        rc3, count, _ = run(["git", "-C", repo, "rev-list", "--count", "HEAD"], timeout=15)
        self.emit(
            "git.repo_registered",
            f"tracking git repository {_display(repo)}"
            + (f" ({remotes[0]})" if remotes else " (no remote)"),
            repo=repo,
            primary=primary,
            remotes=remotes,
            head=head.strip() if rc2 == 0 else None,
            commits_at_start=int(count.strip()) if rc3 == 0 and count.strip().isdigit() else 0,
        )

    # -- main loop ----------------------------------------------------

    def poll(self) -> None:
        # pick up repos the filesystem collector noticed appearing
        try:
            while True:
                self._register(self.ctx.new_repos.popleft())
        except (AttributeError, IndexError):
            pass

        for repo, state in list(self.repos.items()):
            if not os.path.isdir(os.path.join(repo, ".git")):
                continue
            try:
                self._scan_head_reflog(repo, state)
                self._scan_remote_reflogs(repo, state)
                self._scan_fetch(repo, state)
                self._scan_gitignore(repo, state)
                self._scan_config(repo, state)
                state.bootstrapped = True
            except Exception as exc:
                self.error(f"scanning {repo}", exc)

    # -- reflog ---------------------------------------------------------

    def _read_reflog(self, path: str) -> List[Dict[str, Any]]:
        if not os.path.exists(path):
            return []
        entries: List[Dict[str, Any]] = []
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = REFLOG_RE.match(line.rstrip("\n"))
                    if m:
                        entries.append(m.groupdict())
        except OSError:
            return []
        return entries

    def _scan_head_reflog(self, repo: str, state: RepoState) -> None:
        entries = self._read_reflog(os.path.join(repo, ".git", "logs", "HEAD"))
        new = entries[state.head_reflog_lines:]
        first_pass = not state.bootstrapped
        state.head_reflog_lines = len(entries)

        if first_pass:
            # The repo's whole prior history is context, not observation. Summarise
            # it in one event and keep only the tail as individual entries — a repo
            # with 2,000 commits would otherwise flood the log at startup, and the
            # repo plane is what analyses that history properly anyway.
            self._emit_history_baseline(repo, new)
            new = new[-HISTORY_BASELINE_DETAIL:]

        for entry in new:
            self._handle_reflog_entry(repo, state, entry, historical=first_pass)

    def _emit_history_baseline(self, repo: str, entries: List[Dict[str, Any]]) -> None:
        if not entries:
            return
        actions: Dict[str, int] = {}
        for e in entries:
            actions[e["msg"].split(":", 1)[0].strip().split(" (")[0]] = \
                actions.get(e["msg"].split(":", 1)[0].strip().split(" (")[0], 0) + 1
        amends = sum(1 for e in entries if "(amend)" in e["msg"])
        stamps = sorted(int(e["ts"]) for e in entries)
        self.emit(
            "git.history_baseline",
            f"{_display(repo)} already had {len(entries)} reflog entries before "
            f"monitoring began ({actions.get('commit', 0)} commits, {amends} amends) "
            f"— pre-existing history, not observed",
            repo=repo,
            entries=len(entries),
            by_action=actions,
            amends=amends,
            earliest=_stamp(stamps[0]),
            latest=_stamp(stamps[-1]),
            detail_shown=min(len(entries), HISTORY_BASELINE_DETAIL),
        )

    def _handle_reflog_entry(self, repo: str, state: RepoState, entry: Dict[str, Any],
                             historical: bool) -> None:
        msg = entry["msg"]
        old, new = entry["old"], entry["new"]
        when = int(entry["ts"])
        action = msg.split(":", 1)[0].strip()
        # every historical event must read as historical in the timeline, not just
        # carry a flag in its data
        tag = "[pre-existing] " if historical else ""

        if msg.startswith("commit"):
            amended = "(amend)" in msg
            self._emit_commit(repo, new, amended=amended, historical=historical,
                              reflog=msg, prev=old)
            return

        if msg.startswith("clone"):
            self.emit("git.clone", f"{tag}repository cloned: {msg}", severity=SEV_NOTICE,
                      repo=repo, reflog=msg, head=new[:12], historical=historical)
            return

        if msg.startswith("reset"):
            self.emit(
                "git.reset",
                f"{tag}history moved by reset in {_display(repo)}: {msg}",
                severity=SEV_INFO if historical else SEV_WARN,
                repo=repo, reflog=msg, old=old[:12], new=new[:12],
                rewrites_history=not self._is_ancestor(repo, old, new),
                historical=historical,
            )
            return

        if msg.startswith("rebase"):
            self.emit(
                "git.rebase",
                f"{tag}rebase in {_display(repo)}: {msg}",
                severity=SEV_INFO if historical else SEV_WARN,
                repo=repo, reflog=msg, old=old[:12], new=new[:12], historical=historical,
            )
            return

        if msg.startswith(("merge", "pull")):
            self.emit("git.merge", f"{tag}{action} in {_display(repo)}: {msg}",
                      repo=repo, reflog=msg, old=old[:12], new=new[:12], historical=historical)
            return

        if msg.startswith("checkout"):
            self.emit("git.checkout", f"{tag}branch switch in {_display(repo)}: {msg}",
                      repo=repo, reflog=msg, historical=historical)
            return

        self.emit("git.reflog", f"{tag}{action} in {_display(repo)}: {msg}",
                  repo=repo, reflog=msg, old=old[:12], new=new[:12], historical=historical)

    # -- commits ----------------------------------------------------------

    def _emit_commit(self, repo: str, sha: str, amended: bool, historical: bool,
                     reflog: str, prev: str) -> None:
        if sha in state_seen(self.repos[repo]):
            return
        self.repos[repo].seen_commits.add(sha)

        rc, out, _ = run(
            ["git", "-C", repo, "show", "-s", f"--format={COMMIT_FMT}", sha], timeout=15
        )
        if rc != 0 or not out.strip():
            return
        parts = out.strip("\n").split("\x1f")
        if len(parts) < 12:
            return
        (full, an, ae, cn, ce, adate, cdate, gsig, gkey, gsigner, parents, subject) = parts[:12]

        stats = self._diffstat(repo, sha)
        signed = gsig not in ("N", "")
        sig_desc = SIG_MEANING.get(gsig, gsig)

        payload: Dict[str, Any] = {
            "repo": repo,
            "sha": full,
            "short": full[:12],
            "subject": subject,
            "author_name": an,
            "author_email": ae,
            "committer_name": cn,
            "committer_email": ce,
            "author_date": adate,
            "commit_date": cdate,
            "signature_state": gsig,
            "signature_meaning": sig_desc,
            "signing_key": gkey,
            "signer": gsigner,
            "parents": parents.split() if parents else [],
            "amended": amended,
            "reflog": reflog,
            "historical": historical,
            **stats,
        }

        severity = SEV_INFO
        notes: List[str] = []

        if amended:
            severity = SEV_NOTICE if historical else SEV_WARN
            notes.append("amended")

        if self.cfg.require_signed_commits and not signed:
            severity = max(severity, SEV_WARN, key=_sev_key)
            notes.append("unsigned")
        elif gsig in ("B", "R", "E"):
            severity = SEV_CRITICAL
            notes.append(sig_desc)

        fp = self.cfg.registered_gpg_fingerprint.replace(" ", "").upper()
        if fp and gkey and not fp.endswith(gkey.upper()[-16:]):
            severity = SEV_CRITICAL
            notes.append("signed by a key other than the registered one")
            payload["registered_fingerprint"] = fp

        if ae.lower() != ce.lower():
            notes.append("author and committer differ")
            severity = max(severity, SEV_NOTICE, key=_sev_key)

        skew = self._date_skew(adate, cdate)
        payload["author_commit_skew_seconds"] = skew
        if skew is not None and abs(skew) > 3600:
            notes.append("author date is far from commit date")
            severity = max(severity, SEV_WARN, key=_sev_key)

        if not self._within_window(cdate):
            notes.append("committed outside the hackathon window")
            severity = max(severity, SEV_WARN, key=_sev_key)
            payload["outside_window"] = True

        big = (stats.get("insertions", 0) >= self.cfg.bulk_commit_lines
               or stats.get("files_changed", 0) >= self.cfg.bulk_commit_files)
        if big:
            notes.append("large commit")
            severity = max(severity, SEV_NOTICE, key=_sev_key)
            payload["bulk"] = True

        if historical and _sev_key(severity) > _sev_key(SEV_NOTICE):
            # commits that already existed when the agent started are context,
            # not observations — they belong to the repo plane, not this one
            severity = SEV_NOTICE
            payload["severity_capped"] = "pre-existing history, not observed being created"

        payload["notes"] = notes
        summary = (("[pre-existing] " if historical else "") +
            f"commit {full[:8]} “{subject[:70]}” by {an} "
            f"(+{stats.get('insertions', 0)}/-{stats.get('deletions', 0)} "
            f"across {stats.get('files_changed', 0)} file(s)), {sig_desc}"
        )
        if notes:
            summary += " — " + ", ".join(notes)

        self.emit("git.commit", summary, severity=severity, **payload)

    def _diffstat(self, repo: str, sha: str) -> Dict[str, Any]:
        rc, out, _ = run(
            ["git", "-C", repo, "show", "--numstat", "--format=", sha], timeout=20
        )
        files, ins, dels = 0, 0, 0
        paths: List[str] = []
        for line in out.splitlines():
            cols = line.split("\t")
            if len(cols) != 3:
                continue
            files += 1
            if cols[0].isdigit():
                ins += int(cols[0])
            if cols[1].isdigit():
                dels += int(cols[1])
            if len(paths) < 40:
                paths.append(cols[2])
        return {
            "files_changed": files,
            "insertions": ins,
            "deletions": dels,
            "paths": paths,
            "code_files": sum(1 for p in paths if is_code_file(p)),
        }

    def _is_ancestor(self, repo: str, old: str, new: str) -> bool:
        rc, _, _ = run(["git", "-C", repo, "merge-base", "--is-ancestor", old, new], timeout=10)
        return rc == 0

    @staticmethod
    def _date_skew(adate: str, cdate: str) -> Optional[int]:
        try:
            return int((parse_iso(cdate) - parse_iso(adate)).total_seconds())
        except Exception:
            return None

    def _within_window(self, cdate: str) -> bool:
        try:
            when = parse_iso(cdate)
        except Exception:
            return True
        start, end = self.cfg.window()
        return start <= when <= end

    # -- push / fetch ------------------------------------------------------

    def _scan_remote_reflogs(self, repo: str, state: RepoState) -> None:
        base = os.path.join(repo, ".git", "logs", "refs", "remotes")
        if not os.path.isdir(base):
            return
        for dirpath, _dirnames, filenames in os.walk(base):
            for fn in filenames:
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, base)
                entries = self._read_reflog(path)
                seen = state.remote_reflog_lines.get(rel, 0)
                new = entries[seen:]
                first_pass = rel not in state.remote_reflog_lines and not state.bootstrapped
                state.remote_reflog_lines[rel] = len(entries)
                if first_pass:
                    if len(new) > HISTORY_BASELINE_DETAIL:
                        self.emit(
                            "git.push_history_baseline",
                            f"{rel} in {_display(repo)} already had {len(new)} push(es) "
                            "before monitoring began — pre-existing history, not observed",
                            repo=repo, ref=rel, pushes=len(new),
                            detail_shown=HISTORY_BASELINE_DETAIL,
                        )
                    new = new[-HISTORY_BASELINE_DETAIL:]
                for entry in new:
                    forced = not self._is_ancestor(repo, entry["old"], entry["new"]) \
                        and not entry["old"].startswith("0" * 20)
                    kind = "git.force_push" if forced else "git.push"
                    self.emit(
                        kind,
                        f"{'[pre-existing] ' if first_pass else ''}"
                        f"{'force-' if forced else ''}push to {rel} in {_display(repo)}"
                        f" ({entry['old'][:8]} → {entry['new'][:8]})",
                        severity=SEV_CRITICAL if forced and not first_pass else SEV_NOTICE,
                        repo=repo, ref=rel, old=entry["old"][:12], new=entry["new"][:12],
                        reflog=entry["msg"], forced=forced, historical=first_pass,
                    )

    def _scan_fetch(self, repo: str, state: RepoState) -> None:
        path = os.path.join(repo, ".git", "FETCH_HEAD")
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            return
        if state.fetch_head_mtime == 0.0:
            state.fetch_head_mtime = mtime
            return
        if mtime > state.fetch_head_mtime:
            state.fetch_head_mtime = mtime
            head = ""
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    head = fh.readline().strip()[:200]
            except OSError:
                pass
            self.emit("git.fetch", f"fetch/pull in {_display(repo)}",
                      repo=repo, fetch_head=head)

    # -- .gitignore and config -------------------------------------------------

    def _scan_gitignore(self, repo: str, state: RepoState) -> None:
        path = os.path.join(repo, ".gitignore")
        content = ""
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    content = fh.read()
            except OSError:
                return
        digest = sha256_text(content)
        first = state.gitignore_hash is None
        if digest == state.gitignore_hash:
            return
        previous = state.gitignore_hash
        state.gitignore_hash = digest

        ignored = self._ignored_code_files(repo)
        newly = sorted(set(ignored) - state.ignored_code)
        state.ignored_code = set(ignored)

        if first:
            self.emit(
                "git.gitignore_baseline",
                f"{_display(repo)} starts with {len(content.splitlines())} .gitignore rule(s), "
                f"{len(ignored)} ignored code file(s) on disk",
                repo=repo, rules=len(content.splitlines()),
                ignored_code_files=ignored[:50], sha256=digest,
            )
            return

        self.emit(
            "git.gitignore_changed",
            f".gitignore changed in {_display(repo)}"
            + (f" — {len(newly)} code file(s) newly hidden from git" if newly else ""),
            severity=SEV_WARN if newly else SEV_NOTICE,
            repo=repo, sha256=digest, previous_sha256=previous,
            rules=len(content.splitlines()),
            newly_ignored_code=newly[:50],
            ignored_code_count=len(ignored),
        )

    def _ignored_code_files(self, repo: str) -> List[str]:
        rc, out, _ = run(
            ["git", "-C", repo, "ls-files", "--others", "--ignored", "--exclude-standard"],
            timeout=25,
        )
        if rc != 0:
            return []
        files = [p for p in out.splitlines() if p and is_code_file(p)]
        return files[:500]

    def _scan_config(self, repo: str, state: RepoState) -> None:
        keys = ["user.name", "user.email", "user.signingkey", "commit.gpgsign",
                "gpg.format", "gpg.program", "core.hooksPath"]
        values: Dict[str, str] = {}
        for key in keys:
            rc, out, _ = run(["git", "-C", repo, "config", "--get", key], timeout=8)
            values[key] = out.strip() if rc == 0 else ""
        digest = sha256_text(repr(sorted(values.items())))
        if state.config_hash is None:
            state.config_hash = digest
            self.emit(
                "git.config_baseline",
                f"git identity for {_display(repo)}: {values['user.name']} "
                f"<{values['user.email']}>, signing="
                f"{values['commit.gpgsign'] or 'off'}",
                repo=repo, config=values,
            )
            return
        if digest != state.config_hash:
            state.config_hash = digest
            self.emit(
                "git.config_changed",
                f"git identity/signing config changed in {_display(repo)}",
                severity=SEV_WARN, repo=repo, config=values,
            )


def state_seen(state: RepoState) -> set:
    return state.seen_commits


def _sev_key(s: str) -> int:
    from ..models import severity_rank
    return severity_rank(s)


def _stamp(unix_ts: int) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(unix_ts, timezone.utc).isoformat(timespec="seconds")


def _display(path: str) -> str:
    home = os.path.expanduser("~")
    return path.replace(home, "~", 1) if path.startswith(home) else path
