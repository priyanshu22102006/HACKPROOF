"""Normalizer: converts raw Finding objects, blame view entries, and similarity hits into EvidenceItems."""

from __future__ import annotations

from typing import Any

from core.context.models import EvidenceItem, EvidenceType
from core.models import Finding


class EvidenceNormalizer:
    """Transforms heterogeneous analyzer outputs into unified EvidenceItem records."""

    def __init__(self, repository: str = "target_repo") -> None:
        self.repository = repository
        self._item_counter = 0

    def _next_id(self, prefix: str = "ev") -> str:
        self._item_counter += 1
        return f"{prefix}_{self._item_counter:03d}"

    def normalize(
        self,
        findings: list[Finding],
        blame_entries: list[Any] | None = None,
        similarity_matches: list[dict[str, Any]] | None = None,
    ) -> list[EvidenceItem]:
        """Normalize all available inputs into a flat list of EvidenceItem objects."""
        items: list[EvidenceItem] = []

        # 1. Normalize Findings
        for finding in findings:
            items.extend(self._normalize_finding(finding))

        # 2. Normalize Blame entries (e.g. from get_gitignore_blame_view)
        if blame_entries:
            for entry in blame_entries:
                items.extend(self._normalize_blame_entry(entry))

        # 3. Normalize Similarity matches (if passed directly or in findings)
        if similarity_matches:
            for match in similarity_matches:
                items.append(self._normalize_similarity_match(match))

        return items

    def _normalize_finding(self, finding: Finding) -> list[EvidenceItem]:
        ev = finding.evidence if isinstance(finding.evidence, dict) else {}
        # Ignore unevaluable findings to prevent clone-safety false positives
        if ev.get("evaluable") is False:
            return []

        name = finding.check_name
        items: list[EvidenceItem] = []

        # --- GPG Findings ---
        if name.startswith("gpg."):
            items.extend(self._normalize_gpg_finding(finding, ev))

        # --- Gitignore Findings ---
        elif name.startswith("gitignore."):
            items.extend(self._normalize_gitignore_finding(finding, ev))

        # --- Claim / Timestamp Findings ---
        elif name.startswith("claim."):
            items.extend(self._normalize_claim_finding(finding, ev))

        # --- GitHub Findings ---
        elif name.startswith("github."):
            items.extend(self._normalize_github_finding(finding, ev))

        # --- Generic Finding Fallback ---
        else:
            items.append(
                EvidenceItem(
                    evidence_id=self._next_id("ev_finding"),
                    type="finding",
                    severity=finding.severity,
                    repository=self.repository,
                    source=name,
                    value=ev,
                    confidence="HIGH" if not finding.passed else "LOW",
                    message=ev.get("reason") or ev.get("note") or f"{name} passed={finding.passed}",
                )
            )

        return items

    def _normalize_gpg_finding(self, finding: Finding, ev: dict[str, Any]) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        name = finding.check_name

        if name == "gpg.signatures":
            # Per-commit signature verification
            signatures = ev.get("signatures", [])
            for sig in signatures:
                commit = sig.get("commit")
                valid = sig.get("valid", False)
                signer = sig.get("signer")
                author_email = sig.get("author_email")
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_gpg"),
                        type=EvidenceType.SIGNATURE.value,
                        severity="info" if valid else ("hard_flag" if finding.severity == "hard_flag" else "flag"),
                        repository=self.repository,
                        commit=commit,
                        email=author_email,
                        source=name,
                        value={"signer": signer, "valid": valid, "status": sig.get("status")},
                        confidence="HIGH",
                        message=f"Commit {commit[:7] if commit else ''} signature valid={valid} by {signer or 'unknown'}",
                    )
                )

        elif name == "gpg.identity_mismatch":
            mismatches = ev.get("mismatches", [])
            for m in mismatches:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_identity"),
                        type=EvidenceType.IDENTITY.value,
                        severity=finding.severity,
                        repository=self.repository,
                        commit=m.get("commit"),
                        author=m.get("author"),
                        email=m.get("author_email") or m.get("email"),
                        source=name,
                        value=m,
                        confidence="HIGH",
                        message=f"Signer {m.get('signer')} does not match commit author {m.get('author')}",
                    )
                )

        elif name == "gpg.unregistered_signers":
            unreg = ev.get("unregistered_signers", [])
            commits = ev.get("commits", [])
            if unreg or commits:
                for c in commits:
                    items.append(
                        EvidenceItem(
                            evidence_id=self._next_id("ev_unreg"),
                            type=EvidenceType.IDENTITY.value,
                            severity=finding.severity,
                            repository=self.repository,
                            commit=c if isinstance(c, str) else c.get("commit"),
                            author=c.get("author") if isinstance(c, dict) else None,
                            source=name,
                            value={"unregistered_signers": unreg},
                            confidence="HIGH",
                            message=f"Unregistered GPG key used on commit {c if isinstance(c, str) else c.get('commit')}",
                        )
                    )

        elif name == "gpg.signature_coverage":
            cov = ev.get("coverage", 1.0)
            items.append(
                EvidenceItem(
                    evidence_id=self._next_id("ev_gpg_cov"),
                    type=EvidenceType.SIGNATURE.value,
                    severity=finding.severity,
                    repository=self.repository,
                    source=name,
                    value={"coverage": cov, "signed_count": ev.get("signed_count"), "total_count": ev.get("total_count")},
                    confidence="HIGH",
                    message=f"Commit signature coverage: {cov * 100:.1f}%",
                )
            )

        else:
            items.append(
                EvidenceItem(
                    evidence_id=self._next_id("ev_gpg"),
                    type=EvidenceType.SIGNATURE.value,
                    severity=finding.severity,
                    repository=self.repository,
                    source=name,
                    value=ev,
                    confidence="HIGH",
                    message=ev.get("reason") or ev.get("note") or f"{name} check",
                )
            )

        return items

    def _normalize_gitignore_finding(self, finding: Finding, ev: dict[str, Any]) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        name = finding.check_name

        if name == "gitignore.hidden_tracked_files":
            tracked_hidden = ev.get("tracked_hidden", [])
            for th in tracked_hidden:
                path = th.get("path") if isinstance(th, dict) else th
                rule = th.get("rule") if isinstance(th, dict) else None
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_track"),
                        type=EvidenceType.TRACKING.value,
                        severity=finding.severity,
                        repository=self.repository,
                        file=path,
                        source=name,
                        value={"rule": rule},
                        confidence="HIGH",
                        message=f"Tracked file {path} matches gitignore rule: {rule}",
                    )
                )

        elif name == "gitignore.pattern_audit":
            suspicious = ev.get("suspicious_patterns", [])
            for pat in suspicious:
                path = pat.get("pattern") if isinstance(pat, dict) else pat
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_track"),
                        type=EvidenceType.TRACKING.value,
                        severity=finding.severity,
                        repository=self.repository,
                        file=path,
                        source=name,
                        value={"pattern": path},
                        confidence="HIGH",
                        message=f"Suspicious gitignore pattern: {path}",
                    )
                )

        elif name in ("gitignore.assume_unchanged", "gitignore.skip_worktree"):
            files = ev.get("files", [])
            for f in files:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_index"),
                        type=EvidenceType.TRACKING.value,
                        severity=finding.severity,
                        repository=self.repository,
                        file=f,
                        source=name,
                        value={"index_flag": name.split(".")[-1]},
                        confidence="HIGH",
                        message=f"Git index manipulation flag ({name.split('.')[-1]}) on {f}",
                    )
                )

        else:
            items.append(
                EvidenceItem(
                    evidence_id=self._next_id("ev_gi"),
                    type=EvidenceType.TRACKING.value,
                    severity=finding.severity,
                    repository=self.repository,
                    source=name,
                    value=ev,
                    confidence="HIGH",
                    message=ev.get("reason") or ev.get("note") or f"{name} check",
                )
            )

        return items

    def _normalize_claim_finding(self, finding: Finding, ev: dict[str, Any]) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        name = finding.check_name

        if name == "claim.build_window":
            before_t0 = ev.get("commits_before_t0", [])
            t0 = ev.get("t0")
            for c in before_t0:
                sha = c.get("commit") if isinstance(c, dict) else c
                committed_at = c.get("committed_at") if isinstance(c, dict) else None
                author = c.get("author") if isinstance(c, dict) else None
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_time"),
                        type=EvidenceType.TIMESTAMP.value,
                        severity=finding.severity,
                        repository=self.repository,
                        commit=sha,
                        author=author,
                        timestamp=committed_at,
                        source=name,
                        value={"t0": t0, "committed_at": committed_at},
                        confidence="HIGH",
                        message=f"Commit {sha[:7] if sha else ''} predates hackathon start time T0 ({t0})",
                    )
                )

        elif name == "claim.author_committer_delta":
            deltas = ev.get("large_deltas", [])
            for d in deltas:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_time"),
                        type=EvidenceType.TIMESTAMP.value,
                        severity=finding.severity,
                        repository=self.repository,
                        commit=d.get("commit"),
                        author=d.get("author"),
                        timestamp=d.get("committer_date"),
                        source=name,
                        value=d,
                        confidence="HIGH",
                        message=f"Commit {d.get('commit', '')[:7]} has large author/committer delta: {d.get('delta_hours')}h",
                    )
                )

        elif name == "claim.future_dating":
            future_commits = ev.get("future_commits", [])
            for fc in future_commits:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_time"),
                        type=EvidenceType.TIMESTAMP.value,
                        severity=finding.severity,
                        repository=self.repository,
                        commit=fc.get("commit") if isinstance(fc, dict) else fc,
                        source=name,
                        value=fc if isinstance(fc, dict) else {"commit": fc},
                        confidence="HIGH",
                        message=f"Future-dated commit: {fc.get('commit', '')[:7] if isinstance(fc, dict) else str(fc)[:7]}",
                    )
                )

        else:
            items.append(
                EvidenceItem(
                    evidence_id=self._next_id("ev_time"),
                    type=EvidenceType.TIMESTAMP.value,
                    severity=finding.severity,
                    repository=self.repository,
                    source=name,
                    value=ev,
                    confidence="HIGH",
                    message=ev.get("reason") or ev.get("note") or f"{name} check",
                )
            )

        return items

    def _normalize_github_finding(self, finding: Finding, ev: dict[str, Any]) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []
        name = finding.check_name

        if name == "github.local_crosscheck":
            unpushed = ev.get("missing_server_in_local") or ev.get("unpushed_commits") or []
            missing_local = ev.get("missing_local_in_server") or []
            for up in unpushed:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_gh"),
                        type=EvidenceType.GITHUB.value,
                        severity=finding.severity,
                        repository=self.repository,
                        commit=up.get("commit") if isinstance(up, dict) else up,
                        source=name,
                        value={"unpushed": True},
                        confidence="HIGH",
                        message=f"Commit {str(up)[:7]} exists locally but not in remote GitHub repository",
                    )
                )
            for ml in missing_local:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_gh"),
                        type=EvidenceType.GITHUB.value,
                        severity=finding.severity,
                        repository=self.repository,
                        commit=ml.get("commit") if isinstance(ml, dict) else ml,
                        source=name,
                        value={"missing_local": True},
                        confidence="HIGH",
                        message=f"Commit {str(ml)[:7]} exists on GitHub but not in local clone",
                    )
                )

        elif name == "github.force_push_detection":
            force_pushes = ev.get("force_pushes", [])
            for fp in force_pushes:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_gh"),
                        type=EvidenceType.GITHUB.value,
                        severity=finding.severity,
                        repository=self.repository,
                        commit=fp.get("after") if isinstance(fp, dict) else None,
                        source=name,
                        value=fp if isinstance(fp, dict) else {"event": fp},
                        confidence="HIGH",
                        message=f"Force push event detected on GitHub: {fp}",
                    )
                )

        else:
            items.append(
                EvidenceItem(
                    evidence_id=self._next_id("ev_gh"),
                    type=EvidenceType.GITHUB.value,
                    severity=finding.severity,
                    repository=self.repository,
                    source=name,
                    value=ev,
                    confidence="HIGH",
                    message=ev.get("reason") or ev.get("note") or f"{name} check",
                )
            )

        return items

    def _normalize_blame_entry(self, entry: Any) -> list[EvidenceItem]:
        items: list[EvidenceItem] = []

        # entry could be a GitignoreBlameEntry or dict
        if hasattr(entry, "to_dict"):
            d = entry.to_dict()
        elif isinstance(entry, dict):
            d = entry
        else:
            d = {
                "pattern": getattr(entry, "pattern", ""),
                "gitignore_path": getattr(entry, "gitignore_path", ""),
                "sha": getattr(entry, "sha", ""),
                "author": getattr(entry, "author", ""),
                "author_email": getattr(entry, "author_email", ""),
                "committed_at": getattr(entry, "committed_at", ""),
                "classification": getattr(entry, "classification", ""),
                "hidden_files": getattr(entry, "hidden_files", []),
            }

        classification = d.get("classification", "")
        hidden_files = d.get("hidden_files", [])
        pattern = d.get("pattern", "")
        sha = d.get("sha", "")
        author = d.get("author", "")
        email = d.get("author_email", "")
        committed_at = d.get("committed_at", "")

        # Only generate tracking evidence if it's active concealment or suspicious
        if classification == "ACTIVE CONCEALMENT" or hidden_files:
            for hf in hidden_files:
                items.append(
                    EvidenceItem(
                        evidence_id=self._next_id("ev_blame_conceal"),
                        type=EvidenceType.TRACKING.value,
                        severity="flag",
                        repository=self.repository,
                        file=hf,
                        commit=sha,
                        author=author,
                        email=email,
                        timestamp=committed_at,
                        source="gitignore.blame",
                        value={"pattern": pattern, "classification": classification},
                        confidence="HIGH",
                        message=f"Concealed file {hf} hidden by '{pattern}' committed by {author} ({sha})",
                    )
                )
        elif classification == "SUSPICIOUS":
            items.append(
                EvidenceItem(
                    evidence_id=self._next_id("ev_blame_susp"),
                    type=EvidenceType.TRACKING.value,
                    severity="info",
                    repository=self.repository,
                    file=pattern,
                    commit=sha,
                    author=author,
                    email=email,
                    timestamp=committed_at,
                    source="gitignore.blame",
                    value={"pattern": pattern, "classification": classification},
                    confidence="MEDIUM",
                    message=f"Suspicious .gitignore pattern '{pattern}' added by {author} ({sha})",
                )
            )

        return items

    def _normalize_similarity_match(self, match: dict[str, Any]) -> EvidenceItem:
        file = match.get("file") or match.get("local_file")
        matched_repo = match.get("matched_repo") or match.get("external_repo")
        matched_file = match.get("matched_file") or match.get("external_file")
        score = match.get("score") or match.get("similarity_ratio", 0.0)
        repo_date = match.get("matched_repo_date") or match.get("external_repo_date")
        commit = match.get("commit")

        return EvidenceItem(
            evidence_id=self._next_id("ev_sim"),
            type=EvidenceType.SIMILARITY.value,
            severity="flag" if score >= 0.7 else "info",
            repository=self.repository,
            file=file,
            commit=commit,
            source="similarity.ngram_minhash",
            value={
                "matched_repo": matched_repo,
                "matched_file": matched_file,
                "score": score,
                "matched_repo_date": repo_date,
            },
            confidence="HIGH" if score >= 0.85 else "MEDIUM",
            message=f"{file} matches {matched_repo}/{matched_file} with {int(score * 100)}% similarity",
        )
