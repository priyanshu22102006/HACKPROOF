"""Context Correlator: builds the EvidenceGraph and runs Rules 1-7 to produce CorrelationChains."""

from __future__ import annotations

import os
from collections import defaultdict
from typing import Any

from core.context.graph import EdgeType, EvidenceGraph, NodeType
from core.context.models import CorrelationChain, EvidenceItem, EvidenceType

BENIGN_EXTENSIONS = {
    ".lock", ".log", ".json", ".map", ".min.js", ".min.css", ".ico",
    ".png", ".jpg", ".jpeg", ".svg", ".gif", ".woff", ".woff2", ".ttf",
    ".pyc", ".pyd", ".env", ".env.local", ".env.example", ".example"
}
BENIGN_DIRS = {
    "node_modules", "dist", "build", "__pycache__", ".next", ".nuxt",
    ".git", ".venv", "venv", "env", "coverage", ".cache", ".idea", ".vscode"
}
SOURCE_EXTENSIONS = {
    ".py", ".ts", ".js", ".tsx", ".jsx", ".go", ".rs", ".java", ".c",
    ".cpp", ".h", ".cs", ".rb", ".php", ".swift", ".kt", ".scala", ".sh"
}


def is_benign_file(path: str) -> bool:
    """Return True if path looks like a standard build artifact, config, or vendor file."""
    norm = path.replace("\\", "/").strip("/")
    parts = norm.split("/")
    # If any parent directory is a known build/vendor directory
    for p in parts[:-1]:
        if p in BENIGN_DIRS:
            return True
    filename = parts[-1]
    if filename.startswith(".") or filename.endswith(".min.js") or filename.endswith(".min.css"):
        return True
    ext = os.path.splitext(filename)[1].lower()
    return ext in BENIGN_EXTENSIONS


def is_source_file(path: str) -> bool:
    """Return True if path looks like a real source code file."""
    norm = path.replace("\\", "/").strip("/")
    parts = norm.split("/")
    # Build directories take precedence
    for p in parts[:-1]:
        if p in BENIGN_DIRS:
            return False
    filename = parts[-1]
    if filename.endswith(".min.js") or filename.endswith(".min.css") or filename.startswith("."):
        return False
    ext = os.path.splitext(filename)[1].lower()
    return ext in SOURCE_EXTENSIONS or "/src/" in path or path.startswith("src/")


class ContextCorrelator:
    """Correlates isolated findings into narrative evidence chains using an EvidenceGraph."""

    def __init__(self) -> None:
        self.graph = EvidenceGraph()
        self._chain_counter = 0

    def _next_chain_id(self) -> str:
        self._chain_counter += 1
        return f"CHAIN_{self._chain_counter:03d}"

    def build_graph(self, items: list[EvidenceItem]) -> EvidenceGraph:
        """Populate the EvidenceGraph from normalized EvidenceItems."""
        g = self.graph
        for item in items:
            # 1. Add File node
            if item.file:
                file_id = f"file:{item.file}"
                g.add_node(file_id, NodeType.FILE, {"path": item.file})

            # 2. Add Commit node
            if item.commit:
                commit_id = f"commit:{item.commit}"
                g.add_node(commit_id, NodeType.COMMIT, {"sha": item.commit})

            # 3. Add Author / Email node
            if item.author or item.email:
                author_id = f"author:{item.email or item.author}"
                g.add_node(author_id, NodeType.AUTHOR, {"name": item.author, "email": item.email})

            # 4. Add Edges based on available entities
            if item.file and item.commit:
                g.add_edge(f"commit:{item.commit}", f"file:{item.file}", EdgeType.INTRODUCED_BY, {"evidence_id": item.evidence_id})
            if item.commit and (item.author or item.email):
                g.add_edge(f"commit:{item.commit}", f"author:{item.email or item.author}", EdgeType.AUTHORED_BY, {"evidence_id": item.evidence_id})

            # 5. Add specific typed relationships
            if item.type == EvidenceType.SIMILARITY.value and isinstance(item.value, dict):
                match_id = f"ext:{item.value.get('matched_repo')}/{item.value.get('matched_file')}"
                g.add_node(match_id, NodeType.SIMILARITY_CANDIDATE, item.value)
                if item.file:
                    g.add_edge(f"file:{item.file}", match_id, EdgeType.MATCHES, {"score": item.value.get("score")})

            elif item.type == EvidenceType.SIGNATURE.value and isinstance(item.value, dict):
                signer = item.value.get("signer")
                if signer:
                    key_id = f"key:{signer}"
                    g.add_node(key_id, NodeType.KEY, item.value)
                    if item.commit:
                        g.add_edge(f"commit:{item.commit}", key_id, EdgeType.SIGNED_BY, item.value)

            elif item.type == EvidenceType.TIMESTAMP.value and item.timestamp:
                ts_id = f"ts:{item.timestamp}"
                g.add_node(ts_id, NodeType.TIMESTAMP, {"iso": item.timestamp})
                if item.commit:
                    g.add_edge(f"commit:{item.commit}", ts_id, EdgeType.OCCURRED_AT, {"evidence_id": item.evidence_id})

        return g

    def correlate(self, items: list[EvidenceItem]) -> list[CorrelationChain]:
        """Execute Rules 1-7 and produce correlated narrative chains with anti-double-counting."""
        self.build_graph(items)
        chains: list[CorrelationChain] = []
        consumed_item_ids: set[str] = set()

        # Group items by file, by commit, and unattached
        by_file: dict[str, list[EvidenceItem]] = defaultdict(list)
        by_commit: dict[str, list[EvidenceItem]] = defaultdict(list)

        for item in items:
            if item.file:
                by_file[item.file].append(item)
            if item.commit:
                by_commit[item.commit].append(item)

        # -------------------------------------------------------------
        # RULE 1 & 2 & 7: Similarity + Pre-hackathon source + Blame (File-level correlation)
        # -------------------------------------------------------------
        for file_path, file_items in by_file.items():
            sim_items = [i for i in file_items if i.type == EvidenceType.SIMILARITY.value]
            if not sim_items:
                continue

            for sim in sim_items:
                chain_items = [sim]
                val = sim.value if isinstance(sim.value, dict) else {}
                score = val.get("score", 0.0)
                matched_repo = val.get("matched_repo", "unknown")
                matched_file = val.get("matched_file", "unknown")
                matched_date = val.get("matched_repo_date")

                # Check if blamed or concealed or pre-t0
                blame_items = [i for i in file_items if i.type in (EvidenceType.BLAME.value, EvidenceType.TRACKING.value) and i.evidence_id != sim.evidence_id]
                chain_items.extend(blame_items)

                # Connect associated commit timestamp / identity items
                commit_sha = sim.commit or (blame_items[0].commit if blame_items else None)
                if commit_sha and commit_sha in by_commit:
                    for ci in by_commit[commit_sha]:
                        if ci not in chain_items:
                            chain_items.append(ci)

                # Check rule conditions
                has_pre_hackathon = bool(matched_date)
                rule_name = "Rule 1: Similarity + Pre-hackathon source" if has_pre_hackathon else "Rule 2: Similarity + Blame attribution"
                severity = "hard_flag" if (has_pre_hackathon and score >= 0.75) else ("flag" if score >= 0.6 else "info")
                badge = "CONCERN" if severity in ("flag", "hard_flag") else "WARNING"

                narrative: list[str] = [
                    f"[FILE] {file_path}",
                    f"  ├── Similarity Match: {int(score * 100)}% identical to {matched_repo}/{matched_file}",
                ]
                if matched_date:
                    narrative.append(f"  │   └── External Source Date: {matched_date} (Predates hackathon window)")
                if commit_sha:
                    narrative.append(f"  ├── Introduced in Commit: {commit_sha[:7]}")
                for bi in blame_items:
                    narrative.append(f"  ├── Concealment Signal: {bi.message}")

                chain = CorrelationChain(
                    chain_id=self._next_chain_id(),
                    title=f"Code Provenance Match: {file_path}",
                    severity=severity,
                    root_entity=file_path,
                    items=chain_items,
                    narrative=narrative,
                    rule=rule_name,
                    confidence="HIGH" if score >= 0.8 else "MEDIUM",
                    status_badge=badge,
                )
                chains.append(chain)
                for ci in chain_items:
                    consumed_item_ids.add(ci.evidence_id)

        # -------------------------------------------------------------
        # RULE 4: Hidden Tracking + File Concealment (Distinguish benign build artifacts)
        # -------------------------------------------------------------
        for file_path, file_items in by_file.items():
            tracking_items = [i for i in file_items if i.evidence_id not in consumed_item_ids and i.type == EvidenceType.TRACKING.value]
            if not tracking_items:
                continue

            benign = is_benign_file(file_path)
            is_src = is_source_file(file_path)

            chain_items = list(tracking_items)
            # Find any associated commit
            commit_sha = tracking_items[0].commit
            if commit_sha and commit_sha in by_commit:
                for ci in by_commit[commit_sha]:
                    if ci.evidence_id not in consumed_item_ids and ci not in chain_items:
                        chain_items.append(ci)

            if benign and not is_src:
                severity = "info"
                badge = "CLEAN"
                title = f"Standard Build / Env Artifact Ignored: {file_path}"
                desc = "Benign tooling or environment file matching .gitignore rules (expected practice)."
            else:
                severity = "flag"
                badge = "WARNING"
                title = f"Source File Concealment / Index Manipulation: {file_path}"
                desc = "Source code file concealed via gitignore or index flags without standard build rationale."

            narrative = [
                f"[FILE] {file_path}",
                f"  ├── Classification: {'BENIGN BUILD ARTIFACT' if benign and not is_src else 'ACTIVE SOURCE CONCEALMENT'}",
            ]
            for ti in tracking_items:
                narrative.append(f"  ├── Rule/Flag: {ti.message}")
            if commit_sha:
                narrative.append(f"  └── Rule Origin Commit: {commit_sha[:7]} by {tracking_items[0].author or 'unknown'}")

            chain = CorrelationChain(
                chain_id=self._next_chain_id(),
                title=title,
                severity=severity,
                root_entity=file_path,
                items=chain_items,
                narrative=narrative,
                rule="Rule 4: Hidden tracking + File analysis",
                confidence="HIGH",
                status_badge=badge,
            )
            chains.append(chain)
            for ci in chain_items:
                consumed_item_ids.add(ci.evidence_id)

        # -------------------------------------------------------------
        # RULE 3 & 5 & 6: Identity, Signatures, Timeline, GitHub Correlation per Commit
        # -------------------------------------------------------------
        for commit_sha, commit_items in by_commit.items():
            unconsumed = [i for i in commit_items if i.evidence_id not in consumed_item_ids]
            if not unconsumed:
                continue

            # Check if this commit has identity mismatch or unregistered key
            id_items = [i for i in unconsumed if i.type == EvidenceType.IDENTITY.value]
            sig_items = [i for i in unconsumed if i.type == EvidenceType.SIGNATURE.value]
            time_items = [i for i in unconsumed if i.type == EvidenceType.TIMESTAMP.value]
            gh_items = [i for i in unconsumed if i.type == EvidenceType.GITHUB.value]

            if not (id_items or sig_items or time_items or gh_items):
                continue

            chain_items = id_items + sig_items + time_items + gh_items
            rules_triggered = []
            if id_items:
                rules_triggered.append("Rule 3: Identity & Signer correlation")
            if time_items:
                rules_triggered.append("Rule 5: Timeline anomaly correlation")
            if gh_items:
                rules_triggered.append("Rule 6: GitHub remote sync correlation")
            if len(rules_triggered) > 1:
                rules_triggered.append("Rule 7: Multi-signal correlation")

            worst_sev = "info"
            for ci in chain_items:
                if ci.severity == "hard_flag":
                    worst_sev = "hard_flag"
                    break
                elif ci.severity == "flag":
                    worst_sev = "flag"

            badge = "CONCERN" if worst_sev == "hard_flag" else ("WARNING" if worst_sev == "flag" else "VERIFIED")

            author_str = chain_items[0].author or chain_items[0].email or "Unknown Author"
            narrative = [
                f"[COMMIT] {commit_sha[:7]} ({author_str})",
            ]
            for item in chain_items:
                narrative.append(f"  ├── [{item.type.upper()}] {item.message}")

            chain = CorrelationChain(
                chain_id=self._next_chain_id(),
                title=f"Commit Integrity Analysis: {commit_sha[:7]}",
                severity=worst_sev,
                root_entity=f"Commit {commit_sha[:7]}",
                items=chain_items,
                narrative=narrative,
                rule="; ".join(rules_triggered) if rules_triggered else "Rule 7: Multi-signal grouping",
                confidence="HIGH",
                status_badge=badge,
            )
            chains.append(chain)
            for ci in chain_items:
                consumed_item_ids.add(ci.evidence_id)

        # -------------------------------------------------------------
        # Remaining Isolated Items (No double counting, preserve single standalone findings)
        # -------------------------------------------------------------
        remaining = [i for i in items if i.evidence_id not in consumed_item_ids]
        for rem in remaining:
            badge = "CONCERN" if rem.severity == "hard_flag" else ("WARNING" if rem.severity == "flag" else "INFO")
            chain = CorrelationChain(
                chain_id=self._next_chain_id(),
                title=f"Independent Finding: {rem.source or rem.type}",
                severity=rem.severity,
                root_entity=rem.file or (f"Commit {rem.commit[:7]}" if rem.commit else (rem.source or "System")),
                items=[rem],
                narrative=[
                    f"[{rem.type.upper()}] {rem.message}",
                    f"  └── Source: {rem.source} (Severity: {rem.severity})",
                ],
                rule="Standalone Evidence",
                confidence=rem.confidence,
                status_badge=badge,
            )
            chains.append(chain)
            consumed_item_ids.add(rem.evidence_id)

        return chains
