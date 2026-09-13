# HACKPROOF — Hackathon Build-Provenance & Integrity Platform
### Project Ideation & Technical Specification — v1.1

This document is the single source of truth for the project. It is written so that any engineer or AI coding agent can pick up a section and start implementing without needing the rest of the conversation history that produced it.

---

## 1. One-line summary

HACKPROOF is a tool that answers two questions about any hackathon submission, with evidence instead of suspicion: **(1) was this built inside the official window, and (2) was it built only by the registered team.** It works by comparing the same fact — timing, authorship — across three independent sources that a participant cannot all forge at once, and it hands judges a scored, evidence-linked report instead of an accusation.

---

## 2. Problem statement

Hackathon judging currently rewards the *artifact* — the final repo and a five-minute demo — while having almost no visibility into the *process* that produced it. From that narrow view, judges must infer facts they cannot verify:

- Was this written during the event, or pulled from a pre-existing project?
- Did the whole registered team write it, or did an outside person (or a copied private key) contribute?
- Is a quiet team member actually contributing, or only merging/pulling?

Manual repo review is slow, inconsistent between judges, and trivially defeated by anyone who understands git. HACKPROOF replaces manual suspicion with a structured, auditable evidence trail.

---

## 3. Goals and non-goals

### In scope — two verdicts

- **V1 — Build Window Verdict:** was the codebase authored inside `[T0, T1]` (event start/end), or does evidence show it existed, or was substantially written, before `T0`?
- **V2 — Team Authorship Verdict:** was every meaningful contribution made by a device/key/person registered to that team, or is there evidence of an outside contributor or a shared/copied credential?

### In scope — supporting features

- GPG/SSH commit-signature verification against a roster the organizer controls (not reliance on GitHub's own "Verified" badge alone)
- `.gitignore` and hidden-tracking inspection (four hiding mechanisms — see §8.f)
- Detection of manually altered commit timestamps (`GIT_AUTHOR_DATE` / `GIT_COMMITTER_DATE` spoofing, backdating, replayed history)
- System-level checks on the local `.git` directory, not just what's visible on GitHub
- GitHub-side checks: repo metadata, push events, Actions run history, force-push detection
- Contribution fairness scoring per team member
- Code similarity search (cross-team and, if time allows, against public sources)
- Optional editor-level paste telemetry (metadata only, opt-in, disclosure-reconciliation framing — not surveillance)
- Deterministic, rule-based scoring with a human-readable narrative report

### Explicitly out of scope (v1)

- Screen recording, window enumeration, or any OS-level monitoring of what's open on a participant's machine
- Any verdict issued directly by an LLM — the LLM narrates and generates questions; it never decides
- Support for git hosts other than GitHub in v1 (the local-agent/system-plane checks are host-agnostic by construction; GitHub-specific API integration is what's scoped now — see §12 for the extension path)
- Automated code-comprehension interview generation (valuable, but deferred past the 48-hour build — noted in §11 as a strong v2 feature)

---

## 4. Core design principle: the three-plane evidence model

Every fact HACKPROOF cares about — "when was this written," "who wrote this" — is checked against **three independent planes**. A single plane proves very little, because a participant controls it. **Disagreement between planes is the evidence.**

| Plane | What it is | Who controls it | Forgeable by participant? |
|---|---|---|---|
| **Claim plane** | The git commit object itself: author date, committer date, author email, signature | The participant, via `git commit --date`, env vars, editing history | Yes, trivially, with no special tools |
| **System plane** | Filesystem and `.git`-internal artifacts on the participant's own machine: loose-object mtimes, reflog, working-tree file mtimes, hook receipts | The participant's OS, mostly invisible to them | Hard — requires knowing these exist and deliberately scrubbing them |
| **Server plane** | GitHub's own records: repo `created_at`, push event timestamps, Actions run timestamps, GitHub's signature verdict | GitHub, plus HACKPROOF's own webhook receiver clock | No |

Every check in this document is tagged by which plane it belongs to. The verdict engine (§8.i) is essentially a diff across these three planes.

---

## 5. System architecture

```
┌─────────────────────┐        ┌──────────────────────────┐
│  Registration Portal │──────▶│  Postgres: teams, members,│
│  (web, pre-event)     │        │  device fingerprints,     │
└─────────────────────┘        │  roster public keys       │
                                 └──────────┬────────────────┘
                                            │
┌─────────────────────┐                    │
│  Local Agent (CLI)   │──receipts─────────▶│
│  runs on each         │   (signed, hash-  │
│  participant machine  │    chained)       │
└─────────────────────┘                    │
                                            ▼
┌─────────────────────┐        ┌──────────────────────────┐
│  GitHub App /        │──────▶│  FastAPI ingest service   │
│  webhook listener     │        │  (append-only event log,  │
└─────────────────────┘        │  hash-chained)             │
                                 └──────────┬────────────────┘
                                            │
                                            ▼
                                 ┌──────────────────────────┐
                                 │  Analyzer Engine          │
                                 │  - V1 checks (§8.d)       │
                                 │  - V2 checks (§8.e)       │
                                 │  - gitignore inspector    │
                                 │  - contribution scorer    │
                                 │  - similarity search       │
                                 └──────────┬────────────────┘
                                            │
                                            ▼
                                 ┌──────────────────────────┐
                                 │  Verdict Engine (rules)    │
                                 │  + Report Generator (LLM   │
                                 │  narrates, never decides)  │
                                 └──────────┬────────────────┘
                                            │
                                            ▼
                                 ┌──────────────────────────┐
                                 │  Dashboard (organizer +    │
                                 │  per-team provenance page) │
                                 └──────────────────────────┘
```

---

## 6. Data model

### 6.1 Core entities

```
Team
  id, name, project_name, created_at

Member
  id, team_id, display_name, email,
  registered_pubkey_fingerprint, registered_device_fingerprints[]

Repo
  id, team_id, github_full_name, github_repo_id,
  github_created_at, is_fork, fork_parent_full_name

Receipt              # sent by the local agent on every commit / push
  id, repo_id, member_id,
  commit_sha, tree_sha, parent_shas[],
  claimed_author_date, claimed_committer_date, tz_offset,
  device_fingerprint, diffstat {files, insertions, deletions},
  system_snapshot {loose_object_mtimes[], reflog_tail, working_tree_mtimes[]},
  agent_signature,
  server_received_at,          # <- ground truth ONLY when transmission_mode = "live"
  transmission_mode,           # "live" (sent immediately) | "queued" (sent after reconnect)
  prev_receipt_hash, this_receipt_hash   # hash chain

GitHubEvent          # from webhook / API poll
  id, repo_id, event_type (push|force_push|workflow_run|...),
  before_sha, after_sha, forced (bool),
  github_created_at, server_received_at

Flag
  id, repo_id, member_id (nullable), plane, rule_id,
  severity, evidence_ref, created_at, appeal_status
```

### 6.2 The Receipt object (the single most important artifact in the system)

Sent by the local agent's `post-commit` and `pre-push` hooks. Server timestamps it on arrival and discards trust in the claimed dates — the server's own clock is the fact that matters.

```json
{
  "commit_sha": "a1b2c3...",
  "tree_sha": "d4e5f6...",
  "parent_shas": ["9f8e7d..."],
  "author_email": "satoru@example.com",
  "claimed_author_date": "2026-09-12T10:42:00+05:30",
  "claimed_committer_date": "2026-09-12T10:42:00+05:30",
  "tz_offset": "+0530",
  "device_fingerprint": "sha256(salt + machine_id + hostname + mac)",
  "transmission_mode": "live",
  "diffstat": {"files": 3, "insertions": 41, "deletions": 6},
  "system_snapshot": {
    "loose_object_mtimes": ["2026-09-12T10:42:03Z", "..."],
    "reflog_tail": "a1b2c3 HEAD@{0}: commit: add matcher",
    "working_tree_mtime_outliers": []
  },
  "signature": "gpg-signature-over-the-above-fields",
  "prev_receipt_hash": "sha256-of-previous-receipt"
}
```

**Live vs. queued matters.** `server_received_at` is only a hard ground-truth timestamp when `transmission_mode = "live"`. A `queued` Receipt (sent after a reconnect) only proves the commit existed by the time it arrived — not when it was actually made. The two must never be weighted the same way by the verdict engine (see §8.i).

---

## 7. End-to-end workflow

### Phase 0 — Pre-event registration
1. Organizer creates the event with `T0` (start) and `T1` (end).
2. Teams register on the portal: team name, members, member emails.
3. Each member runs `hackproof init --team <token>` locally. This:
   - Generates (or imports) a GPG/SSH keypair, registers the public key against their identity.
   - Computes and registers a device fingerprint.
   - Installs git hooks via `git config core.hooksPath` (non-destructive — chains to any existing hooks).
4. Organizer installs the HACKPROOF GitHub App on the event org; a webhook is registered before `T0`.
5. Each team creates their repo from an organizer-owned template. **The initial template commit is the declared T0 baseline** and is excluded from all scoring — it's declared prior work, not penalized.

### Phase 1 — Development window (`T0` → `T1`)
1. Every commit triggers `post-commit`: the agent builds a Receipt (§6.2), signs it, sends it to the ingest service. Offline queues locally and flushes on reconnect.
2. Every push triggers `pre-push`: the agent sends the ref state (before/after SHA) so force-pushes are independently recorded.
3. The GitHub App receives `push`, `workflow_run` events in real time via webhook, stamped with the server's own receipt clock as a backup to GitHub's own `created_at`.
4. (Optional) The editor extension reports paste-event metadata only, reconciled later against the team's AI-usage disclosure log.

### Phase 2 — Post-event analysis (`T1` → judging)
1. Analyzer engine clones each final repo and runs the full V1 + V2 check suite (§8.d, §8.e) against the accumulated Receipts and GitHubEvents.
2. `.gitignore` / hidden-tracking inspector runs (§8.f).
3. Contribution fairness scorer computes per-member distributions (§8.g).
4. Similarity search runs cross-team first (fast, always available), then against public corpora if time/API budget allows (§8.h).
5. Verdict engine applies deterministic rules (§8.i) → produces Flags and a coverage score per team.
6. Report generator produces the human-readable report: LLM narrates the flagged evidence in plain language; it does not assign the verdict.

### Phase 3 — Judging
1. Organizer dashboard lists all teams sorted by flag severity / ascending coverage score.
2. Judges open a team's Provenance Report alongside the demo. Report shows: timeline (claimed vs. server-received time as two series), signature/device attribution table, contribution distribution, and any flags with linked evidence.
3. Flagged teams get an appeal path: they respond in-app, a human (organizer or lead judge) makes the final call. HACKPROOF never auto-disqualifies.

---

## 8. Component specifications

### 8.a Registration & Key Management Service
- Web portal (can be a simple React + FastAPI form for v1).
- Stores: team roster, member emails, registered public keys, registered device fingerprints.
- Issues a per-team join token used by `hackproof init`.
- **Design decision to make explicitly before building:** does `hackproof init` generate the keypair (better UX for 200 people in 10 minutes, but HACKPROOF technically could have seen the private key at generation time — note this tradeoff in any pitch), or does the participant paste in a pre-existing public key (stronger custody story, worse UX under time pressure)? Recommended default for a 48-hour event: **agent generates the key, on-device, and never transmits the private key** — only the public key is registered. Document this clearly.

### 8.b Local Agent (CLI)
- Distributed as a single binary or `pip install hackproof-agent`.
- Commands:
  - `hackproof init --team <token>` — key + device registration, hook install.
  - `hackproof status` — shows the participant their own receipt coverage (builds trust, catches agent-not-running early).
- Hooks installed via `core.hooksPath` so existing hooks aren't overwritten:
  - `post-commit` → build and send a Receipt.
  - `pre-push` → send ref state (before/after SHA, force flag).
- `hackproof init` must also run `git config commit.gpgsign true` and `git config user.signingkey <fingerprint>`. Without this, most commits arrive unsigned regardless of registration, and the identity checks in §8.e have nothing to verify against.
- Must queue-and-retry on network failure; hackathon wifi is unreliable. Every Receipt is tagged `transmission_mode: live` or `queued` — see the caveat in §6.2.
- System-plane data collected at each snapshot: loose-object mtimes (`find .git/objects -type f -not -path "*/pack/*" -printf '%T@ %p\n'`), reflog tail, working-tree file mtime outliers, presence of `refs/original/` or `.git/filter-repo/` (rewrite artifacts).

### 8.c GitHub App / Webhook Listener
- Installed as a **GitHub App** (not OAuth) on the event org for scoped, revocable access.
- Subscribes to: `push`, `workflow_run`, `pull_request`.
- On receipt of each webhook, records `github_created_at` (GitHub's claim) **and** `server_received_at` (HACKPROOF's own clock) — the gap between these two is itself a useful sanity check on GitHub's own reporting.
- Also polls (or fetches at analysis time):
  - `GET /repos/{o}/{r}` → `created_at`, `fork`, `parent`, `source`
  - `GET /repos/{o}/{r}/events` → historical `PushEvent` list (retention ~90 days, sufficient for a hackathon)
  - `GET /repos/{o}/{r}/actions/runs` → `run_started_at` as an independent clock
  - `GET /repos/{o}/{r}/commits/{sha}` → `commit.verification` (GitHub's own signature verdict, cross-checked against HACKPROOF's own roster-based verification, never trusted alone)

### 8.d Analyzer Engine — V1 checks (build-window verdict)

All checks are tagged by plane. Ordered by strength.

**Server plane**
1. `repo.created_at < T0` → repo existed before the event. Hard flag.
2. `push_event.created_at − commit.author_date` per commit → plot as a chart; large/systematic gaps mean code was written well before it was pushed (or timestamps were faked).
3. Force-push detected (`before_sha` no longer reachable from current `HEAD`) → history rewritten. Cross-check whether any Receipted commits were dropped.
4. `workflow_run.run_started_at` as a second independent clock against claimed commit dates.

**System plane**
5. Loose-object mtime clustering: many objects with a tight mtime cluster while claimed dates span many hours → replayed/scripted history. (Caveat: destroyed by `git gc` — snapshot early and often.)
6. `.git` directory creation time predates `T0`.
7. Reflog vs. log inconsistency: `GIT_COMMITTER_DATE` not set to match `GIT_AUTHOR_DATE`, visible only in reflog.
8. Working-tree file mtimes predating `T0` (weak — destroyed by `cp`, but cheap and worth including).
9. Presence of `refs/original/` or `.git/filter-repo/` → deliberate history rewrite tool was used.

**Claim plane** (fallback — works even with zero agent adoption, on any bare clone)
10. Parent monotonicity violation: a commit dated earlier than its parent.
11. Timezone-offset inconsistency: commits from a `+0530` team suddenly showing `+0000` or another foreign offset.
12. Author-date vs. committer-date spread: near-zero normally; large and *uniform* across every commit signals rewritten history (whitelist genuine rebase/cherry-pick patterns).
13. Commit-interval quantization: real intervals are heavy-tailed and lumpy; faked timelines cluster suspiciously evenly or land on round-minute boundaries.
14. Diff-shape analysis: healthy work shows churn (additions followed by later modifications of the same lines); replayed pre-built code arrives as large, clean, low-churn drops.

### 8.e Analyzer Engine — V2 checks (team-authorship verdict)

**Identity (claim + server plane, cross-checked)**
1. Verify every commit's signature against HACKPROOF's own roster keyring (`git log --pretty='%H %an <%ae> %G? %GK'`), not GitHub's badge alone.
2. Cross-reference against `commit.verification` from the GitHub API — disagreement between the two is itself worth flagging.
3. Roster key signs a commit under a **different member's** author email → someone committed as a teammate. Flag.
4. Non-roster key signs a commit → outside contributor. Hard flag.
5. Unsigned commit → unattributed, not proof of cheating, but zero-provenance code.

**Device binding (system plane — closes the "copied key" hole)**
6. A roster key's signature appearing alongside **two different registered device fingerprints** → the private key was copied onto a second machine. This is the strongest available signal against key-sharing.
7. A Receipt arriving from an **unregistered** device fingerprint → an outside machine entirely.
8. A commit present in the final repo with **no matching Receipt at all** → it bypassed the agent; treat as zero-provenance, factor into the team's coverage score rather than an automatic hard flag (participants might legitimately have the agent crash).

*Caveat: device fingerprints (hostname + MAC + machine-id) are a heuristic, not a cryptographic guarantee — all three inputs are spoofable by someone deliberately trying to defeat the check. A fingerprint mismatch raises the cost of cheating; it should never by itself trigger a hard V2 flag without a corroborating signal from identity checks 1–5 or the behavioral check below.*

**Behavioral (derived from §8.g)**
9. A member with zero authored hunks and only merge/pull activity, cross-referenced against their declared role at registration (a designer or data lead correctly declared as non-coding should not be flagged).

### 8.f `.gitignore` / hidden-tracking inspector

Hidden code has no Receipt, no signature check, nothing — it defeats every check above, so this runs independently and feeds into the coverage score.

| Mechanism | Visibility | Check |
|---|---|---|
| `.gitignore` | Visible in repo | Parse for patterns excluding source dirs/extensions; diff across the event — a rule added late that hides a directory is a strong flag |
| `.git/info/exclude` | **Local only, never committed** | Agent reads it directly at snapshot time |
| `core.excludesFile` (global gitignore) | Local only | `git config --get core.excludesFile`, agent reads target file |
| `assume-unchanged` / `skip-worktree` | Invisible unless checked | `git ls-files -v` — lowercase letters mark flagged files; commit a stub, then edit freely with no diff shown |

Headline metric to surface on the dashboard: **ratio of source files tracked by git to source files present on disk** (via the agent's local snapshot). A large gap is a single, clear number that says "there is unaudited code here."

### 8.g Contribution Fairness Scorer

- Per member: authored commits, **meaningful** LOC changed (excluding lockfiles, generated code, vendored dependencies, binary/asset files), distinct files touched, temporal spread across the window.
- Report as a normalized distribution (Gini coefficient or entropy) rather than raw counts, so team size doesn't skew it.
- Let members declare a non-coding role at registration (design, data collection, pitch) so low-LOC members aren't misread as free-riding.

### 8.h Similarity Search Service

- **Cross-team similarity** (same event): fast, no external dependency, should always run. AST/structural comparison, not raw text — catches renamed variables and reformatting.
- **Public-corpus similarity**: optional if API budget and time allow; run against a general code-search or a plagiarism-detection backend using structural fingerprinting (winnowing-style, as used by MOSS-derived tools) rather than substring matching.
- Output: a similarity score per file pair plus the matched spans, so a flag is always inspectable, never just a number.

### 8.i Verdict Engine

Deterministic and rule-based, every flag traceable to a named rule and its evidence. **No LLM issues a verdict.**

```
V1 = PRE_BUILT if any of:
  - repo.created_at < T0
  - loose_object_mtime_cluster inconsistent with claimed commit spread
  - push_vs_commit_gap exceeds threshold across a large share of the codebase
  - refs/original/ or .git/filter-repo/ present
  - force_push dropped previously Receipted commits

V2 = OUTSIDE_CONTRIBUTION if any of:
  - non-roster signing key found
  - roster key signature on 2+ distinct device fingerprints
  - Receipt from an unregistered device
  - a registered member has zero authored contribution and no declared non-coding role

Otherwise, compute a trust weight per commit, then aggregate by lines changed (not commit count — one huge low-effort commit shouldn't outweigh real work):

  per-commit trust weight:
    1.0  claim + system + server planes all present and consistent
    0.6  only two planes present and consistent (e.g. no system_snapshot, but signature + a *live* server timestamp agree)
    0.3  only the claim plane is present (no Receipt at all — unverifiable, not accused)
    0.0  any plane actively disagrees (push-vs-commit gap over threshold, signature/device mismatch) —
         these lines don't count toward coverage, and the commit may also raise a Flag above

  COVERAGE_SCORE = Σ(trust_weight × meaningful_lines_changed) / Σ(meaningful_lines_changed)

  Note: a *queued* Receipt (§6.2) should be treated as one plane weaker than a *live* one when computing
  this weight — tune the 0.6/0.3 split against real event data before relying on it to rank teams.
```

Every team gets a coverage score even when no hard flag fires — that's what lets judges triage quickly (high coverage → skim, low coverage → read the report closely).

### 8.j Report Generator

- Local LLM (see §9) has exactly three jobs, and never a fourth:
  1. Write the plain-language narrative of the evidence timeline.
  2. (Deferred to v2, see §11) Generate code-comprehension interview questions.
  3. Draft the "please explain" prompt sent to a flagged team.
- Structured JSON output enforced by schema; the narrative is generated *from* the verdict engine's output, never the other way around.
- Final report is hashed and the hash published, so it can't be silently edited after generation.

### 8.k Dashboard

- **Organizer view:** all teams, sortable by flag severity and coverage score ascending.
- **Per-team Provenance Report:** timeline chart (claimed commit time vs. server-received Receipt time as two series), signature/device attribution table, contribution distribution chart, `.gitignore`/hidden-tracking summary, any Flags with linked evidence, appeal status.

---

## 9. Technology stack

| Layer | Choice | Notes |
|---|---|---|
| Ingest API | FastAPI | Receives Receipts and webhooks; append-only event log |
| Database | PostgreSQL | Hash-chained event log in its own table; derived analytics in separate tables so everything is recomputable |
| Queue | Redis + RQ/Celery | For the heavier analysis jobs (clone, similarity search) |
| Repo mining | GitPython / PyDriller, `git` CLI plumbing directly for the low-level checks | Prefer raw `git log --pretty=` and `git ls-files -v` for anything the libraries don't expose cleanly |
| AST / structural diffing | tree-sitter | Language-agnostic |
| Similarity search | copydetect (winnowing-based) for a first pass; consider a structural/AST-comparison tool for stronger cross-repo matching | Start with cross-team only |
| Local LLM | Ollama serving a coding-capable model (e.g. a 30B-class MoE coder model fitting a 24GB GPU) | Narration + question generation only, strict JSON schema output, never the verdict |
| Frontend | React + Vite | Organizer dashboard + per-team report |
| Agent/CLI | Python, packaged via PyInstaller or `pip install` | Hooks via `git config core.hooksPath` |
| GitHub integration | GitHub App + webhooks | Scoped, revocable; poll REST API for historical data at analysis time |

---

## 10. Build roadmap (48-hour hackathon execution)

| Hours | Deliverable |
|---|---|
| 0–4 | FastAPI ingest endpoint + Postgres schema + hash-chained event log. Team/member/device/key registration flow. |
| 4–8 | `hackproof init` CLI: key generation, device fingerprinting, hook installation, receipt signing and transmission. |
| 8–14 | Analyzer: clone a repo, run every claim-plane and server-plane check (§8.d items 1–4, 10–14; §8.e items 1–5). Pure git plumbing + GitHub API, no ML yet. This alone demonstrates both verdicts. |
| 14–20 | System-plane checks wired to actual agent-collected Receipts (§8.d items 5–9; §8.e items 6–8). This is the upgrade from "clever heuristics" to "cryptographically anchored." |
| 20–24 | `.gitignore` / hidden-tracking inspector (§8.f) + contribution fairness scorer (§8.g). |
| 24–32 | React dashboard: team list by severity, per-team timeline (claimed vs. server-received time), attribution table. |
| 32–38 | Cross-team similarity search (§8.h) via copydetect subprocess. |
| 38–44 | Ollama + coding LLM generating the narrative report from structured verdict-engine output; strict JSON schema. |
| 44–48 | Seed with real data: write a `fake-repo.sh` script that generates a convincing backdated, replayed history, and demonstrate HACKPROOF catching it live. Run HACKPROOF on HACKPROOF's own repo during the event — the team's own provenance report becomes part of the submission. |

---

## 11. Known limitations and honest caveats (state these in the pitch, don't let a judge find them first)

- GPG/SSH signatures prove a **key** signed something, not that a specific human typed it. Device binding narrows this but does not eliminate it entirely (a determined participant can still copy both the key and clone the fingerprint inputs, though this requires deliberate technical effort well beyond casual cheating).
- Loose-object mtime evidence is destroyed by `git gc` — snapshot early and frequently, and treat its absence as inconclusive, not exculpatory.
- Working-tree mtimes are trivially reset by a plain `cp`; keep this check but weight it low.
- Coverage score, not binary guilt/innocence, is the right framing for judges — it keeps HACKPROOF in the "evidence provider" role and out of the "accuser" role, which also avoids reputational harm from a false positive.
- Code-comprehension interview questions (having the LLM generate questions about a participant's own diff, asked live by judges) are a strong v2 addition — they catch "someone else wrote this for me" scenarios that no static analysis can, and they reward understanding rather than penalizing AI-assisted work. Deferred here only because of the 48-hour window, not because it's weak.
- **This entire design depends on two organizer-side commitments, not just team-side setup:** (1) every team must start from an organizer-issued template repo so there's a real T0 baseline to anchor V1 against — if teams bring their own pre-existing repos, the baseline logic has nothing to compare to; (2) device fingerprints and public keys are personal-ish data collected at check-in, so state a retention policy up front (delete after judging concludes) and get explicit consent — this matters generally and specifically under regimes like India's DPDP Act.

---

## 12. Extension path (post-hackathon, if this becomes a longer-term product)

- Host-agnostic system-plane checks (§8.d system plane, §8.f) already work with any git remote, since they operate on the local `.git` directory. Extending server-plane checks (§8.d/§8.e server plane) to GitLab, Bitbucket, or self-hosted Gitea only requires swapping the webhook/API integration in §8.c for an equivalent client against each platform's API.
- Code-comprehension interview generation (§11).
- Public-corpus similarity search at scale (§8.h), budget permitting.
