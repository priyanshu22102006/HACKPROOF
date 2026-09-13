## HackProof

Hackathon build-provenance & integrity platform.

HackProof answers two questions about any hackathon submission, with evidence instead of suspicion:

1. **Was this built inside the official window** (not pulled from a pre-existing project)?
2. **Was it built only by the registered team** (no outside contributor, no shared or copied signing key)?

It does this by comparing the same fact — timing, authorship — across three independent sources a participant cannot all forge at once, and hands judges a scored, evidence-linked report instead of an accusation.

Full design spec: [`hackproof-project-spec.md`](./hackproof-project-spec.md) — the single source of truth for architecture, data model, and every check. Everything below is a map of that spec plus what has actually been built and verified against it so far.

---

## ⚠️ Current state: two build tracks, not yet reconciled

Before anything else — this is the fact that matters most for anyone picking the project up:

There are currently **two separate implementations** of overlapping parts of HackProof (mainly GPG verification), built on different machines in different sessions, and they have **not been merged into one repo state**:

| Track | Stack | Where it lives | Status |
|---|---|---|---|
| **A — Analyzer suite** | Python, `git` plumbing, pytest | Satoru's local machine, `~/Desktop/HACKPROOF` | Extensive, 117 tests passing, live-test tooling built and rehearsed. **Not committed/pushed** — the local repo has no commits yet. |
| **B — Context Awareness Engine** | Node / Express / MongoDB / React | The shared GitHub repo, `github.com/priyanshu22102006/HACKPROOF` | Built directly into the shared repo in a separate session (which found the repo contained only a placeholder `Readme.md` at the time), 17/17 tests passing, pushed. |

Track A is the one described in almost every doc below (`gpg-verification.md`, `gitignore-gpg-review.md`, `live-test-tooling.md`, `clone-vs-local-evidence.md`, `gpg-reverify-and-env-gotchas.md`) and is by far the more complete implementation of the spec's V1/V2 checks. Track B (`context-awareness-engine.md`) is a differently-shaped feature (a temporal/contextual anomaly engine) built on a rebuilt copy of the same substrate (Team/Member/Repo/Commit/GpgKey models, its own GPG verification via `openpgp`).

**Before doing more feature work, the repo needs a reconciliation pass:** decide which GPG implementation is canonical (Python, per the shared `Finding` contract in `core/models.py`, is the more battle-tested one), push Track A's work to the shared remote, and decide whether the Context Awareness Engine becomes a module on top of it or a parallel system. Don't trust "the repo has N passing tests" from any single doc below without checking which track it refers to.

---

## The three-plane evidence model

Every fact HackProof checks — *when was this written*, *who wrote it* — is checked against three independent planes. A single plane proves very little, because a participant controls it. **Disagreement between planes is the evidence.**

| Plane | What it is | Who controls it | Forgeable by a participant? |
|---|---|---|---|
| **Claim** | The git commit object itself — author/committer date, email, signature | The participant (`git commit --date`, env vars, rewritten history) | Yes, trivially |
| **System** | Filesystem / `.git`-internal artifacts on the participant's own machine — loose-object mtimes, reflog, working-tree mtimes | The participant's OS, mostly invisible to them | Hard — requires knowing these exist |
| **Server** | GitHub's own records — repo `created_at`, push events, Actions run timestamps, GitHub's own signature verdict | GitHub + HackProof's webhook receiver clock | No |

---

## Architecture (per spec §5)

```
Registration Portal ──▶ Postgres (teams, members, device fingerprints, roster keys)
                              ▲
Local Agent (CLI) ───receipts─┘
                              │
GitHub App / webhook ────────▶ FastAPI ingest (append-only, hash-chained event log)
                              │
                              ▼
                    Analyzer Engine (V1 + V2 checks, .gitignore inspector,
                    contribution scorer, similarity search)
                              │
                              ▼
                    Verdict Engine (deterministic rules)
                    + Report Generator (local LLM narrates, never decides)
                              │
                              ▼
                    Dashboard (organizer view + per-team provenance report)
```

The **local agent + Receipt** is the load-bearing idea in the whole system (spec §6.2): every commit gets a signed, hash-chained Receipt with a server-stamped arrival time, and a `queued` (post-reconnect) Receipt is deliberately weighted lower than a `live` one, because it only proves a commit existed by arrival time, not when it was made.

---

## What's implemented (Track A — Python analyzer suite)

Location: `~/Desktop/HACKPROOF`. Everything below runs through one entry point:

```bash
python3 -m core.engine /path/to/repo --roster roster.json --t0 <event-start-iso>
python3 -m core.engine /path/to/repo --only gpg
python3 -m core.engine /path/to/repo --format json --out report.json
python3 scripts/analyze_repo_url.py <owner/repo | https URL | ssh remote>   # clone, analyze, report, delete
```

Every analyzer is a module exposing exactly one function, `run(repo_path: str) -> list[Finding]`; `core/engine.py` knows nothing else about them. Adding a check is one row in `ANALYZERS`. Every `Finding` is validated at the seam (`core/models.py`) — plane, severity, evidence dict, `passed` bool — and no single analyzer crash can take the whole run down.

### Built and passing (117 tests as of the last verified run)

- **`analyzers/gpg_check.py`** — roster-based GPG/SSH signature verification (spec §8.e checks 1–5). Six checks: `gpg.roster_integrity`, `gpg.signature_verification`, `gpg.unregistered_key`, `gpg.identity_match`, `gpg.key_validity`, `gpg.signature_coverage` (the headline dashboard metric). Status matrix: `VERIFIED / NO_SIGNATURE / INVALID_SIGNATURE / UNKNOWN_KEY / EXPIRED_KEY / REVOKED_KEY / IDENTITY_MISMATCH / PLATFORM_KEY`.
- **`analyzers/gitignore_check.py`** — all four hiding mechanisms from spec §8.f: `.gitignore` pattern audit, `.git/info/exclude`, `core.excludesFile`, `assume-unchanged`/`skip-worktree`, plus the `tracked_source_ratio` headline metric. `BENIGN_NAMES`/`SKIP_WALK_DIRS` keep `node_modules`, `venv`, `dist`, etc. from producing false positives.
- **`analyzers/github_check.py`** — spec §8.e check 2 (previously deferred): `github.repo_metadata` (also covers §8.d check 1 — repo predates T0, forks), `github.signature_crosscheck`, `github.author_login_match`.
- **`scripts/hackproof_enroll.py`** — participant-side enrollment: mints/adopts a GPG or SSH key, configures git signing, proves it works with a real signed test commit.
- **`scripts/build_roster.py`** — organizer-side: merges enrollment cards into `roster.json`, refuses private-key material, refuses duplicate fingerprints across members, takes `--baseline-commit` (the organizer template commit, excluded from scoring per spec §7 phase 0).
- **`scripts/live_test_attacks.sh`** / **`scripts/rehearse_live_test.sh`** — scripted attack scenarios (`legit`, `outsider`, `dripfeed`, `skipworktree`) and a full 3-person rehearsal on one machine.
- **`engine.history_completeness`** — flags shallow clones and repos over the 2000-commit cap before any check runs on truncated history.
- **`evidence["evaluable"]` / `is_evaluable()`** — a check that structurally cannot see what it needs (e.g. system-plane checks on a clone) reports `n/a`, never a false "ok."

### Not yet built

- **Device binding** (spec §8.e checks 6–8) — closing the "copied private key" hole. A copied key still reads as `VERIFIED` today; this is the single biggest open gap and is stated as a known limit in the live-test runbook.
- V1 system-plane checks tied to real agent-collected Receipts (spec §8.d items 5–9) beyond what the clone/local-checkout comparison already demonstrates.
- Contribution fairness scorer (§8.g) and similarity search (§8.h).
- The FastAPI ingest service, Postgres schema, and local agent's `post-commit`/`pre-push` hooks themselves (§8.a–§8.c) — the analyzer engine has been validated standalone against static repos and clones, not yet wired to a live Receipt stream.

### What survives a clone vs. what requires the local checkout

Measured directly (`clone-vs-local-evidence.md`) by running the engine on the same repo from both vantage points:

| Check | Author's machine | Fresh clone |
|---|---|---|
| GPG identity checks (all of `gpg.*`) | evaluated | **evaluated — full parity** |
| `gitignore.pattern_audit` | `hard_flag` | `flag` (partial — committed rules only) |
| `gitignore.assume_unchanged_skip_worktree` | evaluated | **blind → `n/a`** |
| `gitignore.tracked_source_ratio` | real ratio | **blind → always 1.0, `n/a`** |
| `gitignore.info_exclude` / `core_excludes_file` | evaluated | **blind → `n/a`** |

Identity/authorship (the whole of §8.e) is fully answerable from a URL, because signatures live in the commit object. The hiding half of §8.f mostly does not travel, because it's system-plane by construction — which is the strongest concrete argument for actually shipping the local agent, not just the URL-based analyzer.

### Test history

| Point in time | Suite size |
|---|---|
| Initial GPG + engine merge | 36 tests |
| First documented pass | 41 tests |
| `.gitignore` review pass | 48 tests |
| After enrollment/roster/GitHub-cross-check tooling | 97 tests |
| After clone-vs-local URL analysis work | 117 tests |
| Latest re-verification | 116 passed + 1 deselected (`slow`, real key-expiry wait) = 117 |

Run it:
```bash
python3 -m pip install pytest --break-system-packages   # not preinstalled in a fresh session
python3 -m pytest -q -m "not slow"                       # full suite in <1s
bash scripts/make_gpg_fixture_repos.sh                   # NOTE: bash scripts/x.sh, not ./scripts/x.sh
                                                          #   (exec bit doesn't survive on the mounted copy)
```

---

## What's implemented (Track B — Context Awareness Engine)

Location: the shared repo, `backend/` (Node/Express/MongoDB) and `frontend/`.

A temporal-context anomaly engine layered on top of a Node rebuild of the same core substrate (Team/Member/Repo/Commit/GpgKey models, a real GitHub REST integration, roster-based GPG verification via `openpgp`, and a shared, mergeable Evidence Graph).

- **`services/context/eventStream.js`** — normalizes everything (commits, pushes, branches, merges, GPG verifications, key lifecycle) into one ordered event stream.
- **`services/context/contextEngine.js`** — retrieves before/after windows, file/commit history, participant baselines; computes gaps, bursts, commit size, throughput, contribution shift.
- **`services/context/contextualAnomalies.js`** — rule engine: `NORMAL / LOW_ANOMALY / MEDIUM_ANOMALY / HIGH_ANOMALY / INSUFFICIENT_CONTEXT`.
- **`services/context/contextNarrator.js`** — deterministic explanation always; local Ollama model optionally narrates, with redaction and a confidence cap.
- Dashboard: `frontend/src/components/ContextAwarenessPanel.jsx`.

**Safety properties enforced by its own tests:** no single event can push a finding above `LOW_ANOMALY` without a second independent observation; thin evidence returns `INSUFFICIENT_CONTEXT` rather than a guess; long inactivity + one large commit reads as offline work, not an anomaly; a verified signature can only soften severity, never raise it; the LLM cannot invent evidence, change a status, or report confidence the deterministic evidence doesn't support; the word "cheating" appears nowhere in any output, and there is no verdict field. 17/17 tests passing, no DB or network required to run them.

---

## Design principles that apply across both tracks

- **No LLM ever issues a verdict.** In both tracks, the model narrates structured, deterministic engine output — it never decides pass/fail, and it cannot invent evidence outside what's cited.
- **"Unverifiable" must never render as "flagged" — or as "clean."** Stated explicitly in the GPG doc for the flagged direction, and in the clone-vs-local finding for the mirror direction (a check that can't see the system plane reporting `n/a` rather than a false "ok").
- **Coverage score, not binary guilt/innocence**, is the framing judges see — it keeps HackProof in the "evidence provider" role, not the "accuser" role, and limits reputational harm from a false positive.
- **A benign plane disagreement is not a flag.** E.g. a member who registered a key with the organizer but never uploaded it to GitHub reads as `roster_only`, `info` severity — not a mismatch.

---

## Verdict logic (summarized)

```
V1 = PRE_BUILT if repo predates T0, mtime clustering contradicts claimed spread,
     push-vs-commit gap is systemic, history-rewrite artifacts are present,
     or a force-push dropped previously-Receipted commits.

V2 = OUTSIDE_CONTRIBUTION if a non-roster key signs a commit, a roster key
     signs from 2+ device fingerprints, a Receipt arrives from an unregistered
     device, or a registered member has zero contribution and no declared
     non-coding role.

Otherwise: per-commit trust weight (1.0 all 3 planes agree, 0.6 two planes,
0.3 claim-plane only, 0.0 planes disagree) aggregated by lines changed, not
commit count → COVERAGE_SCORE.
```

---

## Known limitations (state these before a judge finds them)

- A signature proves control of a **key**, not that a specific human typed the code. Device binding narrows this; it doesn't close it, and isn't built yet.
- Loose-object mtime evidence is destroyed by `git gc` — its absence is inconclusive, not exculpatory.
- `INVALID_SIGNATURE` is only detectable when the signing key is on the roster; without it, a forged signature and an unknown one both read as "cannot check."
- Identity matching (Track A) is by author **email**, not GitHub login, unless the GitHub cross-check is run.
- GitHub signs its own web-flow merges/edits — these must be recognized as `PLATFORM_KEY` and excluded from coverage, or every honest team using the merge button gets a false hard-flag. (Fixed in Track A; bundled platform keys under `analyzers/platform_keys/`.)
- Device/public-key data collected at enrollment is personal data — spec §11 requires a stated retention policy (delete after judging) and explicit consent, relevant generally and specifically under India's DPDP Act.
- Every team must start from an organizer-issued template repo, or the V1 baseline logic has nothing to anchor against.

## Still open

- Track A's ~117-test Python implementation has **not been committed or pushed** to the shared GitHub repo.
- A stale, empty `.git/index.lock` sits in the local checkout and will block the next `git add`/`commit` until removed (`rm .git/index.lock`).
- Naming: `.chronicle/`, `$CHRONICLE_ROSTER`, `chronicle-*` env vars/paths persist alongside `hackproof-*` ones throughout Track A (an earlier project name, "Chronicle") — worth deliberately confirming or cleaning up.
- Device binding (§8.e 6–8) is unbuilt in both tracks.
- Contribution fairness scoring, cross-team/public-corpus similarity search, and code-comprehension interview generation (a strong v2 idea — see spec §11) are all deferred past the 48-hour window.
- Reconciling Track A and Track B into one coherent implementation (see the callout at the top).

---

## Docs in this project

| Doc | Covers |
|---|---|
| `hackproof-project-spec.md` | Full design spec — source of truth for architecture, data model, every check, roadmap |
| `gpg-verification.md` | Track A's GPG analyzer: roster format, status matrix, six checks, testing guide |
| `context-awareness-engine.md` | Track B: the Node/Mongo Context Awareness Engine built directly into the shared repo |
| `gitignore-gpg-review.md` | Review pass confirming both Track A analyzers work as documented; found and tracked the roster-`.gitignore` bug |
| `live-test-tooling.md` | Enrollment/roster tooling, GitHub cross-check, attack scripts, and the false positives found making it work on a real repo |
| `clone-vs-local-evidence.md` | What a clone can and structurally cannot prove; the `evaluable`/`n/a` fix |
| `gpg-reverify-and-env-gotchas.md` | Latest re-verification (117 tests green) + recurring environment gotchas |
