# GPG commit-signature verification

HACKPROOF §8.e identity checks 1-5, rebuilt as a Python analyzer and merged with
the `.gitignore` inspector behind one entry point.

- `analyzers/gpg_check.py` — the feature
- `analyzers/github_check.py` — §8.e check 2, the GitHub cross-check
- `scripts/hackproof_enroll.py` / `scripts/build_roster.py` — how a real roster gets built
- `docs/LIVE-TEST-RUNBOOK.md` — running all of this against a real repo with real people
- `core/engine.py` — the merge point: runs every analyzer over one repo
- `tests/test_gpg_check.py`, `tests/test_engine.py` — 36 tests, real keys, real commits
- `scripts/make_gpg_fixture_repos.sh` — a clean repo and a repo that fails every way at once

## The shape of the merge

Both features are modules that expose exactly one function:

```python
run(repo_path: str) -> list[Finding]
```

`core/engine.py` knows nothing else about either of them. Adding an analyzer is
one row in `ANALYZERS`. Two rules hold the seam:

1. **One contract, enforced at the seam.** Every object coming back is validated
   against `core/models.py` — plane in `{claim, system, server}`, severity in
   `{info, flag, hard_flag}`, evidence a dict, `passed` a bool, and `passed=True`
   never paired with a flag severity. A module that drifts is reported as
   `engine.<name>` with the violations listed, and the offending object does not
   reach the report.
2. **No analyzer can take down the run.** Each runs in its own try/except. A
   crashed `.gitignore` inspector must not stop signature verification from
   reaching a judge, and vice versa.

Per-analyzer config travels through the environment rather than the signature,
which is what keeps the one-argument contract viable: `--roster` exports
`$HACKPROOF_ROSTER`, which `gpg_check` picks up on its own.

```bash
python3 -m core.engine /path/to/repo --roster roster.json      # both analyzers
python3 -m core.engine /path/to/repo --only gpg                # one of them
python3 -m core.engine /path/to/repo --format json --out r.json
python3 analyzers/gpg_check.py /path/to/repo --roster roster.json   # standalone
```

Exit code is a CI convenience, never a verdict: `0` everything passed, `1`
something did not. Ranking teams is the verdict engine's job (§8.i).

## The roster

The roster is the organizer's record of who registered which public key. Without
it nothing can be attributed, so it is the one input this analyzer genuinely
needs. It is found in this order: `$HACKPROOF_ROSTER` (or `$CHRONICLE_ROSTER`), then
`<repo>/.hackproof/roster.json`, then `<repo>/hackproof-roster.json`.

```json
{
  "team_id": "team-07",
  "baseline_commit": "<organizer template commit, excluded from coverage>",
  "members": [
    {
      "member_id": "satoru",
      "display_name": "Satoru",
      "github_login": "satorugojo",
      "emails": ["satoru@example.com"],
      "keys": [
        {
          "key_id": "satoru-k1",
          "fingerprint": "4673FBA5...",
          "public_key": "-----BEGIN PGP PUBLIC KEY BLOCK----- ...",
          "status": "active",
          "revoked_at": null,
          "expires_at": null
        }
      ]
    }
  ]
}
```

`public_key_path` works instead of inline `public_key`. `fingerprint` is
optional and is cross-checked against the submitted blob — a mismatch rejects
the key rather than trusting either value.

Three things the roster handling does on purpose:

- **Private keys are refused.** A blob containing private key material is caught
  twice (textually, then by gpg reporting a secret key), never imported, and
  hard-flagged as `PRIVATE_KEY_SUBMITTED`. Per spec §8.a the agent generates the
  key on-device and registers only the public half; a private key arriving here
  means that property was broken and the key must be rotated, because HACKPROOF
  has now seen it.
- **Verification never touches your keyring.** Roster keys are imported into a
  throwaway `GNUPGHOME` under `/tmp`, used, and deleted (`gpg-agent` included).
  Your `~/.gnupg` is neither read nor written, which also means a key *you*
  happen to trust locally cannot quietly turn an unregistered commit into a
  verified one. A test asserts no keyring is left behind.
- **Key rotation is normal.** A member may hold several keys; commits signed by
  any of them verify. Revocation is not retroactive: if `revoked_at` is set and a
  commit predates it, the commit stays `VERIFIED` with a note.

The roster carries participants' emails and public keys — personal data under
the retention policy in spec §11. `.gitignore` keeps `.hackproof/` out of git;
delete the roster after judging.

## The status matrix

Every commit lands in exactly one status. `git log --format=%G?` does the
verification in a single pass against the roster keyring; `git verify-commit
--raw` is then run on the non-clean commits only, and its gpg status lines are
kept verbatim in evidence so a judge can audit the claim.

| Status | Means | How to produce it deliberately |
|---|---|---|
| `VERIFIED` | good signature, key on the roster, signer == author | signed commit, key registered under your own identity |
| `NO_SIGNATURE` | no `gpgsig` header | `git commit --no-gpg-sign` |
| `INVALID_SIGNATURE` | signature does not match the commit object | rewrite a signed commit's message, keep its `gpgsig` (see below) |
| `UNKNOWN_KEY` | good signature from a key nobody registered | second key, sign with it, leave it off the roster |
| `EXPIRED_KEY` | good signature, key or signature had expired | `gpg --quick-generate-key "X <x@e.test>" ed25519 sign seconds=5`, sign, wait |
| `REVOKED_KEY` | key revoked — by its own certificate, or by the roster | set `"status": "revoked"` on the roster key, re-run |
| `IDENTITY_MISMATCH` | one member's key signed a commit authored as another | register your key under member A, commit as member B |
| `PLATFORM_KEY` | signed by the git host itself, not by any participant | merge a pull request with GitHub's "Merge pull request" button |

`INVALID_SIGNATURE` is the one you cannot get through GitHub — it never serves a
commit whose signature it has already rejected — so it has to be built by hand:

```bash
git cat-file commit HEAD | sed 's/SIGNED-MESSAGE/TAMPERED-MESSAGE/' > /tmp/forged
FORGED=$(git hash-object -t commit -w --stdin < /tmp/forged)
git update-ref refs/heads/main "$FORGED"
```

Identity matching is separately reported as `MATCH` / `MISMATCH` / `UNKNOWN`, so
a signed commit whose author is not on the roster at all is recorded as
`UNKNOWN` rather than being accused of anything.

## The six checks

| Check | Plane | Worst severity | Fires when |
|---|---|---|---|
| `gpg.roster_integrity` | server | `hard_flag` | private key submitted; `flag` on fingerprint mismatch, failed import, or a malformed roster |
| `gpg.signature_verification` | claim | `hard_flag` | any `INVALID_SIGNATURE` — the commit object was altered after signing |
| `gpg.unregistered_key` | claim | `hard_flag` | any `UNKNOWN_KEY` (§8.e check 4, outside contributor) |
| `gpg.identity_match` | claim | `flag` | any `IDENTITY_MISMATCH` (§8.e check 3 — a flag, not a hard flag) |
| `gpg.key_validity` | claim | `hard_flag` | revoked key; `flag` for expired |
| `gpg.signature_coverage` | claim | always `info` | never flags — it is the metric, `passed` when ≥ 90% verified |

Coverage is the headline number for the dashboard, and it is deliberately
`info`: unsigned commits are *unattributed*, not evidence of cheating. It is the
signature-side twin of the `.gitignore` module's tracked-source ratio.

## Testing

### Level 1 — the suite (8 seconds)

```bash
cd ~/Desktop/HACKPROOF
python3 -m pip install pytest
python3 -m pytest -q          # -> 97 passed
```

97 = 7 `.gitignore` + 29 GPG + 16 engine + 24 GitHub cross-check + 13
enrollment + 8 real-world-key-shape tests. Nothing is mocked: each test mints a real ed25519 key and makes
a real `git commit -S`, and the GitHub tests talk real HTTP to a real server on
localhost rather than to a mocking library.
Hermetic on both axes — `GIT_CONFIG_GLOBAL`/`GIT_CONFIG_SYSTEM` are redirected so
your `~/.gitconfig` can't skew a result, and keys live in a throwaway
`GNUPGHOME` under `/tmp` that is destroyed with its `gpg-agent`. An autouse
fixture fails the test if the analyzer leaves a keyring behind.

Two implementation details worth knowing if a test ever goes red:

- `GNUPGHOME` is created under `/tmp`, not pytest's `tmp_path`, because
  `gpg-agent`'s socket path has a ~104-byte limit and nested pytest temp paths
  exceed it.
- `test_expired_key_is_flagged_not_hard_flagged` sleeps 7s waiting out a real
  key expiry rather than faking a clock. It carries the `slow` marker; skip it
  with `-m "not slow"` and the suite runs in under a second.

### Level 2 — end to end against a repo that cheats every way at once

```bash
./scripts/make_gpg_fixture_repos.sh
R=/tmp/hackproof-gpg-fixtures
python3 -m core.engine $R/clean-repo --roster $R/roster.json
python3 -m core.engine $R/dirty-repo --roster $R/roster.json
```

Clean repo → 11 checks, all `info`, all passed. Dirty repo:

```
FAIL gpg.signature_verification  hard_flag  5 commits: 1 VERIFIED, 1 NO_SIGNATURE,
                                            1 INVALID_SIGNATURE, 1 UNKNOWN_KEY,
                                            1 IDENTITY_MISMATCH
FAIL gpg.unregistered_key        hard_flag  1 commit signed by an unregistered key
FAIL gpg.identity_match          flag       1 identity mismatch
FAIL gpg.signature_coverage      info       verified ratio 0.2
```

The clean repo matters as much as the dirty one. A check that flags everything is
useless to a judge, and the expensive failure mode here is a false positive
against an honest team.

### Level 3 — degradation

```bash
python3 -m core.engine /tmp                       # not a git repo
python3 -m core.engine /tmp/nope                  # missing path
python3 -m core.engine .                          # HACKPROOF: real repo, zero commits
python3 -m core.engine $R/dirty-repo              # the cheating repo, with NO roster
```

All four return 11 findings with a `note`, and no traceback. The fourth is the
one that matters most: with no roster the analyzer has nothing to compare
against, so it reports signature *presence* only and flags nothing — even for
the repo that fails every check when the roster is present. "Unverifiable" must
never render as "flagged".

### What to probe if you want to stress it further

- Register a member's key under the wrong `github_login` and commit normally.
  You should get `IDENTITY_MISMATCH`, which is the same signal as someone
  committing as a teammate — the check cannot tell a check-in typo from
  impersonation, which is exactly why it is a `flag` and why the evidence names
  both readings.
- Put the same key on two members. Both then resolve through one index, and
  whichever member is indexed first wins the attribution. Today that is
  first-write-wins; if it shows up in real data, reject duplicate fingerprints at
  enrollment instead of guessing here.
- ~~Commit with a signing subkey rather than the primary key.~~ **Confirmed
  working.** An rsa4096 cert-only primary with a separate rsa4096 signing subkey
  — the common real-world key shape — verifies correctly: the commit presents the
  subkey fingerprint in `%GF`, the roster registers the primary, and both resolve
  to the same entry because the export carries the subkey. Regression test:
  `tests/test_platform_keys.py::test_rsa_primary_with_a_signing_subkey_verifies`.
- Run it on a repo with a few thousand commits. Verification is one `git log`
  pass, but `MAX_COMMITS` caps at 2000 and the raw-status budget at 25 commits.
  `engine.history_completeness` now reports when a repo exceeds that cap, and
  when the clone is shallow.

## What a real repository adds that a fixture never does

Two things showed up the first time this was pointed at realistic input, and both
turn an honest team's report red for no reason.

**The git host signs some commits itself.** GitHub's "Merge pull request" and
"Squash and merge" buttons, and any edit made in the web UI, are signed with
GitHub's own key rather than with anything a participant holds. A team using pull
requests — the ordinary workflow — accumulates several of these, and before this
was handled, every one of them resolved to `UNKNOWN_KEY` and raised a
`hard_flag`. GitHub's two real web-flow keys are now bundled in
`analyzers/platform_keys/` (fetched from `https://github.com/web-flow.gpg`, so
verification stays offline) and imported alongside the roster. Commits signed by
them get their own `PLATFORM_KEY` status: verified as the host's, never
attributed to a member, never flagged, and excluded from the coverage
denominator, because a merge GitHub performed is not code anyone typed.

This is not a hole. Signing into that bucket requires GitHub's private key, which
no participant has — the contrast with a roster key, where possession is the
whole limitation, is the point. `$HACKPROOF_PLATFORM_KEYS` adds keys for another
host (GitLab, Gitea, self-hosted); `$HACKPROOF_NO_PLATFORM_KEYS=1` turns the
mechanism off for an organizer who would rather see every non-roster signature as
`UNKNOWN_KEY`. There is a test asserting an outsider is still caught with the
host keys loaded.

**A shallow clone answers confidently about a fraction of the history.** `git
clone --depth 1` gives the analyzers one commit, and every check then reports on
that one commit without saying so — "coverage 1.0" on a repo whose other 200
commits were never read. `engine.history_completeness` now reports this before
anything else. It sits under `engine.` rather than in an analyzer because it is a
fact about the analysis run, not about the team, and it stays `info` severity for
the same reason: the shallow clone is the judge's doing.

## Honest limits

State these before a judge finds them.

- **A signature proves control of a key, not authorship.** Everything here
  narrows *who held the key*. It cannot show who typed the code. Device binding
  (§8.e checks 6-8) is what closes the copied-key hole, and it is not in this
  module.
- **`INVALID_SIGNATURE` is only detectable when the signing key is on the
  roster.** Without the public key, gpg cannot distinguish a forged signature
  from an unknown one — both come back as "cannot check". You can see this in the
  level-3 run: the forged commit reports `UNKNOWN_KEY`-class degradation rather
  than `INVALID_SIGNATURE` when no roster is supplied.
- **Verification here is local and offline.** This module never calls the
  GitHub API, and that is still the right default: local roster verification is
  the stronger evidence, and §8.e check 1 says never to trust GitHub's badge
  alone. §8.e check 2 — cross-referencing GitHub's own `commit.verification` and
  flagging disagreement — now lives in `analyzers/github_check.py` as a separate
  analyzer, so an offline run degrades to `info` instead of failing. It needs a
  `GITHUB_TOKEN` for a private repo, and costs a handful of calls per repo rather
  than one per commit: the list-commits endpoint carries `commit.verification`
  for every entry, so pagination covers the whole history.
- **Identity matching is by email, not by GitHub login.** Locally, a commit
  carries an author email and nothing else. Registered emails are matched
  directly, and `<digits>+login@users.noreply.github.com` is decoded back to a
  login, but a participant who commits with an unregistered personal email shows
  up as `UNKNOWN` author, not as a mismatch. The Node version compared against
  the GitHub author login, which needs the API.
- **No status means cheating.** `UNKNOWN_KEY` is also what a forgotten
  `git config user.signingkey` looks like. The evidence dict says so in the
  finding itself, so a narrated report cannot quietly drop the caveat.

## Differences from the Node/MongoDB version

Your teammate's build and this one are the same feature on different substrates.
This one was rebuilt in Python to match `core/models.py` and spec §9 (FastAPI +
Postgres), so both features share one contract, one test suite and one runtime
instead of bridging two. What that costs, and what it would take to reconcile:

| Node version | Here | To reconcile |
|---|---|---|
| Express + Mongoose models, `/api/gpg/...` routes | library only, no service | wrap `run()` in FastAPI handlers; the analyzer needs no change |
| Mongo collections for keys and teams | roster JSON file | the roster is the same shape as a `members` collection — swap `load_roster` for a DB query |
| Per-team enrollment tokens, participant panel | not built | belongs in the registration service (§8.a), not in an analyzer |
| `POST /api/gpg/keys/<id>/revoke` | `"status": "revoked"` on the roster key | the endpoint writes the field this already reads |
| GitHub webhook with HMAC + duplicate-delivery detection | not built | belongs in the ingest service (§8.c) |
| Identity match vs. GitHub author login | vs. registered email + noreply login, plus `github.author_login_match` | done — the cross-check analyzer resolves the account |
| Per-team enrollment tokens, participant panel | `scripts/hackproof_enroll.py` + `scripts/build_roster.py` | CLI rather than a web portal; the card format is the same data the portal would POST |
| 31 Jest tests, 3 needing MongoDB | 86 pytest tests, zero external services | — |
| Judge dashboard panels | `render_table` / JSON report | the dashboard consumes `Finding` objects from either analyzer |

The practical upshot: the enrollment, webhook and dashboard layers of his build
are still wanted, and they sit *above* this module rather than inside it. They
need a storage decision first (SQLite now, Postgres per §9) — that is the next
piece of work, not a rewrite of what is here.
