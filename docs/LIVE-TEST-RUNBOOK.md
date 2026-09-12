# Live test runbook — three people, one GitHub repo

How to run HACKPROOF against a real repository with real people and real keys,
and see each check fire for the reason it is supposed to.

Three roles. One person per role, one machine per person:

| Role | Who | Signing method | On the roster? |
|---|---|---|---|
| Member A | you | OpenPGP | yes |
| Member B | your teammate | SSH | yes |
| The outsider | your third person | either — their own key | **no** |

Member A and B sign with different methods on purpose. The analyzer supports
both, the mixed case is the one least likely to have been exercised, and a
hackathon of 200 people will contain both.

---

## 0. Rehearse it alone first

Before anyone else is involved:

```bash
cd ~/Desktop/HACKPROOF
python3 -m pip install pytest
python3 -m pytest -q                 # expect: all green
./scripts/rehearse_live_test.sh      # ~20 seconds
```

The rehearsal stands up three fake machines, enrolls two of them, builds a
roster, commits honest work, runs all three attacks, and checks that the
expected flags fired — using the same scripts the live run uses. If it ends with
"Every expected flag fired", the toolchain works and anything that goes wrong on
the day is environmental, not a bug you are discovering in front of three people.

`--keep` leaves the workspace behind if you want to poke at it.

---

## 0b. What a real repo does that the fixtures don't

Three things behave differently on a live repository. All three are handled, but
knowing them means you can explain the report instead of being surprised by it.

**Pull-request merges are signed by GitHub, not by you.** If you use the "Merge
pull request" or "Squash and merge" button, GitHub signs that commit with its own
key. Those commits come back as `PLATFORM_KEY`: verified as GitHub's, not
attributed to any member, not flagged, and left out of the coverage denominator —
a merge GitHub performed is not code anyone typed. GitHub's real keys are bundled
in `analyzers/platform_keys/`, so this works offline.

If your organizer wants the strict reading instead, where any non-roster
signature is `UNKNOWN_KEY`:

```bash
HACKPROOF_NO_PLATFORM_KEYS=1 python3 -m core.engine <clone> --roster roster.json
```

For a host other than GitHub, point `$HACKPROOF_PLATFORM_KEYS` at its public key
(os.pathsep-separated for several).

**Never analyze a shallow clone.** `git clone --depth 1` hands every check one
commit, and they will all answer confidently about that one commit.
`engine.history_completeness` reports this at the top of the run — if you see it
say SHALLOW, stop and re-clone:

```bash
git clone git@github.com:team-07/project.git      # no --depth
# or, on a clone you already have:
git fetch --unshallow
```

**Ordinary RSA keys work.** Most real GPG keys are an rsa4096 primary that only
certifies, with a separate signing subkey. The commit presents the subkey's
fingerprint, the roster holds the primary, and they resolve to the same member
because the public export carries both. Confirmed with a regression test — you do
not need to do anything special at enrollment.

---

## 1. Prerequisites

Everyone:

```bash
git --version        # must be >= 2.34 for SSH signing
```

Member A and the outsider (OpenPGP):

```bash
# macOS
brew install gnupg pinentry-mac
echo 'export GPG_TTY=$(tty)' >> ~/.zshrc && source ~/.zshrc
```

That `GPG_TTY` line is the single most common reason commit signing silently
fails on macOS. Enrollment makes a real signed commit to prove signing works, so
you will find out at check-in rather than at hour 30 — but set it first anyway.

---

## 2. The organizer creates the repo

One person acts as organizer (you can be both organizer and Member A).

Create an **empty** repo on GitHub — `team-07/project`, private is fine — then:

```bash
git clone git@github.com:team-07/project.git
cd project
mkdir -p src && echo 'print("hello")' > src/app.py
git add src/app.py
git commit --no-gpg-sign -m "chore: organizer template"
git push -u origin main
git rev-parse HEAD          # <-- the BASELINE commit. Write it down.
```

That first commit is the T0 baseline from spec §7 phase 0: declared prior work,
excluded from scoring. **Record it.** If you skip it, the organizer's own
unsigned template commit counts against the team's signature coverage — a false
positive you manufactured yourself. The rehearsal script catches exactly this.

Note the time you started, in ISO 8601 — that is `T0` for the repo-metadata
check: `2026-09-12T09:00:00Z`.

---

## 3. Enrollment — each person, on their own machine

### Member A (OpenPGP)

```bash
cd ~/Desktop/HACKPROOF
python3 scripts/hackproof_enroll.py \
  --member-id satoru --name "Satoru" \
  --email satoru@example.com \
  --github-login satorugojo \
  --method gpg \
  --repo ~/code/project
```

Use the email git actually commits with (`git config user.email`), and the
GitHub login the account really has. Both are what the checks match on.

### Member B (SSH)

```bash
python3 scripts/hackproof_enroll.py \
  --member-id priyanshu --name "Priyanshu" \
  --email priyanshu@example.com \
  --github-login priyanshu-dev \
  --method ssh \
  --repo ~/code/project
```

Each run prints the key, proves it can sign, configures the clone to sign every
commit, and writes `enrollment-<id>-<method>.json`. **Send that file to the
organizer.** It holds the public half only — the script refuses to write a file
containing private key material, and the roster builder refuses to read one.

### The outsider

The outsider runs the *same* command with their own details:

```bash
python3 scripts/hackproof_enroll.py \
  --member-id eve --name "Eve" --email eve@example.com --method gpg
```

…and then **does not send the card to anyone.** That is the whole attack: a
working key that the organizer never registered.

---

## 4. The organizer builds the roster

Collect the two submitted cards, then:

```bash
python3 scripts/build_roster.py \
  --team-id team-07 \
  --baseline-commit <BASELINE SHA from step 2> \
  --out roster.json \
  enrollment-satoru-gpg.json enrollment-priyanshu-ssh.json
```

It refuses duplicate fingerprints across members, refuses private key material,
and loads the result back through the analyzer's own parser before declaring
success.

`roster.json` and `enrollment-*.json` are gitignored — they carry participants'
emails and public keys, which is personal data under the retention policy in
spec §11. Delete them after judging.

---

## 5. Honest work — the control case

Both members work normally in their clone. Signing is already configured, so
plain `git commit` is signed.

```bash
./scripts/live_test_attacks.sh legit ~/code/project \
  --method gpg --key <YOUR FINGERPRINT> --name "Satoru" --email satoru@example.com
git push
```

Then analyze, before any attack:

```bash
cd ~/Desktop/HACKPROOF
python3 -m core.engine ~/code/project --roster roster.json --skip github
```

**Everything must be `ok`.** This is the most important run in the whole test. A
tool that flags an honest team is worse than no tool, and a false positive here
is the failure mode that actually costs something. If anything fails at this
stage, stop and fix it before continuing.

---

## 6. The three attacks

Run each, then analyze, so you see one flag appear at a time.

### Attack 1 — the outsider, committing as a teammate

On the **outsider's** machine, in a clone of the repo:

```bash
./scripts/live_test_attacks.sh outsider ~/code/project \
  --method gpg --key <EVE'S FINGERPRINT> \
  --name "Satoru" --email satoru@example.com
git push
```

Expect:

```
FAIL gpg.unregistered_key  hard_flag  claim
```

Two things to be clear about, because they are the difference between a demo
that survives questions and one that does not:

- **The flag fires on the key, not on the spoofed name.** `gpg.identity_match`
  stays `ok`. That check is for a *registered* key signing under another
  member's identity — a teammate-for-teammate swap. An outsider's key is not on
  the roster at all, which is a different failure with its own check.
- **`gpg.signature_verification` also stays `ok`.** It hard-flags only on
  `INVALID_SIGNATURE`, meaning the commit object was altered after it was signed.
  You cannot produce that through GitHub — it never serves a commit whose
  signature it has already rejected — which is why
  `scripts/make_gpg_fixture_repos.sh` builds one by hand instead.

**How the commit gets pushed does not matter.** The analyzer reads local git
history offline; it does not care whose GitHub credentials ran `git push`. So
the outsider can push with their own account, or with yours, or hand you the
commit to push. What lands in the commit object — author field and signature —
is the entire input.

**Do not hand the outsider a registered member's real private key.** That case
comes back `VERIFIED`, with no flag, by design: a signature proves control of a
key, not authorship. Device binding (spec §8.e checks 6–8) is what closes that
hole and is not built. Worth demonstrating deliberately as a known limit — just
don't be surprised by it.

### Attack 2 — the `.gitignore` drip-feed

```bash
./scripts/live_test_attacks.sh dripfeed ~/code/project
git push
```

Expect:

```
FAIL gitignore.pattern_audit        hard_flag  claim
FAIL gitignore.tracked_source_ratio info       system   tracked source ratio < 1.0
```

This is **one** check, not two. The history-diffing logic lives inside
`gitignore.pattern_audit` as `evidence.late_added_rules`, and when a late-added
rule is found it raises that check's severity to `hard_flag`. There is no
separate `gitignore.late_added_rules` check. Read the evidence with
`--format json` to see the commit that added the rule and who authored it.

`tracked_source_ratio` shows `FAIL` at `info` severity. That is intentional: it
is a metric, not an accusation — the number a judge triages on.

### Attack 3 — skip-worktree

```bash
./scripts/live_test_attacks.sh skipworktree ~/code/project
git push
```

Expect:

```
FAIL gitignore.assume_unchanged_skip_worktree  hard_flag  system
```

`hard_flag` specifically because the file was edited *after* the commit that
last touched it — the "commit a stub, then edit freely" pattern. Setting the bit
without editing afterwards is only a `flag`. Note that `git status` reports a
clean tree the entire time; `git ls-files -v` is the only thing that shows it.

---

## 7. The GitHub cross-check

Everything so far runs offline. This step asks GitHub the same questions
independently — spec §8.e check 2 and §8.d check 1.

```bash
export GITHUB_TOKEN=ghp_...        # required for a private repo
python3 -m core.engine ~/code/project \
  --roster roster.json \
  --t0 2026-09-12T09:00:00Z
```

Three more checks appear:

| Check | What it asks |
|---|---|
| `github.repo_metadata` | was the repo created before T0? is it a fork? |
| `github.signature_crosscheck` | does GitHub's verdict match ours, commit by commit? |
| `github.author_login_match` | does GitHub attribute these commits to registered accounts? |

What to expect on the outsider's commit: GitHub will **also** decline to verify
it, because Eve's key is not on the account whose email authored it. Both
sources reject it independently — that is recorded as an agreement, and it is
the strongest evidence in the report.

One disagreement is expected and benign: a member who registered a key with the
organizer but never uploaded it to GitHub shows `roster_only` — HACKPROOF
verified, GitHub did not. That is recorded at `info` and never flagged. If you
want it to agree, each member uploads their public key at
GitHub → Settings → SSH and GPG keys.

Without a token, the API allows about 60 requests an hour; with one, 5000.
Everything degrades to `info` with a note if GitHub cannot be reached — bad wifi
must never render as a flag.

---

## 8. Judging from a URL alone

Everything above analyzes a checkout you have on disk. The judging path is
different: you are handed a repo URL and nothing else.

```bash
python3 scripts/analyze_repo_url.py https://github.com/team-07/project \
  --roster roster.json \
  --t0 2026-09-12T09:00:00Z \
  --out report.json
```

It clones the repo into a temp directory, runs every analyzer, prints the
report, and deletes the clone. `owner/repo`, an https URL and an ssh remote all
work. A private repo clones with whatever git credentials you already have; if
that fails and `GITHUB_TOKEN` is set it retries with the token, which is never
printed.

### What a clone can and cannot tell you

This is the part to understand before you trust a report, and the tool prints it
rather than relying on you to remember it.

**The identity half survives completely.** Signatures travel with commits, so a
commit signed by a key that is not on the roster is caught from a clone exactly
as it would be on the author's own laptop. Your "did a third person push code
here" question is fully answered by a URL:

```
FAIL gpg.unregistered_key  hard_flag  claim
```

**Most of the hiding half does not survive.** Three of the four mechanisms in
spec §8.f are system plane — they live on the participant's machine and are
never pushed:

| Check | Why a clone cannot see it |
|---|---|
| `gitignore.assume_unchanged_skip_worktree` | the bits live in the local git index; a clone builds a fresh index that cannot carry them |
| `gitignore.info_exclude` | `.git/info/exclude` is local by design and never committed |
| `gitignore.core_excludes_file` | local git config, never pushed |
| `gitignore.tracked_source_ratio` | compares tracked files against files on disk — a clone writes out exactly the tracked files, so the ratio is 1.0 by construction |

Those four report **`n/a`**, not `ok`:

```
n/a  gitignore.assume_unchanged_skip_worktree  info  system

n/a = not evaluable here, NOT clean: 4 check(s) had no evidence to read.
```

The distinction is the whole point. `ok` would tell a judge the team is clean on
a check that never ran — the same error as flagging unverifiable work, just in
the direction that flatters. To evaluate those you need the participant's own
checkout, or agent Receipts (spec §8.b). That is what the system plane is *for*,
and it is the strongest argument for shipping the local agent.

**What does survive of the hiding half:** the committed `.gitignore` and its full
history. So a rule added to hide a directory is still visible, and
`gitignore.pattern_audit` still runs and still flags ignore rules that exclude
paths where first-party source normally lives. On a clone it drops from
`hard_flag` to `flag`, because the late-added-rule logic also wants to see the
hidden files on disk and they were never pushed. Read
`evidence.clone_limitation` in the JSON for the exact boundary.

So for the drip-feed scenario — a team building behind `.gitignore` and moving
code out piece by piece — a URL gets you the suspicious rule and its history, not
the proof. Treat it as the question to put to the team, which is the framing the
whole tool is built around.

### Branches

The tool analyzes the default branch and tells you if commits exist elsewhere:

```
note: 2 commit(s) exist on other branches and were NOT analyzed.
      Branches: main, octocat-patch-1, test
      re-run with --branch <name> to analyze one of them
```

Worth checking on a real submission: an outside contributor's commit can easily
be sitting on a feature branch or an unmerged PR rather than on `main`.

## 8. Reading the final report

```bash
python3 -m core.engine ~/code/project --roster roster.json \
  --t0 2026-09-12T09:00:00Z --format json --out report.json
```

Full evidence per check: the commits involved, the raw gpg status lines, the
commit that added an ignore rule, GitHub's own reason strings. Every flag is
inspectable, which is the point — the tool supplies evidence, a human decides.

Exit code is a CI convenience, never a verdict: `0` everything passed, `1`
something did not. Ranking teams is the verdict engine's job (spec §8.i), which
is not built yet.

## What this test does not prove

State these before someone else finds them:

- A signature proves control of a key, not authorship. Everything here narrows
  *who held the key*, not who typed the code.
- A copied private key reads as `VERIFIED`. Device binding (§8.e 6–8) is the
  answer and is not implemented.
- `UNKNOWN_KEY` is also what a forgotten `git config user.signingkey` looks
  like. The evidence says so in the finding itself.
- Identity matching is by email locally; only the GitHub cross-check sees the
  actual account.
