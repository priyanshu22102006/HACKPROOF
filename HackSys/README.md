# HackSys — the system-plane agent for HackProof

HackProof reviews a hackathon submission from two independent angles:

| plane | what it looks at | where it runs |
|---|---|---|
| **system** (this repo) | what actually happened on the participant's machine during the window | the participant's laptop, for the length of the event |
| **repo** | the submitted public GitHub repository | the HackProof server |

Each plane produces a report. The server hands both to the LLM comparator,
which writes the final review by looking for agreement and disagreement
between them. A repo that looks impeccable but was assembled by copying files
in from `~/Downloads` is exactly the case neither plane catches alone.

This repository is plane 1.

---

## What it records

The agent is a LaunchAgent running as the participant — no root, no kernel
extension, nothing hidden. Seven collectors write to one append-only log:

| collector | what it answers |
|---|---|
| `filesystem` | What changed on disk, and did anything in the submission already exist somewhere else on this machine? |
| `clipboard` | Did a copy happen, where was it copied from, and did that content later land in a project file? |
| `git` | Every commit, its signature, its diffstat, plus amends, resets, rebases, pushes and force pushes — read from git's own reflogs |
| `gpg` | Which signing keys existed at the start, and did that change mid-event? |
| `process` | Watchlisted process launches, foreground application changes, and any screen-sharing or remote-control tool |
| `integrity` | Is the agent itself still running, is its log intact, and has the system clock been moved? |

### What it deliberately does not record

No keystrokes. No screenshots. No audio. No browsing history or page content.
No clipboard *text* — only its SHA-256, its length, its shape and which app
was focused. No file contents — only hashes. Nothing outside the configured
watch roots.

`hacksys init` prints this list and refuses to run until the participant
types *I agree*. The consent, and the hash of the text they agreed to, is the
first event in the log.

---

## Why the log is worth anything

The participant owns the machine, so the log cannot be made tamper-*proof*.
It is made tamper-*evident* instead: every event hashes over its predecessor,
so deleting a line, editing one, or reordering two breaks the chain from that
point on, and `hacksys verify` names the line where it broke.

The other half of that guarantee is coverage. The agent heartbeats to disk
every fifteen seconds and into the log every five minutes. If it is killed,
the *next* start notices the gap and records how long it was blind. The report
leads with coverage for that reason: a report from an agent that ran for 40%
of the window is not a clean report, and it says so.

---

## Install

Requires Python 3.11+ and macOS.

```bash
git clone <this repo> HackSys && cd HackSys
python3 -m venv .venv && source .venv/bin/activate
pip install -e .

hacksys doctor      # checks deps and macOS permissions
```

Two macOS permissions matter, both requested from System Settings → Privacy
& Security:

- **Full Disk Access** for the Python binary — without it, parts of the home
  folder cannot be watched, and the report will say the coverage was partial.
- **Accessibility** — only for reading the name of the foreground app. Skip it
  and everything else still works.

## Use

```bash
# 1. set up, review the consent notice, agree.
#    Only --project is required; everything else has a sensible default.
hacksys init --participant satoru --project ~/Desktop/my-submission --hours 12

# the full form, once you have the event's details:
export HACKPROOF_TOKEN=...          # --token reads this if you omit the flag
hacksys init \
  --participant satoru \
  --team nitrkl-07 \
  --event hackfest-2026 \
  --project ~/Desktop/my-submission \
  --start 2026-09-13T09:00:00+05:30 \
  --end   2026-09-14T21:00:00+05:30 \
  --gpg-fingerprint 3AA5C34371567BD2 \
  --server https://hackproof.example.com

# 2. run it in the background for the whole event
hacksys install

# 3. any time during the event
hacksys status
hacksys events --tail 30 --severity notice

# 4. when the window closes and the repo is submitted
hacksys seal --submit
```

`seal` stops the agent, verifies the chain, runs every check, writes
`~/.hacksys/reports/latest.md` and `latest.json`, and POSTs to
`POST {server}/api/v1/reports/system`. If the network is down it spools to
disk; `hacksys submit --retry` drains the spool later.

### Other commands

```
hacksys start              run in the foreground instead of via launchd
hacksys report             render the report without sealing
hacksys verify             check the hash chain
hacksys uninstall          remove the launchd job
```

---

## The report

`reports/latest.md` is written to be read by a judge in five minutes:

1. **What this report says** — one of *clear*, *notes*, *review*, *significant
   questions*, plus the disclaimer.
2. **Monitoring coverage** — percentage of the window observed, and every gap
   with its reason.
3. **Checks** — fifteen named checks, each with a plain-English explanation and
   a table of the evidence behind it.
4. **Timeline** — every above-routine event, in order.
5. **How to verify** — the chain tip and the command to re-check it.

`reports/latest.json` carries the same content as `Finding` objects:

```python
Finding(check_name, plane, severity, evidence, passed)
```

— the same contract the HackProof repo-plane analyzers emit, so the two planes
merge without translation.

### The checks

| check | question |
|---|---|
| `log_chain_integrity` | Was the log itself altered? |
| `monitoring_coverage` | Was the agent running for the whole window? |
| `system_clock_integrity` | Was the system clock moved? |
| `collector_health` | Did every collector actually work? |
| `external_code_ingestion` | Do submission files match files that already existed elsewhere? |
| `clipboard_code_movement` | Did clipboard content end up in submission files? |
| `reference_repository_copying` | Was a second repo on this machine used as a source? |
| `downloaded_code_provenance` | Did downloaded files land in the submission, and from which URL? |
| `commit_signing` | Were commits signed, and by the registered key? |
| `history_rewriting` | Were commits amended, reset, rebased, or force-pushed? |
| `commit_timeline` | Do commit dates fall inside the window? |
| `gitignore_hidden_code` | Were source files hidden from git mid-event? |
| `signing_key_stability` | Did signing material change during the event? |
| `monitoring_environment` | Did anything interfere with the agent? |
| `assistant_tooling_context` | Was AI tooling in use? (context only, never fails) |

---

## A note on interpretation

Nothing this agent records proves misconduct, and the report never claims
otherwise.

A byte-identical file means a copy happened — vendored libraries, framework
scaffolding and a participant's own earlier work all produce it. A valid GPG
signature proves control of a key, not authorship. An amended commit is an
amended commit. A large commit is often just `package-lock.json`.

Every check therefore reports *what was observed* plus the events behind it,
and the summary says at most that there are questions worth asking. The
decision belongs to a human who can ask the participant about it.

---

## Development

```bash
pip install -e ".[dev]"
pytest                      # unit tests
python scripts/simulate.py  # end-to-end: builds a sandbox, misbehaves in it,
                            # runs the agent, prints the resulting report
```

`scripts/simulate.py` creates a throwaway project, copies a file in from a
fake Downloads folder, copies another in from a second git clone, makes an
unsigned commit, amends it, and hides a source file with `.gitignore` — then
seals and prints the report. It touches nothing outside its sandbox.

## Layout

```
hacksys/
  models.py         Event and Finding — the contract shared with HackProof
  config.py         TOML config, defaults, exclusion list
  eventlog.py       append-only hash-chained log + verifier
  context.py        shared state: clipboard index, file-hash index
  daemon.py         supervisor, signal handling, pid file
  analysis.py       events -> Findings
  report.py         Findings -> Markdown + JSON
  transport.py      upload with offline spool
  install_macos.py  launchd plist
  cli.py            the `hacksys` command
  collectors/       filesystem, clipboard, git_activity, gpg_watch,
                    process_watch, integrity
```
