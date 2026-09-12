#!/usr/bin/env bash
# Rehearse the whole three-person live test on one machine, start to finish.
#
# Before you get three people and a GitHub repo into a room, run this. It walks
# the real tooling -- the real enrollment CLI, the real roster builder, the real
# attack scripts, the real engine -- with three isolated fake "machines" standing
# in for three laptops:
#
#   satoru     a registered member, signing with OpenPGP
#   priyanshu  a registered member, signing with SSH
#   eve        an outsider, holding a key nobody registered
#
# Everything lives under one throwaway directory. Your ~/.gnupg, your ~/.ssh and
# your global git config are never read or written.
#
#   ./scripts/rehearse_live_test.sh
#   ./scripts/rehearse_live_test.sh --keep      # leave the workspace for poking at
#
# The run asserts its own expectations at the end, so a green finish means the
# toolchain works and the flags fire where they should.

set -euo pipefail

KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="$(mktemp -d "/tmp/hackproof-rehearsal-XXXXXX")"
export HACKPROOF_ROSTER=""   # never inherit a roster from the caller's shell

# Three isolated "machines".
SATORU_HOME="$ROOT/machines/satoru"
PRIYANSHU_HOME="$ROOT/machines/priyanshu"
EVE_HOME="$ROOT/machines/eve"
mkdir -p "$SATORU_HOME/gnupg" "$PRIYANSHU_HOME/ssh" "$EVE_HOME/gnupg"
chmod 700 "$SATORU_HOME/gnupg" "$EVE_HOME/gnupg"

SATORU_EMAIL="satoru@example.test"
PRIYANSHU_EMAIL="priyanshu@example.test"

cleanup() {
  for home in "$SATORU_HOME/gnupg" "$EVE_HOME/gnupg"; do
    GNUPGHOME="$home" HOME="$home" gpgconf --kill gpg-agent >/dev/null 2>&1 || true
  done
  if [ "$KEEP" = "1" ]; then
    echo
    echo "workspace kept at $ROOT"
  else
    rm -rf "$ROOT"
  fi
}
trap cleanup EXIT

rule() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

# ---------------------------------------------------------------------------
rule "1. enrollment -- what each participant runs on their own machine"

GNUPGHOME="$SATORU_HOME/gnupg" HOME="$SATORU_HOME" \
  python3 "$HERE/scripts/hackproof_enroll.py" \
    --member-id satoru --name "Satoru" --email "$SATORU_EMAIL" \
    --github-login satorugojo --method gpg \
    --out "$ROOT/enrollment-satoru.json" | sed 's/^/  [satoru]    /'

HOME="$PRIYANSHU_HOME" \
  python3 "$HERE/scripts/hackproof_enroll.py" \
    --member-id priyanshu --name "Priyanshu" --email "$PRIYANSHU_EMAIL" \
    --github-login priyanshu-dev --method ssh \
    --key-path "$PRIYANSHU_HOME/ssh/id_hackproof" \
    --out "$ROOT/enrollment-priyanshu.json" | sed 's/^/  [priyanshu] /'

# Eve enrolls too -- but with the organizer she never talks to, so her card is
# generated and then deliberately thrown away. She still needs a working key.
GNUPGHOME="$EVE_HOME/gnupg" HOME="$EVE_HOME" \
  python3 "$HERE/scripts/hackproof_enroll.py" \
    --member-id eve --name "Eve" --email "eve@example.test" --method gpg \
    --out "$ROOT/enrollment-eve-NEVER-SUBMITTED.json" | sed 's/^/  [eve]       /'

SATORU_FPR=$(python3 -c "import json;print(json.load(open('$ROOT/enrollment-satoru.json'))['key']['fingerprint'])")
PRIYANSHU_KEY="$PRIYANSHU_HOME/ssh/id_hackproof.pub"
EVE_FPR=$(python3 -c "import json;print(json.load(open('$ROOT/enrollment-eve-NEVER-SUBMITTED.json'))['key']['fingerprint'])")

# ---------------------------------------------------------------------------
rule "2. the team repo, created from the organizer's template"

REPO="$ROOT/project"
git init -q -b main "$REPO"
git -C "$REPO" config user.name "Team"
git -C "$REPO" config user.email "team@example.test"
git -C "$REPO" remote add origin "https://github.com/team-07/project.git"
mkdir -p "$REPO/src"
printf 'print("hello")\n' > "$REPO/src/app.py"
git -C "$REPO" add src/app.py
git -C "$REPO" commit -q --no-gpg-sign -m "chore: organizer template"
BASELINE=$(git -C "$REPO" rev-parse HEAD)
echo "  baseline (template) commit $BASELINE"

# ---------------------------------------------------------------------------
rule "3. the organizer builds the roster from the cards that were submitted"

# --baseline-commit matters: spec §7 phase 0 declares the template commit as the
# T0 baseline and excludes it from scoring. Without it, the organizer's own
# unsigned template commit counts against the team's signature coverage -- which
# is a false positive manufactured by the organizer, against an honest team.
python3 "$HERE/scripts/build_roster.py" \
  --team-id team-07 --baseline-commit "$BASELINE" --out "$ROOT/roster.json" \
  "$ROOT/enrollment-satoru.json" "$ROOT/enrollment-priyanshu.json" | sed 's/^/  /'
echo "  (eve's card was never submitted -- her key is not on the roster)"

# ---------------------------------------------------------------------------
rule "4. honest work by both registered members"

GNUPGHOME="$SATORU_HOME/gnupg" HOME="$SATORU_HOME" \
  "$HERE/scripts/live_test_attacks.sh" legit "$REPO" \
    --method gpg --key "$SATORU_FPR" --name "Satoru" --email "$SATORU_EMAIL" \
  | sed 's/^/  /'

HOME="$PRIYANSHU_HOME" \
  "$HERE/scripts/live_test_attacks.sh" legit "$REPO" \
    --method ssh --key "$PRIYANSHU_KEY" --name "Priyanshu" --email "$PRIYANSHU_EMAIL" \
  | sed 's/^/  /'

rule "4b. checkpoint: an honest repo must come back clean"
set +e
CLEAN_REPORT=$(python3 -m core.engine "$REPO" --roster "$ROOT/roster.json" --skip github 2>&1)
set -e
echo "$CLEAN_REPORT" | sed 's/^/  /'
if echo "$CLEAN_REPORT" | grep -qE "^FAIL .*(hard_flag|flag) "; then
  echo
  echo "  !! REHEARSAL FAILED: the honest repo produced a flag." >&2
  echo "     A false positive against an honest team is the expensive failure here." >&2
  exit 1
fi
if echo "$CLEAN_REPORT" | grep -qE "^FAIL +gpg\.signature_coverage"; then
  echo
  echo "  note: coverage is below threshold but nothing is flagged. Coverage is a" >&2
  echo "        metric, not an accusation -- check the baseline_commit is set." >&2
fi

# ---------------------------------------------------------------------------
rule "5. attack 1 -- the outsider, committing as Satoru with her own key"

GNUPGHOME="$EVE_HOME/gnupg" HOME="$EVE_HOME" \
  "$HERE/scripts/live_test_attacks.sh" outsider "$REPO" \
    --method gpg --key "$EVE_FPR" --name "Satoru" --email "$SATORU_EMAIL" \
  | sed 's/^/  /'

rule "6. attack 2 -- the .gitignore drip-feed"
"$HERE/scripts/live_test_attacks.sh" dripfeed "$REPO" | sed 's/^/  /'

rule "7. attack 3 -- skip-worktree"
"$HERE/scripts/live_test_attacks.sh" skipworktree "$REPO" | sed 's/^/  /'

# ---------------------------------------------------------------------------
rule "8. the verdict"

set +e
REPORT=$(python3 -m core.engine "$REPO" --roster "$ROOT/roster.json" --skip github 2>&1)
set -e
echo "$REPORT"

rule "9. checking the rehearsal against what it promised"

fail=0
expect_fail() {
  if echo "$REPORT" | grep -qE "^FAIL +$1 +$2"; then
    printf '  ok    %-44s %s\n' "$1" "$2"
  else
    printf '  MISS  %-44s expected %s\n' "$1" "$2"
    fail=1
  fi
}
# The outsider lands on unregistered_key, NOT on signature_verification:
# signature_verification hard-flags only on INVALID_SIGNATURE, which means the
# commit object was altered after signing. An unregistered key is a different
# failure with a different check, and conflating the two would teach a judge to
# read the report wrong. (A forged commit object cannot be pushed through GitHub
# at all -- see scripts/make_gpg_fixture_repos.sh, which builds one by hand.)
expect_fail "gpg.unregistered_key"                     "hard_flag"
expect_fail "gitignore.pattern_audit"                  "hard_flag"
expect_fail "gitignore.assume_unchanged_skip_worktree" "hard_flag"

echo
if [ "$fail" = "0" ]; then
  echo "  Every expected flag fired. The toolchain is ready for the live run."
  echo
  echo "  Next, on the real repo, add the GitHub cross-check:"
  echo "    export GITHUB_TOKEN=...   # needed for a private repo"
  echo "    python3 -m core.engine <clone> --roster roster.json --t0 <event start ISO8601>"
else
  echo "  Some expected flags did not fire -- see MISS above." >&2
  exit 1
fi
