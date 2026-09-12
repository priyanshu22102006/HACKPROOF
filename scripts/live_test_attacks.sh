#!/usr/bin/env bash
# Perform one HACKPROOF attack scenario against a real repository.
#
# Each subcommand makes real commits in a real repo -- point it at a clone of the
# team's GitHub repo and push afterwards. Nothing here touches ~/.gnupg, ~/.ssh
# or your global git config: signing identity is passed per-invocation with
# `git -c`, so running an attack never leaves your machine configured as the
# attacker.
#
#   ./scripts/live_test_attacks.sh legit    <repo> --method gpg --key <FPR> \
#                                                  --name "Satoru" --email satoru@example.com
#   ./scripts/live_test_attacks.sh outsider <repo> --method gpg --key <EVE_FPR> \
#                                                  --name "Satoru" --email satoru@example.com
#   ./scripts/live_test_attacks.sh dripfeed <repo>
#   ./scripts/live_test_attacks.sh skipworktree <repo>
#
# --method ssh takes a path to the PUBLIC half for --key, exactly as
# `git config user.signingkey` does for SSH signing.
#
# What each one should produce is printed at the end of the run, so the
# expectation is on screen next to the result rather than in a doc somewhere.

set -euo pipefail

usage() {
  sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-1}"
}

REPO=""; METHOD="gpg"; KEY=""; NAME=""; EMAIL=""
CMD="${1:-}"; shift || usage 1
case "$CMD" in
  legit|outsider|dripfeed|skipworktree) ;;
  -h|--help|help) usage 0 ;;
  *) echo "unknown subcommand: $CMD" >&2; usage 1 ;;
esac

REPO="${1:-}"; shift || true
[ -n "$REPO" ] || { echo "a repository path is required" >&2; usage 1; }
[ -d "$REPO/.git" ] || { echo "$REPO is not a git repository" >&2; exit 1; }

while [ $# -gt 0 ]; do
  case "$1" in
    --method) METHOD="$2"; shift 2 ;;
    --key)    KEY="$2";    shift 2 ;;
    --name)   NAME="$2";   shift 2 ;;
    --email)  EMAIL="$2";  shift 2 ;;
    *) echo "unknown option: $1" >&2; usage 1 ;;
  esac
done

# Signing identity is applied per-command, never written to the repo's config.
sign_args() {
  if [ "$METHOD" = "ssh" ]; then
    printf '%s\n' -c gpg.format=ssh -c "user.signingkey=$KEY"
  else
    printf '%s\n' -c gpg.format=openpgp -c "user.signingkey=$KEY"
  fi
}

commit_as() {
  # commit_as <message> <signed:yes|no>
  local message="$1" signed="$2"
  local -a args=()
  if [ "$signed" = "yes" ]; then
    [ -n "$KEY" ] || { echo "--key is required to sign" >&2; exit 1; }
    mapfile -t args < <(sign_args)
    GIT_AUTHOR_NAME="$NAME" GIT_AUTHOR_EMAIL="$EMAIL" \
    GIT_COMMITTER_NAME="$NAME" GIT_COMMITTER_EMAIL="$EMAIL" \
      git -C "$REPO" "${args[@]}" commit -S -q -m "$message"
  else
    GIT_AUTHOR_NAME="$NAME" GIT_AUTHOR_EMAIL="$EMAIL" \
    GIT_COMMITTER_NAME="$NAME" GIT_COMMITTER_EMAIL="$EMAIL" \
      git -C "$REPO" commit -q --no-gpg-sign -m "$message"
  fi
  git -C "$REPO" rev-parse --short HEAD
}

need_identity() {
  [ -n "$NAME" ]  || { echo "--name is required"  >&2; exit 1; }
  [ -n "$EMAIL" ] || { echo "--email is required" >&2; exit 1; }
}

case "$CMD" in

  legit)
    need_identity
    echo "==> honest signed commit as $NAME <$EMAIL>"
    mkdir -p "$REPO/src"
    printf 'def feature_%s():\n    return "written during the event"\n' "$RANDOM" \
      >> "$REPO/src/app.py"
    git -C "$REPO" add src/app.py
    SHA=$(commit_as "feat: work by $NAME" yes)
    echo "    $SHA signed with $METHOD key $KEY"
    echo
    echo "Expect: gpg.signature_verification VERIFIED, gpg.identity_match MATCH,"
    echo "        no flag of any kind. This is the control case -- a check that"
    echo "        flags an honest team is worse than no check at all."
    ;;

  outsider)
    # Spec §8.e check 4: a key nobody registered signs code in the repo. The
    # author field is set to a registered teammate, which is what makes it an
    # impersonation rather than just an unknown contributor -- but note that the
    # flag fires on the *key*, not on the spoofed name.
    need_identity
    echo "==> outsider commit, authored as $NAME <$EMAIL>, signed with an UNREGISTERED key"
    mkdir -p "$REPO/src"
    cat >> "$REPO/src/secret_helper.py" <<'PY'


def written_by_someone_outside_the_team():
    """Committed under a teammate's name by a person who is not on the roster."""
    return "this key was never enrolled"
PY
    git -C "$REPO" add src/secret_helper.py
    SHA=$(commit_as "feat: add helper" yes)
    echo "    $SHA authored as $EMAIL, signed with $METHOD key $KEY"
    echo
    echo "Expect: FAIL gpg.unregistered_key  hard_flag  (commit status UNKNOWN_KEY)"
    echo "        gpg.signature_verification stays 'ok' -- it hard-flags only on"
    echo "        INVALID_SIGNATURE, meaning a commit object altered after signing."
    echo "        The flag is raised by the key being off the roster, NOT by the"
    echo "        spoofed author name. If this person had used a registered"
    echo "        member's actual private key it would read as VERIFIED --"
    echo "        that hole is device binding (§8.e 6-8), which is not built."
    ;;

  dripfeed)
    # Spec §8.f: the rule is added *after* the code exists, so the diff across
    # history is what gives it away, not the .gitignore as it stands today.
    echo "==> drip-feed: pre-written code hidden by a late .gitignore rule"
    if [ ! -f "$REPO/.gitignore" ]; then
      printf '__pycache__/\n*.pyc\n' > "$REPO/.gitignore"
      git -C "$REPO" add .gitignore
      NAME="${NAME:-Team}" EMAIL="${EMAIL:-team@example.com}" commit_as "chore: add gitignore" no >/dev/null
    fi

    mkdir -p "$REPO/modules/prebuilt"
    cat > "$REPO/modules/prebuilt/engine.py" <<'PY'
"""Written weeks before the event and carried in wholesale."""


class PrebuiltEngine:
    def solve(self, problem):
        return "answer"
PY
    cat > "$REPO/modules/prebuilt/models.py" <<'PY'
class PrebuiltModel:
    weights = "trained long before T0"
PY
    echo "    wrote modules/prebuilt/{engine,models}.py into the working tree"

    printf '\n# build artifacts\nmodules/prebuilt/\n' >> "$REPO/.gitignore"
    git -C "$REPO" add .gitignore
    SHA=$(NAME="${NAME:-Team}" EMAIL="${EMAIL:-team@example.com}" commit_as "chore: ignore build artifacts" no)
    echo "    $SHA added 'modules/prebuilt/' to .gitignore, AFTER the code was on disk"
    echo
    echo "Expect: FAIL gitignore.pattern_audit  hard_flag"
    echo "        evidence.late_added_rules names the commit that added the rule,"
    echo "        and gitignore.tracked_source_ratio drops below 1.0."
    echo "        Note this is ONE check, not two -- the history finding and the"
    echo "        current-state finding share the pattern_audit check, and the"
    echo "        worse severity wins."
    ;;

  skipworktree)
    # Spec §8.f: invisible unless someone runs `git ls-files -v`. Commit a stub,
    # flag it, then edit freely -- git shows a clean tree the whole time.
    echo "==> skip-worktree: commit a stub, then edit it with the bit set"
    mkdir -p "$REPO/modules"
    cat > "$REPO/modules/secret_sauce.py" <<'PY'
def solve():
    return None  # TODO
PY
    git -C "$REPO" add modules/secret_sauce.py
    SHA=$(NAME="${NAME:-Team}" EMAIL="${EMAIL:-team@example.com}" commit_as "wip: stub solver" no)
    echo "    $SHA committed the stub"

    git -C "$REPO" update-index --skip-worktree modules/secret_sauce.py
    echo "    set skip-worktree on modules/secret_sauce.py"

    # The check compares the file's mtime against its last commit with a 2s
    # tolerance, so the edit has to land outside that window to read as
    # "edited after being flagged" rather than as part of the commit.
    sleep 3
    cat > "$REPO/modules/secret_sauce.py" <<'PY'
def solve(problem):
    """The real implementation, which git will never show as modified."""
    return complex_solution(problem)


def complex_solution(problem):
    return "the actual work, invisible to git status"
PY
    echo "    rewrote the file; 'git status' still reports a clean tree:"
    git -C "$REPO" status --short || true
    echo
    echo "Expect: FAIL gitignore.assume_unchanged_skip_worktree  hard_flag"
    echo "        hard_flag specifically because the file was modified AFTER the"
    echo "        commit that last touched it. Setting the bit without editing"
    echo "        afterwards is only a 'flag'."
    ;;
esac

echo
echo "Now analyze it:"
echo "  python3 -m core.engine $REPO --roster <roster.json>"
