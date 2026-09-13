#!/usr/bin/env bash
# Build GPG signature fixtures for analyzers/gpg_check.py.
#
# Creates two repos and one roster, all under /tmp, touching nothing outside it:
#
#   clean-repo  every commit signed by a registered key, author matches  -> all info
#   dirty-repo  one commit per failure mode                              -> flags
#
# Keys are generated in a throwaway GNUPGHOME inside the fixture directory, so
# your real ~/.gnupg is never read or written.
#
#   ./scripts/make_gpg_fixture_repos.sh
#   python3 analyzers/gpg_check.py /tmp/hackproof-gpg-fixtures/clean-repo \
#       --roster /tmp/hackproof-gpg-fixtures/roster.json
#   python3 analyzers/gpg_check.py /tmp/hackproof-gpg-fixtures/dirty-repo \
#       --roster /tmp/hackproof-gpg-fixtures/roster.json
#
# Or run both analyzers together through the engine:
#   python3 -m core.engine /tmp/hackproof-gpg-fixtures/dirty-repo \
#       --roster /tmp/hackproof-gpg-fixtures/roster.json

set -euo pipefail

ROOT="${HACKPROOF_FIXTURE_ROOT:-/tmp/hackproof-gpg-fixtures}"
export GNUPGHOME="$ROOT/gnupg"

rm -rf "$ROOT"
mkdir -p "$GNUPGHOME"
chmod 700 "$GNUPGHOME"

gpg_q() { gpg --batch --no-tty --yes --pinentry-mode loopback --passphrase "" "$@"; }

fingerprint_of() {
  gpg_q --with-colons --fingerprint "$1" | awk -F: '/^fpr:/ {print $10; exit}'
}

echo "==> generating keys in $GNUPGHOME"
gpg_q --quick-generate-key "Satoru <satoru@example.test>"       ed25519 sign 0 >/dev/null 2>&1
gpg_q --quick-generate-key "Priyanshu <priyanshu@example.test>" ed25519 sign 0 >/dev/null 2>&1
gpg_q --quick-generate-key "Outsider <outsider@example.test>"   ed25519 sign 0 >/dev/null 2>&1

SATORU_FPR=$(fingerprint_of "satoru@example.test")
PRIYANSHU_FPR=$(fingerprint_of "priyanshu@example.test")
OUTSIDER_FPR=$(fingerprint_of "outsider@example.test")

echo "    satoru    $SATORU_FPR"
echo "    priyanshu $PRIYANSHU_FPR"
echo "    outsider  $OUTSIDER_FPR   (deliberately NOT registered)"

# --- roster: the two team members only ---------------------------------------
python3 - "$ROOT/roster.json" "$SATORU_FPR" "$PRIYANSHU_FPR" <<'PY'
import json, subprocess, sys

out_path, satoru_fpr, priyanshu_fpr = sys.argv[1:4]

def export(fpr):
    return subprocess.run(
        ["gpg", "--batch", "--no-tty", "--armor", "--export", fpr],
        stdout=subprocess.PIPE, check=True,
    ).stdout.decode()

roster = {
    "team_id": "fixture-team",
    "members": [
        {
            "member_id": "satoru",
            "display_name": "Satoru",
            "github_login": "satorugojo",
            "emails": ["satoru@example.test"],
            "keys": [{
                "key_id": "satoru-k1",
                "fingerprint": satoru_fpr,
                "public_key": export(satoru_fpr),
                "status": "active",
            }],
        },
        {
            "member_id": "priyanshu",
            "display_name": "Priyanshu",
            "github_login": "priyanshu22102006",
            "emails": ["priyanshu@example.test"],
            "keys": [{
                "key_id": "priyanshu-k1",
                "fingerprint": priyanshu_fpr,
                "public_key": export(priyanshu_fpr),
                "status": "active",
            }],
        },
    ],
}
with open(out_path, "w", encoding="utf-8") as handle:
    json.dump(roster, handle, indent=2)
print(f"    roster -> {out_path}")
PY

init_repo() {
  local dir="$1"
  mkdir -p "$dir"
  git -C "$dir" init -q -b main
  git -C "$dir" config user.name "Fixture Author"
  git -C "$dir" config user.email "author@example.test"
  git -C "$dir" config commit.gpgsign false
  git -C "$dir" config gpg.program gpg
}

# sign_commit <repo> <file> <message> <fingerprint> <author-email>
sign_commit() {
  local dir="$1" file="$2" msg="$3" fpr="$4" email="$5"
  printf '# %s\nvalue = 1\n' "$msg" > "$dir/$file"
  git -C "$dir" add -A
  GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_EMAIL="$email" \
  GIT_AUTHOR_NAME="$email" GIT_COMMITTER_NAME="$email" \
    git -C "$dir" -c "user.signingkey=$fpr" -c commit.gpgsign=true \
      commit -S -q -m "$msg"
}

# plain_commit <repo> <file> <message> <author-email>
plain_commit() {
  local dir="$1" file="$2" msg="$3" email="$4"
  printf '# %s\nvalue = 1\n' "$msg" > "$dir/$file"
  git -C "$dir" add -A
  GIT_AUTHOR_EMAIL="$email" GIT_COMMITTER_EMAIL="$email" \
  GIT_AUTHOR_NAME="$email" GIT_COMMITTER_NAME="$email" \
    git -C "$dir" commit --no-gpg-sign -q -m "$msg"
}

# --- clean repo ---------------------------------------------------------------
echo "==> building clean-repo"
CLEAN="$ROOT/clean-repo"
init_repo "$CLEAN"
sign_commit "$CLEAN" "app.py"    "add entry point"   "$SATORU_FPR"    "satoru@example.test"
sign_commit "$CLEAN" "parser.py" "add parser"        "$PRIYANSHU_FPR" "priyanshu@example.test"
sign_commit "$CLEAN" "utils.py"  "add helpers"       "$SATORU_FPR"    "satoru@example.test"

# --- dirty repo: one commit per failure mode ---------------------------------
echo "==> building dirty-repo"
DIRTY="$ROOT/dirty-repo"
init_repo "$DIRTY"

# 1. VERIFIED baseline, so the report has something clean in it too.
sign_commit "$DIRTY" "app.py" "honest signed work" "$SATORU_FPR" "satoru@example.test"

# 2. NO_SIGNATURE -- zero provenance, not an accusation.
plain_commit "$DIRTY" "unsigned.py" "unsigned work" "satoru@example.test"

# 3. UNKNOWN_KEY -- signed by a key that is not on the roster.
sign_commit "$DIRTY" "outside.py" "from an unregistered key" "$OUTSIDER_FPR" "satoru@example.test"

# 4. IDENTITY_MISMATCH -- Satoru's key signs a commit authored as Priyanshu.
sign_commit "$DIRTY" "teammate.py" "committed as a teammate" "$SATORU_FPR" "priyanshu@example.test"

# 5. INVALID_SIGNATURE -- rewrite a signed commit's message, keep its gpgsig.
sign_commit "$DIRTY" "tampered.py" "SIGNED-MESSAGE" "$SATORU_FPR" "satoru@example.test"
git -C "$DIRTY" cat-file commit HEAD | sed 's/SIGNED-MESSAGE/TAMPERED-MESSAGE/' > "$ROOT/forged-commit"
FORGED=$(git -C "$DIRTY" hash-object -t commit -w --stdin < "$ROOT/forged-commit")
git -C "$DIRTY" update-ref refs/heads/main "$FORGED"
echo "    forged commit $FORGED (bad signature)"

cat <<EOF

Fixtures ready under $ROOT

  roster      $ROOT/roster.json
  clean-repo  $CLEAN    (expect: all six checks info / passed)
  dirty-repo  $DIRTY    (expect: hard_flag on signature_verification +
                         unregistered_key, flag on identity_match,
                         verified_ratio well under 1.0)

Run them:
  python3 -m core.engine $CLEAN --roster $ROOT/roster.json
  python3 -m core.engine $DIRTY --roster $ROOT/roster.json

Clean up (kills the fixture gpg-agent first):
  gpgconf --kill gpg-agent; rm -rf $ROOT
EOF
