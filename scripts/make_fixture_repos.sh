#!/usr/bin/env bash
# Build throwaway git repos that exercise every mechanism analyzers/gitignore_check.py
# looks for, so the analyzer can be eyeballed end-to-end before integration.
#
#   ./scripts/make_fixture_repos.sh [dest_dir]     # default: /tmp/hackproof-fixtures
#
# Creates:
#   <dest>/clean-repo   nothing hidden  -> every check should pass
#   <dest>/dirty-repo   all four hiding mechanisms in use
#
# Nothing outside <dest> is touched: core.excludesFile is set repo-locally, so
# your real ~/.gitconfig is left alone.
set -euo pipefail

DEST="${1:-/tmp/hackproof-fixtures}"
rm -rf "$DEST"
mkdir -p "$DEST"

export GIT_AUTHOR_NAME="Fixture Author"   GIT_AUTHOR_EMAIL="author@example.test"
export GIT_COMMITTER_NAME="Fixture Author" GIT_COMMITTER_EMAIL="author@example.test"

BENIGN_IGNORE=$'node_modules/\n__pycache__/\n*.pyc\n.env\ndist/\n'

# ---------------------------------------------------------------- clean repo
CLEAN="$DEST/clean-repo"
mkdir -p "$CLEAN/src"
git -C "$CLEAN" init -q -b main
printf '%s' "$BENIGN_IGNORE"          > "$CLEAN/.gitignore"
printf '# fixture\n'                  > "$CLEAN/README.md"
printf 'def main():\n    return 42\n' > "$CLEAN/src/main.py"
printf 'VALUE = 1\n'                  > "$CLEAN/src/utils.py"
git -C "$CLEAN" add -A
git -C "$CLEAN" commit -qm "initial commit"

# ---------------------------------------------------------------- dirty repo
DIRTY="$DEST/dirty-repo"
mkdir -p "$DIRTY/src"
git -C "$DIRTY" init -q -b main
printf '%s' "$BENIGN_IGNORE"     > "$DIRTY/.gitignore"
printf '# fixture\n'             > "$DIRTY/README.md"
printf 'STUB = True\n'           > "$DIRTY/src/app.py"
printf 'HELPER = 1\n'            > "$DIRTY/src/helper.py"
git -C "$DIRTY" add -A
git -C "$DIRTY" commit -qm "initial commit"

# (1) .gitignore: a rule added LATE that hides a directory full of real source
mkdir -p "$DIRTY/engine"
printf 'def solve():\n    return "the real work"\n' > "$DIRTY/engine/solver.py"
printf 'WEIGHTS = [1, 2, 3]\n'                      > "$DIRTY/engine/weights.py"
printf '%sengine/\n' "$BENIGN_IGNORE" > "$DIRTY/.gitignore"
git -C "$DIRTY" add -A
git -C "$DIRTY" commit -qm "tidy up ignores"

# (2) .git/info/exclude: local-only, never committed, invisible to reviewers
mkdir -p "$DIRTY/vendor_src"
printf 'def borrowed():\n    pass\n' > "$DIRTY/vendor_src/borrowed.py"
printf '# local excludes\nvendor_src/\n' >> "$DIRTY/.git/info/exclude"

# (3) core.excludesFile: an ignore file living outside the repo entirely
printf 'src_hidden/\n*.ts\n' > "$DEST/global_ignore"
git -C "$DIRTY" config core.excludesFile "$DEST/global_ignore"
printf 'export const secret = 1;\n' > "$DIRTY/src/secret.ts"

# (4) skip-worktree: commit a stub, then edit the file freely with no diff shown
git -C "$DIRTY" update-index --skip-worktree src/app.py
printf 'REAL = "the actual implementation"\n' > "$DIRTY/src/app.py"
python3 - "$DIRTY/src/app.py" <<'PY'
import os, sys, time
t = time.time() + 600          # unambiguously after the commit timestamp
os.utime(sys.argv[1], (t, t))
PY

echo "fixtures built:"
echo "  clean: $CLEAN"
echo "  dirty: $DIRTY"
echo
echo "expected result for dirty-repo:"
echo "  gitignore.pattern_audit                  claim   hard_flag  (engine/ added late over existing source)"
echo "  gitignore.info_exclude                   system  hard_flag  (vendor_src/)"
echo "  gitignore.core_excludes_file             system  hard_flag  (src_hidden/, *.ts -> src/secret.ts)"
echo "  gitignore.assume_unchanged_skip_worktree system  hard_flag  (src/app.py edited after commit)"
echo "  gitignore.tracked_source_ratio           system  info       (ratio well below 1.0)"
