#!/bin/sh
# scan-internal.sh [<revision range>...]: looks for what must never be published.
#   - every pattern of $PATTERNS_FILE (outside the repository), case-insensitive, in the
#     added lines and the messages of the commits, and in their author and committer
#   - gitleaks over the same commits (.gitleaksignore lists the reviewed test keys)
# With no range: every commit of every branch and tag. Exits 1 on any finding, showing
# the commit and the file but never the matching text (it may be the secret).
set -eu
. "$(dirname "$0")/config.sh"
[ -f "$PATTERNS_FILE" ] || die "no $PATTERNS_FILE"
[ $# -gt 0 ] || set -- --all
cd "$ROOT"

patterns=$(mktemp)
trap 'rm -f "$patterns"' EXIT
grep -v -e '^#' -e '^[[:space:]]*$' "$PATTERNS_FILE" > "$patterns"

found=0
# Added lines, messages and identities, commit by commit.
for c in $(git rev-list "$@"); do
  if git log -1 --format='%an %ae %cn %ce%n%B' "$c" | grep -qiEf "$patterns"; then
    echo "INTERNAL  ${c%"${c#????????????}"} message or identity"
    found=1
  fi
  files=$(git show --format= --unified=0 --no-color --diff-merges=first-parent "$c" |
    awk '/^\+\+\+ b\// {f = substr($0, 7)} /^\+[^+]/ {print f "\t" substr($0, 2)}' |
    grep -iEf "$patterns" | cut -f1 | sort -u || true)
  for f in $files; do
    echo "INTERNAL  ${c%"${c#????????????}"} $f"
    found=1
  done
done
echo "patterns: $(git rev-list "$@" | wc -l | tr -d ' ') commits checked"

if command -v gitleaks >/dev/null 2>&1; then
  if [ "$1" = --all ]; then opts=--all; else opts="$*"; fi
  gitleaks git --no-banner --redact --log-opts="$opts" . >/dev/null 2>&1 \
    || { echo "SECRET    gitleaks: gitleaks git --redact --log-opts='$opts' ."; found=1; }
  echo "gitleaks: done"
else
  echo "gitleaks not installed: brew install gitleaks"; found=1
fi
[ "$found" -eq 0 ] && echo "nothing internal found" || exit 1
