#!/bin/sh
# Read-only: where the GitHub setup of this repository stands, and any drift from
# config.sh. Safe any time.
set -eu
. "$(dirname "$0")/config.sh"
ok()   { echo "  ok    $*"; }
todo() { echo "  TODO  $*"; }
same() { # <label> <wanted json> <have json>
  d=$(drift "$2" "$3")
  if [ -z "$d" ]; then ok "$1"; else echo "$d" | while IFS= read -r l; do todo "$1: $l"; done; fi
}

echo "gh"
ok "signed in as $(gh api user --jq .login)"

echo "keys and this clone"
for k in "$AUTH_KEY" "$SIGNING_KEY"; do
  if [ -f "$k.pub" ]; then ok "$k"; else todo "$k (create it with a passphrase and register it on GitHub)"; fi
done
grep -q "^Host $SSH_ALIAS\$" "$HOME/.ssh/config" 2>/dev/null && ok "Host $SSH_ALIAS" || todo "Host $SSH_ALIAS"
k=$(cut -d' ' -f2 "$SIGNING_KEY.pub")
grep -q "$k" "$ROOT/.github/allowed_signers" && ok "signing key in .github/allowed_signers" || todo "signing key not in .github/allowed_signers"
[ "$(git -C "$ROOT" config user.email || true)" = "$EMAIL" ] && ok "identity $EMAIL" || todo "identity is not $EMAIL (git config user.email)"
[ "$(git -C "$ROOT" config commit.gpgSign || true)" = true ] && ok "this clone signs commits" || todo "this clone does not sign commits"
[ -f "$PATTERNS_FILE" ] && ok "internal patterns $PATTERNS_FILE" || todo "internal patterns file $PATTERNS_FILE"

echo "repository $ORG/$REPO"
if exists "repos/$ORG/$REPO"; then
  r=$(gh api "repos/$ORG/$REPO")
  ok "$(echo "$r" | jq -r '"\(.visibility), default branch \(.default_branch)"')"
  same "settings" "$(echo "$REPO_SETTINGS" | jq 'if '"$(echo "$r" | jq .private)"' then . else del(.private) end')" "$r"
  exists "repos/$ORG/$REPO/vulnerability-alerts" && ok "Dependabot alerts" || todo "Dependabot alerts (40-repo.sh)"
  if [ "$(echo "$r" | jq -r .visibility)" = public ]; then
    n=$(gh api "repos/$ORG/$REPO/rulesets" --jq 'length')
    [ "$n" -ge 2 ] && ok "rulesets ($n)" || todo "rulesets (60-protect.sh)"
  elif [ "$FINAL_VISIBILITY" = public ]; then
    todo "public is the goal: 50-publish.sh, then 60-protect.sh"
  fi
else
  todo "not created (40-repo.sh)"
fi

echo "working tree"
[ "$(git -C "$ROOT" remote get-url origin 2>/dev/null || true)" = "$REMOTE_URL" ] && ok "origin $REMOTE_URL" || todo "origin is not $REMOTE_URL (40-repo.sh)"
[ -x "$(git -C "$ROOT" rev-parse --git-common-dir)/hooks/pre-push" ] && ok "pre-push hook" || todo "pre-push hook (40-repo.sh)"
[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] && ok "nothing uncommitted" || todo "uncommitted changes"
