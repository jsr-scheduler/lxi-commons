#!/bin/sh
# Creates $ORG/$REPO as a PRIVATE repository with REPO_SETTINGS, Dependabot alerts and
# security updates and its topics; sets `origin` to $REMOTE_URL (the SSH alias);
# installs the pre-push hook; scans the whole history (scan-internal.sh); pushes
# $LOCAL_BRANCH as main (asks first). Can be run again.
#
# On the Free plan a private repository has no rulesets and no arm64 runners: the hook
# does on this machine what a ruleset would do, and the CI runs on amd64 only.
set -eu
. "$(dirname "$0")/config.sh"

if exists "repos/$ORG/$REPO"; then
  echo "$ORG/$REPO exists"
else
  gh repo create "$ORG/$REPO" --private --disable-wiki >/dev/null
  echo "$ORG/$REPO created (private)"
fi
echo "$REPO_SETTINGS" | gh api -X PATCH "repos/$ORG/$REPO" --input - --silent
gh api -X PUT "repos/$ORG/$REPO/vulnerability-alerts" --silent
gh api -X PUT "repos/$ORG/$REPO/automated-security-fixes" --silent
for t in $TOPICS; do set -- "$@" --add-topic "$t"; done
gh repo edit "$ORG/$REPO" "$@" >/dev/null
echo "settings, Dependabot alerts and security updates, topics"

if git -C "$ROOT" remote get-url origin >/dev/null 2>&1; then
  git -C "$ROOT" remote set-url origin "$REMOTE_URL"
else
  git -C "$ROOT" remote add origin "$REMOTE_URL"
fi
hook="$(git -C "$ROOT" rev-parse --git-common-dir)/hooks/pre-push"
case "$hook" in /*) ;; *) hook="$ROOT/$hook";; esac
cp "$HERE/pre-push" "$hook" && chmod 755 "$hook"
echo "origin $REMOTE_URL; pre-push hook installed"

[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ] || die "uncommitted changes: commit them first"
"$HERE/scan-internal.sh" || die "something internal in the history: not pushing"

echo "local $LOCAL_BRANCH at $(git -C "$ROOT" log --oneline -1 "$LOCAL_BRANCH")"
confirm "push $LOCAL_BRANCH to $ORG/$REPO (private) as main?"
git -C "$ROOT" push origin "$LOCAL_BRANCH:main"
git -C "$ROOT" branch --set-upstream-to=origin/main "$LOCAL_BRANCH"
gh repo edit "$ORG/$REPO" --default-branch main
echo "pushed; CI: gh run list --repo $ORG/$REPO"
