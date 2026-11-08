#!/bin/sh
# Makes $ORG/$REPO public. This publishes the whole history: it cannot be taken back.
# Then run 60-protect.sh at once.
set -eu
. "$(dirname "$0")/config.sh"
exists "repos/$ORG/$REPO" || die "run 40-repo.sh first"
[ "$(gh api "repos/$ORG/$REPO" --jq .visibility)" = public ] && { echo "already public"; exit 0; }

printf 'Type the repository name (%s) to make it public: ' "$ORG/$REPO"
read -r answer
[ "$answer" = "$ORG/$REPO" ] || die "stopped"
gh repo edit "$ORG/$REPO" --visibility public --accept-visibility-change-consequences
echo "public: https://github.com/$ORG/$REPO — now 60-protect.sh"
