# Sourced by every script here. One place for the names. The organization, its Actions
# settings (GitHub's own actions pinned by SHA, read-only token) and the keys are set up
# once for the whole organization.
ORG=jsr-scheduler
REPO=lxi-commons
GH_USER=guigra
MAINTAINER="Ricardo Guillén"
EMAIL=guigra@gmail.com

AUTH_KEY="$HOME/.ssh/id_jsr_auth"        # git push/pull through the alias below
SIGNING_KEY="$HOME/.ssh/id_jsr_signing"  # signs commits and tags
SSH_ALIAS=github-jsr                     # Host in ~/.ssh/config: only AUTH_KEY
REMOTE_URL="git@$SSH_ALIAS:$ORG/$REPO.git"
# The branch that becomes main on GitHub.
LOCAL_BRANCH=main
# Regular expressions that must never be published; outside the repository on purpose
# (shared by the whole series).
PATTERNS_FILE="$HOME/.config/jsr/internal-patterns"
# Visibility this repository is meant to end with (public: 50-publish.sh, 60-protect.sh).
FINAL_VISIBILITY=private

# The repository (PATCH /repos/{org}/{repo}).
REPO_SETTINGS='{
  "private": true,
  "description": "Shared Rust crates for IBM i-style services on Linux: PostgreSQL client with real deadlines, TOCTOU-free files, bounded IPC frames, exit codes, verified audit export",
  "has_wiki": false,
  "has_projects": false,
  "allow_merge_commit": false,
  "allow_squash_merge": true,
  "allow_rebase_merge": true,
  "delete_branch_on_merge": true,
  "squash_merge_commit_title": "PR_TITLE",
  "squash_merge_commit_message": "PR_BODY"
}'
TOPICS="rust postgresql ibm-i linux security"

# The repository's working tree: the parent of this folder.
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)

die() { echo "error: $*" >&2; exit 1; }
# True when a GET of the API path answers 2xx.
exists() { gh api "$1" >/dev/null 2>&1; }
# Asks before anything that cannot be taken back.
confirm() {
  printf '%s [y/N] ' "$1"
  read -r answer
  [ "$answer" = y ] || [ "$answer" = Y ] || die "stopped"
}
# Prints "key: wanted X, have Y" for each key of $1 (JSON) that differs in $2 (JSON).
drift() {
  jq -rn --argjson want "$1" --argjson have "$2" \
    '$want | to_entries[] | select($have[.key] != .value) | "\(.key): wanted \(.value), have \($have[.key])"'
}
