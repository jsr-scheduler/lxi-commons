#!/bin/sh
# Protections of the public repository. Run again after any change here: every step
# replaces what is there.
#   - ruleset "main": no deletion, no force-push, changes through pull requests; owners
#     may push directly (one maintainer approves nothing of their own)
#   - ruleset "release tags": only owners create, move or delete v* tags
#   - private vulnerability reporting, Dependabot alerts, secret scanning and push
#     protection; workflow token read-only by default
set -eu
. "$(dirname "$0")/config.sh"
r="repos/$ORG/$REPO"
[ "$(gh api "$r" --jq .visibility)" = public ] || die "the repository is not public (50-publish.sh): Free has no rulesets for private ones"

# Creates the ruleset or replaces the one of that name.
ruleset() {
  name=$1 body=$2
  id=$(gh api "$r/rulesets" --jq ".[] | select(.name == \"$name\") | .id")
  if [ -n "$id" ]; then
    echo "$body" | gh api -X PUT "$r/rulesets/$id" --input - --silent
  else
    echo "$body" | gh api -X POST "$r/rulesets" --input - --silent
  fi
  echo "ruleset $name"
}
owners='[{"actor_id": 1, "actor_type": "OrganizationAdmin", "bypass_mode": "always"}]'

ruleset main "{
  \"name\": \"main\", \"target\": \"branch\", \"enforcement\": \"active\",
  \"conditions\": {\"ref_name\": {\"include\": [\"~DEFAULT_BRANCH\"], \"exclude\": []}},
  \"bypass_actors\": $owners,
  \"rules\": [
    {\"type\": \"deletion\"},
    {\"type\": \"non_fast_forward\"},
    {\"type\": \"pull_request\", \"parameters\": {
      \"required_approving_review_count\": 0, \"dismiss_stale_reviews_on_push\": true,
      \"require_code_owner_review\": false, \"require_last_push_approval\": false,
      \"required_review_thread_resolution\": true}}
  ]}"

ruleset "release tags" "{
  \"name\": \"release tags\", \"target\": \"tag\", \"enforcement\": \"active\",
  \"conditions\": {\"ref_name\": {\"include\": [\"refs/tags/v*\"], \"exclude\": []}},
  \"bypass_actors\": $owners,
  \"rules\": [{\"type\": \"creation\"}, {\"type\": \"update\"}, {\"type\": \"deletion\"},
              {\"type\": \"non_fast_forward\"}]}"

gh api -X PUT "$r/private-vulnerability-reporting" --silent
gh api -X PUT "$r/vulnerability-alerts" --silent
echo '{"security_and_analysis": {"secret_scanning": {"status": "enabled"},
       "secret_scanning_push_protection": {"status": "enabled"}}}' |
  gh api -X PATCH "$r" --input - --silent
gh api -X PUT "$r/actions/permissions/workflow" --silent \
  -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
echo "vulnerability reporting, Dependabot alerts, secret scanning, read-only token"
