#!/usr/bin/env bash
# verify-tag.sh <tag> [expected-commit]: refuses a release tag that is not
#   - signed by a key of .github/allowed_signers as it is on origin/main (never the
#     tagged commit's own copy, which could add its own key), with this very name inside
#     the signed object,
#   - pointing into origin/main,
#   - equal to v<version of Cargo.toml>,
#   - still at expected-commit, if given (a tag moved after the push).
# Exit 0 only when every check passes; each refusal says which.
set -euo pipefail
tag=${1:?usage: verify-tag.sh <tag> [expected-commit]}
expected=${2:-}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
git fetch --quiet --force origin "refs/tags/$tag:refs/tags/$tag" main
git cat-file -t "$tag" | grep -qx tag || { echo "REFUSED $tag: a lightweight tag, not signed"; exit 1; }
git merge-base --is-ancestor "$tag^{commit}" origin/main || { echo "REFUSED $tag: not in main"; exit 1; }
git show origin/main:.github/allowed_signers > "$work/allowed_signers"
git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile="$work/allowed_signers" verify-tag "$tag" 2>"$work/verify" \
  || { echo "REFUSED $tag: no valid signature by an allowed key"; cat "$work/verify"; exit 1; }
# The name inside the signed object must be this tag's: a signed tag published under
# another ref name (a pre-release turned into a release, an old release reused) is refused.
signed_name=$(git cat-file tag "$tag" | sed -n 's/^tag //p' | head -1)
[[ $signed_name == "$tag" ]] || { echo "REFUSED $tag: the signed tag is named $signed_name"; exit 1; }
if [[ -n $expected ]]; then
  [[ $(git rev-parse "$tag^{commit}") == "$(git rev-parse "$expected")" ]] \
    || { echo "REFUSED $tag: no longer points at $expected"; exit 1; }
fi
version=$(git show "$tag^{commit}:Cargo.toml" | sed -n 's/^version = "\(.*\)"/\1/p' | head -1)
[[ "v$version" == "$tag" || "$tag" == "v$version"-* ]] || { echo "REFUSED $tag: Cargo.toml says $version"; exit 1; }
echo "VERIFIED $tag ($(git rev-parse --short "$tag^{commit}"), version $version)"
