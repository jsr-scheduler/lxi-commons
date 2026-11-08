#!/usr/bin/env bash
# Exercises verify-tag.sh in a throwaway repository with its own origin and keys: a good
# signed tag and a pre-release pass; a lightweight tag, an unsigned one, one signed by
# another key, one outside main and one whose version differs are refused.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ssh-keygen -q -t ed25519 -N '' -C good -f "$work/good"
ssh-keygen -q -t ed25519 -N '' -C other -f "$work/other"
git init -q --bare "$work/origin.git"
git init -q -b main "$work/repo"
cd "$work/repo"
git config user.name test; git config user.email test@example.invalid
git config gpg.format ssh; git config tag.gpgSign false; git config commit.gpgSign false
mkdir .github
echo "test@example.invalid namespaces=\"git\" $(cut -d' ' -f1,2 "$work/good.pub")" > .github/allowed_signers
printf '[package]\nname = "t"\nversion = "0.1.0"\n' > Cargo.toml
git add -A && git commit -q -m one
git remote add origin "$work/origin.git"
git push -q origin main
sign() { git -c user.signingkey="$work/$1.pub" tag -s -m "$2" "$2" "${3:-HEAD}"; }
fail=0
expect() { # <pass|refuse> <tag>
  if "$here/verify-tag.sh" "$2" >"$work/out" 2>&1; then got=pass; else got=refuse; fi
  if [[ $got == "$1" ]]; then echo "ok    $1 $2"; else echo "WRONG $2: wanted $1, got $got"; cat "$work/out"; fail=1; fi
}
sign good v0.1.0; git push -q origin v0.1.0; expect pass v0.1.0
sign good v0.1.0-rc.1; git push -q origin v0.1.0-rc.1; expect pass v0.1.0-rc.1
git tag v0.1.0-light; git push -q origin v0.1.0-light; expect refuse v0.1.0-light
git tag -a -m unsigned v0.1.0-unsigned; git push -q origin v0.1.0-unsigned; expect refuse v0.1.0-unsigned
sign other v0.1.0-other; git push -q origin v0.1.0-other; expect refuse v0.1.0-other
git switch -q -c side; echo x > x; git add x; git commit -q -m side; git push -q origin side
sign good v0.1.0-side; git push -q origin v0.1.0-side; expect refuse v0.1.0-side
git switch -q main; sign good v0.2.0; git push -q origin v0.2.0; expect refuse v0.2.0
exit $fail
