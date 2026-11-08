# Publishing lxi-commons on GitHub

`jsr-scheduler/lxi-commons`: keys `jsr-auth` and `jsr-signing`, alias `github-jsr`,
Actions limited to GitHub's own actions pinned by SHA, read-only workflow token. The
organization, its Actions settings and the keys are set up once for the organization;
this folder only holds what is particular to this repository. Visibility: **public** (since 2026-11-08), protected by the rulesets of `60-protect.sh`.

```sh
./00-check.sh         # where things stand, drift from config.sh (read-only)
./scan-internal.sh    # nothing internal or secret in any commit (also run by the hook)
./40-repo.sh          # private repository, settings, origin, hook, scan, push main as main (asks)
#   watch the CI (gh run list --repo jsr-scheduler/lxi-commons); fix what fails
./50-publish.sh       # make it public (asks you to type the name): cannot be taken back
./60-protect.sh       # rulesets main and release tags, vulnerability reporting, secret scanning
```

## Rules

- Every commit and tag is signed with `id_jsr_signing` (this clone: `commit.gpgSign`,
  `tag.gpgSign`, identity `Ricardo Guillén <guigra@gmail.com>`). The history made before
  signing is listed by SHA in `.github/unsigned-history`.
- The pre-push hook (`pre-push`, installed by `40-repo.sh`) refuses deleting or rewriting
  `main`, anything internal or secret (`scan-internal.sh`: the series' patterns in
  `~/.config/jsr/internal-patterns`, kept outside the repository, and gitleaks), and any
  unsigned new commit. On a private repository of the Free plan GitHub enforces nothing,
  so this is the control; `git push --no-verify` skips it (a net, not a guarantee).
- The CI (`.github/workflows/ci.yml`) runs the repository's own tools on amd64 (and arm64
  once public). It is supplementary: acceptance stays local on macOS ARM64 and Linux
  AArch64, and the amd64 integration reports DEV_ONLY.

## History

The repository starts from a single signed commit (2026-11-08): the earlier local history
was kept outside the repository and is not published. `.github/unsigned-history` is
therefore empty.
