# Packaging tools

Shared by the services of the series. A service copies this folder to its own `tools/`
(with a header line naming the lxi-commons commit) and describes itself in
`packaging/manifest.sh`:

```sh
NAME=my-service                      # package name
SUMMARY="One line"
DESCRIPTION="One paragraph."
LICENSE="MIT OR Apache-2.0"
URL=https://github.com/org/my-service
MAINTAINER="Name <email>"
CARGO_ARGS="--bin my-service"        # what cargo build --release builds
BINARIES=(my-service)                # installed in /usr/bin
FILES=("packaging/my-service.service|/usr/lib/systemd/system/my-service.service|644")
CONFFILES=()                         # files under /etc kept on upgrade and removal
DEB_DEPENDS="libc6 (>= 2.31), systemd"
RPM_REQUIRES="systemd, glibc >= 2.31"
```

Optional: `packaging/deb/{postinst,prerm,postrm}`, `packaging/rpm/{pre,post,preun,postun}.sh`,
and `packaging/test-scenario.sh` (run by `package-test.sh` inside the test containers).

| Script | What it does |
|---|---|
| `package.sh [amd64] [arm64]` | Reproducible `.deb` and `.rpm` in `dist/`, built in `rust:1.90-slim-bullseye` (glibc 2.31) pinned by digest, `SOURCE_DATE_EPOCH` from the commit |
| `repro-check.sh [arch]` | Builds twice in fresh target volumes and compares byte for byte |
| `package-test.sh` | Installs the package in Debian 12 and Rocky Linux 9 with systemd and runs the service's scenario; host architecture only |
| `verify-tag.sh <tag> [commit]` | A release tag must be signed by a key of `origin/main:.github/allowed_signers`, point into `main`, match `Cargo.toml` (or be a pre-release of it), and still name the commit built |
| `test-verify-tag.sh` | The good and the refused tags of `verify-tag.sh`, in a throwaway repository |
