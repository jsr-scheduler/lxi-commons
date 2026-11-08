#!/usr/bin/env bash
# Builds the .deb and .rpm packages a service describes in packaging/manifest.sh.
#
#   tools/packaging/package.sh [amd64] [arm64]      # default: both
#
# Needs podman. Compiles in rust:1.90-slim-bullseye (glibc 2.31) with the cargo target in
# a podman volume, so only the packages reach dist/. Reproducible: the image is pinned by
# digest and SOURCE_DATE_EPOCH is the commit's time, so a commit gives the same packages.
# PKG_OUT (default dist) and PKG_TARGET (the target volume) are for repro-check.sh.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
cd "$root"
[[ -f packaging/manifest.sh ]] || { echo "no packaging/manifest.sh" >&2; exit 2; }
# shellcheck source=/dev/null
. packaging/manifest.sh
ARCHES=("$@")
[[ $# -eq 0 ]] && ARCHES=(amd64 arm64)
VERSION=${PKG_VERSION:-$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)}
OUTDIR=${PKG_OUT:-dist}
TARGET=${PKG_TARGET:-$NAME-pkg-target}
# rust:1.90-slim-bullseye, the multi-architecture index.
IMAGE=docker.io/library/rust@sha256:63a3432f5182b5fb2e5a0d8c2a7c189b0e35735342155a1459e735d6786007c3
EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
mkdir -p "$OUTDIR"
echo "== $NAME $VERSION for ${ARCHES[*]} (SOURCE_DATE_EPOCH=$EPOCH)"
podman run --rm -v "$root":/src:ro -v "$root/$OUTDIR":/dist -w /src \
  -v "$NAME-cargo-registry":/usr/local/cargo/registry -v "$TARGET":/build \
  -e CARGO_TARGET_DIR=/build -e VERSION="$VERSION" -e SOURCE_DATE_EPOCH="$EPOCH" \
  "$IMAGE" \
  bash /src/tools/packaging/build-in-container.sh "${ARCHES[@]}"
ls -l "$OUTDIR"
