#!/usr/bin/env bash
# Builds the packages twice, each in a fresh cargo target volume, and checks the two builds
# are identical byte for byte. Needs podman.
#
#   tools/packaging/repro-check.sh [amd64] [arm64]      # default: the host's architecture
#
# The packages of the first build stay in dist/repro/a, with their SHA256SUMS.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."
# shellcheck source=/dev/null
. packaging/manifest.sh
ARCHES=("$@")
[[ $# -eq 0 ]] && ARCHES=("$(podman info --format '{{.Host.Arch}}')")
export SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}
rm -rf dist/repro
cleanup() { podman volume rm -f "$NAME-repro-a" "$NAME-repro-b" >/dev/null 2>&1 || true; }
trap cleanup EXIT
for run in a b; do
  podman volume rm -f "$NAME-repro-$run" >/dev/null 2>&1 || true
  PKG_OUT="dist/repro/$run" PKG_TARGET="$NAME-repro-$run" "$here/package.sh" "${ARCHES[@]}"
  (cd "dist/repro/$run" && shasum -a 256 -- *.deb *.rpm > SHA256SUMS)
done
if diff dist/repro/a/SHA256SUMS dist/repro/b/SHA256SUMS; then
  echo "REPRODUCIBLE: $(wc -l < dist/repro/a/SHA256SUMS | tr -d ' ') packages identical"
else
  echo "NOT REPRODUCIBLE: the packages above differ (compare them with diffoscope)"
  exit 1
fi
