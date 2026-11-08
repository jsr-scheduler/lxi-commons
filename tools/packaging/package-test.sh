#!/usr/bin/env bash
# Installs the service's package from dist/ in clean Debian 12 and Rocky Linux 9 containers
# with systemd as PID 1 and runs the service's own scenario there
# (packaging/test-scenario.sh, which installs, operates and removes the package).
#
#   tools/packaging/package.sh arm64 && tools/packaging/package-test.sh
#
# The scenario gets the package as /pkg/<file>, FAMILY (deb or rpm), PKG (that path) and
# the variables of PKG_TEST_ENV_FILE (an env file, e.g. lab passwords; never on argv).
# PKG_TEST_PODMAN_ARGS adds options to the container (e.g. --network of a lab PostgreSQL).
# Exit 0 when both families pass. Only the host's architecture: systemd cannot run as
# PID 1 under user-mode emulation.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here/../.."
# shellcheck source=/dev/null
. packaging/manifest.sh
[[ -f packaging/test-scenario.sh ]] || { echo "no packaging/test-scenario.sh" >&2; exit 2; }
arch=$(podman info --format '{{.Host.Arch}}')
case $arch in amd64) rpmarch=x86_64 ;; arm64) rpmarch=aarch64 ;; *) echo "unsupported $arch" >&2; exit 2 ;; esac
version=$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
read -r -a extra <<<"${PKG_TEST_PODMAN_ARGS:-}"
env_args=()
[[ -n ${PKG_TEST_ENV_FILE:-} ]] && env_args=(--env-file "$PKG_TEST_ENV_FILE")
status=0
for family in deb rpm; do
  if [[ $family == deb ]]; then pkg="dist/${NAME}_${version}_${arch}.deb"; else pkg="dist/${NAME}-${version}-1.${rpmarch}.rpm"; fi
  [[ -f $pkg ]] || { echo "missing $pkg (tools/packaging/package.sh $arch)" >&2; exit 2; }
  image=localhost/lxi-pkg-$family:latest
  ctr=$NAME-pkg-$family-$$
  echo "== $family: $(basename "$pkg")"
  podman build -q -t "$image" -f "$here/Containerfile.pkg-$family" "$here" >/dev/null
  podman run -d --name "$ctr" --systemd=always ${extra[@]+"${extra[@]}"} ${env_args[@]+"${env_args[@]}"} \
    -e FAMILY="$family" -e PKG="/pkg/$(basename "$pkg")" "$image" >/dev/null
  trap 'podman rm -f "$ctr" >/dev/null 2>&1 || true' EXIT
  for _ in $(seq 1 60); do
    s=$(podman exec "$ctr" systemctl is-system-running 2>/dev/null || true)
    [[ $s == running || $s == degraded ]] && break
    sleep 1
  done
  podman exec "$ctr" mkdir -p /pkg
  podman cp "$pkg" "$ctr:/pkg/"
  podman cp packaging/test-scenario.sh "$ctr:/pkg/scenario.sh"
  if podman exec "$ctr" bash /pkg/scenario.sh; then echo "PASS $family"; else echo "FAIL $family"; status=1; fi
  podman rm -f "$ctr" >/dev/null
  trap - EXIT
done
exit $status
