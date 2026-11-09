#!/usr/bin/env bash
# Runs inside rust:1.90-slim-bullseye for package.sh: builds the service's binaries for each
# architecture, stages the files its packaging/manifest.sh lists, and makes one .deb and
# one .rpm per architecture in /dist.
#
# Reproducible: fixed file modes, paths that do not name this machine, every timestamp from
# SOURCE_DATE_EPOCH (dpkg-deb and rpmbuild read it too).
set -euo pipefail
umask 022
: "${SOURCE_DATE_EPOCH:?set by package.sh}"
: "${VERSION:?set by package.sh}"
export SOURCE_DATE_EPOCH
cd /src
# shellcheck source=/dev/null
. packaging/manifest.sh
# Optional in the manifest.
if [[ -z ${BUILD_DEPENDS+set} ]]; then BUILD_DEPENDS=(); fi
export RUSTFLAGS="--remap-path-prefix=/src=/$NAME --remap-path-prefix=/usr/local/cargo/registry/src=/cargo --remap-path-prefix=/usr/local/cargo/git/checkouts=/cargo-git --remap-path-prefix=/usr/local/rustup=/rustup"
host=$(dpkg --print-architecture)
apt_get() { DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends "$@" >/dev/null; }
# Debian 11 left the regular mirrors when its support ended: use the archive, over https.
# Its Release files have expired, so their age is not checked; signatures still are.
if grep -q bullseye /etc/os-release; then
  rm -f /etc/apt/sources.list.d/*
  printf '%s\n' "deb https://archive.debian.org/debian bullseye main" \
    "deb https://archive.debian.org/debian-security bullseye-security main" > /etc/apt/sources.list
  echo 'Acquire::Check-Valid-Until "false";' > /etc/apt/apt.conf.d/99archive
fi
for arch in "$@"; do if [[ $arch != "$host" ]]; then dpkg --add-architecture "$arch"; fi; done
apt-get update -qq
apt_get rpm file git ca-certificates
for arch in "$@"; do
  if [[ $arch != "$host" ]]; then
    case $arch in
      amd64) apt_get gcc-x86-64-linux-gnu libc6-dev-amd64-cross ;;
      arm64) apt_get gcc-aarch64-linux-gnu libc6-dev-arm64-cross ;;
    esac
  fi
  # The libraries the service links (manifest BUILD_DEPENDS), for this architecture.
  for dep in "${BUILD_DEPENDS[@]}"; do apt_get "$dep:$arch"; done
done

triple() { case $1 in amd64) echo x86_64-unknown-linux-gnu ;; arm64) echo aarch64-unknown-linux-gnu ;; esac; }
rpmarch() { case $1 in amd64) echo x86_64 ;; arm64) echo aarch64 ;; esac; }
filearch() { case $1 in amd64) echo x86-64 ;; arm64) echo aarch64 ;; esac; }

for arch in "$@"; do
  t=$(triple "$arch")
  rustup target add "$t" >/dev/null 2>&1
  if [[ $arch != "$host" ]]; then
    gcc=$( [[ $arch == amd64 ]] && echo x86_64-linux-gnu-gcc || echo aarch64-linux-gnu-gcc )
    up=$(echo "$t" | tr 'a-z-' 'A-Z_')
    export "CARGO_TARGET_${up}_LINKER=$gcc" "CC_${t//-/_}=$gcc" "AR_${t//-/_}=${gcc%gcc}ar"
  fi
  echo "== building $NAME $VERSION for $arch ($t)"
  # shellcheck disable=SC2086
  cargo build --locked --release --target "$t" $CARGO_ARGS
  bin=/build/$t/release

  stage=/tmp/stage-$arch/$NAME
  rm -rf "/tmp/stage-$arch"
  for b in "${BINARIES[@]}"; do
    file "$bin/$b" | grep -q "$(filearch "$arch")"
    install -D -m 755 "$bin/$b" "$stage/usr/bin/$b"
  done
  # FILES: "source|destination|mode", relative to the repository and to /.
  for entry in "${FILES[@]}"; do
    IFS='|' read -r src dst mode <<<"$entry"
    install -D -m "$mode" "$src" "$stage$dst"
  done
  find "$stage" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +

  # .deb
  d=$stage
  mkdir -p "$d/DEBIAN"
  for s in postinst prerm postrm; do
    if [[ -f packaging/deb/$s ]]; then install -m 755 "packaging/deb/$s" "$d/DEBIAN/$s"; fi
  done
  : > "$d/DEBIAN/conffiles"
  for c in "${CONFFILES[@]}"; do echo "$c" >> "$d/DEBIAN/conffiles"; done
  [[ -s $d/DEBIAN/conffiles ]] || rm -f "$d/DEBIAN/conffiles"
  size=$(du -sk --exclude=DEBIAN "$d" | cut -f1)
  cat > "$d/DEBIAN/control" <<CONTROL
Package: $NAME
Version: $VERSION
Architecture: $arch
Maintainer: $MAINTAINER
Installed-Size: $size
Depends: $DEB_DEPENDS
Section: admin
Priority: optional
Homepage: $URL
Description: $SUMMARY
 $DESCRIPTION
CONTROL
  touch -h -d "@$SOURCE_DATE_EPOCH" "$d/DEBIAN" "$d/DEBIAN"/*
  dpkg-deb --root-owner-group --build "$d" "/dist/${NAME}_${VERSION}_${arch}.deb" >/dev/null
  rm -rf "$d/DEBIAN"

  # .rpm: the same tree, a spec generated from the manifest.
  top=/tmp/stage-$arch/rpm
  root=$top/SOURCES/root
  mkdir -p "$root" "$top/SPECS"
  cp -a "$stage/." "$root/"
  find "$root" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
  spec=$top/SPECS/$NAME.spec
  {
    echo "Name: $NAME"
    echo "Version: $VERSION"
    echo "Release: 1"
    echo "Summary: $SUMMARY"
    echo "License: $LICENSE"
    echo "URL: $URL"
    echo "Requires: $RPM_REQUIRES"
    echo "%global debug_package %{nil}"
    echo "%global __strip /bin/true"
    echo "%description"
    echo "$DESCRIPTION"
    echo "%install"
    echo "cp -a %{_sourcedir}/root/. %{buildroot}/"
    for s in pre post preun postun; do
      if [[ -f packaging/rpm/$s.sh ]]; then echo "%$s"; cat "packaging/rpm/$s.sh"; fi
    done
    echo "%files"
    (cd "$root" && find . -type f -o -type l | sed 's|^\.||' | LC_ALL=C sort) | while read -r f; do
      if printf '%s\n' "${CONFFILES[@]}" | grep -qxF "$f"; then echo "%config(noreplace) $f"; else echo "$f"; fi
    done
  } > "$spec"
  rpmbuild -bb --quiet --target "$(rpmarch "$arch")" \
    --define "_topdir $top" \
    --define "use_source_date_epoch_as_buildtime 1" --define "clamp_mtime_to_source_date_epoch 1" \
    --define "_buildhost reproducible" \
    --define "_rpmdir /dist" --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
    "$spec"
done
