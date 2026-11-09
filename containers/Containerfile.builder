# Linux AArch64 builder for checks, PG and PAM integration tests. Never a runtime image.
# rust:1.90-slim-bookworm, arm64, pinned by digest. Built as localhost/lxi-builder:1.90-pam.
FROM docker.io/library/rust@sha256:13c63e00aecdc716d04866b340403995b9ddb0e0c7fcc097dea9c62119191715
RUN rustup component add rustfmt clippy && rustc --version && cargo clippy --version && cargo fmt --version
# lxi-pam links libpam (nonstick); the PAM integration test runs pam_unix as root here.
RUN apt-get update && apt-get install -y --no-install-recommends \
      libpam0g-dev=1.5.2-6+deb12u2 libpam0g=1.5.2-6+deb12u2 \
      libpam-modules=1.5.2-6+deb12u2 libpam-modules-bin=1.5.2-6+deb12u2 \
    && rm -rf /var/lib/apt/lists/* && dpkg -l libpam0g-dev libpam-modules | tail -2
