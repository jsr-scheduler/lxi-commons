# Linux AArch64 builder for checks and PG integration tests. Never a runtime image.
# rust:1.90-slim-bookworm, arm64, pinned by digest.
FROM docker.io/library/rust@sha256:13c63e00aecdc716d04866b340403995b9ddb0e0c7fcc097dea9c62119191715
RUN rustup component add rustfmt clippy && rustc --version && cargo clippy --version && cargo fmt --version
