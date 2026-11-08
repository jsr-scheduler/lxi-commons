# lxi-commons — local engineering contract

Shared Rust crates for a series of IBM i-style services on Linux. One implementer; no
subagents unless explicitly authorized. Read docs/standards/RUST_ENGINEERING.md,
docs/standards/PANIC_POLICY.md, docs/standards/INHERITED_LESSONS.md and
tools/check_rust_policy.py before changes.

No crate knows a concrete service: no service schemas, no business rules. Every crate
forbids unsafe_code, unused_must_use and clippy unwrap/expect/panic/todo/unimplemented/
unreachable/indexing_slicing/string_slice/arithmetic_side_effects/as_conversions/
dbg_macro, in all targets including tests. Typed errors; fail closed; unknown input never
becomes permission. Bound frames, queues, connections, timeouts and storage. Separate
denial from unavailability.

Pin toolchain and Cargo.lock; consumers depend by git with a fixed rev. fmt, Clippy
-Dwarnings, debug/release tests, real PostgreSQL 16 integration in podman and
cargo-deny on macOS ARM64 and Linux AArch64 before a change is merged. Missing tool is
NOT_RUN/FAIL. Panic absence NOT_DEMONSTRATED. No push without the owner's request.
UTF-8 and UTC by default, configurable (series rule). Keep secrets out of Git/logs.
A change that moves code from a consumer into a crate keeps that consumer's behaviour
exactly; prove it with the consumer's own tests and a differential check.
