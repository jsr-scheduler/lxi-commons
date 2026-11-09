# lxi-commons

Shared Rust crates for a series of IBM i-style services on Linux. Each crate is small,
has no knowledge of any concrete service, and follows the series standards
(docs/standards).

| Crate | What |
|---|---|
| `lxi-audit` | Verified audit export: a new 0600 file with the SHA256 of its lines, removed on any error, and bounded file hashes to compare with the service's seal |
| `lxi-exit` | The series exit codes (0, 3, 64, 69, 70, 73, 74, 75, 77) |
| `lxi-files` | Private (secret) and public (CA) files and trusted directories, walked from `/` with `openat` and checked on the descriptor that is read: no TOCTOU, trusted symlinks only, no `..` written in the path, no FIFO blocking |
| `lxi-http` | Sessions of local users with sign-in throttling, the sign-in sequence (refusals at 4 s, bounded PAM slots), and an HTTPS server with JSR's limits (header timeout, body size, concurrency, response headers) |
| `lxi-ipc` | Bounded JSON frames over Unix streams: unique keys, size and key limits checked before allocation, per-frame deadlines with `poll`, non-blocking connect and the peer UID |
| `lxi-oidc` | OIDC access tokens: asymmetric algorithms only, issuer, audience, whole-second time claims, rotating JWKS read again on an unknown `kid` |
| `lxi-pam` | Unix passwords with PAM (no `PAM_USER` change) and a yes/no root helper over `lxi-ipc` with UID checks both ways |
| `lxi-pgclient` | Synchronous PostgreSQL client with per-statement and total deadlines, server-side cancellation on timeout, a small pool, and a transport policy (Unix socket with peer check, verified TLS, explicit plaintext) |

Consumers depend by git with a fixed rev and keep their own Cargo.lock.

Checks: `python3 tools/check_rust_policy.py --project . --manifest Cargo.toml`,
`tools/check_lint_controls.py`, `tools/run_linux_policy.py`, `tools/run_deny.py`,
`tools/run_pg_integration.py --target macos|linux|host`, `tools/run_pam_integration.py`
(Linux, real PAM). The Linux builder is `localhost/lxi-builder:1.90-pam`, built from
`containers/Containerfile.builder`.
