Test-only TLS files, copied from JSR `crates/api-rest/tests/fixtures` (3b75827). They
protect nothing: never use them anywhere else. `tls-*.pem` is a server certificate for
localhost and 127.0.0.1, signed by the test CA `ca.pem` (whose private key was discarded).
