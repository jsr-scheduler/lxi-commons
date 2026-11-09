Test-only TLS files, copied from JSR `crates/api-rest/tests/fixtures` (3b75827). They
protect nothing: never use them anywhere else. `tls-*.pem` is a server certificate for
localhost and 127.0.0.1, signed by the test CA `ca.pem` (whose private key was discarded).

`client-*.pem` (M3, made with openssl): a client certificate (`clientAuth`) signed by the
test CA `client-ca.pem`; `foreign-*.pem`, one signed by another CA. Both CA keys were
discarded.
