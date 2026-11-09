Test-only keys, copied from JSR `crates/api-rest/tests/fixtures` (3b75827). They protect
nothing: never use them anywhere else. `trusted.pem` signs valid tokens and its public half
is `jwks.json`; `foreign.pem` signs tokens that must be rejected.

`rotated.pem` stands for the issuer's next key after a rotation: its public half is the
second key, `test-key-2`, of `jwks-rotated.json`, whose first key is that of `jwks.json`.
