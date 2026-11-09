# M2 — lxi-oidc, lxi-pam y lxi-http — plan de implementación

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:executing-plans (inline; AGENTS.md
> prohíbe subagentes). Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** tres crates de la serie para que `ab-admind` (M3) autentique personas y
aplicaciones por HTTPS como JSR: tokens OIDC, contraseñas Unix por PAM (también a través de
un ayudante con root) y sesiones con límites de intentos, sobre un servidor TLS acotado.

**Architecture:** código de JSR `3b75827` adaptado sin tocar JSR: `api-rest/src/auth.rs` →
`lxi-oidc`; `auth-local/src/lib.rs` → `lxi-pam`; `api-rest/src/sessions.rs`, el inicio de
sesión y `serve_tls` de `api-rest/src/lib.rs` → `lxi-http`. Ningún crate conoce un servicio:
la identidad sale como datos (`Verified`, `Account`) y cada servicio decide qué perfil es.
`lxi-pam` y `lxi-http` no dependen uno de otro: `lxi-http` define el puerto `LocalUsers` y
el servicio lo conecta con `lxi-pam`.

**Tech Stack:** Rust 1.90 (edición 2021 del workspace), las versiones de JSR fijadas con
`=`: `jsonwebtoken =9.3.1`, `nonstick =0.1.2`, `axum =0.8.x`, `axum-server =0.8.x`,
`rustls =0.23.x` (ring), `hyper-util`, `tokio`, `getrandom =0.2.x`, `sha2`, `base64` (las
exactas del `Cargo.lock` de JSR).

**Spec:** `../authority-broker/docs/superpowers/specs/2026-11-09-ibmi-authority-model-and-management-design.md`
§3.2 (identidad) y §4 punto 2.

## Global Constraints

- AGENTS.md de lxi-commons: lints del workspace en todos los targets (incluido
  `as_conversions`), errores tipados, cerrar ante la duda, todo acotado, separar denegación
  de indisponibilidad, sin `unsafe` propio (el de `nonstick` y `ring` es de dependencias).
- Mismo comportamiento que JSR en cada regla portada; cada test de JSR que la cubre se
  porta con sus aserciones (nombres abajo). Lo que cambia respecto a JSR es solo la forma
  (tipos genéricos en vez de `Principal`) y va en el ledger como `Ruling:`.
- Constantes de JSR, exactas: leeway 60 s; relectura por `kid` desconocido como mucho cada
  30 s; sesión inactiva 30 min, vida 12 h, 1024 sesiones, 16 por usuario; refresco 45 s,
  cada 15 s, caducada sin refresco a los 180 s; ventana 15 min, 5 fallos por dirección, 50
  por usuario, 50 000 claves por tabla, 100 intentos por segundo; rechazo en 4 s; 16
  inicios de sesión a la vez; consulta de cuenta 10 s, 4 a la vez; cuerpo 64 KiB;
  cabeceras 10 s; usuario 1–64 bytes `[A-Za-z0-9._@-]`, contraseña 1–1024 bytes.
- Ayudante PAM: frames de `lxi-ipc` con `Limits::SERIES`; la contraseña en `Zeroizing` y
  borrada con `scrub` después de usarla.
- Gates en macOS ARM64 y Linux AArch64 antes del merge: `tools/check_rust_policy.py`,
  `tools/run_linux_policy.py --output …`, `tools/check_lint_controls.py --output …`,
  `tools/run_deny.py --output …`, `tools/run_pg_integration.py` (sin cambios: no hay PG
  nuevo) y el nuevo `tools/run_pam_integration.py` en Linux.
- Nada se sube sin que lo pida el propietario; JSR no se modifica; el broker no cambia en M2.

## Review Focus

1. Un token firmado con HS256 usando la clave pública como secreto: rechazado aunque el
   JWKS tenga la clave (prueba en Task 1).
2. Un `nbf`/`exp` como cadena: rechazado, no ignorado (GHSA-h395-gr6q-cpjc; Task 1).
3. Un módulo PAM que cambia `PAM_USER`: rechazado, nunca se acepta otra cuenta (Task 2).
4. Fallos simultáneos mientras PAM aún responde: cuentan antes de la respuesta, no pasan
   del límite (Task 3).
5. El ayudante: una petición más grande que el frame, un UID distinto del permitido o un
   cliente que no envía nada no bloquean ni llegan a PAM (Task 2).

---

### Task 1: lxi-oidc

**Files:**
- Create: `crates/lxi-oidc/{Cargo.toml,src/lib.rs}`, `crates/lxi-oidc/tests/verify.rs`,
  `crates/lxi-oidc/tests/fixtures/` (copias de `jwks.json`, `jwks-rotated.json`,
  `trusted.pem`, `rotated.pem`, `foreign.pem` y su README, de JSR)
- Modify: `Cargo.toml` (miembro), `Cargo.lock`

**Interfaces:**
- Produces:
  - `pub struct Settings { issuer, audience: String, algorithms: Vec<String>,
    jwks_file: PathBuf, subject_claim, groups_claim, application_claim,
    application_value: String }`
  - `pub enum Kind { User, Application }`
  - `pub struct Verified { pub kind: Kind, pub name: String, pub sub: String,
    pub groups: BTreeSet<String>, pub expires: i64 }`
  - `pub struct Verifier`: `new(&Settings, jwks: &str) -> Result<Self, ConfigError>`,
    `from_file(&Settings)`, `with_read_interval(Duration)`, `reload() -> Result<usize, _>`,
    `verify(&str) -> Result<Verified, TokenError>`
  - `ConfigError { Jwks, Algorithm, NoKeys, Read, NoFile }`,
    `TokenError { Missing, Malformed, UnknownKey, Invalid(String), NoSubject,
    NoSubjectClaim(String) }`

- [ ] **Step 1: portar los tests** de `jsr api-rest/tests/rest.rs`: `a_valid_token_gives_a_user_principal_with_groups`,
  `an_application_token_is_a_technical_client`, `invalid_tokens_are_rejected` (incluye
  `typ: ID`, `nbf` cadena, emisor, audiencia, caducado, clave ajena),
  `hmac_algorithms_cannot_be_configured`, `the_subject_claim_names_the_principal`,
  `a_bad_jwks_file_on_reload_keeps_the_keys_in_use`,
  `an_unknown_kid_reads_the_file_again_at_most_once_per_interval`; y uno nuevo
  `an_hs256_token_signed_with_the_public_key_is_rejected`. Afirman sobre `Verified`
  (`kind`, `name`, `groups`) donde JSR afirmaba sobre `Principal`.
- [ ] **Step 2:** `cargo test -p lxi-oidc` → no compila (crate vacío). Esperado: FAIL.
- [ ] **Step 3: implementar** `src/lib.rs` desde `auth.rs`: mismas validaciones y orden;
  el aviso de relectura sale por un `log: fn(&str)` opcional en vez de `eprintln!` con
  `jsrd:` (el servicio pone su prefijo).
- [ ] **Step 4:** `cargo test -p lxi-oidc` → PASS; `tools/check_rust_policy.py` → CHECKS_PASS.
- [ ] **Step 5: commit** `lxi-oidc: OIDC access tokens as JSR verifies them`.

### Task 2: lxi-pam y su ayudante

**Files:**
- Create: `crates/lxi-pam/{Cargo.toml,src/lib.rs,src/helper.rs}`,
  `crates/lxi-pam/tests/pam.rs`, `tools/run_pam_integration.py`
- Modify: `containers/Containerfile.builder` (añade `libpam0g-dev`), `Cargo.toml`,
  `Cargo.lock`, `deny.toml` solo si `nonstick` o `nix` lo piden

**Interfaces:**
- Produces:
  - `pub struct Account { pub name: String, pub uid: u32, pub groups: BTreeSet<String>,
    pub superuser: bool }`; `pub fn account_of_uid(uid, gid) -> Result<Account, String>`,
    `pub fn lookup(user: &str) -> Result<Option<Account>, AuthError>`
  - `pub enum AuthError { Rejected(String), Unavailable(String) }`
  - `pub struct Pam { service: String }`: `new(service)`,
    `authenticate(&self, user, password) -> Result<Account, AuthError>` (JSR
    `PamUsers::authenticate`: PAM también para nombres inexistentes, `account_management`,
    comprobación de `PAM_USER`).
  - `helper::serve(stream: UnixStream, pam: &Pam, allowed_uid: u32) -> Result<(), lxi_ipc::Error>`:
    comprueba `peer_uid`, lee un frame `{"v":1,"user","password"}` (`exact`, `text` 64 y
    1024), responde `{"v":1,"result":"accepted"|"rejected"|"unavailable"}` y nada más
    (sin grupos ni motivo); borra la contraseña.
  - `helper::Client { socket: PathBuf }`: `authenticate(user, password) ->
    Result<Account, AuthError>`: pregunta al ayudante y, si acepta, `lookup(user)` en el
    propio proceso (no hace falta root para leer grupos). Socket que no responde o
    respuesta mal formada: `Unavailable`.

- [ ] **Step 1: tests unitarios** portados de `auth-local`:
  `the_current_user_has_a_principal_with_groups`, `an_unknown_user_is_rejected`, el
  `#[ignore]` `a_wrong_password_is_rejected` (con `LXI_TEST_PAM_USER`, nunca el usuario que
  corre los tests); y del ayudante, con un `Pam` de prueba detrás de un trait interno:
  `the_helper_refuses_another_uid_before_reading`,
  `the_helper_answers_only_yes_or_no`, `an_oversized_frame_never_reaches_pam`,
  `a_silent_client_is_dropped_at_the_deadline`, `the_client_treats_garbage_as_unavailable`.
- [ ] **Step 2:** `cargo test -p lxi-pam` → FAIL (no existe).
- [ ] **Step 3: implementar** `lib.rs` desde `auth-local` y `helper.rs` sobre `lxi-ipc`.
- [ ] **Step 4:** macOS `cargo test -p lxi-pam` → PASS (los `#[ignore]` no corren).
- [ ] **Step 5: integración real en Linux.** `tools/run_pam_integration.py --output DIR`:
  en el builder (como root, `--network=none`, efímero) crea `lxitest` con contraseña
  aleatoria, `/etc/pam.d/lxi-test` con `pam_unix`, y corre los `#[ignore]` de
  `tests/pam.rs`: `right_password_is_accepted`, `wrong_password_is_rejected`,
  `unknown_user_is_rejected`, `a_locked_account_is_rejected` (`passwd -l`),
  `the_helper_accepts_through_its_socket`. Mismo formato de evidencia que
  `run_linux_policy.py` (comandos, códigos, SHA256).
  Esperado: todos PASS.
- [ ] **Step 6: commit** `lxi-pam: PAM passwords as JSR checks them, and a yes/no helper`.

### Task 3: lxi-http — sesiones e inicio de sesión

**Files:**
- Create: `crates/lxi-http/{Cargo.toml,src/lib.rs,src/sessions.rs,src/sign_in.rs}`
- Modify: `Cargo.toml`, `Cargo.lock`

**Interfaces:**
- Produces:
  - `pub trait LocalUsers: Send + Sync + 'static { type Account: Clone + Send + Sync;
    fn authenticate(&self, user, password) -> Result<Self::Account, LocalAuthError>;
    fn lookup(&self, user) -> Result<Option<Self::Account>, LocalAuthError>;
    fn name(account: &Self::Account) -> &str;
    fn eligible(&self, account: &Self::Account) -> Result<(), &'static str>; }`
    (JSR comprobaba uid 0 y grupos de `[roles]` dentro de `Sessions`; aquí lo hace el
    servicio en `eligible`, con la misma regla).
  - `LocalAuthError { Rejected, Unavailable }`, `SignInError { Rejected, Throttled,
    Unavailable, Full }`
  - `pub struct Sessions<U: LocalUsers>`: `new(users: Arc<U>, token_prefix: &'static str)`,
    `with_user_failure_limit`, `with_lasting_user_failures`, `begin`, `check`, `open`,
    `verify`, `current`, `start_refreshing`, `due`, `refreshed`, `close`, `live_keys`;
    `pub struct Active<A> { pub account: A, pub remaining: Duration }`
  - `sign_in::SignIn<U>`: `new(Arc<Sessions<U>>)`,
    `async fn attempt(&self, user: &str, password: Zeroizing<String>, peer: IpAddr) ->
    Result<(String, U::Account), SignInError>` (validación, `begin`, 16 a la vez,
    `spawn_blocking`, rechazo a los 4 s desde el comienzo, `open`);
    `pub fn valid_user_name`, `pub fn throttle_address`;
    `async fn refresh(sessions: Arc<Sessions<U>>)` (bucle de refresco de JSR).

- [ ] **Step 1: portar los 18 tests de `sessions.rs`** (líneas 471–872 de JSR, mismos
  nombres y aserciones, con un `LocalUsers` de prueba) y de `tests/rest.rs`
  `a_refused_sign_in_takes_as_long_whatever_the_password` (tiempo de tokio en pausa)
  más `the_user_name_and_password_bounds_are_enforced`,
  `an_ipv6_address_is_throttled_by_its_64`, `a_refresh_that_times_out_keeps_the_session_until_stale`.
- [ ] **Step 2:** `cargo test -p lxi-http` → FAIL.
- [ ] **Step 3: implementar** desde JSR: genérico sobre `U`, `principal.name` →
  `U::name(&account)`, `eligible` → `self.users.eligible`.
- [ ] **Step 4:** `cargo test -p lxi-http` → PASS.
- [ ] **Step 5: commit** `lxi-http: sessions and sign-in throttling as JSR has them`.

### Task 4: lxi-http — servidor TLS y piezas de petición

**Files:**
- Create: `crates/lxi-http/src/server.rs`, `crates/lxi-http/tests/server.rs`,
  `crates/lxi-http/tests/fixtures/{tls-cert.pem,tls-key.pem}` (de JSR)

**Interfaces:**
- Produces:
  - `pub async fn serve_tls(listen: SocketAddr, cert: &Path, key: &Path, app: axum::Router,
    handle: axum_server::Handle<SocketAddr>) -> std::io::Result<()>`: proveedor ring,
    cabeceras en 10 s, `ConnectInfo<SocketAddr>`.
  - `pub fn limits(app: Router) -> Router`: cuerpo 64 KiB y las cabeceras de seguridad de
    JSR (`nosniff`, `no-store`, `Referrer-Policy`, `X-Frame-Options`, HSTS).
  - `pub fn bearer(headers: &HeaderMap) -> Option<&str>`,
    `pub fn session_cookie(name: &str, value: &str, max_age: Option<u64>) -> Option<HeaderValue>`
    (`HttpOnly; Secure; SameSite=Strict; Path=/`), `pub fn cookie<'h>(headers, name) -> Option<&'h str>`.

- [ ] **Step 1: tests:** `a_client_that_never_finishes_its_headers_is_dropped`,
  `a_body_over_64_kib_is_refused`, `every_response_carries_the_security_headers`,
  `bearer_and_cookie_are_read_and_nothing_else_is_trusted`,
  `the_session_cookie_is_http_only_secure_and_strict`, y uno de extremo a extremo con un
  cliente rustls contra `serve_tls` en `127.0.0.1:0`.
- [ ] **Step 2:** `cargo test -p lxi-http --test server` → FAIL.
- [ ] **Step 3: implementar** desde `serve_tls` y las capas de JSR `lib.rs`.
- [ ] **Step 4:** `cargo test -p lxi-http` → PASS.
- [ ] **Step 5: docs y gates.** `docs/design/2026-11-09-oidc-pam-http.md` (como las de
  2026-11-08: qué viene de JSR y las decisiones mías) y README (crates nuevos). Gates de
  Global Constraints en los dos targets, con evidencia en `build/evidence/m2-*`.
- [ ] **Step 6: commit** `lxi-http: TLS server with JSR's limits; M2 docs`.

## Fuera de M2

mTLS para aplicaciones y el binario `ab-pam-helper` con su unidad systemd (activación por
socket, `SocketUser`/`SocketMode=0600`) son de M3, en el broker, sobre estas piezas.
