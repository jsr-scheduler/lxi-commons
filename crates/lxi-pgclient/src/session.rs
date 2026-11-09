//! One PostgreSQL session with real client deadlines. A statement that runs out of
//! time is cancelled on the server before `Timeout` is returned, and the session is
//! marked broken so a pool never reuses it.

use crate::budget::Budget;
use crate::error::{Error, Result};
use crate::policy::{classify, Policy, Transport};
use std::future::Future;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::runtime::{Builder, Runtime};
use tokio_postgres::config::{Host, SslMode};
use tokio_postgres::types::ToSql;
use tokio_postgres::{CancelToken, Client, NoTls, Row};
use tokio_postgres_rustls::MakeRustlsConnect;
use zeroize::Zeroizing;

const CA_LIMIT: u64 = 65536;
pub const DEFAULT_TIMEZONE: &str = "UTC";

/// How to reach PostgreSQL. Deliberately not `Debug`: the DSN carries a password.
#[derive(Clone)]
pub struct Settings {
    pub dsn: Zeroizing<String>,
    /// PEM CA bundle; when present TLS is required and verified against it alone.
    pub ca_file: Option<PathBuf>,
    pub policy: Policy,
    /// Session time zone (IANA), UTC by default (series rule); PostgreSQL validates it.
    pub timezone: String,
    /// TCP user timeout on Linux (unacknowledged data before the kernel drops the
    /// connection). `None` uses the per-statement limit.
    pub tcp_user_timeout: Option<Duration>,
    /// The password, kept out of the DSN (for example read from a private file). A DSN
    /// that also has one is refused.
    pub password: Option<Zeroizing<String>>,
}

impl Settings {
    pub fn new(dsn: Zeroizing<String>, ca_file: Option<PathBuf>, policy: Policy) -> Self {
        Self {
            dsn,
            ca_file,
            policy,
            timezone: DEFAULT_TIMEZONE.to_owned(),
            tcp_user_timeout: None,
            password: None,
        }
    }

    /// The TCP user timeout a session with `budget` uses.
    pub fn user_timeout(&self, budget: &Budget) -> Duration {
        self.tcp_user_timeout.unwrap_or(budget.statement)
    }
}

/// A CA bundle, read by lxi-files: walked with `openat` through trusted directories,
/// regular (no symlink, no FIFO), of root or the service user, not writable by group
/// or others, at most 64 KiB.
fn read_ca(path: &Path) -> Result<Vec<u8>> {
    lxi_files::read_public(path, CA_LIMIT).map_err(|_| Error::Configuration)
}

fn tls(ca_file: &Path) -> Result<MakeRustlsConnect> {
    use rustls_pki_types::pem::PemObject;
    let pem = read_ca(ca_file)?;
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pki_types::CertificateDer::pem_slice_iter(&pem) {
        roots
            .add(certificate.map_err(|_| Error::Configuration)?)
            .map_err(|_| Error::Configuration)?;
    }
    if roots.is_empty() {
        return Err(Error::Configuration);
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Error::Configuration)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

fn server_error(error: &tokio_postgres::Error) -> Error {
    match error.as_db_error() {
        Some(db) => Error::Server {
            sqlstate: db.code().code().to_owned(),
            message: db.message().to_owned(),
            detail: db.detail().unwrap_or_default().to_owned(),
        },
        None => Error::Unavailable,
    }
}

/// The socket file of a Unix-socket host.
fn socket_path(config: &tokio_postgres::Config) -> Result<PathBuf> {
    let Some(Host::Unix(dir)) = config.get_hosts().first() else {
        return Err(Error::Configuration);
    };
    let port = config.get_ports().first().copied().unwrap_or(5432);
    Ok(dir.join(format!(".s.PGSQL.{port}")))
}

/// Anyone who can create a file in the socket directory, or swap it through an
/// ancestor, can plant a socket and pose as the server. Without a pinned peer UID the
/// directory must belong to root or the service user, sit on a trusted chain and be
/// writable by nobody else; a directory that cannot be read is refused.
fn unix_dir_allowed(dir: &Path, policy: &Policy) -> Result<()> {
    // A pinned peer is verified by the kernel; a consumer may accept shared directories.
    if policy.unix_peer_uid.is_some() || policy.shared_socket_dir {
        return Ok(());
    }
    // Of root or the service user, reached through a trusted chain (lxi-files), and
    // writable by nobody else, not even with the sticky bit.
    let meta = lxi_files::trusted_dir(dir).map_err(|_| Error::Configuration)?;
    if meta.mode() & 0o022 != 0 {
        return Err(Error::Configuration);
    }
    Ok(())
}

/// The uid of the process at the other end of a Unix stream.
fn peer_uid(stream: &tokio::net::UnixStream) -> Result<u32> {
    #[cfg(target_os = "linux")]
    let uid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|_| Error::Configuration)?
        .uid();
    #[cfg(target_os = "macos")]
    let uid = nix::unistd::getpeereid(stream)
        .map_err(|_| Error::Configuration)?
        .0
        .as_raw();
    Ok(uid)
}

enum Outcome<T> {
    Done(T),
    Failed(tokio_postgres::Error),
    Elapsed,
}

/// Runs one statement's future with a client-side limit.
fn wait<T>(
    runtime: &Runtime,
    limit: Duration,
    work: impl Future<Output = std::result::Result<T, tokio_postgres::Error>>,
) -> Outcome<T> {
    match runtime.block_on(async { tokio::time::timeout(limit, work).await }) {
        Ok(Ok(value)) => Outcome::Done(value),
        Ok(Err(error)) => Outcome::Failed(error),
        Err(_elapsed) => Outcome::Elapsed,
    }
}

enum Cancel {
    Tcp(Option<MakeRustlsConnect>),
    Unix {
        path: PathBuf,
        uid: Option<u32>,
        policy: Policy,
    },
}

pub struct Session {
    runtime: Runtime,
    client: Client,
    cancel_token: CancelToken,
    cancel: Cancel,
    /// The budget `renew` restores.
    base: Budget,
    /// The budget in force since `opened`.
    budget: Budget,
    opened: Instant,
    broken: bool,
    /// Between a `begin` and its `commit` or `rollback` (or a failed one): the pool never
    /// hands such a session to another checkout.
    in_transaction: bool,
    /// What `open` sets on the server, set again after `reset`.
    statement_ms: u64,
    timezone: String,
    _driver: tokio::task::JoinHandle<()>,
}

impl Session {
    /// Connects along the route the policy allows, within `budget.connect`, then
    /// sets the server's statement_timeout to the per-statement limit and the time
    /// zone. The total budget starts now.
    pub fn open(settings: &Settings, budget: Budget) -> Result<(Self, Transport)> {
        let opened = Instant::now();
        let mut config: tokio_postgres::Config =
            settings.dsn.parse().map_err(|_| Error::Configuration)?;
        if let Some(password) = &settings.password {
            // One place for the password: never both the DSN and the settings.
            if config.get_password().is_some() {
                return Err(Error::Configuration);
            }
            config.password(password.as_bytes());
        }
        let transport = classify(&config, settings.ca_file.is_some(), &settings.policy)?;
        config.connect_timeout(budget.connect);
        if transport != Transport::Unix {
            config
                .keepalives(true)
                .keepalives_idle(Duration::from_secs(5))
                .keepalives_interval(Duration::from_secs(1))
                .keepalives_retries(3)
                .tcp_user_timeout(settings.user_timeout(&budget));
        }
        let runtime = Builder::new_current_thread().enable_all().build()?;
        let connector = match (&settings.ca_file, transport.tls()) {
            (Some(ca), true) => Some(tls(ca)?),
            (None, false) => None,
            _ => return Err(Error::Configuration),
        };
        config.ssl_mode(if connector.is_some() {
            SslMode::Require
        } else {
            SslMode::Disable
        });
        let unix_uid = settings.policy.unix_peer_uid;
        let (client, driver, cancel) = runtime.block_on(async {
            let limit = budget.connect;
            if transport == Transport::Unix {
                let path = socket_path(&config)?;
                unix_dir_allowed(path.parent().ok_or(Error::Configuration)?, &settings.policy)?;
                if let Some(expected) = unix_uid {
                    let meta = std::fs::symlink_metadata(&path)?;
                    if !meta.file_type().is_socket() || meta.uid() != expected {
                        return Err(Error::Configuration);
                    }
                }
                let stream = tokio::time::timeout(limit, tokio::net::UnixStream::connect(&path))
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(|_| Error::Unavailable)?;
                if let Some(expected) = unix_uid {
                    if peer_uid(&stream)? != expected {
                        return Err(Error::Configuration);
                    }
                }
                let (client, connection) =
                    tokio::time::timeout(limit, config.connect_raw(stream, NoTls))
                        .await
                        .map_err(|_| Error::Timeout)?
                        .map_err(|_| Error::Unavailable)?;
                let driver = tokio::spawn(async move {
                    let _ended = connection.await;
                });
                Ok((
                    client,
                    driver,
                    Cancel::Unix {
                        path,
                        uid: unix_uid,
                        policy: settings.policy,
                    },
                ))
            } else if let Some(connector) = connector {
                let (client, connection) =
                    tokio::time::timeout(limit, config.connect(connector.clone()))
                        .await
                        .map_err(|_| Error::Timeout)?
                        .map_err(|_| Error::Unavailable)?;
                let driver = tokio::spawn(async move {
                    let _ended = connection.await;
                });
                Ok((client, driver, Cancel::Tcp(Some(connector))))
            } else {
                let (client, connection) = tokio::time::timeout(limit, config.connect(NoTls))
                    .await
                    .map_err(|_| Error::Timeout)?
                    .map_err(|_| Error::Unavailable)?;
                let driver = tokio::spawn(async move {
                    let _ended = connection.await;
                });
                Ok((client, driver, Cancel::Tcp(None)))
            }
        })?;
        let cancel_token = client.cancel_token();
        let mut session = Self {
            runtime,
            client,
            cancel_token,
            cancel,
            base: budget,
            budget,
            opened,
            broken: false,
            in_transaction: false,
            statement_ms: u64::try_from(budget.statement.as_millis())
                .map_err(|_| Error::Configuration)?,
            timezone: settings.timezone.clone(),
            _driver: driver,
        };
        session.apply_settings()?;
        Ok((session, transport))
    }

    /// The server-side statement limit and the time zone of this session.
    fn apply_settings(&mut self) -> Result<()> {
        let statement_ms = self.statement_ms;
        self.batch_execute(&format!("SET statement_timeout = {statement_ms}"))?;
        let timezone = self.timezone.clone();
        self.query_one(
            "SELECT pg_catalog.set_config('TimeZone', $1, false)",
            &[&timezone],
        )
        .map_err(|e| match e {
            Error::Server { .. } => Error::Configuration,
            other => other,
        })?;
        Ok(())
    }

    /// Forgets everything the previous user of a pooled session left (settings, roles,
    /// temporary objects, prepared statements, advisory locks) and sets this crate's
    /// settings again. The pool's `setup` runs after it.
    pub(crate) fn reset(&mut self) -> Result<()> {
        self.batch_execute("DISCARD ALL")?;
        self.apply_settings()
    }

    /// Starts a new total budget, for example for each heartbeat.
    pub fn renew(&mut self) {
        self.budget = self.base;
        self.opened = Instant::now();
    }

    /// Like `renew`, but the new total never exceeds `left`.
    pub fn renew_within(&mut self, left: Duration) -> Result<()> {
        self.budget = self.base.within(left)?;
        self.opened = Instant::now();
        Ok(())
    }

    /// The budget `renew` restores from now on (the pool's, for a session opened
    /// with a shorter one).
    pub(crate) fn rebase(&mut self, base: Budget) {
        self.base = base;
    }

    /// True once a statement timed out or the connection broke: do not reuse it.
    pub fn is_broken(&self) -> bool {
        self.broken || self.client.is_closed()
    }

    /// Asks the server to cancel the running statement, bounded by `budget.connect`.
    fn cancel_on_server(&self) {
        let token = self.cancel_token.clone();
        let limit = self.budget.connect;
        let _sent = match &self.cancel {
            Cancel::Tcp(Some(connector)) => {
                let connector = connector.clone();
                self.runtime
                    .block_on(async {
                        tokio::time::timeout(limit, token.cancel_query(connector)).await
                    })
                    .map(|r| r.is_ok())
            }
            Cancel::Tcp(None) => self
                .runtime
                .block_on(async { tokio::time::timeout(limit, token.cancel_query(NoTls)).await })
                .map(|r| r.is_ok()),
            Cancel::Unix { path, uid, policy } => self
                .runtime
                .block_on(async {
                    tokio::time::timeout(limit, async {
                        // The cancel key goes only where a session could go.
                        unix_dir_allowed(path.parent().ok_or(Error::Configuration)?, policy)?;
                        let stream = tokio::net::UnixStream::connect(path)
                            .await
                            .map_err(|_| Error::Unavailable)?;
                        if let Some(expected) = uid {
                            if peer_uid(&stream)? != *expected {
                                return Err(Error::Configuration);
                            }
                        }
                        token
                            .cancel_query_raw(stream, NoTls)
                            .await
                            .map_err(|_| Error::Unavailable)
                    })
                    .await
                })
                .map(|r| r.is_ok()),
        };
    }

    /// The wait allowed for the next statement, or why there is none.
    fn prepare(&self) -> Result<Duration> {
        if self.is_broken() {
            return Err(Error::Unavailable);
        }
        self.budget.limit(self.opened, Instant::now())
    }

    fn finish<T>(&mut self, outcome: Outcome<T>) -> Result<T> {
        match outcome {
            Outcome::Done(value) => Ok(value),
            Outcome::Failed(error) => {
                if error.as_db_error().is_none() {
                    self.broken = true;
                }
                Err(server_error(&error))
            }
            Outcome::Elapsed => {
                self.broken = true;
                self.cancel_on_server();
                Err(Error::Timeout)
            }
        }
    }

    pub fn batch_execute(&mut self, sql: &str) -> Result<()> {
        let limit = self.prepare()?;
        let outcome = wait(&self.runtime, limit, self.client.batch_execute(sql));
        self.finish(outcome)
    }

    pub fn query(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Vec<Row>> {
        let limit = self.prepare()?;
        let outcome = wait(&self.runtime, limit, self.client.query(sql, params));
        self.finish(outcome)
    }

    pub fn query_one(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<Row> {
        let limit = self.prepare()?;
        let outcome = wait(&self.runtime, limit, self.client.query_one(sql, params));
        self.finish(outcome)
    }

    pub fn execute(&mut self, sql: &str, params: &[&(dyn ToSql + Sync)]) -> Result<u64> {
        let limit = self.prepare()?;
        let outcome = wait(&self.runtime, limit, self.client.execute(sql, params));
        self.finish(outcome)
    }

    /// Opens a transaction. Use this, not a raw `BEGIN`, so the pool knows about it.
    pub fn begin(&mut self) -> Result<()> {
        self.in_transaction = true;
        self.batch_execute("BEGIN")
    }

    /// Ends the transaction; if `COMMIT` fails the session stays marked and is not pooled.
    pub fn commit(&mut self) -> Result<()> {
        self.batch_execute("COMMIT")?;
        self.in_transaction = false;
        Ok(())
    }

    pub fn rollback(&mut self) -> Result<()> {
        self.batch_execute("ROLLBACK")?;
        self.in_transaction = false;
        Ok(())
    }

    /// True after a `begin` that was not ended by a successful `commit` or `rollback`.
    pub fn in_transaction(&self) -> bool {
        self.in_transaction
    }
}

#[cfg(test)]
mod ca_tests {
    use super::*;

    #[test]
    fn an_unpinned_socket_directory_must_be_trusted() -> Result<()> {
        use std::os::unix::fs::PermissionsExt;
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Configuration)?
            .as_nanos();
        let base = std::env::temp_dir().join(format!("lxi-sock-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&base)?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))?;
        let dir = base.join("run");
        std::fs::create_dir(&dir)?;
        let mut pinned = Policy::STRICT;
        pinned.unix_peer_uid = Some(nix::unistd::geteuid().as_raw());
        let mut accepted = Policy::STRICT;
        accepted.shared_socket_dir = true;
        // Ours, through a trusted chain, and nobody else can write it: allowed.
        for (mode, strict_ok) in [
            (0o755, true),
            (0o750, true),
            (0o2775, false),
            (0o775, false),
            (0o777, false),
            (0o1777, false),
        ] {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(mode))?;
            assert_eq!(
                unix_dir_allowed(&dir, &Policy::STRICT).is_ok(),
                strict_ok,
                "{mode:o}"
            );
            assert!(
                unix_dir_allowed(&dir, &pinned).is_ok(),
                "{mode:o} with a pinned peer"
            );
            assert!(
                unix_dir_allowed(&dir, &accepted).is_ok(),
                "{mode:o} accepted explicitly"
            );
        }
        // An ancestor others can write to: someone could swap the directory.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777))?;
        assert!(
            unix_dir_allowed(&dir, &Policy::STRICT).is_err(),
            "unsafe ancestor"
        );
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755))?;
        assert!(unix_dir_allowed(&dir, &Policy::STRICT).is_ok());
        // A directory that cannot be read is refused unless the peer is pinned or the
        // consumer accepted shared directories (then the connection fails as before).
        let absent = dir.join("absent");
        assert!(unix_dir_allowed(&absent, &Policy::STRICT).is_err());
        assert!(unix_dir_allowed(&absent, &pinned).is_ok());
        assert!(unix_dir_allowed(&absent, &accepted).is_ok());
        Ok(())
    }

    #[test]
    fn a_password_in_both_places_is_refused() -> Result<()> {
        let budget = Budget::new(
            Duration::from_secs(1),
            Duration::from_millis(1500),
            Duration::from_secs(2),
        )?;
        let mut loopback = Policy::STRICT;
        loopback.loopback_plaintext = true;
        let mut settings = Settings::new(
            Zeroizing::new("host=127.0.0.1 port=1 user=u dbname=d password=x".to_owned()),
            None,
            loopback,
        );
        settings.password = Some(Zeroizing::new("y".to_owned()));
        // Refused before any connection (port 1 would otherwise be Unavailable).
        assert!(matches!(
            Session::open(&settings, budget),
            Err(Error::Configuration)
        ));
        Ok(())
    }

    #[test]
    fn the_tcp_user_timeout_is_the_statement_limit_unless_set() -> Result<()> {
        let budget = Budget::new(
            Duration::from_secs(1),
            Duration::from_millis(1500),
            Duration::from_secs(7),
        )?;
        let mut settings = Settings::new(Zeroizing::new(String::new()), None, Policy::STRICT);
        assert_eq!(settings.user_timeout(&budget), Duration::from_millis(1500));
        settings.tcp_user_timeout = Some(Duration::from_secs(3));
        assert_eq!(settings.user_timeout(&budget), Duration::from_secs(3));
        Ok(())
    }
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn a_ca_under_an_unsafe_directory_is_refused() -> Result<()> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Configuration)?
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("lxi-ca-{}-{stamp}", std::process::id()));
        std::fs::create_dir(&dir)?;
        let ca = dir.join("ca.pem");
        std::fs::File::create(&ca)?.write_all(b"not a certificate")?;
        std::fs::set_permissions(&ca, std::fs::Permissions::from_mode(0o644))?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        assert_eq!(read_ca(&ca)?.len(), 17);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777))?;
        assert!(matches!(read_ca(&ca), Err(Error::Configuration)));
        Ok(())
    }
}
