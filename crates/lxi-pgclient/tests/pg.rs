//! lxi-pgclient against a real PostgreSQL 16, provisioned by tools/run_pg_integration.py.
//! Every test is #[ignore]: run them only through the runner, which records NOT_RUN.
#![forbid(unsafe_code, unused_must_use)]
#![forbid(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::todo,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::string_slice,
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::dbg_macro
)]

use lxi_pgclient::{Budget, Error, Policy, Pool, Session, Settings, Transport};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn env(name: &str) -> TestResult<String> {
    std::env::var(name)
        .map_err(|_| format!("{name} not set: run tools/run_pg_integration.py").into())
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn budget(statement: u64, total: u64) -> TestResult<Budget> {
    Ok(Budget::new(
        ms(2000).min(ms(total)),
        ms(statement),
        ms(total),
    )?)
}

/// Verified TLS to the lab PG (127.0.0.1 on macOS, the container's name on Linux).
fn tls_settings(ca: &str) -> TestResult<Settings> {
    let host = std::env::var("LXI_IT_TLS_HOSTNAME").unwrap_or_else(|_| "127.0.0.1".to_owned());
    Ok(Settings::new(
        Zeroizing::new(format!(
            "host={host} port={} dbname=postgres user=postgres password={}",
            env("LXI_IT_PG_PORT")?,
            env("LXI_IT_SUPER_PASSWORD")?
        )),
        Some(ca.into()),
        Policy::STRICT,
    ))
}

fn lab() -> TestResult<Settings> {
    tls_settings(&env("LXI_IT_CA_FILE")?)
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn verified_tls_and_a_wrong_ca() -> TestResult {
    let (mut session, transport) = Session::open(&lab()?, budget(1500, 4000)?)?;
    assert!(transport.tls(), "{transport:?}");
    let row = session.query_one("SELECT current_setting('TimeZone')", &[])?;
    assert_eq!(
        row.try_get::<_, String>(0)?,
        "UTC",
        "UTC by default (series rule)"
    );
    let wrong = tls_settings(&env("LXI_IT_WRONG_CA_FILE")?)?;
    assert!(matches!(
        Session::open(&wrong, budget(1500, 4000)?),
        Err(Error::Unavailable)
    ));
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn strict_policy_refuses_plaintext_before_connecting() -> TestResult {
    let mut settings = lab()?;
    settings.ca_file = None;
    assert!(matches!(
        Session::open(&settings, budget(1500, 4000)?),
        Err(Error::Configuration)
    ));
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn a_client_timeout_cancels_the_statement_on_the_server() -> TestResult {
    // Server statement_timeout follows the per-statement limit (5 s); the total
    // (900 ms) is shorter, so only the client's cancellation can stop pg_sleep.
    let (mut session, _) = Session::open(&lab()?, budget(5000, 900)?)?;
    let began = Instant::now();
    let slow = session.batch_execute("SELECT pg_sleep(10) /* lxi-cancel-probe */");
    assert!(matches!(slow, Err(Error::Timeout)), "{slow:?}");
    assert!(began.elapsed() < ms(2500));
    assert!(session.is_broken(), "a timed-out session is not reused");
    let (mut observer, _) = Session::open(&lab()?, budget(1500, 4000)?)?;
    let deadline = Instant::now().checked_add(ms(2000)).ok_or("deadline")?;
    loop {
        let running: i64 = observer
            .query_one(
                "SELECT count(*) FROM pg_stat_activity WHERE query LIKE '%lxi-cancel-probe%' AND pid <> pg_backend_pid() AND state = 'active'",
                &[],
            )?
            .try_get(0)?;
        if running == 0 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "pg_sleep still running on the server"
        );
        std::thread::sleep(ms(50));
    }
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn the_total_budget_is_not_renewed_by_queries() -> TestResult {
    let (mut session, _) = Session::open(&lab()?, budget(1500, 1500)?)?;
    session.batch_execute("SELECT pg_sleep(0.6)")?;
    session.batch_execute("SELECT pg_sleep(0.6)")?;
    assert!(matches!(
        session.batch_execute("SELECT pg_sleep(0.6)"),
        Err(Error::Timeout)
    ));
    let (mut fresh, _) = Session::open(&lab()?, budget(1500, 1500)?)?;
    fresh.batch_execute("SELECT 1")?;
    fresh.renew();
    fresh.batch_execute("SELECT pg_sleep(0.6)")?;
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn the_unix_socket_peer_must_be_the_expected_uid() -> TestResult {
    let Ok(dir) = std::env::var("LXI_IT_PG_SOCKET_DIR") else {
        println!("NOT_RUN:the_unix_socket_peer_must_be_the_expected_uid");
        return Ok(());
    };
    let uid: u32 = env("LXI_IT_PG_UID")?.parse()?;
    let dsn = |_: ()| -> TestResult<Zeroizing<String>> {
        Ok(Zeroizing::new(format!(
            "host={dir} port=5432 dbname=postgres user=postgres password={}",
            env("LXI_IT_SUPER_PASSWORD")?
        )))
    };
    let mut policy = Policy::STRICT;
    policy.unix_peer_uid = Some(uid);
    let (mut session, transport) =
        Session::open(&Settings::new(dsn(())?, None, policy), budget(1500, 4000)?)?;
    assert_eq!(transport, Transport::Unix);
    session.batch_execute("SELECT 1")?;
    policy.unix_peer_uid = uid.checked_add(1);
    assert!(matches!(
        Session::open(&Settings::new(dsn(())?, None, policy), budget(1500, 4000)?),
        Err(Error::Configuration)
    ));
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn the_pool_is_bounded_and_drops_broken_sessions() -> TestResult {
    let pool = Pool::new(lab()?, budget(5000, 900)?, 2, |s: &mut Session| {
        s.batch_execute("SET search_path=pg_catalog")
    })?;
    {
        let mut first = pool.get()?;
        let _second = pool.get()?;
        assert!(matches!(pool.get(), Err(Error::Unavailable)), "max 2");
        assert!(matches!(
            first.session()?.batch_execute("SELECT pg_sleep(10)"),
            Err(Error::Timeout)
        ));
    }
    assert_eq!(
        pool.idle(),
        1,
        "the broken session was dropped, the healthy one kept"
    );
    let mut again = pool.get()?;
    again.session()?.batch_execute("SELECT 1")?;
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn a_checkout_never_gets_more_than_its_request_has_left() -> TestResult {
    let pool = Pool::new(lab()?, budget(5000, 3000)?, 1, |s: &mut Session| {
        s.batch_execute("SET search_path=pg_catalog")
    })?;
    // A new session opened for a short request...
    {
        let mut short = pool.get_within(ms(400))?;
        short.session()?.batch_execute("SELECT 1")?;
    }
    // ...goes back with the pool's full budget for the next one.
    {
        let mut full = pool.get()?;
        full.session()?.batch_execute("SELECT pg_sleep(1)")?;
    }
    // A reused session is cut to what its request has left.
    {
        let mut short = pool.get_within(ms(400))?;
        let started = Instant::now();
        assert!(matches!(
            short.session()?.batch_execute("SELECT pg_sleep(2)"),
            Err(Error::Timeout)
        ));
        assert!(started.elapsed() < ms(1500), "cut at 400 ms, not 3 s");
    }
    assert!(matches!(pool.get_within(ms(0)), Err(Error::Timeout)));
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn a_session_left_in_a_transaction_never_goes_back_to_the_pool() -> TestResult {
    let pool = Pool::new(lab()?, budget(5000, 3000)?, 1, |s: &mut Session| {
        s.batch_execute("SET search_path=pg_catalog")
    })?;
    // Committed: the session is clean and goes back.
    {
        let mut used = pool.get()?;
        used.session()?.begin()?;
        used.session()?.batch_execute("SELECT 1")?;
        used.session()?.commit()?;
    }
    assert_eq!(pool.idle(), 1, "a committed session is reused");
    // Left open (for example after an error): never handed to the next checkout.
    {
        let mut used = pool.get()?;
        used.session()?.begin()?;
        used.session()?
            .batch_execute("SET LOCAL application_name = 'leaked'")?;
    }
    assert_eq!(pool.idle(), 0, "a session inside a transaction is dropped");
    let mut next = pool.get()?;
    let name: String = next
        .session()?
        .query_one("SELECT pg_catalog.current_setting('application_name')", &[])?
        .try_get(0)?;
    assert_ne!(name, "leaked");
    Ok(())
}

#[test]
#[ignore = "needs tools/run_pg_integration.py"]
fn a_reused_session_starts_clean_with_its_settings() -> TestResult {
    let pool = Pool::new(lab()?, budget(1500, 3000)?, 1, |s: &mut Session| {
        s.batch_execute("SET search_path=pg_catalog")
    })?;
    {
        let mut used = pool.get()?;
        // Session-level state a checkout must never pass on.
        used.session()?.batch_execute(
            "SET application_name = 'leaked'; SET search_path = public; \
             CREATE TEMP TABLE leaked(x int); SELECT pg_advisory_lock(42)",
        )?;
    }
    assert_eq!(pool.idle(), 1);
    let mut next = pool.get()?;
    let db = next.session()?;
    let row = db.query_one(
        "SELECT current_setting('application_name'), current_setting('search_path'),
                current_setting('statement_timeout'), current_setting('TimeZone'),
                to_regclass('pg_temp.leaked') IS NULL,
                NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory'
                            AND pid = pg_backend_pid())",
        &[],
    )?;
    let app: String = row.try_get(0)?;
    let path: String = row.try_get(1)?;
    let timeout: String = row.try_get(2)?;
    let zone: String = row.try_get(3)?;
    let no_temp: bool = row.try_get(4)?;
    let no_lock: bool = row.try_get(5)?;
    assert_ne!(app, "leaked");
    assert_eq!(path, "pg_catalog", "setup ran again");
    assert_eq!(timeout, "1500ms", "the statement limit is set again");
    assert_eq!(zone, "UTC", "the time zone is set again");
    assert!(no_temp, "temporary objects are gone");
    assert!(no_lock, "advisory locks are released");
    Ok(())
}
