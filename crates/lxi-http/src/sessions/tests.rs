//! JSR `crates/api-rest/src/sessions.rs` tests (3b75827), same names and assertions,
//! with a generic account in place of JSR's `Principal` and the role rule in `eligible`.

use super::*;
use std::collections::BTreeSet;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const PREFIX: &str = "test_";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Acct {
    name: String,
    groups: BTreeSet<String>,
    superuser: bool,
}

fn acct(name: &str, groups: &[&str], superuser: bool) -> Acct {
    Acct {
        name: name.into(),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
        superuser,
    }
}

/// JSR's eligibility: never uid 0, and in some `[roles]` group.
fn eligible(roles: &BTreeSet<String>, a: &Acct) -> Result<(), &'static str> {
    if a.superuser {
        return Err("uid 0 cannot sign in");
    }
    if a.groups.is_disjoint(roles) {
        return Err("in no [roles] group");
    }
    Ok(())
}

fn roles(names: &[&str]) -> BTreeSet<String> {
    names.iter().map(|g| (*g).to_owned()).collect()
}

struct Fake(BTreeSet<String>);

impl LocalUsers for Fake {
    type Account = Acct;

    fn authenticate(&self, user: &str, password: &str) -> Result<Acct, LocalAuthError> {
        if password != "secret" {
            return Err(LocalAuthError::Rejected("bad password".into()));
        }
        let groups = match user {
            "ana" => ["jsroper", "sales"].as_slice(),
            "root" => ["root"].as_slice(),
            _ => ["staff"].as_slice(),
        };
        Ok(acct(user, groups, user == "root"))
    }

    fn name(account: &Acct) -> &str {
        &account.name
    }

    fn eligible(&self, account: &Acct) -> Result<(), &'static str> {
        eligible(&self.0, account)
    }
}

/// Accounts whose groups the test changes.
struct Directory(Mutex<HashMap<String, Vec<&'static str>>>, BTreeSet<String>);

impl LocalUsers for Directory {
    type Account = Acct;

    fn authenticate(&self, user: &str, _: &str) -> Result<Acct, LocalAuthError> {
        self.lookup(user)?
            .ok_or_else(|| LocalAuthError::Rejected("no such user".into()))
    }

    fn lookup(&self, user: &str) -> Result<Option<Acct>, LocalAuthError> {
        let accounts = self
            .0
            .lock()
            .map_err(|_| LocalAuthError::Unavailable("poisoned".into()))?;
        Ok(accounts.get(user).map(|groups| acct(user, groups, false)))
    }

    fn name(account: &Acct) -> &str {
        &account.name
    }

    fn eligible(&self, account: &Acct) -> Result<(), &'static str> {
        eligible(&self.1, account)
    }
}

fn at(t: Instant, d: Duration) -> TestResult<Instant> {
    t.checked_add(d).ok_or_else(|| "time".into())
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn checked<U: LocalUsers>(s: &Sessions<U>, user: &str, password: &str) -> TestResult<U::Account> {
    s.check(user, password)
        .map_err(|(e, why)| format!("{e}: {why}").into())
}

fn sessions() -> Sessions<Fake> {
    Sessions::new(
        Arc::new(Fake(roles(&["jsradm", "jsroper", "jsruser"]))),
        PREFIX,
    )
}

fn directory(accounts: &[(&str, Vec<&'static str>)], role_names: &[&str]) -> Arc<Directory> {
    Arc::new(Directory(
        Mutex::new(
            accounts
                .iter()
                .map(|(n, g)| ((*n).to_owned(), g.clone()))
                .collect(),
        ),
        roles(role_names),
    ))
}

fn edit(
    d: &Directory,
) -> TestResult<std::sync::MutexGuard<'_, HashMap<String, Vec<&'static str>>>> {
    d.0.lock().map_err(|_| "poisoned".into())
}

fn groups(a: Option<Active<Acct>>) -> Option<Vec<String>> {
    a.map(|a| a.account.groups.into_iter().collect())
}

fn third(n: usize) -> usize {
    n.checked_div(FAILURE_LIMIT).unwrap_or(0)
}

#[test]
fn lasting_failures_wait_for_a_success_not_for_the_window() -> TestResult {
    // IBM i resets QMAXSIGN's count only on a success: so does the gateway (JSR S-08).
    let s = sessions()
        .with_user_failure_limit(2)
        .with_lasting_user_failures();
    let t0 = Instant::now();
    assert!(s.begin("JSRBATCH", "10.0.0.1", t0));
    assert!(s.begin("JSRBATCH", "10.0.0.2", t0));
    let later = at(t0, FAILURE_WINDOW.saturating_add(secs(60)))?;
    assert!(!s.begin("JSRBATCH", "10.0.0.3", later));
    // With the window, the same attempt would have been let through.
    let windowed = sessions().with_user_failure_limit(2);
    assert!(windowed.begin("JSRBATCH", "10.0.0.1", t0));
    assert!(windowed.begin("JSRBATCH", "10.0.0.2", t0));
    assert!(windowed.begin("JSRBATCH", "10.0.0.3", later));
    Ok(())
}

#[test]
fn a_session_follows_its_users_groups_when_refreshed() -> TestResult {
    let d = directory(
        &[("ana", vec!["jsroper"]), ("bob", vec!["jsruser"])],
        &["jsradm", "jsroper", "jsruser"],
    );
    let s = Sessions::new(Arc::clone(&d), PREFIX);
    let t0 = Instant::now();
    let ana = s.open(checked(&s, "ana", "x")?, "ana", "a", t0)?;
    let bob = s.open(checked(&s, "bob", "x")?, "bob", "a", t0)?;
    {
        let mut accounts = edit(&d)?;
        accounts.insert("ana".into(), vec!["jsradm"]);
        accounts.insert("bob".into(), vec!["staff"]);
    }
    let refresh = |when: Instant| {
        for user in s.due(when) {
            s.refreshed(&user, when, s.users().lookup(&user));
        }
    };
    // Trusted until due, then read again, once.
    refresh(at(t0, secs(30))?);
    assert_eq!(groups(s.verify(&ana, t0)), Some(vec!["jsroper".into()]));
    let later = at(t0, REFRESH)?;
    assert_eq!(s.due(later), ["ana", "bob"]);
    assert!(s.due(later).is_empty(), "claimed: not started twice");
    for user in ["ana", "bob"] {
        s.refreshed(user, later, s.users().lookup(user));
    }
    assert_eq!(groups(s.current(&ana, later)), Some(vec!["jsradm".into()]));
    assert!(
        s.verify(&bob, later).is_none(),
        "bob is in no role group now"
    );
    // An unreadable database keeps the session; a vanished account ends it.
    s.refreshed(
        "ana",
        later,
        Err(LocalAuthError::Unavailable("down".into())),
    );
    assert!(s.verify(&ana, later).is_some());
    edit(&d)?.remove("ana");
    let last = at(later, REFRESH)?;
    refresh(last);
    assert!(s.verify(&ana, last).is_none(), "ana no longer exists");
    Ok(())
}

#[test]
fn an_old_answer_never_changes_a_newer_session_and_a_stalled_refresher_fails_closed() -> TestResult
{
    let d = directory(&[("ana", vec!["jsroper"])], &["jsroper"]);
    let s = Sessions::new(Arc::clone(&d), PREFIX);
    s.start_refreshing();
    let t0 = Instant::now();
    // A lookup asked at t0 answers "gone" after ana signed in again at t1.
    let t1 = at(t0, secs(5))?;
    let token = s.open(checked(&s, "ana", "x")?, "ana", "a", t1)?;
    s.refreshed("ana", t0, Ok(None));
    assert!(s.verify(&token, t1).is_some(), "the newer session stays");
    // No refresh for three minutes: refused, and usable again once refreshed.
    let late = at(t1, STALE)?;
    assert!(s.verify(&token, late).is_none());
    for user in s.due(late) {
        s.refreshed(&user, late, s.users().lookup(&user));
    }
    assert!(s.verify(&token, late).is_some());
    Ok(())
}

#[test]
fn checking_a_session_for_a_stream_does_not_extend_it() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let token = s.open(checked(&s, "ana", "secret")?, "ana", "a", t0)?;
    assert!(s
        .current(&token, at(t0, IDLE.saturating_sub(secs(1)))?)
        .is_some());
    assert!(
        s.current(&token, at(t0, IDLE)?).is_none(),
        "idle since sign-in"
    );
    Ok(())
}

#[test]
fn a_session_carries_the_principal_and_expires_when_idle() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let account = checked(&s, "ana", "secret")?;
    let token = s.open(account, "ana", "10.0.0.1", t0)?;
    assert!(token.starts_with(PREFIX));
    assert_eq!(Some(token.len()), PREFIX.len().checked_add(43));

    let active = s
        .verify(&token, at(t0, secs(29 * 60))?)
        .ok_or("no session")?;
    assert_eq!(active.account.name, "ana");
    assert_eq!(active.remaining, IDLE);
    // Used at 29 min: valid until 59 min.
    assert!(s.verify(&token, at(t0, secs(58 * 60))?).is_some());
    assert!(s.verify(&token, at(t0, secs(89 * 60))?).is_none());
    assert!(s.verify(&token, t0).is_none(), "an expired session is gone");
    Ok(())
}

#[test]
fn a_session_ends_after_twelve_hours_however_used() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let token = s.open(checked(&s, "ana", "secret")?, "ana", "10.0.0.1", t0)?;
    for minutes in (20..12 * 60).step_by(20) {
        assert!(s.verify(&token, at(t0, secs(minutes * 60))?).is_some());
    }
    assert!(s.verify(&token, at(t0, LIFETIME)?).is_none());
    Ok(())
}

#[test]
fn closing_ends_the_session_and_unknown_tokens_are_refused() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let token = s.open(checked(&s, "ana", "secret")?, "ana", "10.0.0.1", t0)?;
    assert!(s.verify("test_forged", t0).is_none());
    assert!(s.close(&token));
    assert!(s.verify(&token, t0).is_none());
    assert!(!s.close(&token));
    Ok(())
}

#[test]
fn root_and_users_without_a_role_cannot_sign_in() {
    let s = sessions();
    let refused = |user: &str, password: &str| s.check(user, password).err().map(|(e, _)| e);
    assert_eq!(refused("root", "secret"), Some(SignInError::Rejected));
    assert_eq!(refused("bob", "secret"), Some(SignInError::Rejected));
    assert_eq!(refused("ana", "nope"), Some(SignInError::Rejected));
}

#[test]
fn five_attempts_throttle_the_address_even_while_pending() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    // Five attempts still waiting for PAM already count.
    for _ in 0..FAILURE_LIMIT {
        assert!(s.begin("ana", "10.0.0.1", t0));
    }
    assert!(!s.begin("eve", "10.0.0.1", t0), "the address");
    // One address cannot lock the user out: ana signs in from her own.
    assert!(s.begin("ana", "10.0.0.9", t0));
    assert!(s.begin("eve", "10.0.0.8", t0));
    assert!(s.begin("eve", "10.0.0.1", at(t0, FAILURE_WINDOW)?));
    Ok(())
}

#[test]
fn failures_from_many_addresses_throttle_the_user() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    for n in 0..USER_FAILURE_LIMIT {
        assert!(s.begin("ana", &format!("10.0.{}.1", third(n)), t0));
    }
    assert!(!s.begin("ana", "10.9.9.9", t0), "the user");
    assert!(!s.begin("ANA", "10.9.9.9", t0), "the user, in any case");
    assert!(s.begin("eve", "10.9.9.9", t0));
    assert!(s.begin("ana", "10.9.9.9", at(t0, FAILURE_WINDOW)?));
    Ok(())
}

#[test]
fn a_success_clears_the_users_failures_and_its_own_attempt() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let four = FAILURE_LIMIT.saturating_sub(1);
    for _ in 0..four {
        assert!(s.begin("ana", "10.0.0.1", t0));
    }
    assert!(s.begin("ana", "10.0.0.2", t0));
    s.open(checked(&s, "ana", "secret")?, "ana", "10.0.0.2", t0)?;
    for _ in 0..four {
        assert!(s.begin("ana", "10.0.0.2", t0));
    }
    assert!(
        s.begin("ana", "10.0.0.3", t0),
        "four failures left, not five"
    );
    Ok(())
}

#[test]
fn a_user_cannot_push_other_users_out() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let first = s.open(checked(&s, "ana", "secret")?, "ana", "a", t0)?;
    for n in 1..=MAX_SESSIONS_PER_USER {
        let when = at(t0, ms(u64::try_from(n)?))?;
        s.open(checked(&s, "ana", "secret")?, "ana", "a", when)?;
    }
    assert!(s.verify(&first, t0).is_none(), "ana's oldest session ended");
    assert_eq!(s.lock().sessions.len(), MAX_SESSIONS_PER_USER);
    Ok(())
}

#[test]
fn a_full_table_refuses_new_sessions_instead_of_ending_others() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let mut account = checked(&s, "ana", "secret")?;
    let mut first = None;
    for n in 0..MAX_SESSIONS {
        account.name = format!("user{n}");
        let name = account.name.clone();
        let token = s.open(account.clone(), &name, "a", t0)?;
        first.get_or_insert(token);
    }
    account.name = "late".into();
    assert_eq!(
        s.open(account, "late", "a", t0).err(),
        Some(SignInError::Full)
    );
    assert!(s.verify(&first.ok_or("no first")?, t0).is_some());
    Ok(())
}

#[test]
fn address_churn_cannot_push_a_throttled_user_out() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    for n in 0..USER_FAILURE_LIMIT {
        s.begin("ana", &format!("x{}", third(n)), t0);
    }
    // 80 000 addresses at the highest rate the server admits, within ana's window.
    for n in 0..80_000u64 {
        let when = at(t0, ms(n.saturating_mul(10)))?;
        s.begin(
            &format!("u{}", n.checked_rem(1000).unwrap_or(0)),
            &format!("addr{n}"),
            when,
        );
    }
    let t1 = at(t0, secs(800))?;
    assert!(!s.begin("ana", "fresh", t1), "ana is still throttled");
    Ok(())
}

#[test]
fn user_name_churn_cannot_reset_a_user_close_to_the_limit() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    // Below the user's limit, past the address limit.
    for n in 0..USER_FAILURE_LIMIT.saturating_sub(1) {
        assert!(s.begin("ana", &format!("x{}", third(n)), t0));
    }
    // 80 000 distinct user names at the highest rate the server admits.
    for n in 0..80_000u64 {
        let when = at(t0, ms(n.saturating_mul(10)))?;
        s.begin(&format!("u{n}"), &format!("addr{n}"), when);
    }
    let t1 = at(t0, secs(800))?;
    assert!(s.begin("ana", "fresh", t1), "the last failure left");
    assert!(!s.begin("ana", "fresh2", t1), "ana's count was kept");
    Ok(())
}

#[test]
fn the_server_admits_a_bounded_number_of_attempts_per_second() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    for n in 0..ATTEMPTS_PER_SECOND {
        assert!(s.begin(&format!("u{n}"), &format!("a{n}"), t0));
    }
    assert!(!s.begin("late", "10.9.9.9", t0));
    assert!(s.begin("late", "10.9.9.9", at(t0, secs(1))?));
    Ok(())
}

#[test]
fn a_throttled_entry_is_never_forgotten_to_make_room() {
    let mut table: HashMap<String, VecDeque<Instant>> = HashMap::new();
    let t0 = Instant::now();
    for n in 0..MAX_FAILURE_KEYS {
        table.insert(format!("k{n}"), [t0; FAILURE_LIMIT].into());
    }
    assert!(
        !room(&mut table, "new", t0),
        "only throttled entries: no room"
    );
    assert_eq!(table.len(), MAX_FAILURE_KEYS);
    table.insert("k0".into(), [t0].into());
    assert!(room(&mut table, "new", t0));
    assert!(table.get("k1").is_some_and(|l| l.len() == FAILURE_LIMIT));
}

#[test]
fn the_failure_table_stays_bounded() -> TestResult {
    let s = sessions();
    let t0 = Instant::now();
    let total = u64::try_from(MAX_FAILURE_KEYS.saturating_add(10))?;
    for n in 0..total {
        let when = at(t0, ms(n.saturating_mul(10)))?;
        s.begin(&format!("u{n}"), &format!("addr{n}"), when);
    }
    let inner = s.lock();
    assert!(inner.users.len() <= MAX_FAILURE_KEYS);
    assert!(inner.addresses.len() <= MAX_FAILURE_KEYS);
    Ok(())
}
