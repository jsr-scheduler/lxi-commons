//! Sessions of local users, as JSR keeps them (`crates/api-rest/src/sessions.rs`,
//! 3b75827; JSR ADR-0016): opaque tokens held in memory as SHA-256 hashes, with idle and
//! absolute expiry and sign-in throttling. The password check is a port ([`LocalUsers`]);
//! this module does no I/O. Who may hold a session is the service's rule
//! ([`LocalUsers::eligible`]).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use base64::Engine as _;
use sha2::{Digest, Sha256};

const IDLE: Duration = Duration::from_secs(30 * 60);
const LIFETIME: Duration = Duration::from_secs(12 * 60 * 60);
const MAX_SESSIONS: usize = 1024;
/// How long a session's account is trusted before it is read again. With
/// [`REFRESH_EVERY`], a user removed from a role group, or from the host, loses that
/// within a minute.
pub const REFRESH: Duration = Duration::from_secs(45);
/// How often the refresher looks for sessions due ([`crate::sign_in::refresh`]).
pub const REFRESH_EVERY: Duration = Duration::from_secs(15);
/// With a refresher running, a session whose account has not been read for this long is
/// refused: a stalled refresher must not extend privileges that may have been removed.
const STALE: Duration = Duration::from_secs(180);
/// Sessions per user; a new one ends that user's oldest, never someone else's.
const MAX_SESSIONS_PER_USER: usize = 16;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);
/// Failures from one address, whatever the user names, within the window.
const FAILURE_LIMIT: usize = 5;
/// Failures for one user name from all addresses within the window. Higher than
/// [`FAILURE_LIMIT`]: one address can never lock a user out, it takes ten; it still bounds
/// guessing spread over many addresses (`pam_faillock` is the account's own lock-out).
const USER_FAILURE_LIMIT: usize = 50;
/// User names and addresses tracked for throttling, each in its own table so churn of
/// one cannot push the other out.
const MAX_FAILURE_KEYS: usize = 50_000;
/// Sign-in attempts per second on the whole server. With it, one window admits at most
/// 90 000 attempts: 18 000 throttled addresses and 1 800 throttled user names, well below
/// [`MAX_FAILURE_KEYS`], so a throttled entry is never forgotten early and a table never
/// fills with throttled entries.
const ATTEMPTS_PER_SECOND: usize = 100;

/// Checks a password and builds the service's account. Blocking.
pub trait LocalUsers: Send + Sync + 'static {
    type Account: Clone + Send + Sync + 'static;

    fn authenticate(&self, user: &str, password: &str) -> Result<Self::Account, LocalAuthError>;

    /// The account as it is now, without a password; `None` when it no longer exists.
    /// Blocking. An error keeps the session's account as it was.
    fn lookup(&self, user: &str) -> Result<Option<Self::Account>, LocalAuthError> {
        Err(LocalAuthError::Unavailable(format!(
            "{user}: accounts cannot be read again here"
        )))
    }

    /// The name sessions are counted and refreshed by.
    fn name(account: &Self::Account) -> &str;

    /// Whether the account may hold a session (JSR: never uid 0, and in a role group).
    fn eligible(&self, account: &Self::Account) -> Result<(), &'static str>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAuthError {
    /// Wrong user or password, or an account PAM does not accept. The text is for the log.
    Rejected(String),
    /// PAM or the user database could not answer.
    Unavailable(String),
}

impl fmt::Display for LocalAuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(why) => write!(f, "rejected: {why}"),
            Self::Unavailable(why) => write!(f, "unavailable: {why}"),
        }
    }
}

impl std::error::Error for LocalAuthError {}

/// Why a sign-in was refused, as the client sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignInError {
    /// A user name or password outside the bounds; nothing was asked.
    Invalid,
    Rejected,
    Throttled,
    Unavailable,
    Full,
}

impl fmt::Display for SignInError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "a user name and a password are required",
            Self::Rejected => "wrong user name or password",
            Self::Throttled => "too many failed attempts; try again later",
            Self::Unavailable => "the user database is not available",
            Self::Full => "too many open sessions; try again later",
        })
    }
}

impl std::error::Error for SignInError {}

#[derive(Debug, Clone)]
struct Session<A> {
    account: A,
    name: String,
    created: Instant,
    last_used: Instant,
    /// When the account was last read from the user database (asked, for a refresh).
    refreshed: Instant,
    /// When a refresh of it was last started, if one was.
    claimed: Option<Instant>,
}

impl<A> Session<A> {
    fn expires(&self) -> Instant {
        self.last_used
            .checked_add(IDLE)
            .unwrap_or(self.last_used)
            .min(self.created.checked_add(LIFETIME).unwrap_or(self.created))
    }
}

#[derive(Debug)]
struct Inner<A> {
    sessions: HashMap<[u8; 32], Session<A>>,
    /// Recent failed or pending attempts by lower-case user name.
    users: HashMap<String, VecDeque<Instant>>,
    /// Recent failed or pending attempts by address (IPv6 by /64).
    addresses: HashMap<String, VecDeque<Instant>>,
    /// Every attempt of the last second.
    recent: VecDeque<Instant>,
}

impl<A> Default for Inner<A> {
    fn default() -> Self {
        Self {
            sessions: HashMap::new(),
            users: HashMap::new(),
            addresses: HashMap::new(),
            recent: VecDeque::new(),
        }
    }
}

/// A verified session: its account and how long it remains valid.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Active<A> {
    pub account: A,
    pub remaining: Duration,
}

/// Open sessions and the sign-in policy.
pub struct Sessions<U: LocalUsers> {
    users: Arc<U>,
    token_prefix: &'static str,
    /// A refresher reads the accounts again ([`Sessions::start_refreshing`]).
    refreshing: AtomicBool,
    /// Failures for one user name from all addresses within the window.
    user_failure_limit: usize,
    /// Whether a user's failures expire with the window, or last until a success.
    user_failures_expire: bool,
    inner: Mutex<Inner<U::Account>>,
}

impl<U: LocalUsers> fmt::Debug for Sessions<U> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sessions").finish_non_exhaustive()
    }
}

fn hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

/// The key a session is kept under: the SHA-256 of its token.
pub fn token_key(token: &str) -> [u8; 32] {
    hash(token)
}

impl<U: LocalUsers> Sessions<U> {
    /// `token_prefix` tells a session token from a JWT (JSR: `jsrs_`).
    pub fn new(users: Arc<U>, token_prefix: &'static str) -> Self {
        Self {
            users,
            token_prefix,
            refreshing: AtomicBool::new(false),
            user_failure_limit: USER_FAILURE_LIMIT,
            user_failures_expire: true,
            inner: Mutex::new(Inner::default()),
        }
    }

    /// A lower limit per user name, for back ends that lock an account after a few
    /// failures (JSR's IBM i gateway keeps it below QMAXSIGN, S-08).
    #[must_use]
    pub fn with_user_failure_limit(mut self, limit: usize) -> Self {
        self.user_failure_limit = limit;
        self
    }

    /// A user's failures count until that user signs in, not for a window: for a back end
    /// whose own counter only a success resets, as IBM i's QMAXSIGN (S-08).
    #[must_use]
    pub fn with_lasting_user_failures(mut self) -> Self {
        self.user_failures_expire = false;
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner<U::Account>> {
        // A panic while holding the lock cannot leave the maps inconsistent.
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Starts a sign-in attempt, before asking PAM. Refused (false) when the address
    /// reached [`FAILURE_LIMIT`] or the user its limit. Otherwise the attempt counts as a
    /// failure until [`Sessions::open`] turns it into a success: concurrent attempts
    /// cannot get past the limit while PAM is still answering. User names are compared
    /// case-insensitively, as some directories resolve them.
    pub fn begin(&self, user: &str, address: &str, now: Instant) -> bool {
        let user = user.to_lowercase();
        let mut inner = self.lock();
        let Inner {
            users,
            addresses,
            recent,
            ..
        } = &mut *inner;
        while recent
            .front()
            .is_some_and(|t| now.saturating_duration_since(*t) >= Duration::from_secs(1))
        {
            recent.pop_front();
        }
        if recent.len() >= ATTEMPTS_PER_SECOND
            || (if self.user_failures_expire {
                recent_failures(users, &user, now)
            } else {
                users.get(&user).map_or(0, VecDeque::len)
            }) >= self.user_failure_limit
            || recent_failures(addresses, address, now) >= FAILURE_LIMIT
        {
            return false;
        }
        // A lasting count mirrors a counter on the back end that never expires (QMAXSIGN):
        // none is ever evicted, and a full table refuses new names (fail closed).
        let user_room = if self.user_failures_expire {
            room(users, &user, now)
        } else {
            users.contains_key(&user) || users.len() < MAX_FAILURE_KEYS
        };
        if !(user_room && room(addresses, address, now)) {
            return false;
        }
        recent.push_back(now);
        users.entry(user).or_default().push_back(now);
        addresses
            .entry(address.to_owned())
            .or_default()
            .push_back(now);
        true
    }

    /// Checks the password (blocking) and decides whether the account may sign in.
    pub fn check(&self, user: &str, password: &str) -> Result<U::Account, (SignInError, String)> {
        let account = self
            .users
            .authenticate(user, password)
            .map_err(|e| match e {
                LocalAuthError::Rejected(why) => (SignInError::Rejected, why),
                LocalAuthError::Unavailable(why) => (SignInError::Unavailable, why),
            })?;
        self.users
            .eligible(&account)
            .map_err(|why| (SignInError::Rejected, why.into()))?;
        Ok(account)
    }

    /// Opens a session for an account accepted in the attempt [`Sessions::begin`] started
    /// for `user` (as typed) from `address`; returns the token. The attempt stops counting
    /// as a failure, and so do the user's earlier ones.
    pub fn open(
        &self,
        account: U::Account,
        user: &str,
        address: &str,
        now: Instant,
    ) -> Result<String, SignInError> {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|_| SignInError::Unavailable)?;
        let token = format!(
            "{}{}",
            self.token_prefix,
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
        );
        let name = U::name(&account).to_owned();
        let mut inner = self.lock();
        inner.users.remove(&user.to_lowercase());
        if let Some(list) = inner.addresses.get_mut(address) {
            list.pop_back();
        }
        inner.sessions.retain(|_, s| s.expires() > now);
        let mut own: Vec<([u8; 32], Instant)> = inner
            .sessions
            .iter()
            .filter(|(_, s)| s.name == name)
            .map(|(k, s)| (*k, s.created))
            .collect();
        own.sort_by_key(|(_, created)| *created);
        let excess = own
            .len()
            .saturating_add(1)
            .saturating_sub(MAX_SESSIONS_PER_USER);
        for (key, _) in own.into_iter().take(excess) {
            inner.sessions.remove(&key);
        }
        if inner.sessions.len() >= MAX_SESSIONS {
            return Err(SignInError::Full);
        }
        inner.sessions.insert(
            hash(&token),
            Session {
                account,
                name,
                created: now,
                last_used: now,
                refreshed: now,
                claimed: None,
            },
        );
        Ok(token)
    }

    /// The session of `token`, if valid; using it extends its idle expiry. Never blocks on
    /// the user database: accounts are read again by the refresher ([`Sessions::due`]).
    pub fn verify(&self, token: &str, now: Instant) -> Option<Active<U::Account>> {
        self.active(token, now, true)
    }

    /// The session of `token`, if still valid, without extending it: for a connection
    /// opened with it (an event stream) that must end with the session.
    pub fn current(&self, token: &str, now: Instant) -> Option<Active<U::Account>> {
        self.active(token, now, false)
    }

    fn active(&self, token: &str, now: Instant, touch: bool) -> Option<Active<U::Account>> {
        let key = hash(token);
        let mut inner = self.lock();
        let session = inner.sessions.get_mut(&key)?;
        if session.expires() <= now {
            inner.sessions.remove(&key);
            return None;
        }
        let refreshing = self.refreshing.load(Ordering::Relaxed);
        if refreshing && now.saturating_duration_since(session.refreshed) >= STALE {
            return None; // kept: a refresher that catches up makes it usable again
        }
        if touch {
            session.last_used = now;
        }
        Some(Active {
            account: session.account.clone(),
            remaining: session.expires().saturating_duration_since(now),
        })
    }

    /// Declares that a refresher calls [`Sessions::due`] and [`Sessions::refreshed`] from
    /// now on; from then a session not refreshed for three minutes is refused.
    pub fn start_refreshing(&self) {
        self.refreshing.store(true, Ordering::Relaxed);
    }

    /// The users whose sessions' accounts were read more than [`REFRESH`] ago, each once;
    /// they count as claimed now, so a slow lookup is never started twice. A session is
    /// refreshed only by an answer that completes.
    pub fn due(&self, now: Instant) -> Vec<String> {
        let mut inner = self.lock();
        inner.sessions.retain(|_, s| s.expires() > now);
        let mut users: Vec<String> = Vec::new();
        for session in inner.sessions.values_mut() {
            let claimed = session.claimed.unwrap_or(session.refreshed);
            if now.saturating_duration_since(claimed) >= REFRESH {
                session.claimed = Some(now);
                users.push(session.name.clone());
            }
        }
        users.sort();
        users.dedup();
        users
    }

    /// Applies what the user database answered for `user` to a lookup started at `asked`:
    /// the new account for each of the user's sessions, or the end of them when the
    /// account is gone or no longer eligible. Sessions read after `asked` (a sign-in during
    /// the lookup) are newer than the answer and left alone. An error keeps them as they
    /// were, and they become refused once [`STALE`].
    pub fn refreshed(
        &self,
        user: &str,
        asked: Instant,
        answer: Result<Option<U::Account>, LocalAuthError>,
    ) {
        let fresh = match answer {
            Err(_) => return,
            Ok(Some(a)) if U::name(&a) == user && self.users.eligible(&a).is_ok() => Some(a),
            Ok(_) => None,
        };
        let mut inner = self.lock();
        let older = |s: &Session<U::Account>| s.name == user && s.refreshed <= asked;
        match fresh {
            Some(account) => {
                for session in inner.sessions.values_mut() {
                    if older(session) {
                        session.account = account.clone();
                        session.refreshed = asked;
                    }
                }
            }
            None => inner.sessions.retain(|_, s| !older(s)),
        }
    }

    /// The user database, to read accounts again off the request path.
    pub fn users(&self) -> Arc<U> {
        Arc::clone(&self.users)
    }

    /// Ends the session of `token`; true if there was one.
    pub fn close(&self, token: &str) -> bool {
        self.lock().sessions.remove(&hash(token)).is_some()
    }

    /// Keys of the sessions still valid, without extending them: a service that keeps
    /// something per session (a connection) drops what is no longer here.
    pub fn live_keys(&self, now: Instant) -> std::collections::HashSet<[u8; 32]> {
        let mut inner = self.lock();
        inner.sessions.retain(|_, s| s.expires() > now);
        inner.sessions.keys().copied().collect()
    }
}

/// Makes room for `key` in a full table: expired entries go first, then the stalest with
/// fewer than [`FAILURE_LIMIT`] failures. An entry with more is never forgotten early, even
/// below its own table's limit, so churn cannot reset a user name close to
/// [`USER_FAILURE_LIMIT`]; one window admits at most 18 000 such entries. If only those
/// are left (which [`ATTEMPTS_PER_SECOND`] rules out) a new key is refused.
fn room(table: &mut HashMap<String, VecDeque<Instant>>, key: &str, now: Instant) -> bool {
    if table.contains_key(key) || table.len() < MAX_FAILURE_KEYS {
        return true;
    }
    table.retain(|_, list| {
        list.back()
            .is_some_and(|t| now.saturating_duration_since(*t) < FAILURE_WINDOW)
    });
    let target = MAX_FAILURE_KEYS.saturating_sub(MAX_FAILURE_KEYS / 10);
    if table.len() > target {
        let mut keys: Vec<(String, Instant)> = table
            .iter()
            .filter(|(_, list)| list.len() < FAILURE_LIMIT)
            .filter_map(|(k, list)| list.back().map(|t| (k.clone(), *t)))
            .collect();
        keys.sort_by_key(|(_, t)| *t);
        let excess = table.len().saturating_sub(target);
        for (k, _) in keys.into_iter().take(excess) {
            table.remove(&k);
        }
    }
    table.len() < MAX_FAILURE_KEYS
}

/// Failures of `key` within the window, forgetting older ones.
fn recent_failures(
    failures: &mut HashMap<String, VecDeque<Instant>>,
    key: &str,
    now: Instant,
) -> usize {
    let Some(list) = failures.get_mut(key) else {
        return 0;
    };
    while list
        .front()
        .is_some_and(|t| now.saturating_duration_since(*t) >= FAILURE_WINDOW)
    {
        list.pop_front();
    }
    let n = list.len();
    if n == 0 {
        failures.remove(key);
    }
    n
}

#[cfg(test)]
mod tests;
