//! The sign-in sequence of JSR's `POST /api/v1/sessions` (`crates/api-rest/src/lib.rs`,
//! 3b75827), without HTTP, and the refresher that reads accounts again.

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::sessions::{LocalUsers, Sessions, SignInError, REFRESH_EVERY};

/// Every refused sign-in answers this long after it began, whatever PAM did: a wrong
/// password (with PAM's own fail delay of about 2 s) and a right password for an account
/// that may not sign in look the same (JSR security review S-07).
pub const SIGN_IN_REFUSAL_TIME: Duration = Duration::from_secs(4);
/// PAM conversations at once; more wait for none but answer `unavailable` (S-17).
pub const MAX_SIGN_INS: usize = 16;
/// A lookup that takes longer is abandoned (its thread finishes on its own); the session
/// stays as it was and is refused once its account is three minutes old.
pub const LOOKUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Account lookups running at once, at most.
pub const MAX_LOOKUPS: usize = 4;
/// Longest password accepted, in bytes.
pub const MAX_PASSWORD: usize = 1024;

/// 1–64 bytes of `[A-Za-z0-9._@-]`.
pub fn valid_user_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-@".contains(&b))
}

/// The key sign-in attempts from `ip` count under: the address, an IPv6 one by its /64,
/// which one host usually owns whole.
pub fn throttle_address(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => v4.to_string(),
            None => {
                let [a, b, c, d, ..] = v6.segments();
                format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
            }
        },
    }
}

/// An accepted sign-in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedIn<A> {
    pub token: String,
    pub account: A,
}

/// Sign-ins against `sessions`, at most [`MAX_SIGN_INS`] at once.
pub struct SignIn<U: LocalUsers> {
    sessions: Arc<Sessions<U>>,
    slots: Arc<Semaphore>,
}

impl<U: LocalUsers> std::fmt::Debug for SignIn<U> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignIn").finish_non_exhaustive()
    }
}

impl<U: LocalUsers> SignIn<U> {
    pub fn new(sessions: Arc<Sessions<U>>) -> Self {
        Self {
            sessions,
            slots: Arc::new(Semaphore::new(MAX_SIGN_INS)),
        }
    }

    pub fn sessions(&self) -> Arc<Sessions<U>> {
        Arc::clone(&self.sessions)
    }

    /// One sign-in from `peer`. The error carries the reason for the service's log; the
    /// client sees only the [`SignInError`].
    pub async fn attempt(
        &self,
        user: &str,
        password: Zeroizing<String>,
        peer: IpAddr,
    ) -> Result<SignedIn<U::Account>, (SignInError, String)> {
        let user = user.trim().to_owned();
        if !valid_user_name(&user) || password.is_empty() || password.len() > MAX_PASSWORD {
            return Err((SignInError::Invalid, "bounds".into()));
        }
        let address = throttle_address(peer);
        if !self.sessions.begin(&user, &address, Instant::now()) {
            return Err((SignInError::Throttled, format!("{address} throttled")));
        }
        let started = tokio::time::Instant::now();
        let Ok(slot) = Arc::clone(&self.slots).try_acquire_owned() else {
            return Err((SignInError::Unavailable, "too many sign-ins at once".into()));
        };
        // The slot goes with the PAM conversation, not with the request: a client that
        // goes away does not free it while PAM still runs (JSR held it in the request).
        let check = {
            let sessions = Arc::clone(&self.sessions);
            let user = user.clone();
            tokio::task::spawn_blocking(move || {
                let _slot = slot;
                sessions.check(&user, &password)
            })
            .await
        };
        let account = match check {
            Ok(Ok(account)) => account,
            Ok(Err((SignInError::Unavailable, why))) => {
                return Err((SignInError::Unavailable, why));
            }
            Ok(Err((_, why))) => {
                // The attempt begun above stays recorded as a failure.
                let left = SIGN_IN_REFUSAL_TIME.saturating_sub(started.elapsed());
                tokio::time::sleep(left).await;
                return Err((SignInError::Rejected, why));
            }
            Err(e) => return Err((SignInError::Unavailable, format!("sign-in task: {e}"))),
        };
        let token = self
            .sessions
            .open(account.clone(), &user, &address, Instant::now())
            .map_err(|e| (e, "open".into()))?;
        Ok(SignedIn { token, account })
    }
}

/// Reads the accounts of open sessions again every [`REFRESH_EVERY`], off the request
/// path and one lookup at a time: the user database may be slow (LDAP). Never returns;
/// `log` receives what JSR wrote to stderr.
pub async fn refresh<U: LocalUsers>(sessions: Arc<Sessions<U>>, log: fn(&str)) {
    refresh_with(sessions, REFRESH_EVERY, LOOKUP_TIMEOUT, log).await;
}

pub(crate) async fn refresh_with<U: LocalUsers>(
    sessions: Arc<Sessions<U>>,
    every: Duration,
    timeout: Duration,
    log: fn(&str),
) {
    sessions.start_refreshing();
    // Lookups still running, abandoned ones included: a user database that hangs must not
    // pile up blocked threads. While too many run, refreshes wait, and sessions whose
    // accounts grow three minutes old are refused.
    let running = Arc::new(AtomicUsize::new(0));
    loop {
        tokio::time::sleep(every).await;
        if running.load(Ordering::Relaxed) >= MAX_LOOKUPS {
            log("the user database is not answering; refreshes wait");
            continue;
        }
        for user in sessions.due(Instant::now()) {
            if running.load(Ordering::Relaxed) >= MAX_LOOKUPS {
                break;
            }
            let asked = Instant::now();
            let users = sessions.users();
            let name = user.clone();
            let counter = Arc::clone(&running);
            counter.fetch_add(1, Ordering::Relaxed);
            let lookup = tokio::task::spawn_blocking(move || {
                let answer = users.lookup(&name);
                counter.fetch_sub(1, Ordering::Relaxed);
                answer
            });
            match tokio::time::timeout(timeout, lookup).await {
                Ok(Ok(answer)) => sessions.refreshed(&user, asked, answer),
                Ok(Err(e)) => log(&format!("reading account {user}: {e}")),
                Err(_) => log(&format!("reading account {user}: no answer in time")),
            }
        }
    }
}

#[cfg(test)]
mod tests;
