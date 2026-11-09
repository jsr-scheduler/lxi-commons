//! The sign-in sequence of JSR's `POST /api/v1/sessions` (3b75827) and its refresher,
//! without HTTP.
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

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use lxi_http::sessions::{LocalAuthError, LocalUsers, Sessions, SignInError};
use lxi_http::sign_in::{throttle_address, valid_user_name, SignIn};
use zeroize::Zeroizing;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// A current-thread runtime (`#[tokio::test]` expands to an allow the workspace forbids).
fn run<F: std::future::Future<Output = TestResult>>(paused: bool, test: F) -> TestResult {
    let mut builder = tokio::runtime::Builder::new_current_thread();
    builder.enable_time();
    if paused {
        builder.start_paused(true);
    }
    builder.build()?.block_on(test)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Acct {
    name: String,
    groups: BTreeSet<String>,
}

/// `ana` and `root` know `secret`; root may not sign in; `down` finds PAM down.
struct Users;

fn acct(name: &str, groups: &[&str]) -> Acct {
    Acct {
        name: name.into(),
        groups: groups.iter().map(|g| (*g).to_owned()).collect(),
    }
}

impl LocalUsers for Users {
    type Account = Acct;

    fn authenticate(&self, user: &str, password: &str) -> Result<Acct, LocalAuthError> {
        match (user, password) {
            ("down", _) => Err(LocalAuthError::Unavailable("PAM open".into())),
            (_, "secret") => Ok(acct(user, &["role"])),
            _ => Err(LocalAuthError::Rejected("PAM authenticate".into())),
        }
    }

    fn name(account: &Acct) -> &str {
        &account.name
    }

    fn eligible(&self, account: &Acct) -> Result<(), &'static str> {
        if account.name == "root" {
            return Err("uid 0 cannot sign in");
        }
        if !account.groups.contains("role") {
            return Err("in no role group");
        }
        Ok(())
    }
}

fn sign_in() -> SignIn<Users> {
    SignIn::new(Arc::new(Sessions::new(Arc::new(Users), "test_")))
}

fn ip(text: &str) -> TestResult<IpAddr> {
    Ok(text.parse()?)
}

fn pw(text: &str) -> Zeroizing<String> {
    Zeroizing::new(text.to_owned())
}

#[test]
fn a_refused_sign_in_takes_as_long_whatever_the_password() -> TestResult {
    run(true, async {
        // A right password for an account that may not sign in, and a wrong one, both answer
        // after the same time: no password oracle (JSR S-07).
        let s = sign_in();
        for (user, password) in [("ana", "nope"), ("root", "secret")] {
            let started = tokio::time::Instant::now();
            let refused = s.attempt(user, pw(password), ip("10.0.0.1")?).await.err();
            assert_eq!(
                refused.map(|(e, _)| e),
                Some(SignInError::Rejected),
                "{user}"
            );
            let took = started.elapsed();
            assert!(took >= Duration::from_secs(4), "{user}: {took:?}");
        }
        // Unavailable is not a refusal: answered at once, as JSR does.
        let started = tokio::time::Instant::now();
        let down = s.attempt("down", pw("x"), ip("10.0.0.2")?).await.err();
        assert_eq!(down.map(|(e, _)| e), Some(SignInError::Unavailable));
        assert!(started.elapsed() < Duration::from_secs(4));
        Ok(())
    })
}

#[test]
fn a_right_password_opens_a_session() -> TestResult {
    run(false, async {
        let s = sign_in();
        let signed = s
            .attempt(" ana ", pw("secret"), ip("10.0.0.1")?)
            .await
            .map_err(|(e, why)| format!("{e}: {why}"))?;
        assert_eq!(signed.account.name, "ana");
        assert!(signed.token.starts_with("test_"));
        let active = s
            .sessions()
            .verify(&signed.token, Instant::now())
            .ok_or("no session")?;
        assert_eq!(active.account.name, "ana");
        Ok(())
    })
}

#[test]
fn the_user_name_and_password_bounds_are_enforced() -> TestResult {
    run(false, async {
        let s = sign_in();
        let long_user = "a".repeat(65);
        let long_password = "p".repeat(1025);
        for (user, password) in [
            ("", "secret"),
            ("   ", "secret"),
            (long_user.as_str(), "secret"),
            ("ana bob", "secret"),
            ("ana/..", "secret"),
            ("ana", ""),
            ("ana", long_password.as_str()),
        ] {
            let refused = s.attempt(user, pw(password), ip("10.0.0.1")?).await.err();
            assert_eq!(
                refused.map(|(e, _)| e),
                Some(SignInError::Invalid),
                "{user}"
            );
        }
        // Nothing was counted: the address is not throttled.
        assert!(s
            .attempt("ana", pw("secret"), ip("10.0.0.1")?)
            .await
            .is_ok());
        assert!(valid_user_name("ana.b-c_d@example.com"));
        assert!(valid_user_name(&"a".repeat(64)));
        assert!(!valid_user_name("ñandú"));
        Ok(())
    })
}

#[test]
fn an_ipv6_address_is_throttled_by_its_64() -> TestResult {
    run(true, async {
        assert_eq!(
            throttle_address(ip("2001:db8:1:2:3:4:5:6")?),
            "2001:db8:1:2::/64"
        );
        assert_eq!(throttle_address(ip("::ffff:10.0.0.1")?), "10.0.0.1");
        assert_eq!(throttle_address(ip("10.0.0.1")?), "10.0.0.1");
        let s = sign_in();
        for n in 1..=5 {
            let peer = ip(&format!("2001:db8:1:2::{n}"))?;
            let refused = s.attempt("eve", pw("nope"), peer).await.err();
            assert_eq!(refused.map(|(e, _)| e), Some(SignInError::Rejected));
        }
        let next = s
            .attempt("ana", pw("secret"), ip("2001:db8:1:2:ffff::9")?)
            .await
            .err();
        assert_eq!(next.map(|(e, _)| e), Some(SignInError::Throttled));
        // Another /64 is another address.
        assert!(s
            .attempt("ana", pw("secret"), ip("2001:db8:1:3::1")?)
            .await
            .is_ok());
        Ok(())
    })
}
