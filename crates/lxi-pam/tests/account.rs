//! Accounts and PAM on any host, ported from JSR `crates/auth-local` (3b75827).
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

use lxi_pam::{account_of_uid, lookup, AuthError, Pam};
use nix::unistd::{Gid, Uid};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn the_current_user_has_a_principal_with_groups() -> TestResult {
    let a = account_of_uid(Uid::current().as_raw(), Gid::current().as_raw())?;
    assert!(!a.name.is_empty());
    assert_eq!(a.uid, Uid::current().as_raw());
    assert!(!a.groups.is_empty());
    assert_eq!(a.superuser, Uid::current().is_root());
    assert_eq!(lookup(&a.name)?, Some(a));
    Ok(())
}

#[test]
fn an_unknown_user_is_rejected() {
    let err = Pam::new("lxi-test").authenticate("no-such-user-lxi", "x");
    assert!(matches!(err, Err(AuthError::Rejected(_))), "{err:?}");
    assert_eq!(lookup("no-such-user-lxi").ok(), Some(None));
}
