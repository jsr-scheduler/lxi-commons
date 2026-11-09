//! Real PAM with throwaway accounts, provisioned by tools/run_pam_integration.py inside the
//! Linux builder. Every test is #[ignore]: a wrong password is a failed login of that
//! account, so they never run against the account running the tests (JSR auth-local).
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

use std::os::unix::net::UnixListener;

use lxi_pam::helper::{serve, Client};
use lxi_pam::{AuthError, Pam};
use nix::unistd::{Uid, User};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn env(name: &str) -> TestResult<String> {
    std::env::var(name)
        .map_err(|_| format!("{name} not set: run tools/run_pam_integration.py").into())
}

/// The throwaway account, never the one running the tests.
fn account() -> TestResult<(String, String)> {
    let user = env("LXI_TEST_PAM_USER")?;
    let me = User::from_uid(Uid::current())?.ok_or("no current user")?;
    if user == me.name {
        return Err("never fail a login of the account running the tests".into());
    }
    Ok((user, env("LXI_TEST_PAM_PASSWORD")?))
}

fn pam() -> TestResult<Pam> {
    Ok(Pam::new(env("LXI_TEST_PAM_SERVICE")?))
}

#[test]
#[ignore = "real PAM: run through tools/run_pam_integration.py"]
fn right_password_is_accepted() -> TestResult {
    let (user, password) = account()?;
    let a = pam()?.authenticate(&user, &password)?;
    assert_eq!(a.name, user);
    assert!(!a.superuser);
    assert!(a.groups.contains(&env("LXI_TEST_PAM_GROUP")?));
    Ok(())
}

#[test]
#[ignore = "real PAM: run through tools/run_pam_integration.py"]
fn wrong_password_is_rejected() -> TestResult {
    let (user, _) = account()?;
    let err = pam()?.authenticate(&user, "certainly not the password");
    assert!(matches!(err, Err(AuthError::Rejected(_))), "{err:?}");
    Ok(())
}

#[test]
#[ignore = "real PAM: run through tools/run_pam_integration.py"]
fn unknown_user_is_rejected() -> TestResult {
    let err = pam()?.authenticate("no-such-user-lxi", "x");
    assert!(matches!(err, Err(AuthError::Rejected(_))), "{err:?}");
    Ok(())
}

#[test]
#[ignore = "real PAM: run through tools/run_pam_integration.py"]
fn a_locked_account_is_rejected() -> TestResult {
    let user = env("LXI_TEST_PAM_LOCKED")?;
    let err = pam()?.authenticate(&user, &env("LXI_TEST_PAM_PASSWORD")?);
    assert!(matches!(err, Err(AuthError::Rejected(_))), "{err:?}");
    Ok(())
}

#[test]
#[ignore = "real PAM: run through tools/run_pam_integration.py"]
fn the_helper_accepts_through_its_socket() -> TestResult {
    let (user, password) = account()?;
    let dir = std::env::temp_dir().join(format!("lxi-pam-it-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("helper.sock");
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path)?;
    let me = Uid::effective().as_raw();
    let service = env("LXI_TEST_PAM_SERVICE")?;
    let server = std::thread::spawn(move || -> Result<(), String> {
        let pam = Pam::new(service);
        for _ in 0..2 {
            let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
            serve(stream, &pam, me).map_err(|e| e.to_string())?;
        }
        Ok(())
    });
    let client = Client::new(&path, me);
    assert_eq!(client.authenticate(&user, &password)?.name, user);
    assert!(matches!(
        client.authenticate(&user, "certainly not the password"),
        Err(AuthError::Rejected(_))
    ));
    server.join().map_err(|_| "server thread")??;
    Ok(())
}
