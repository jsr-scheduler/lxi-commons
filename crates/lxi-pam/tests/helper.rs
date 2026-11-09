//! The yes/no helper and its client, with a stand-in for PAM.
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

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use lxi_ipc::Limits;
use lxi_pam::helper::{serve, Client};
use lxi_pam::{AuthError, Check};
use serde_json::{json, Value};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// Accepts `ana` with `secret`, says PAM is down for `down`, rejects the rest.
#[derive(Default)]
struct Fake {
    calls: AtomicUsize,
}

impl Check for Fake {
    fn check(&self, user: &str, password: &str) -> Result<(), AuthError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match (user, password) {
            ("ana", "secret") => Ok(()),
            ("down", _) => Err(AuthError::Unavailable("PAM open: no module".into())),
            _ => Err(AuthError::Rejected("PAM authenticate: wrong".into())),
        }
    }
}

fn me() -> u32 {
    nix::unistd::Uid::effective().as_raw()
}

fn ask(user: &str, password: &str, fake: &Fake, allowed: u32) -> TestResult<Value> {
    let (mut client, server) = UnixStream::pair()?;
    lxi_ipc::write_frame(
        &mut client,
        &json!({"v": 1, "user": user, "password": password}),
        &Limits::SERIES,
    )?;
    serve(server, fake, allowed)?;
    Ok(lxi_ipc::read_frame(&mut client, &Limits::SERIES)?)
}

#[test]
fn the_helper_answers_only_yes_or_no() -> TestResult {
    let fake = Fake::default();
    for (user, password, result) in [
        ("ana", "secret", "accepted"),
        ("ana", "wrong", "rejected"),
        ("nobody", "secret", "rejected"),
        ("down", "x", "unavailable"),
    ] {
        let reply = ask(user, password, &fake, me())?;
        // Nothing but the answer: no reason, no groups, no account data.
        assert_eq!(reply, json!({"v": 1, "result": result}), "{user}");
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 4);
    Ok(())
}

#[test]
fn the_helper_refuses_another_uid_before_reading() -> TestResult {
    let fake = Fake::default();
    let (mut client, server) = UnixStream::pair()?;
    lxi_ipc::write_frame(
        &mut client,
        &json!({"v": 1, "user": "ana", "password": "secret"}),
        &Limits::SERIES,
    )?;
    // Set before the helper closes: macOS refuses socket options on a closed peer.
    client.set_nonblocking(false)?;
    client.set_read_timeout(Some(Duration::from_secs(2)))?;
    let other = me().checked_add(1).ok_or("uid")?;
    assert!(serve(server, &fake, other).is_err());
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    // The connection is closed without an answer: an end of stream, or on Linux a reset
    // (the helper closed with the request unread).
    let mut rest = Vec::new();
    match client.read_to_end(&mut rest) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {}
        Err(e) => return Err(e.into()),
    }
    assert!(rest.is_empty());
    Ok(())
}

#[test]
fn an_oversized_frame_never_reaches_pam() -> TestResult {
    let fake = Fake::default();
    let (mut client, server) = UnixStream::pair()?;
    client.write_all(&(1_u32 << 20).to_be_bytes())?;
    assert!(serve(server, &fake, me()).is_err());
    // Malformed shapes do not reach it either.
    for bad in [
        json!({"v": 1, "user": "ana"}),
        json!({"v": 2, "user": "ana", "password": "secret"}),
        json!({"v": 1, "user": "ana", "password": "secret", "extra": 1}),
        json!({"v": 1, "user": "", "password": "secret"}),
        json!({"v": 1, "user": "ana", "password": ""}),
        json!({"v": 1, "user": "a".repeat(65), "password": "secret"}),
        json!({"v": 1, "user": "ana", "password": "p".repeat(1025)}),
        json!({"v": 1, "user": "ana/../x", "password": "secret"}),
    ] {
        let (mut client, server) = UnixStream::pair()?;
        lxi_ipc::write_frame(&mut client, &bad, &Limits::SERIES)?;
        assert!(serve(server, &fake, me()).is_err(), "{bad}");
    }
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

#[test]
fn a_silent_client_is_dropped_at_the_deadline() -> TestResult {
    let fake = Fake::default();
    let (_client, server) = UnixStream::pair()?;
    let started = Instant::now();
    assert!(serve(server, &fake, me()).is_err());
    let took = started.elapsed();
    assert!(took >= Duration::from_millis(1900), "{took:?}");
    assert!(took < Duration::from_secs(5), "{took:?}");
    assert_eq!(fake.calls.load(Ordering::SeqCst), 0);
    Ok(())
}

fn socket(test: &str) -> TestResult<PathBuf> {
    let dir = std::env::temp_dir().join(format!("lxi-pam-{}-{test}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("helper.sock");
    let _ = std::fs::remove_file(&path);
    Ok(path)
}

/// A helper on `path` that answers each connection with `reply` (raw bytes).
fn fake_helper(path: &PathBuf, reply: Vec<u8>) -> TestResult<std::thread::JoinHandle<()>> {
    let listener = UnixListener::bind(path)?;
    Ok(std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = lxi_ipc::read_frame(&mut stream, &Limits::SERIES);
            let _ = stream.write_all(&reply);
        }
    }))
}

fn framed(value: &Value) -> TestResult<Vec<u8>> {
    let body = value.to_string().into_bytes();
    let mut out = u32::try_from(body.len())?.to_be_bytes().to_vec();
    out.extend(body);
    Ok(out)
}

#[test]
fn the_client_treats_garbage_as_unavailable() -> TestResult {
    let me_name = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .ok_or("no current user")?
        .name;
    for (test, reply) in [
        ("garbage", b"\x00\x00\x00\x05nope!".to_vec()),
        ("empty", Vec::new()),
        ("unknown", framed(&json!({"v": 1, "result": "maybe"}))?),
        (
            "extra",
            framed(&json!({"v": 1, "result": "accepted", "x": 1}))?,
        ),
        ("version", framed(&json!({"v": 2, "result": "accepted"}))?),
    ] {
        let path = socket(test)?;
        let helper = fake_helper(&path, reply)?;
        let answer = Client::new(&path, me()).authenticate(&me_name, "secret");
        assert!(
            matches!(answer, Err(AuthError::Unavailable(_))),
            "{test}: {answer:?}"
        );
        helper.join().map_err(|_| "helper thread")?;
    }
    // No helper at all.
    let path = socket("none")?;
    assert!(matches!(
        Client::new(&path, me()).authenticate(&me_name, "secret"),
        Err(AuthError::Unavailable(_))
    ));
    Ok(())
}

#[test]
fn the_client_follows_the_helpers_answer() -> TestResult {
    let me_name = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .ok_or("no current user")?
        .name;
    let path = socket("answers")?;
    let listener = UnixListener::bind(&path)?;
    let fake = Arc::new(FakeFor(me_name.clone()));
    let server = {
        let fake = Arc::clone(&fake);
        std::thread::spawn(move || -> Result<(), String> {
            for _ in 0..3 {
                let (stream, _) = listener.accept().map_err(|e| e.to_string())?;
                serve(stream, fake.as_ref(), me()).map_err(|e| e.to_string())?;
            }
            Ok(())
        })
    };
    let client = Client::new(&path, me());
    let account = client.authenticate(&me_name, "secret")?;
    assert_eq!(account.name, me_name);
    assert_eq!(account.uid, nix::unistd::Uid::current().as_raw());
    assert!(!account.groups.is_empty());
    assert!(matches!(
        client.authenticate(&me_name, "wrong"),
        Err(AuthError::Rejected(_))
    ));
    assert!(matches!(
        client.authenticate("down", "x"),
        Err(AuthError::Unavailable(_))
    ));
    server.join().map_err(|_| "server thread")??;
    Ok(())
}

/// [`Fake`], with the current account as the one that knows `secret`.
struct FakeFor(String);

impl Check for FakeFor {
    fn check(&self, user: &str, password: &str) -> Result<(), AuthError> {
        if user == "down" {
            return Err(AuthError::Unavailable("down".into()));
        }
        if user == self.0 && password == "secret" {
            Ok(())
        } else {
            Err(AuthError::Rejected("wrong".into()))
        }
    }
}

/// Whoever can create the socket must not receive passwords: the client checks the
/// helper's UID before it sends anything (automated review).
#[test]
fn the_client_sends_nothing_to_a_helper_with_another_uid() -> TestResult {
    let me_name = nix::unistd::User::from_uid(nix::unistd::Uid::current())?
        .ok_or("no current user")?
        .name;
    let path = socket("impostor")?;
    let listener = UnixListener::bind(&path)?;
    let impostor = std::thread::spawn(move || -> Vec<u8> {
        let mut got = Vec::new();
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
            let _ = stream.read_to_end(&mut got);
            let _ = stream
                .write_all(&framed(&json!({"v": 1, "result": "accepted"})).unwrap_or_default());
        }
        got
    });
    let helper_uid = me().checked_add(1).ok_or("uid")?;
    let answer = Client::new(&path, helper_uid).authenticate(&me_name, "secret");
    assert!(
        matches!(answer, Err(AuthError::Unavailable(_))),
        "{answer:?}"
    );
    let got = impostor.join().map_err(|_| "impostor thread")?;
    assert!(got.is_empty(), "the impostor received {} bytes", got.len());
    Ok(())
}
