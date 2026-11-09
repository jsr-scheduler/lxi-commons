use super::*;
use crate::sessions::LocalAuthError;
use std::sync::{mpsc, Mutex};

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

fn poisoned<T>(_: T) -> LocalAuthError {
    LocalAuthError::Unavailable("poisoned".into())
}

/// `amy`'s lookups wait for the test; `bob`'s answer the groups the test sets.
struct Users {
    hold: Mutex<Option<mpsc::Receiver<()>>>,
    bob: Mutex<Vec<String>>,
}

impl LocalUsers for Users {
    type Account = (String, Vec<String>);

    fn authenticate(&self, _: &str, _: &str) -> Result<Self::Account, LocalAuthError> {
        Err(LocalAuthError::Rejected("not used".into()))
    }

    fn lookup(&self, user: &str) -> Result<Option<Self::Account>, LocalAuthError> {
        match user {
            "amy" => {
                let hold = self.hold.lock().map_err(poisoned)?.take();
                if let Some(hold) = hold {
                    let _ = hold.recv();
                }
                Ok(Some((user.into(), vec!["role".into()])))
            }
            _ => Ok(Some((
                user.into(),
                self.bob.lock().map_err(poisoned)?.clone(),
            ))),
        }
    }

    fn name(account: &Self::Account) -> &str {
        &account.0
    }

    fn eligible(&self, account: &Self::Account) -> Result<(), &'static str> {
        if account.1.iter().any(|g| g == "role") {
            Ok(())
        } else {
            Err("in no role group")
        }
    }
}

#[test]
fn a_refresh_that_times_out_keeps_the_session_until_stale() -> TestResult {
    run(false, async {
        let (release, hold) = mpsc::channel();
        let users = Arc::new(Users {
            hold: Mutex::new(Some(hold)),
            bob: Mutex::new(vec!["role".into()]),
        });
        let sessions = Arc::new(Sessions::new(Arc::clone(&users), "test_"));
        // Opened a minute ago: due for a refresh now.
        let opened = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .ok_or("time")?;
        let role = || vec!["role".to_owned()];
        let amy = sessions.open(("amy".into(), role()), "amy", "a", opened)?;
        let bob = sessions.open(("bob".into(), role()), "bob", "a", opened)?;
        users.bob.lock().map_err(|_| "poisoned")?.clear();
        let refresher = tokio::spawn(refresh_with(
            Arc::clone(&sessions),
            Duration::from_millis(20),
            Duration::from_millis(200),
            |_: &str| {},
        ));
        // amy's lookup hangs and is abandoned; bob's is read after it, in the same pass.
        let mut bob_gone = false;
        for _ in 0..100 {
            tokio::time::sleep(Duration::from_millis(20)).await;
            if sessions.current(&bob, Instant::now()).is_none() {
                bob_gone = true;
                break;
            }
        }
        assert!(
            bob_gone,
            "bob lost the role while amy's lookup hung (amy is read first)"
        );
        // amy keeps its session until its account is three minutes old.
        assert!(sessions.current(&amy, Instant::now()).is_some());
        let stale = opened.checked_add(Duration::from_secs(180)).ok_or("time")?;
        assert!(sessions.current(&amy, stale).is_none());
        refresher.abort();
        release.send(())?;
        Ok(())
    })
}

/// Every check but `quick`'s waits until the test opens the gate.
struct Held {
    entered: std::sync::atomic::AtomicUsize,
    gate: Mutex<bool>,
    open: std::sync::Condvar,
}

impl LocalUsers for Held {
    type Account = (String, Vec<String>);

    fn authenticate(&self, user: &str, _: &str) -> Result<Self::Account, LocalAuthError> {
        if user != "quick" {
            self.entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut open = self.gate.lock().map_err(poisoned)?;
            while !*open {
                open = self.open.wait(open).map_err(poisoned)?;
            }
        }
        Ok((user.into(), vec!["role".into()]))
    }

    fn name(account: &Self::Account) -> &str {
        &account.0
    }

    fn eligible(&self, _: &Self::Account) -> Result<(), &'static str> {
        Ok(())
    }
}

/// A client that goes away does not free its PAM slot while PAM still runs (automated
/// review; JSR dropped the permit with the request).
#[test]
fn an_abandoned_sign_in_keeps_its_slot_until_pam_answers() -> TestResult {
    run(false, async {
        let users = Arc::new(Held {
            entered: std::sync::atomic::AtomicUsize::new(0),
            gate: Mutex::new(false),
            open: std::sync::Condvar::new(),
        });
        let sign_in = Arc::new(SignIn::new(Arc::new(Sessions::new(
            Arc::clone(&users),
            "test_",
        ))));
        let mut tasks = Vec::new();
        for n in 0..MAX_SIGN_INS {
            let sign_in = Arc::clone(&sign_in);
            let peer: IpAddr = format!("10.0.1.{n}").parse()?;
            tasks.push(tokio::spawn(async move {
                let _ = sign_in
                    .attempt(&format!("u{n}"), Zeroizing::new("pw".into()), peer)
                    .await;
            }));
        }
        for _ in 0..500 {
            if users.entered.load(std::sync::atomic::Ordering::SeqCst) >= MAX_SIGN_INS {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let entered = users.entered.load(std::sync::atomic::Ordering::SeqCst);
        if entered != MAX_SIGN_INS {
            *users.gate.lock().map_err(|_| "poisoned")? = true;
            users.open.notify_all();
            return Err(format!("{entered} checks started").into());
        }
        // The clients go away; their PAM conversations go on.
        for task in &tasks {
            task.abort();
        }
        for task in tasks {
            let _ = task.await;
        }
        let peer: IpAddr = "10.0.2.1".parse()?;
        let refused = sign_in
            .attempt("quick", Zeroizing::new("pw".into()), peer)
            .await
            .err()
            .map(|(e, _)| e);
        // PAM answers (before any assertion: a held thread would keep the runtime alive).
        *users.gate.lock().map_err(|_| "poisoned")? = true;
        users.open.notify_all();
        assert_eq!(refused, Some(SignInError::Unavailable));
        // The slots come back.
        let mut accepted = false;
        for n in 0..200_u32 {
            let peer: IpAddr = format!("10.0.3.{}", n.checked_rem(250).unwrap_or(0)).parse()?;
            if sign_in
                .attempt("quick", Zeroizing::new("pw".into()), peer)
                .await
                .is_ok()
            {
                accepted = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(accepted);
        Ok(())
    })
}
