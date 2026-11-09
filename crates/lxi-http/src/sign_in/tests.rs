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
