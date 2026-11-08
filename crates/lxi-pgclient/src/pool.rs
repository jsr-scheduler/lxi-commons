//! A small, bounded pool. It never waits: a full pool answers `Unavailable`. A
//! session that timed out, broke or was left inside a transaction is dropped, never
//! handed out again; a reused one is reset (`DISCARD ALL`) and set up again first.

use crate::budget::Budget;
use crate::error::{Error, Result};
use crate::session::{Session, Settings};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

pub const MAX_SESSIONS: usize = 16;

type Setup = Box<dyn Fn(&mut Session) -> Result<()> + Send + Sync>;

pub struct Pool {
    settings: Settings,
    budget: Budget,
    max: usize,
    idle: Mutex<Vec<Session>>,
    open: AtomicUsize,
    setup: Setup,
}

impl Pool {
    /// `setup` runs on every new session (session settings, the consumer's contract
    /// check). `max` is between 1 and 16.
    pub fn new(
        settings: Settings,
        budget: Budget,
        max: usize,
        setup: impl Fn(&mut Session) -> Result<()> + Send + Sync + 'static,
    ) -> Result<Self> {
        if max == 0 || max > MAX_SESSIONS {
            return Err(Error::Configuration);
        }
        Ok(Self {
            settings,
            budget,
            max,
            idle: Mutex::new(Vec::new()),
            open: AtomicUsize::new(0),
            setup: Box::new(setup),
        })
    }

    /// Sessions waiting to be reused.
    pub fn idle(&self) -> usize {
        self.idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    fn release_slot(&self) {
        let _released = self
            .open
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| n.checked_sub(1));
    }

    /// An idle session with a fresh total budget, or a new one up to `max`.
    pub fn get(&self) -> Result<Pooled<'_>> {
        self.get_within(self.budget.total)
    }

    /// Like `get`, but the session's budget (connection and setup included for a
    /// new one) never exceeds `left`, for example what a queued request has left.
    /// Back in the pool, the session has the pool's full budget again.
    pub fn get_within(&self, left: Duration) -> Result<Pooled<'_>> {
        let budget = self.budget.within(left)?;
        let reused = self
            .idle
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .pop();
        if let Some(mut session) = reused {
            if let Err(error) = session.renew_within(left) {
                self.idle
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(session);
                return Err(error);
            }
            // A reused session starts clean: nothing of the previous checkout survives.
            match session.reset().and_then(|()| (self.setup)(&mut session)) {
                Ok(()) => {
                    return Ok(Pooled {
                        pool: self,
                        session: Some(session),
                    })
                }
                // It could not be cleaned: dropped, and its slot serves a new session.
                Err(_) => {
                    drop(session);
                    self.release_slot();
                }
            }
        }
        let max = self.max;
        self.open
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < max).then(|| n.saturating_add(1))
            })
            .map_err(|_| Error::Unavailable)?;
        let opened = Session::open(&self.settings, budget).and_then(|(mut session, _)| {
            (self.setup)(&mut session)?;
            session.rebase(self.budget);
            Ok(session)
        });
        match opened {
            Ok(session) => Ok(Pooled {
                pool: self,
                session: Some(session),
            }),
            Err(error) => {
                self.release_slot();
                Err(error)
            }
        }
    }
}

/// A session borrowed from the pool; it goes back on drop unless it broke.
pub struct Pooled<'a> {
    pool: &'a Pool,
    session: Option<Session>,
}

impl Pooled<'_> {
    /// The borrowed session. Always present until the guard is dropped.
    pub fn session(&mut self) -> Result<&mut Session> {
        self.session.as_mut().ok_or(Error::Unavailable)
    }
}

impl Drop for Pooled<'_> {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            if session.is_broken() || session.in_transaction() {
                drop(session);
                self.pool.release_slot();
            } else {
                self.pool
                    .idle
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .push(session);
            }
        }
    }
}
