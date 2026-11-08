//! Deadlines: per statement, and a total counted from opening that is never renewed
//! by queries.

use crate::error::{Error, Result};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Budget {
    pub connect: Duration,
    pub statement: Duration,
    pub total: Duration,
}

impl Budget {
    /// All three non-zero and the connection within the total. A per-statement limit
    /// above the total is allowed: each statement waits at most what is left anyway.
    pub fn new(connect: Duration, statement: Duration, total: Duration) -> Result<Self> {
        if connect.is_zero() || statement.is_zero() || connect > total {
            return Err(Error::Configuration);
        }
        Ok(Self {
            connect,
            statement,
            total,
        })
    }

    /// The same budget cut to `left` (for example what remains of a request that
    /// waited in a queue): the total and the connection never exceed it.
    pub fn within(&self, left: Duration) -> Result<Self> {
        if left.is_zero() {
            return Err(Error::Timeout);
        }
        let total = self.total.min(left);
        Ok(Self {
            connect: self.connect.min(total),
            statement: self.statement,
            total,
        })
    }

    /// The wait allowed for one statement started at `now`, in a session opened at
    /// `opened`: the smaller of the per-statement limit and what is left of the total.
    pub fn limit(&self, opened: Instant, now: Instant) -> Result<Duration> {
        let spent = now.checked_duration_since(opened).unwrap_or(Duration::ZERO);
        let left = self
            .total
            .checked_sub(spent)
            .filter(|d| !d.is_zero())
            .ok_or(Error::Timeout)?;
        Ok(left.min(self.statement))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_budget_within_what_is_left() -> Result<()> {
        let budget = Budget::new(ms(1000), ms(1500), ms(1800))?;
        assert_eq!(
            budget.within(ms(5000))?,
            budget,
            "never more than the total"
        );
        let short = budget.within(ms(700))?;
        assert_eq!(short.total, ms(700));
        assert_eq!(short.connect, ms(700), "the connection fits too");
        assert_eq!(short.statement, ms(1500), "the total still bounds it");
        assert!(matches!(budget.within(ms(0)), Err(Error::Timeout)));
        Ok(())
    }

    #[test]
    fn a_budget_must_be_coherent() {
        assert!(Budget::new(ms(1000), ms(1500), ms(4000)).is_ok());
        assert!(Budget::new(ms(0), ms(1500), ms(4000)).is_err());
        assert!(
            Budget::new(ms(1000), ms(5000), ms(4000)).is_ok(),
            "the total still bounds it"
        );
        assert!(Budget::new(ms(5000), ms(1500), ms(4000)).is_err());
    }

    #[test]
    fn each_statement_gets_the_smaller_of_its_limit_and_what_is_left() -> Result<()> {
        let budget = Budget::new(ms(1000), ms(1500), ms(4000))?;
        let opened = Instant::now();
        let at = |n: u64| opened.checked_add(ms(n)).ok_or(Error::Timeout);
        assert_eq!(budget.limit(opened, at(0)?)?, ms(1500));
        assert_eq!(budget.limit(opened, at(3000)?)?, ms(1000));
        assert!(matches!(
            budget.limit(opened, at(4000)?),
            Err(Error::Timeout)
        ));
        assert!(matches!(
            budget.limit(opened, at(9000)?),
            Err(Error::Timeout)
        ));
        Ok(())
    }
}
