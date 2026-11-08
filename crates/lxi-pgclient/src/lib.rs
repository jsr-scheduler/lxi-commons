//! Synchronous PostgreSQL client for the series: transport policy, per-statement
//! and total deadlines with server-side cancellation, and a small pool.
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

mod budget;
mod error;
mod policy;
mod pool;
mod session;

pub use budget::Budget;
pub use error::{Error, Result};
pub use policy::{classify, Policy, Transport};
pub use pool::{Pool, Pooled, MAX_SESSIONS};
pub use session::{Session, Settings, DEFAULT_TIMEZONE};
pub use tokio_postgres::types::ToSql;
pub use tokio_postgres::Row;
