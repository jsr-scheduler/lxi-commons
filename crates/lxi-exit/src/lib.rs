//! Exit codes shared by every command of the series (INHERITED_LESSONS.md). Each
//! service maps its own errors and decisions onto these; the numbers never change.
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

/// Allowed, or the operation was done.
pub const ALLOWED: u8 = 0;
/// Denied by policy: a decision, not a failure.
pub const DENIED: u8 = 3;
/// Input or configuration rejected (sysexits EX_USAGE).
pub const INPUT: u8 = 64;
/// Unavailable for this request (EX_UNAVAILABLE).
pub const UNAVAILABLE: u8 = 69;
/// A daemon lost a critical dependency and must be restarted (EX_SOFTWARE).
pub const SERVICE_LOST: u8 = 70;
/// Conflict with existing state (EX_CANTCREAT).
pub const CONFLICT: u8 = 73;
/// Local input/output failed (EX_IOERR).
pub const IO: u8 = 74;
/// A deadline passed (EX_TEMPFAIL).
pub const TIMEOUT: u8 = 75;
/// The caller lacks the authority for the operation (EX_NOPERM).
pub const AUTHORITY: u8 = 77;

/// The process exit status for a series code.
pub fn exit_code(code: u8) -> std::process::ExitCode {
    std::process::ExitCode::from(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_series_table_is_fixed() {
        assert_eq!(
            [
                ALLOWED,
                DENIED,
                INPUT,
                UNAVAILABLE,
                SERVICE_LOST,
                CONFLICT,
                IO,
                TIMEOUT,
                AUTHORITY
            ],
            [0, 3, 64, 69, 70, 73, 74, 75, 77]
        );
    }
}
