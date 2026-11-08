//! Verified audit archiving for the series: export a range of canonical lines to a
//! new private file with their SHA256, so the service can purge that range only if
//! its own hash of the range is the same. The pages come from the caller.
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

use sha2::{Digest, Sha256};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

/// Why an export or a hash failed. `Source` is the caller's own page error.
#[derive(Debug)]
pub enum Error<E> {
    Source(E),
    /// No event in the range, or more than the caller allows.
    Range,
    /// The file breaks the rules (not regular, too large) or a count overflowed.
    Refused,
    Io(std::io::Error),
}

impl<E: fmt::Display> fmt::Display for Error<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Source(error) => write!(f, "{error}"),
            Self::Range => f.write_str("LXI_AUDIT_RANGE"),
            Self::Refused => f.write_str("LXI_AUDIT_REFUSED"),
            Self::Io(error) => write!(f, "LXI_AUDIT_IO:{:?}", error.kind()),
        }
    }
}

impl<E> From<std::io::Error> for Error<E> {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

#[must_use]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportSummary {
    pub events: u32,
    pub sha256: String,
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Lowercase hex SHA256.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

/// SHA256 of a regular file of at most `limit` bytes, without following a final
/// symlink and without waiting on a FIFO (`O_NONBLOCK`; a regular file reads as usual).
pub fn file_sha256<E>(path: &Path, limit: u64) -> Result<String, Error<E>> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_NONBLOCK | nix::libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() > limit {
        return Err(Error::Refused);
    }
    let mut bytes = Vec::new();
    file.take(limit.checked_add(1).ok_or(Error::Refused)?)
        .read_to_end(&mut bytes)?;
    if u64::try_from(bytes.len()).map_err(|_| Error::Refused)? > limit {
        return Err(Error::Refused);
    }
    Ok(sha256_hex(&bytes))
}

fn export_into<E>(
    file: &mut File,
    max_events: u32,
    page: usize,
    mut fetch: impl FnMut(i64) -> Result<Vec<(i64, String)>, E>,
) -> Result<ExportSummary, Error<E>> {
    let mut hasher = Sha256::new();
    let mut after: i64 = 0;
    let mut events: u32 = 0;
    loop {
        let rows = fetch(after).map_err(Error::Source)?;
        for (id, line) in &rows {
            events = events.checked_add(1).ok_or(Error::Refused)?;
            if events > max_events {
                return Err(Error::Range);
            }
            file.write_all(line.as_bytes())?;
            hasher.update(line.as_bytes());
            after = *id;
        }
        if rows.len() < page {
            break;
        }
    }
    if events == 0 {
        return Err(Error::Range);
    }
    file.sync_all()?;
    Ok(ExportSummary {
        events,
        sha256: hex(&hasher.finalize()),
    })
}

/// Writes every line `fetch(after)` returns, page after page, to a new 0600 `file`
/// (an existing file is never touched) and syncs it. `fetch` returns `(id, line)`
/// rows after `after`; a page shorter than `page` is the last. At most `max_events`;
/// none is `Range`. On any error the partial file is removed.
pub fn export<E>(
    file: &Path,
    max_events: u32,
    page: usize,
    fetch: impl FnMut(i64) -> Result<Vec<(i64, String)>, E>,
) -> Result<ExportSummary, Error<E>> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(file)?;
    let result = export_into(&mut output, max_events, page, fetch);
    if result.is_err() {
        drop(output);
        std::fs::remove_file(file)?;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    type Plain = Error<&'static str>;

    fn dir() -> Result<PathBuf, Plain> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("lxi-audit-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    fn line(id: i64) -> (i64, String) {
        (id, format!("{id}\t2026-11-07T00:00:00.000000Z\t{{}}\n"))
    }

    /// Pages of `page` rows from 1..=total, after `after`.
    fn source(
        total: i64,
        page: usize,
    ) -> impl FnMut(i64) -> Result<Vec<(i64, String)>, &'static str> {
        move |after| {
            Ok((after.saturating_add(1)..=total)
                .take(page)
                .map(line)
                .collect())
        }
    }

    #[test]
    fn canonical_hash_vector() {
        let lines = "1\t2026-11-07T00:00:00.000000Z\t{\"a\": 1}\n2\t2026-11-07T00:00:01.000000Z\t{\"b\": 2}\n";
        assert_eq!(
            sha256_hex(lines.as_bytes()),
            "61e4f77a932b518e0f7653cbe2d0052f61e51b7346b8717da2e0beae8a2e346c"
        );
    }

    #[test]
    fn an_export_over_several_pages_matches_its_file() -> Result<(), Plain> {
        use std::os::unix::fs::PermissionsExt;
        let file = dir()?.join("range.audit");
        let summary = export(&file, 1000, 100, source(250, 100))?;
        assert_eq!(summary.events, 250);
        assert_eq!(file_sha256::<&str>(&file, 1 << 20)?, summary.sha256);
        assert_eq!(
            std::fs::metadata(&file)?.permissions().mode() & 0o777,
            0o600
        );
        let expected: String = (1..=250).map(|id| line(id).1).collect();
        assert_eq!(std::fs::read_to_string(&file)?, expected);
        Ok(())
    }

    #[test]
    fn an_existing_file_is_never_touched() -> Result<(), Plain> {
        let file = dir()?.join("kept.audit");
        std::fs::write(&file, b"kept")?;
        assert!(matches!(
            export(&file, 10, 100, source(3, 100)),
            Err(Error::Io(_))
        ));
        assert_eq!(std::fs::read(&file)?, b"kept");
        Ok(())
    }

    #[test]
    fn empty_or_too_large_ranges_leave_no_file() -> Result<(), Plain> {
        let base = dir()?;
        let empty = base.join("empty.audit");
        assert!(matches!(
            export(&empty, 10, 100, source(0, 100)),
            Err(Error::Range)
        ));
        assert!(!empty.exists());
        let large = base.join("large.audit");
        assert!(matches!(
            export(&large, 10, 4, source(30, 4)),
            Err(Error::Range)
        ));
        assert!(!large.exists());
        Ok(())
    }

    #[test]
    fn a_source_error_leaves_no_file() -> Result<(), Plain> {
        let file = dir()?.join("failed.audit");
        let mut calls = 0;
        let failing = |after: i64| {
            calls += 1;
            if calls > 1 {
                return Err("SOURCE_FAILED");
            }
            Ok((after.saturating_add(1)..=after.saturating_add(4))
                .map(line)
                .collect())
        };
        assert!(matches!(
            export(&file, 100, 4, failing),
            Err(Error::Source("SOURCE_FAILED"))
        ));
        assert!(!file.exists());
        Ok(())
    }

    #[test]
    fn file_hash_rules() -> Result<(), Plain> {
        let base = dir()?;
        let file = base.join("small");
        std::fs::write(&file, b"abc")?;
        assert_eq!(
            file_sha256::<&str>(&file, 3)?,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert!(matches!(file_sha256::<&str>(&file, 2), Err(Error::Refused)));
        let link = base.join("link");
        std::os::unix::fs::symlink(&file, &link)?;
        assert!(matches!(file_sha256::<&str>(&link, 3), Err(Error::Io(_))));
        assert!(matches!(file_sha256::<&str>(&base, 3), Err(Error::Refused)));
        // A FIFO is refused at once: opening it never waits for a writer.
        let fifo = base.join("fifo");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o600))
            .map_err(|e| Error::Io(e.into()))?;
        assert!(matches!(file_sha256::<&str>(&fifo, 3), Err(Error::Refused)));
        Ok(())
    }
}
