//! Reading configuration, token and CA files for the series without TOCTOU: the
//! path is walked from `/` with `openat`, and every check is made on the descriptor
//! that is then used (docs/design/2026-11-08-lxi-files.md).
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

use nix::fcntl::{openat, readlinkat, AtFlags, OFlag};
use nix::sys::stat::{fstatat, Mode, SFlag};
use std::collections::VecDeque;
use std::ffi::OsString;
use std::fmt;
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
    /// The path or the file breaks the rules.
    Refused,
    /// The system failed on a directory of the chain (for example, it does not exist).
    Io(std::io::Error),
    /// The file itself could not be opened: missing, a symlink (`ELOOP`), no access.
    Open(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused => f.write_str("LXI_FILE_REFUSED"),
            Self::Io(error) => write!(f, "LXI_FILE_IO:{:?}", error.kind()),
            Self::Open(error) => write!(f, "LXI_FILE_OPEN:{:?}", error.kind()),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Self::Io(error)
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Most symlinks one walk follows.
const MAX_LINKS: u32 = 40;

fn uid() -> u32 {
    nix::unistd::geteuid().as_raw()
}

fn io(errno: nix::errno::Errno) -> Error {
    Error::Io(errno.into())
}

fn trusted_owner(owner: u32) -> bool {
    owner == 0 || owner == uid()
}

/// The metadata of an open descriptor (std's types are the same on every target).
fn meta(fd: &OwnedFd) -> Result<Metadata> {
    Ok(File::from(fd.try_clone()?).metadata()?)
}

/// A directory nobody else can change: of root or the user, and not writable by
/// group or others unless sticky.
fn check_dir(meta: &Metadata) -> Result<()> {
    let shared = meta.mode() & 0o022 != 0;
    let sticky = meta.mode() & 0o1000 != 0;
    if !meta.is_dir() || !trusted_owner(meta.uid()) || (shared && !sticky) {
        return Err(Error::Refused);
    }
    Ok(())
}

/// One step of a walk.
enum Part {
    Name(OsString),
    /// `..`, only from a symlink's target: back to the parent real directory.
    Up,
}

fn parts(path: &Path, allow_up: bool) -> Result<VecDeque<Part>> {
    path.components()
        .filter(|c| !matches!(c, Component::RootDir | Component::CurDir))
        .map(|c| match c {
            Component::Normal(name) => Ok(Part::Name(name.to_os_string())),
            Component::ParentDir if allow_up => Ok(Part::Up),
            _ => Err(Error::Refused),
        })
        .collect()
}

fn open_root() -> Result<OwnedFd> {
    let root = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_CLOEXEC)
        .open("/")?;
    let fd = OwnedFd::from(root);
    check_dir(&meta(&fd)?)?;
    Ok(fd)
}

/// Opens the directory `path` by walking it from `/`. Every directory is opened with
/// `O_NOFOLLOW` and checked on its own descriptor; the descriptors of the real chain
/// are kept, so `..` in a symlink's target goes back to an already checked directory.
/// With `last_not_link`, the last component written in `path` may not be a symlink.
fn walk_dir(path: &Path, last_not_link: bool) -> Result<OwnedFd> {
    if path.as_os_str().is_empty() {
        // What the OS reports for an empty path.
        return Err(io(nix::errno::Errno::ENOENT));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    // `..` written in the path itself is refused; only a link's target may use it.
    let mut pending: VecDeque<(Part, bool)> = parts(&absolute, false)?
        .into_iter()
        .map(|part| (part, false))
        .collect();
    if let Some(last) = pending.back_mut() {
        last.1 = true;
    }
    let mut chain = vec![open_root()?];
    let mut links: u32 = 0;
    while let Some((part, written_last)) = pending.pop_front() {
        let name = match part {
            Part::Up => {
                if chain.len() > 1 {
                    let _parent = chain.pop();
                }
                continue;
            }
            Part::Name(name) => name,
        };
        let current = chain.last().ok_or(Error::Refused)?;
        let stat = fstatat(current, name.as_os_str(), AtFlags::AT_SYMLINK_NOFOLLOW).map_err(io)?;
        if SFlag::from_bits_truncate(stat.st_mode) & SFlag::S_IFMT == SFlag::S_IFLNK {
            if last_not_link && written_last {
                return Err(Error::Refused);
            }
            links = links.checked_add(1).ok_or(Error::Refused)?;
            if links > MAX_LINKS {
                // What the OS reports for too many links.
                return Err(io(nix::errno::Errno::ELOOP));
            }
            if !trusted_owner(stat.st_uid) {
                return Err(Error::Refused);
            }
            let target = PathBuf::from(readlinkat(current, name.as_os_str()).map_err(io)?);
            let mut spliced: VecDeque<(Part, bool)> = parts(&target, true)?
                .into_iter()
                .map(|part| (part, false))
                .collect();
            spliced.extend(pending);
            pending = spliced;
            if target.is_absolute() {
                chain.truncate(1);
            }
            continue;
        }
        let next = openat(
            current,
            name.as_os_str(),
            OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::empty(),
        )
        .map_err(io)?;
        check_dir(&meta(&next)?)?;
        chain.push(next);
    }
    chain.pop().ok_or(Error::Refused)
}

/// The final component of `path`, opened without following a symlink or blocking on
/// a FIFO, inside its walked parent. A failure to open it is `Open`.
fn open_leaf(path: &Path, strict_parent: bool) -> Result<(OwnedFd, File)> {
    let name = path.file_name().ok_or(Error::Refused)?;
    let parent = walk_dir(path.parent().ok_or(Error::Refused)?, strict_parent)?;
    let fd = openat(
        &parent,
        name,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|e| Error::Open(e.into()))?;
    Ok((parent, File::from(fd)))
}

/// Reads 1..=`limit` bytes of a regular file already validated by the caller.
fn read_limited(file: File, meta: &Metadata, limit: u64, into: &mut Vec<u8>) -> Result<()> {
    if !meta.is_file() || meta.len() > limit {
        return Err(Error::Refused);
    }
    file.take(limit.checked_add(1).ok_or(Error::Refused)?)
        .read_to_end(into)?;
    let read = u64::try_from(into.len()).map_err(|_| Error::Refused)?;
    if read == 0 || read > limit {
        return Err(Error::Refused);
    }
    Ok(())
}

/// A secret: parent directory of the effective user and 0700; a regular file with one
/// link, of the effective user, no group or other permissions; 1..=`limit` bytes.
pub fn read_private(path: &Path, limit: u64) -> Result<Zeroizing<Vec<u8>>> {
    let (parent, file) = open_leaf(path, true)?;
    let dir = meta(&parent)?;
    if dir.uid() != uid() || dir.mode() & 0o077 != 0 {
        return Err(Error::Refused);
    }
    let meta = file.metadata()?;
    if meta.nlink() != 1 || meta.uid() != uid() || meta.mode() & 0o077 != 0 {
        return Err(Error::Refused);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    read_limited(file, &meta, limit, &mut bytes)?;
    Ok(bytes)
}

/// A public file such as a CA bundle: regular, of root or the effective user, not
/// writable by group or others; 1..=`limit` bytes.
pub fn read_public(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let (_parent, file) = open_leaf(path, false)?;
    let meta = file.metadata()?;
    if !trusted_owner(meta.uid()) || meta.mode() & 0o022 != 0 {
        return Err(Error::Refused);
    }
    let mut bytes = Vec::new();
    read_limited(file, &meta, limit, &mut bytes)?;
    Ok(bytes)
}

/// A directory reached through a trusted chain, and its metadata for the caller's
/// own rules (for example, the 0700 directory of a Unix socket).
pub fn trusted_dir(path: &Path) -> Result<Metadata> {
    Ok(File::from(walk_dir(path, false)?).metadata()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn dir() -> Result<PathBuf> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Refused)?
            .as_nanos();
        // Parallel tests can read the same clock value: a counter keeps names unique.
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("lxi-files-{}-{stamp}-{n}", std::process::id()));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755))?;
        Ok(dir)
    }

    fn mode(path: &Path, mode: u32) -> Result<()> {
        Ok(std::fs::set_permissions(
            path,
            std::fs::Permissions::from_mode(mode),
        )?)
    }

    fn file(path: &Path, bytes: usize, file_mode: u32) -> Result<()> {
        std::fs::File::create(path)?.write_all(&vec![b'x'; bytes])?;
        mode(path, file_mode)
    }

    /// `base/private/token` with the private rules met.
    fn private_tree(base: &Path) -> Result<PathBuf> {
        let private = base.join("private");
        std::fs::create_dir(&private)?;
        mode(&private, 0o700)?;
        let token = private.join("token");
        file(&token, 64, 0o600)?;
        Ok(token)
    }

    #[test]
    fn a_private_file_through_a_trusted_chain() -> Result<()> {
        // temp_dir is under /var (a root symlink on macOS): trusted symlinks are followed.
        let token = private_tree(&dir()?)?;
        assert_eq!(read_private(&token, 65536)?.len(), 64);
        Ok(())
    }

    #[test]
    fn private_file_rules() -> Result<()> {
        let base = dir()?;
        let token = private_tree(&base)?;
        mode(&token, 0o640)?;
        assert!(matches!(read_private(&token, 65536), Err(Error::Refused)));
        mode(&token, 0o600)?;
        assert!(
            matches!(read_private(&token, 10), Err(Error::Refused)),
            "limit"
        );
        std::fs::hard_link(&token, base.join("private").join("second"))?;
        assert!(
            matches!(read_private(&token, 65536), Err(Error::Refused)),
            "one link"
        );
        std::fs::remove_file(base.join("private").join("second"))?;
        mode(&base.join("private"), 0o750)?;
        assert!(
            matches!(read_private(&token, 65536), Err(Error::Refused)),
            "0700 parent"
        );
        mode(&base.join("private"), 0o700)?;
        let empty = base.join("private").join("empty");
        file(&empty, 0, 0o600)?;
        assert!(matches!(read_private(&empty, 65536), Err(Error::Refused)));
        // The leaf itself cannot be opened: the OS error, as `Open`.
        assert!(matches!(
            read_private(&base.join("private").join("missing"), 65536),
            Err(Error::Open(e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
        // A directory of the chain is missing: the OS error, as `Io`.
        assert!(matches!(
            read_private(&base.join("nodir").join("token"), 65536),
            Err(Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound
        ));
        Ok(())
    }

    #[test]
    fn the_parent_of_a_secret_is_never_a_symlink() -> Result<()> {
        let base = dir()?;
        let token = private_tree(&base)?;
        std::os::unix::fs::symlink(base.join("private"), base.join("alias"))?;
        assert!(matches!(
            read_private(&base.join("alias").join("token"), 65536),
            Err(Error::Refused)
        ));
        // A link above the parent is followed like any trusted link.
        std::os::unix::fs::symlink(&base, base.join("up"))?;
        assert_eq!(
            read_private(&base.join("up").join("private").join("token"), 65536)?.len(),
            64
        );
        assert!(read_private(&token, 65536).is_ok());
        Ok(())
    }

    #[test]
    fn a_bare_file_name_has_no_directory() {
        assert!(matches!(
            read_private(Path::new("token"), 65536),
            Err(Error::Io(e)) if e.raw_os_error() == Some(nix::libc::ENOENT)
        ));
    }

    #[test]
    fn an_unsafe_ancestor_refuses_a_private_file() -> Result<()> {
        let base = dir()?;
        let token = private_tree(&base)?;
        mode(&base, 0o775)?;
        assert!(matches!(read_private(&token, 65536), Err(Error::Refused)));
        mode(&base, 0o755)?;
        assert!(read_private(&token, 65536).is_ok());
        Ok(())
    }

    #[test]
    fn a_symlink_cannot_hide_an_unsafe_real_ancestor() -> Result<()> {
        let base = dir()?;
        let open = base.join("open");
        std::fs::create_dir(&open)?;
        mode(&open, 0o777)?;
        let inner = open.join("inner");
        std::fs::create_dir(&inner)?;
        mode(&inner, 0o755)?;
        private_tree(&inner)?;
        let link = base.join("link");
        std::os::unix::fs::symlink(&inner, &link)?;
        let through = link.join("private").join("token");
        assert!(matches!(read_private(&through, 65536), Err(Error::Refused)));
        // The same tree behind a safe directory is read through the same kind of link.
        mode(&open, 0o755)?;
        assert!(read_private(&through, 65536).is_ok());
        Ok(())
    }

    #[test]
    fn dot_dot_is_refused_in_the_path_but_resolved_in_a_link() -> Result<()> {
        let base = dir()?;
        let token = private_tree(&base)?;
        let dotted = base
            .join("private")
            .join("..")
            .join("private")
            .join("token");
        assert!(matches!(read_private(&dotted, 65536), Err(Error::Refused)));
        let sub = base.join("sub");
        std::fs::create_dir(&sub)?;
        mode(&sub, 0o755)?;
        // sub/up -> .. is the real base: followed, and base is checked as usual.
        std::os::unix::fs::symlink("..", sub.join("up"))?;
        let through = sub.join("up").join("private").join("token");
        assert_eq!(read_private(&through, 65536)?.len(), 64);
        std::os::unix::fs::symlink("../sub/..", sub.join("twice"))?;
        assert!(read_private(&sub.join("twice").join("private").join("token"), 65536).is_ok());
        // `..` climbing to an unsafe directory is refused by that directory's check.
        let wide = base.join("wide");
        std::fs::create_dir(&wide)?;
        mode(&wide, 0o777)?;
        private_tree(&wide)?;
        std::os::unix::fs::symlink("../wide", sub.join("towide"))?;
        assert!(matches!(
            read_private(&sub.join("towide").join("private").join("token"), 65536),
            Err(Error::Refused)
        ));
        assert!(read_private(&token, 65536).is_ok());
        Ok(())
    }

    #[test]
    fn a_symlink_loop_is_refused() -> Result<()> {
        let base = dir()?;
        std::os::unix::fs::symlink(base.join("b"), base.join("a"))?;
        std::os::unix::fs::symlink(base.join("a"), base.join("b"))?;
        // As the OS reports a loop: ELOOP, as `Io`.
        assert!(matches!(
            read_public(&base.join("a").join("ca.pem"), 65536),
            Err(Error::Io(e)) if e.raw_os_error() == Some(nix::libc::ELOOP)
        ));
        Ok(())
    }

    #[test]
    fn public_file_rules() -> Result<()> {
        let dir = dir()?;
        let good = dir.join("ca.pem");
        file(&good, 10, 0o644)?;
        assert_eq!(read_public(&good, 65536)?.len(), 10);
        let writable = dir.join("open.pem");
        file(&writable, 10, 0o666)?;
        assert!(matches!(read_public(&writable, 65536), Err(Error::Refused)));
        let large = dir.join("large.pem");
        file(&large, 71_680, 0o644)?;
        assert!(matches!(read_public(&large, 65536), Err(Error::Refused)));
        let link = dir.join("link.pem");
        std::os::unix::fs::symlink(&good, &link)?;
        assert!(
            matches!(read_public(&link, 65536), Err(Error::Open(e)) if e.raw_os_error() == Some(nix::libc::ELOOP)),
            "final link: never followed, the OS's ELOOP"
        );
        Ok(())
    }

    #[test]
    fn a_fifo_never_blocks() -> Result<()> {
        let dir = dir()?;
        let fifo = dir.join("ca.pem");
        nix::unistd::mkfifo(&fifo, nix::sys::stat::Mode::from_bits_truncate(0o644))
            .map_err(|e| Error::Io(e.into()))?;
        assert!(matches!(read_public(&fifo, 65536), Err(Error::Refused)));
        Ok(())
    }

    #[test]
    fn a_trusted_dir_and_its_metadata() -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        let base = dir()?;
        let socket_dir = base.join("run");
        std::fs::create_dir(&socket_dir)?;
        mode(&socket_dir, 0o700)?;
        let meta = trusted_dir(&socket_dir)?;
        assert!(meta.is_dir());
        assert_eq!(meta.mode() & 0o777, 0o700);
        assert_eq!(meta.uid(), nix::unistd::geteuid().as_raw());
        mode(&base, 0o777)?;
        assert!(matches!(trusted_dir(&socket_dir), Err(Error::Refused)));
        mode(&base, 0o755)?;
        file(&base.join("plain"), 1, 0o644)?;
        // Not a directory: the OS's ENOTDIR, as for any path through a file.
        assert!(matches!(
            trusted_dir(&base.join("plain")),
            Err(Error::Io(e)) if e.raw_os_error() == Some(nix::libc::ENOTDIR)
        ));
        Ok(())
    }
}
