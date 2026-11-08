//! Local IPC for the series: length-prefixed JSON frames over a Unix stream, bounded
//! before allocation, with unique keys, a deadline per frame and peer checks.
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

use nix::errno::Errno;
use nix::poll::{poll, PollFd, PollFlags, PollTimeout};
use serde::de::{MapAccess, Visitor};
use serde::{de, Deserializer};
use serde_json::Value;
use std::fmt;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

#[derive(Debug)]
pub enum Error {
    /// A malformed, oversized or late frame, or a peer that broke the protocol.
    Protocol,
    /// A socket path that cannot be a Unix address.
    Configuration,
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol => f.write_str("LXI_IPC_PROTOCOL"),
            Self::Configuration => f.write_str("LXI_IPC_CONFIGURATION"),
            Self::Io(error) => write!(f, "LXI_IPC_IO:{:?}", error.kind()),
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

/// Bounds of one frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Largest JSON body in bytes.
    pub frame: usize,
    /// Time to read, write or connect one frame.
    pub deadline: Duration,
    /// Most keys of the top-level object.
    pub keys: usize,
}

impl Limits {
    /// The series' values: 4 KiB, 2 s, 16 keys.
    pub const SERIES: Self = Self {
        frame: 4096,
        deadline: Duration::from_secs(2),
        keys: 16,
    };
}

struct Unique {
    keys: usize,
}

impl<'de> Visitor<'de> for Unique {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("unique object keys")
    }
    fn visit_map<A: MapAccess<'de>>(self, mut input: A) -> std::result::Result<Value, A::Error> {
        let mut map = serde_json::Map::new();
        while let Some((key, value)) = input.next_entry::<String, Value>()? {
            if map.len() >= self.keys || map.insert(key, value).is_some() {
                return Err(de::Error::custom("duplicate/excessive keys"));
            }
        }
        Ok(Value::Object(map))
    }
}

/// One JSON object with unique keys and nothing after it.
pub fn parse(data: &[u8], limits: &Limits) -> Result<Value> {
    if data.is_empty() || data.len() > limits.frame {
        return Err(Error::Protocol);
    }
    let mut reader = serde_json::Deserializer::from_slice(data);
    let value = reader
        .deserialize_map(Unique { keys: limits.keys })
        .map_err(|_| Error::Protocol)?;
    reader.end().map_err(|_| Error::Protocol)?;
    Ok(value)
}

/// A non-empty string field of at most `limit` bytes.
pub fn text<'a>(value: &'a Value, field: &str, limit: usize) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= limit)
        .ok_or(Error::Protocol)
}

/// Exactly these keys, no more and no fewer.
pub fn exact(value: &Value, keys: &[&str]) -> Result<()> {
    let map = value.as_object().ok_or(Error::Protocol)?;
    if map.len() != keys.len() || !keys.iter().all(|k| map.contains_key(*k)) {
        return Err(Error::Protocol);
    }
    Ok(())
}

/// Overwrites a secret string field (a technical token) once it has been used.
pub fn scrub(message: &mut Value, field: &str) {
    use zeroize::Zeroize;
    if let Some(Value::String(secret)) = message.get_mut(field) {
        secret.zeroize();
    }
}

/// Time left before `deadline`; none left is a protocol failure.
pub fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
        .ok_or(Error::Protocol)
}

fn wait_io(stream: &UnixStream, flags: PollFlags, deadline: Instant) -> Result<()> {
    loop {
        let mut descriptors = [PollFd::new(stream.as_fd(), flags)];
        let timeout = PollTimeout::try_from(remaining(deadline)?).map_err(|_| Error::Protocol)?;
        match poll(&mut descriptors, timeout) {
            Ok(0) => return Err(Error::Protocol),
            Ok(_) => return Ok(()),
            Err(Errno::EINTR) => continue,
            Err(error) => return Err(Error::Io(error.into())),
        }
    }
}

fn read_until(stream: &mut UnixStream, buffer: &mut [u8], deadline: Instant) -> Result<()> {
    stream.set_nonblocking(true)?;
    let mut offset = 0;
    while offset < buffer.len() {
        remaining(deadline)?;
        let part = buffer.get_mut(offset..).ok_or(Error::Protocol)?;
        let count = match stream.read(part) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_io(stream, PollFlags::POLLIN, deadline)?;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            return Err(Error::Protocol);
        }
        offset = offset.checked_add(count).ok_or(Error::Protocol)?;
    }
    Ok(())
}

/// Reads one frame within `limits.deadline`; the length is checked before the body
/// is allocated.
pub fn read_frame(stream: &mut UnixStream, limits: &Limits) -> Result<Value> {
    let deadline = Instant::now()
        .checked_add(limits.deadline)
        .ok_or(Error::Protocol)?;
    let mut header = [0_u8; 4];
    read_until(stream, &mut header, deadline)?;
    let length = usize::try_from(u32::from_be_bytes(header)).map_err(|_| Error::Protocol)?;
    if length == 0 || length > limits.frame {
        return Err(Error::Protocol);
    }
    let mut bytes = Zeroizing::new(vec![0_u8; length]);
    read_until(stream, &mut bytes, deadline)?;
    parse(&bytes, limits)
}

struct Bounded {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for Bounded {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        let length = self
            .bytes
            .len()
            .checked_add(input.len())
            .ok_or_else(|| std::io::Error::other("LXI_FRAME_CAPACITY"))?;
        if length > self.limit {
            return Err(std::io::Error::other("LXI_FRAME_CAPACITY"));
        }
        self.bytes
            .try_reserve(input.len())
            .map_err(|_| std::io::Error::other("LXI_FRAME_ALLOCATION"))?;
        self.bytes.extend_from_slice(input);
        Ok(input.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Writes one frame within `limits.deadline`; serialization stops at `limits.frame`.
pub fn write_frame(stream: &mut UnixStream, value: &Value, limits: &Limits) -> Result<()> {
    stream.set_nonblocking(true)?;
    let mut output = Bounded {
        bytes: Vec::new(),
        limit: limits.frame,
    };
    serde_json::to_writer(&mut output, value).map_err(|_| Error::Protocol)?;
    let bytes = Zeroizing::new(output.bytes);
    if bytes.is_empty() || bytes.len() > limits.frame {
        return Err(Error::Protocol);
    }
    let mut packet = Zeroizing::new(Vec::from(
        u32::try_from(bytes.len())
            .map_err(|_| Error::Protocol)?
            .to_be_bytes(),
    ));
    packet.extend_from_slice(&bytes);
    let deadline = Instant::now()
        .checked_add(limits.deadline)
        .ok_or(Error::Protocol)?;
    let mut offset = 0;
    while offset < packet.len() {
        remaining(deadline)?;
        let count = match stream.write(packet.get(offset..).ok_or(Error::Protocol)?) {
            Ok(count) => count,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                wait_io(stream, PollFlags::POLLOUT, deadline)?;
                continue;
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        };
        if count == 0 {
            return Err(Error::Protocol);
        }
        offset = offset.checked_add(count).ok_or(Error::Protocol)?;
    }
    Ok(())
}

/// Connects without blocking past `limits.deadline`; the stream is close-on-exec and
/// returned in blocking mode.
pub fn connect(socket: &Path, limits: &Limits) -> Result<UnixStream> {
    use nix::sys::socket::{
        connect as open_connection, socket as open_socket, AddressFamily, SockFlag, SockType,
        UnixAddr,
    };
    let fd = open_socket(
        AddressFamily::Unix,
        SockType::Stream,
        SockFlag::empty(),
        None,
    )
    .map_err(|e| Error::Io(e.into()))?;
    let stream = UnixStream::from(fd);
    stream.set_nonblocking(true)?;
    nix::fcntl::fcntl(
        &stream,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .map_err(|e| Error::Io(e.into()))?;
    let address = UnixAddr::new(socket).map_err(|_| Error::Configuration)?;
    let deadline = Instant::now()
        .checked_add(limits.deadline)
        .ok_or(Error::Protocol)?;
    loop {
        let _left = remaining(deadline)?;
        match open_connection(stream.as_raw_fd(), &address) {
            Ok(()) | Err(Errno::EISCONN) => break,
            Err(Errno::EAGAIN | Errno::EINPROGRESS | Errno::EALREADY) => {
                let mut descriptors = [PollFd::new(stream.as_fd(), PollFlags::POLLOUT)];
                let timeout =
                    PollTimeout::try_from(remaining(deadline)?).map_err(|_| Error::Protocol)?;
                let ready = poll(&mut descriptors, timeout).map_err(|e| Error::Io(e.into()))?;
                if ready == 0 {
                    return Err(Error::Protocol);
                }
                if let Some(error) = stream.take_error()? {
                    return Err(Error::Io(error));
                }
                // Completion is observed on the socket. A second connect after
                // EINPROGRESS is not portable (Darwin may return EINVAL).
                if stream.peer_addr().is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(Error::Io(error.into())),
        }
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}

/// The peer's effective UID, from the kernel.
pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    #[cfg(target_os = "linux")]
    let uid = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map_err(|_| Error::Protocol)?
        .uid();
    #[cfg(target_os = "macos")]
    let uid = nix::unistd::getpeereid(stream)
        .map_err(|_| Error::Protocol)?
        .0
        .as_raw();
    Ok(uid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Write;

    const SERIES: Limits = Limits::SERIES;

    #[test]
    fn duplicate_keys_trailing_data_and_oversize_reject() -> Result<()> {
        assert!(parse(br#"{"v":1,"v":2}"#, &SERIES).is_err());
        assert!(parse(br#"{"v":1} false"#, &SERIES).is_err());
        assert!(parse(&vec![b' '; 4097], &SERIES).is_err());
        assert!(parse(br#"[]"#, &SERIES).is_err());
        assert!(parse(b"", &SERIES).is_err());
        assert_eq!(parse(br#"{"v":1}"#, &SERIES)?, json!({"v":1}));
        Ok(())
    }

    #[test]
    fn the_key_and_size_limits_are_the_callers() -> Result<()> {
        let keys: String = (0..17)
            .map(|n| format!("\"k{n}\":{n}"))
            .collect::<Vec<_>>()
            .join(",");
        let seventeen = format!("{{{keys}}}");
        assert!(
            parse(seventeen.as_bytes(), &SERIES).is_err(),
            "16 keys at most"
        );
        let wide = Limits { keys: 32, ..SERIES };
        assert!(parse(seventeen.as_bytes(), &wide).is_ok());
        let small = Limits { frame: 8, ..SERIES };
        assert!(parse(br#"{"v":1}"#, &small).is_ok());
        assert!(parse(br#"{"v":100}"#, &small).is_err());
        Ok(())
    }

    #[test]
    fn bounded_frames_reject_before_body_allocation() -> Result<()> {
        let (mut left, mut right) = UnixStream::pair()?;
        left.write_all(&4097_u32.to_be_bytes())?;
        assert!(read_frame(&mut right, &SERIES).is_err());
        let (mut left, mut right) = UnixStream::pair()?;
        left.write_all(&0_u32.to_be_bytes())?;
        assert!(read_frame(&mut right, &SERIES).is_err(), "empty frame");
        Ok(())
    }

    #[test]
    fn a_frame_round_trip() -> Result<()> {
        let (mut left, mut right) = UnixStream::pair()?;
        let message = json!({"v":1,"subject":"reader"});
        write_frame(&mut left, &message, &SERIES)?;
        assert_eq!(read_frame(&mut right, &SERIES)?, message);
        Ok(())
    }

    #[test]
    fn a_silent_peer_hits_the_deadline() -> Result<()> {
        let (_left, mut right) = UnixStream::pair()?;
        let quick = Limits {
            deadline: Duration::from_millis(150),
            ..SERIES
        };
        let started = std::time::Instant::now();
        assert!(matches!(
            read_frame(&mut right, &quick),
            Err(Error::Protocol)
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }

    #[test]
    fn exact_shape_and_string_bounds() -> Result<()> {
        let value = parse(br#"{"v":1,"subject":"reader"}"#, &SERIES)?;
        assert_eq!(text(&value, "subject", 6)?, "reader");
        assert!(text(&value, "subject", 5).is_err());
        assert!(text(&value, "v", 5).is_err(), "not a string");
        assert!(exact(&value, &["v"]).is_err());
        exact(&value, &["v", "subject"])?;
        Ok(())
    }

    #[test]
    fn serialization_is_bounded_before_growing_the_output() -> Result<()> {
        let (mut left, _right) = UnixStream::pair()?;
        assert!(write_frame(&mut left, &json!({"text":"x".repeat(8192)}), &SERIES).is_err());
        Ok(())
    }

    #[test]
    fn scrub_clears_the_token() {
        let mut message = json!({"v":1,"token":"a".repeat(64),"subject":"x"});
        scrub(&mut message, "token");
        assert_eq!(message.get("token"), Some(&json!("")));
        assert_eq!(message.get("subject"), Some(&json!("x")));
    }

    #[test]
    fn unavailable_socket_is_a_controlled_connection_failure() {
        assert!(connect(Path::new("/private/lxi-ipc-absent-test/socket"), &SERIES).is_err());
    }

    #[test]
    fn connect_and_peer_uid() -> Result<()> {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| Error::Protocol)?
            .as_nanos();
        let path = std::env::temp_dir().join(format!("lxi-ipc-{}-{stamp}", std::process::id()));
        let listener = std::os::unix::net::UnixListener::bind(&path)?;
        let client = connect(&path, &SERIES)?;
        let (server, _) = listener.accept()?;
        assert_eq!(peer_uid(&server)?, nix::unistd::geteuid().as_raw());
        assert_eq!(peer_uid(&client)?, nix::unistd::geteuid().as_raw());
        std::fs::remove_file(&path)?;
        Ok(())
    }
}
