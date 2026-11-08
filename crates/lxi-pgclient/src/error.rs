use std::fmt;

/// Failures a caller can act on. `Server` carries the SQLSTATE and the server's
/// message for the caller to map; this crate never prints it.
#[derive(Debug)]
pub enum Error {
    /// The settings or the DSN break the transport policy or are malformed.
    Configuration,
    /// PostgreSQL could not be reached or the connection broke.
    Unavailable,
    /// A deadline (connect, statement or total) passed; the server was asked to cancel.
    Timeout,
    /// The server refused a statement.
    Server {
        sqlstate: String,
        message: String,
    },
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration => f.write_str("LXI_PG_CONFIGURATION"),
            Self::Unavailable => f.write_str("LXI_PG_UNAVAILABLE"),
            Self::Timeout => f.write_str("LXI_PG_TIMEOUT"),
            Self::Server { sqlstate, .. } => write!(f, "LXI_PG_SERVER:{sqlstate}"),
            Self::Io(error) => write!(f, "LXI_PG_IO:{:?}", error.kind()),
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
