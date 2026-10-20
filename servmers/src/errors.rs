use std::{fmt, io};

use grammers_tl_types as tl;
use servmers_mtproto::{mtp, transport};

/// This error occurs when reading from the network fails.
#[derive(Debug)]
pub enum ReadError {
    /// Connection timeout.
    Timeout,
    /// Unsupported transport.
    UnsupportedTransport,
    /// No authentication.
    Forbidden,
    /// Standard I/O error.
    Io(io::Error),
    /// Error propagated from the underlying [`transport`].
    Transport(transport::Error),
    /// Error propagated from attempting to deserialize an invalid [`tl::Deserializable`].
    Deserialize(mtp::DeserializeError),
}

impl std::error::Error for ReadError {}

impl Clone for ReadError {
    fn clone(&self) -> Self {
        match self {
            Self::Timeout => Self::Timeout,
            Self::UnsupportedTransport => Self::UnsupportedTransport,
            Self::Forbidden => Self::Forbidden,
            Self::Io(e) => Self::Io(
                e.raw_os_error()
                    .map(io::Error::from_raw_os_error)
                    .unwrap_or_else(|| io::Error::new(e.kind(), e.to_string())),
            ),
            Self::Transport(e) => Self::Transport(e.clone()),
            Self::Deserialize(e) => Self::Deserialize(e.clone()),
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "connection timeout"),
            Self::UnsupportedTransport => write!(f, "unsupported transport"),
            Self::Forbidden => write!(f, "no authentication"),
            Self::Io(err) => write!(f, "read error, IO failed: {err}"),
            Self::Transport(err) => write!(f, "read error, transport-level: {err}"),
            Self::Deserialize(err) => write!(f, "read error, bad request: {err}"),
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<transport::Error> for ReadError {
    fn from(error: transport::Error) -> Self {
        Self::Transport(error)
    }
}

impl From<mtp::DeserializeError> for ReadError {
    fn from(error: mtp::DeserializeError) -> Self {
        Self::Deserialize(error)
    }
}

impl From<tl::deserialize::Error> for ReadError {
    fn from(error: tl::deserialize::Error) -> Self {
        Self::Deserialize(error.into())
    }
}
