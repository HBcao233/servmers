use std::{fmt, io};

// use grammers_tl_types as tl;
use servmers_mtproto::{mtp, transport};

/// This error occurs when reading from the network fails.
#[derive(Debug)]
pub enum ConnectionError {
    /// Connection timeout.
    Timeout,
    /// Overflow
    Overflow,
    /// No authentication.
    Forbidden,
    /// Standard I/O error.
    Io(io::Error),
    /// Error propagated from the underlying [`transport`].
    Transport(transport::DriverError),
    /// Error propagated from the underlying [`mtp`].
    Mtp(mtp::Error),
}

impl std::error::Error for ConnectionError {}

impl Clone for ConnectionError {
    fn clone(&self) -> Self {
        match self {
            Self::Timeout => Self::Timeout,
            Self::Overflow => Self::Overflow,
            Self::Forbidden => Self::Forbidden,
            Self::Io(e) => Self::Io(
                e.raw_os_error()
                    .map(io::Error::from_raw_os_error)
                    .unwrap_or_else(|| io::Error::new(e.kind(), e.to_string())),
            ),
            Self::Transport(e) => Self::Transport(e.clone()),
            Self::Mtp(e) => Self::Mtp(e.clone()),
        }
    }
}

impl fmt::Display for ConnectionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "connection timeout"),
            Self::Overflow => write!(f, "read buffer overflow"),
            Self::Forbidden => write!(f, "no authentication"),
            Self::Io(err) => write!(f, "read error, IO failed: {err}"),
            Self::Transport(err) => write!(f, "read error, transport-level: {err}"),
            Self::Mtp(err) => write!(f, "read error, mtp-level: {err}"),
        }
    }
}

impl From<io::Error> for ConnectionError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<transport::DriverError> for ConnectionError {
    fn from(error: transport::DriverError) -> Self {
        Self::Transport(error)
    }
}

impl From<mtp::Error> for ConnectionError {
    fn from(error: mtp::Error) -> Self {
        Self::Mtp(error)
    }
}

/*
impl From<tl::deserialize::Error> for ConnectionError {
    fn from(error: tl::deserialize::Error) -> Self {
        Self::Deserialize(error.into())
    }
}
*/
