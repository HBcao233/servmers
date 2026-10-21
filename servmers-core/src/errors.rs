use std::{fmt, io};

// use grammers_tl_types as tl;
use servmers_mtproto::decode;

/// This error occurs when reading from the network fails.
#[derive(Debug)]
pub enum ReadError {
    /// Connection timeout.
    Timeout,
    /// Overflow
    Overflow,
    /// No authentication.
    Forbidden,
    /// Standard I/O error.
    Io(io::Error),
    /// Error propagated from the underlying [`decode`].
    Decode(decode::Error),
}

impl std::error::Error for ReadError {}

impl Clone for ReadError {
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
            Self::Decode(e) => Self::Decode(e.clone()),
        }
    }
}

impl fmt::Display for ReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => write!(f, "connection timeout"),
            Self::Overflow => write!(f, "read buffer overflow"),
            Self::Forbidden => write!(f, "no authentication"),
            Self::Io(err) => write!(f, "read error, IO failed: {err}"),
            Self::Decode(err) => write!(f, "read error, decode-level: {err}"),
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<decode::Error> for ReadError {
    fn from(error: decode::Error) -> Self {
        Self::Decode(error)
    }
}

/*
impl From<tl::deserialize::Error> for ReadError {
    fn from(error: tl::deserialize::Error) -> Self {
        Self::Deserialize(error.into())
    }
}
*/
