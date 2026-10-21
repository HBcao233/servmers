use std::fmt;

use bytes::{Buf, BytesMut};
use tracing::debug;

use crate::transport::{self, DetectError, Detected, Transport, UnpackedOffset};

/// Result of a single `Decoder::drive` call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drive {
    /// At least one frame was produced; call `drive` again on the remainder.
    Progress,
    /// The buffer does not hold a complete frame yet; go read more bytes.
    NeedMore,
}

#[derive(Clone, Debug)]
pub enum Error {
    UnsupportedTransport,
    Transport(transport::Error),
    MessageBufferTooSmall,
    // Deserialize(DeserializeError),
}

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTransport => write!(f, "unsupported transport"),
            Self::Transport(err) => write!(f, "{err}"),
            Self::MessageBufferTooSmall => write!(
                f,
                "client requested with a payload that's too small to fit a valid message"
            ),
        }
    }
}

#[derive(Debug)]
pub struct Payload {
    pub auth_key_id: [u8; 8],
    pub payload: BytesMut,
}

/// Connection state.
enum State {
    /// Still sniffing the first bytes
    Negotiating { need: usize },
    /// Transport established, steady state.
    Ready { transport: Transport },
}

pub struct Decoder {
    state: State,
}

impl Decoder {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            state: State::Negotiating { need: 1 },
        }
    }

    pub fn drive(&mut self, buf: &mut BytesMut, out: &mut Vec<Payload>) -> Result<Drive, Error> {
        loop {
            match self.state {
                State::Negotiating { need } => {
                    if buf.len() < need {
                        return Ok(Drive::NeedMore);
                    }

                    match transport::detect(buf) {
                        Ok(Detected {
                            transport,
                            preamble,
                        }) => {
                            debug!(preamble, "transport negotiated");
                            buf.advance(preamble);
                            self.state = State::Ready { transport };
                        }
                        Err(DetectError::NeedMore(need)) => {
                            self.state = State::Negotiating { need };
                        }
                        Err(DetectError::Unsupported) => {
                            return Err(Error::UnsupportedTransport);
                        }
                    }
                }
                State::Ready { ref mut transport } => {
                    let UnpackedOffset {
                        data_range,
                        next_offset,
                    } = match transport.unpack(buf) {
                        Ok(offset) => offset,
                        Err(transport::Error::MissingBytes) => return Ok(Drive::NeedMore),
                        Err(err) => return Err(Error::Transport(err)),
                    };

                    debug!("deserializing valid transport packet...");
                    // SAFETY
                    let mut packet = buf.split_to(next_offset);
                    let mut payload = packet
                        .split_off(data_range.start)
                        .split_to(data_range.end - data_range.start);
                    if payload.len() < 8 {
                        return Err(Error::MessageBufferTooSmall);
                    }

                    let auth_key_id = payload[..8].try_into().unwrap();
                    payload.advance(8);
                    let payload = Payload {
                        auth_key_id,
                        payload,
                    };
                    out.push(payload);

                    return Ok(Drive::Progress);
                }
            }
        }
    }
}
