use std::fmt;

use bytes::{Buf, BytesMut};
use servmers_crypto::DequeBuffer;
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
pub enum DriverError {
    UnsupportedTransport,
    Transport(transport::Error),
    // Deserialize(DeserializeError),
}

impl std::error::Error for DriverError {}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedTransport => write!(f, "unsupported transport"),
            Self::Transport(err) => write!(f, "{err}"),
        }
    }
}

/// Connection state.
enum State {
    /// Still sniffing the first bytes
    Negotiating { need: usize },
    /// Transport established, steady state.
    Ready { transport: Transport },
}

pub struct TransportDriver {
    state: State,
}

impl TransportDriver {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            state: State::Negotiating { need: 1 },
        }
    }

    /// Try to negotiate transport, and then read a packet from buffer.
    pub fn drive(
        &mut self,
        buf: &mut BytesMut,
        out: &mut Vec<BytesMut>,
    ) -> Result<Drive, DriverError> {
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
                            return Err(DriverError::UnsupportedTransport);
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
                        Err(err) => return Err(DriverError::Transport(err)),
                    };

                    // SAFETY
                    let mut packet = buf.split_to(next_offset);
                    let packet = packet
                        .split_off(data_range.start)
                        .split_to(data_range.end - data_range.start);

                    out.push(packet);

                    return Ok(Drive::Progress);
                }
            }
        }
    }

    /// Using negotiated transport to pack the input buffer in-place.
    ///
    /// # Panics
    ///
    /// Panics if transport has not yet been negotiated.
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        match self.state {
            State::Negotiating { .. } => panic!("Transport has not yet been negotiated."),
            State::Ready { ref mut transport } => transport.pack(buffer),
        }
    }
}
