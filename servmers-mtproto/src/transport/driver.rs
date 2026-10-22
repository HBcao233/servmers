use bytes::{Buf, BytesMut};
use tracing::debug;

use crate::transport::{self, DetectError, Detected, Packer, UnpackedOffset, Unpacker};

/// The result of [`TransportDriver::drive`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drive {
    /// At least one frame was produced; call `drive` again on the remainder.
    Progress,
    /// The buffer does not hold a complete packet yet; go read more bytes.
    NeedMore,
}

pub enum NegotiateResult {
    /// The buffer does not detected transport yet; go read more bytes.
    NeedMore,
    /// Negotiated transport; returns packer half
    Negotiated { packer: Box<dyn Packer> },
}

pub enum NegotiateError {
    /// The client uses an unsupported transport.
    UnsupportedTransport,
}

/// Connection state.
enum State {
    /// Still sniffing the first bytes
    Negotiating { need: usize },
    /// Transport established, steady state.
    Ready { unpacker: Box<dyn Unpacker> },
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

    pub fn negotiate(&mut self, buf: &mut BytesMut) -> Result<NegotiateResult, NegotiateError> {
        match self.state {
            State::Negotiating { need } => {
                if buf.len() < need {
                    return Ok(NegotiateResult::NeedMore);
                }

                match transport::detect(buf) {
                    Ok(Detected {
                        packer,
                        unpacker,
                        preamble,
                    }) => {
                        debug!(preamble, "transport negotiated");
                        buf.advance(preamble);
                        self.state = State::Ready { unpacker };
                        Ok(NegotiateResult::Negotiated { packer })
                    }
                    Err(DetectError::NeedMore(need)) => {
                        self.state = State::Negotiating { need };
                        Ok(NegotiateResult::NeedMore)
                    }
                    Err(DetectError::Unsupported) => Err(NegotiateError::UnsupportedTransport),
                }
            }
            State::Ready { .. } => {
                panic!("Already negotiated.");
            }
        }
    }

    /// Try to negotiate transport, and then read a packet from buffer.
    pub fn drive(
        &mut self,
        buf: &mut BytesMut,
        out: &mut Vec<BytesMut>,
    ) -> Result<Drive, transport::Error> {
        match self.state {
            State::Negotiating { .. } => panic!("Transport has not yet been negotiated."),
            State::Ready { ref mut unpacker } => {
                let UnpackedOffset {
                    data_range,
                    next_offset,
                } = match unpacker.unpack(buf) {
                    Ok(offset) => offset,
                    Err(transport::Error::MissingBytes) => return Ok(Drive::NeedMore),
                    Err(err) => return Err(err),
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
