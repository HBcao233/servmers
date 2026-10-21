// mod encrypted;
// mod plain;

// use std::fmt;

pub use grammers_mtproto::mtp::{
    ENCRYPTED_PACKET_HEADER_LEN, Encrypted, MAX_TRANSPORT_HEADER_LEN, MESSAGE_CONTAINER_HEADER_LEN,
    PLAIN_PACKET_HEADER_LEN,
};
/*
use grammers_tl_types as tl;
pub use plain::Plain;
use servmers_crypto as crypto;
use servmers_crypto::DequeBuffer;

use crate::MsgId;

/// Manual implementation of Telegram's `rpc_result`.
#[derive(Debug)]
pub struct ClientRequest {
    /// Message identifier matching that of the outgoing RPC.
    pub msg_id: MsgId,
    /// Unprocessed response body for the associated RPC.
    pub body: Vec<u8>,
}

/// The error type for the deserialization of client messages.
#[derive(Clone, Debug, PartialEq)]
pub enum DeserializeError {
    /// The client's Authorization Key did not match our expectations.
    BadAuthKey { got: i64, expected: i64 },

    /// The client's message ID did not match our expectations.
    BadMessageId { got: i64 },

    /// The client's session ID did not match our expectations.
    BadSessionId { got: i64, expected: i64 },

    /// The server's message length was not strictly positive.
    NegativeMessageLength { got: i32 },

    /// The server's message length was past the buffer.
    TooLongMessageLength { got: usize, max_length: usize },

    /// The received buffer is too small to contain a valid response message,
    /// or the response seemed valid at first but trying to deserialize it
    /// proved the buffer to be too small.
    MessageBufferTooSmall,

    /// The server responded with compressed data which we failed to decompress.
    DecompressionFailed,

    /// While deserializing the response types one of them had a constructor
    /// that did not match our expectations. The invalid ID is contained
    /// within this variant.
    UnexpectedConstructor { id: u32 },

    /// Attempting to decrypt the message failed in some way.
    DecryptionError(crypto::Error),
}

impl std::error::Error for DeserializeError {}

impl fmt::Display for DeserializeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BadAuthKey { got, expected } => {
                write!(f, "bad server auth key (got {got}, expected {expected})")
            }
            Self::BadMessageId { got } => write!(f, "bad server message id (got {got})"),
            Self::BadSessionId { got, expected } => {
                write!(f, "bad session id (got {got}, expected {expected})")
            }
            Self::NegativeMessageLength { got } => {
                write!(f, "bad server message length (got {got})")
            }
            Self::TooLongMessageLength { got, max_length } => write!(
                f,
                "bad server message length (got {got}, when at most it should be {max_length})"
            ),
            Self::MessageBufferTooSmall => write!(
                f,
                "server responded with a payload that's too small to fit a valid message"
            ),
            Self::DecompressionFailed => write!(f, "failed to decompress server's data"),
            Self::UnexpectedConstructor { id } => write!(f, "unexpected constructor: {id:08x}"),
            Self::DecryptionError(ref error) => write!(f, "failed to decrypt message: {error}"),
        }
    }
}

impl From<tl::deserialize::Error> for DeserializeError {
    fn from(error: tl::deserialize::Error) -> Self {
        use tl::deserialize::Error as Err;

        match error {
            Err::UnexpectedEof => DeserializeError::MessageBufferTooSmall,
            Err::UnexpectedConstructor { id } => DeserializeError::UnexpectedConstructor { id },
        }
    }
}

impl From<crypto::Error> for DeserializeError {
    fn from(error: crypto::Error) -> Self {
        Self::DecryptionError(error)
    }
}

/// The trait used by the [Mobile Transport Protocol] to serialize outgoing
/// messages and deserialize incoming ones into proper responses.
///
/// [Mobile Transport Protocol]: https://core.telegram.org/mtproto/description
pub enum Mtp {
    Plain(Plain),
    Encrypted(Box<Encrypted>),
}

impl Mtp {
    /// Deserializes a single incoming message payload into zero or more requests.
    pub fn deserialize(
        &mut self,
        payload: &mut [u8],
    ) -> Result<Vec<ClientRequest>, DeserializeError> {
        match self {
            Self::Plain(plain) => plain.deserialize(payload),
            Self::Encrypted(encrypted) => encrypted.deserialize(payload),
        }
    }

    /// Serializes one response to the input buffer.
    /// The same buffer should be used until `finalize` is called.
    ///
    /// Returns the message ID assigned the request if it was serialized, or `None` if the buffer
    /// is full and cannot hold more requests.
    ///
    /// # Panics
    ///
    /// The method panics if the body length is not padded to 4 bytes.
    /// The serialization of requests will always be correctly padded.
    ///
    /// The method also panics if the body length exceeds roughly 1MB.
    /// Such large requests would essentially kill the connection otherwise.
    pub fn push(&mut self, buffer: &mut DequeBuffer<u8>, response: &[u8]) -> Option<MsgId> {
        match self {
            Self::Plain(plain) => plain.push(buffer, response),
            Self::Encrypted(encrypted) => encrypted.push(buffer, response),
        }
    }

    /// Finalizes the buffer of responses.
    ///
    /// Note that even if there are no requests to serialize, the protocol may
    /// produce data that has to be sent after deserializing incoming messages.
    ///
    /// The buffer may remain empty if there are no actions to take.
    ///
    /// When at least one message is serialized, the last generated `MsgId` is returned.
    /// This will either belong to the container (if used) or the last serialized message.
    pub fn finalize(&mut self, buffer: &mut DequeBuffer<u8>) -> Option<MsgId> {
        match self {
            Self::Plain(plain) => plain.finalize(buffer),
            Self::Encrypted(encrypted) => encrypted.finalize(buffer),
        }
    }
}
*/
