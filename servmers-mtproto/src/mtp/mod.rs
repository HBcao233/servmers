mod encrypted;
mod plain;

pub use encrypted::{
    ENCRYPTED_PACKET_HEADER_LEN, Encrypted, MAX_TRANSPORT_HEADER_LEN, MESSAGE_CONTAINER_HEADER_LEN,
    PLAIN_PACKET_HEADER_LEN,
};
pub use plain::Plain;

use std::fmt;

use grammers_tl_types as tl;
use servmers_crypto as crypto;

use crate::MsgId;

/// Manual implementation of Telegram's `rpc_result`.
#[derive(Debug)]
pub struct ClientMessage {
    /// Message identifier.
    pub msg_id: MsgId,
    /// Unprocessed request body.
    pub body: Vec<u8>,
}

#[derive(Debug)]
pub struct DecryptedMessages {
    /// The salt of this message.
    pub salt: i64,
    /// The session identifier provided by client.
    pub session_id: i64,
    /// Decrypted messages from this packet.
    pub messages: Vec<ClientMessage>,
}

/// The error type for the deserialization of client messages.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The client's Authorization Key did not match our expectations.
    BadAuthKey { got: i64, expected: i64 },

    /// The client's message ID did not match our expectations.
    BadMessageId { got: i64 },

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

impl std::error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BadAuthKey { got, expected } => {
                write!(f, "bad server auth key (got {got}, expected {expected})")
            }
            Self::BadMessageId { got } => write!(f, "bad server message id (got {got})"),
            Self::NegativeMessageLength { got } => {
                write!(f, "bad server message length (got {got})")
            }
            Self::TooLongMessageLength { got, max_length } => write!(
                f,
                "bad client message length (got {got}, when at most it should be {max_length})"
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

impl From<tl::deserialize::Error> for Error {
    fn from(error: tl::deserialize::Error) -> Self {
        use tl::deserialize::Error as Err;

        match error {
            Err::UnexpectedEof => Self::MessageBufferTooSmall,
            Err::UnexpectedConstructor { id } => Self::UnexpectedConstructor { id },
        }
    }
}

impl From<crypto::Error> for Error {
    fn from(error: crypto::Error) -> Self {
        Self::DecryptionError(error)
    }
}
