mod deserialize;
mod plain;
mod serialize;

pub use grammers_mtproto::mtp::{
    ENCRYPTED_PACKET_HEADER_LEN, MAX_TRANSPORT_HEADER_LEN, MESSAGE_CONTAINER_HEADER_LEN,
    PLAIN_PACKET_HEADER_LEN,
};

use std::fmt;

use grammers_tl_types::{self as tl, Identifiable, Serializable};
use plain::Plain;
use servmers_crypto::{self as crypto, AuthKey};

use crate::MsgId;

/// Manual implementation of Telegram's `rpc_result`.
#[derive(Debug)]
pub struct Message {
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
    pub messages: Vec<Message>,
}

#[derive(Debug)]
pub enum ClientMessages {
    Plain(Message),
    Encrypted(DecryptedMessages),
}

/// The error type for the deserialization of client messages.
#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// The client's Authorization Key did not match our expectations.
    BadAuthKey { got: i64, expected: i64 },

    /// The client's message ID did not match our expectations.
    BadMessageId { got: i64 },

    /// The client's session id is changed.
    SessionIdChanged,

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
                write!(f, "bad client auth key (got {got}, expected {expected})")
            }
            Self::BadMessageId { got } => write!(f, "bad client message id (got {got})"),
            Self::SessionIdChanged => write!(f, "client changed it's session id"),
            Self::NegativeMessageLength { got } => {
                write!(f, "bad client message length (got {got})")
            }
            Self::TooLongMessageLength { got, max_length } => write!(
                f,
                "bad client message length (got {got}, when at most it should be {max_length})"
            ),
            Self::MessageBufferTooSmall => write!(
                f,
                "client requested with a payload that's too small to fit a valid message"
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

pub enum Outbound {
    RpcResult {
        req_msg_id: i64,
        result: Vec<u8>,
    },
    RpcError {
        req_msg_id: i64,
        code: i32,
        message: String,
    },
    Update(Vec<u8>),
    Other(Vec<u8>),
}

impl Outbound {
    pub fn content_related(&self) -> bool {
        match self {
            Self::RpcResult { .. } => true,
            Self::RpcError { .. } => true,
            Self::Update(_) => true,
            Self::Other(_) => false,
        }
    }
}

impl Serializable for Outbound {
    fn serialize(&self, buf: &mut impl Extend<u8>) {
        match self {
            Self::RpcResult { req_msg_id, result } => {
                crate::manual_tl::RpcResult::CONSTRUCTOR_ID.serialize(buf);
                req_msg_id.serialize(buf);
                result.serialize(buf);
            }
            Self::RpcError {
                req_msg_id,
                code,
                message,
            } => {
                crate::manual_tl::RpcResult::CONSTRUCTOR_ID.serialize(buf);
                req_msg_id.serialize(buf);
                let error = tl::enums::RpcError::Error(tl::types::RpcError {
                    error_code: *code,
                    error_message: message.clone(),
                });
                error.serialize(buf);
            }
            Self::Update(update) => update.serialize(buf),
            Self::Other(other) => other.serialize(buf),
        }
    }
}

/// An implementation of the [Mobile Transport Protocol] for ciphertext
/// (encrypted) messages.
///
/// [Mobile Transport Protocol]: https://core.telegram.org/mtproto
pub struct Mtp {
    /// The Authorization Key used for encryption and decryption.
    auth_key: Option<AuthKey>,

    /// The ID of session given by client.
    session_id: i64,

    /// Identifiers that need to be acknowledged to the server.
    ///
    /// A [Content-related Message] is "a message requiring an explicit
    /// acknowledgment. These include all the user and many service messages,
    /// virtually all with the exception of containers and acknowledgments."
    ///
    /// [Content-related Message]: https://core.telegram.org/mtproto/description#content-related-message
    pending_ack: Vec<i64>,

    /// Temporary deserialization results.
    deserialization: Vec<Message>,

    /// The ID of the last message.
    last_msg_id: u64,

    /// The current message sequence number.
    sequence: i32,

    /// How many messages are there in the buffer.
    msg_count: usize,

    /// If present, the threshold in bytes at which a message will be
    /// considered large enough to attempt compressing it. Otherwise,
    /// outgoing messages will never be compressed.
    compression_threshold: Option<usize>,
}

impl Mtp {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            auth_key: None,
            session_id: 0,
            pending_ack: Vec::new(),
            deserialization: Vec::new(),
            last_msg_id: 0,
            sequence: 0,
            msg_count: 0,
            compression_threshold: crate::DEFAULT_COMPRESSION_THRESHOLD,
        }
    }

    pub fn is_auth_key_configured(&self) -> bool {
        self.auth_key.is_some()
    }

    pub fn set_auth_key(&mut self, auth_key: AuthKey) {
        self.auth_key = Some(auth_key);
    }

    pub fn set_session_id(&mut self, session_id: i64) -> Result<(), Error> {
        if self.session_id == 0 {
            self.session_id = session_id;
            Ok(())
        } else if self.session_id != session_id {
            Err(Error::SessionIdChanged)
        } else {
            Ok(())
        }
    }
}
