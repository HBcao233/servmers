pub mod decode;
// mod manual_tl;
pub mod mtp;
mod transport;
// mod utils;

pub use grammers_mtproto::DEFAULT_COMPRESSION_THRESHOLD;

/// A Message Identifier.
///
/// When requests are deserialized, a new message identifier is attached to them.
/// As server responses get processed, some of them will be RPC responses.
/// The message identifier in the response can be matched with the message identifier
/// that was assigned to the request to determine which request the response is for.
#[derive(Copy, Clone, Debug, Hash, PartialEq, PartialOrd, Eq, Ord)]
pub struct MsgId(i64);
