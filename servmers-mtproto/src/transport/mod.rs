//! Implementation of the several [MTProto transports].
//!
//! This layer is responsible for taking serialized messages from the MTP and
//! packing them in a format that can be sent over a protocol, such as TCP, HTTP or UDP.
//!
//! [MTProto transports]: https://core.telegram.org/mtproto#mtproto-transport

mod detect;
mod driver;
mod transport;

pub use detect::{DetectError, Detected, detect};
pub use driver::{Drive, DriverError, TransportDriver};
pub use transport::{Error, Transport, UnpackedOffset};
