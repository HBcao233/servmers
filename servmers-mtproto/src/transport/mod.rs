// This code is modified from grammers (https://codeberg.org/Lonami/grammers.git).
//
// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! Implementation of the several [MTProto transports].
//!
//! This layer is responsible for taking serialized messages from the MTP and
//! packing them in a format that can be sent over a protocol, such as TCP, HTTP or UDP.
//!
//! [MTProto transports]: https://core.telegram.org/mtproto#mtproto-transport

pub mod abridged;
mod detect;
mod driver;
pub mod full;
pub mod intermediate;
pub mod obfuscated;

pub use abridged::Abridged;
pub use detect::{DetectError, Detected, detect};
pub use driver::{Drive, NegotiateError, NegotiateResult, TransportDriver};
pub use full::Full;
pub use intermediate::Intermediate;
pub use obfuscated::Obfuscated;

pub use grammers_mtproto::transport::{Error, UnpackedOffset};
use servmers_crypto::DequeBuffer;

pub trait Packer: Send {
    /// Packs the input buffer in-place.
    ///
    /// Panics if `buffer.len()` is not divisible by 4.
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>);
}

pub trait Unpacker: Send {
    /// Unpacks the input buffer in-place.
    ///
    /// Subsequent calls to `unpack` should be made with the same buffer,
    /// with the data on the ranges from previous `UnpackedOffset` removed.
    /// Failing to do so will cause transports such as [`Obfuscated`] to misbehave.
    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error>;
}

pub trait IntoSplit {
    type PackerHalf: Packer;
    type UnpackerHalf: Unpacker;
    fn into_split(self) -> (Self::PackerHalf, Self::UnpackerHalf);
}

pub trait Tagged {
    const TAG: [u8; 4];
}
