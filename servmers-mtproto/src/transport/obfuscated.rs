// This code is modified from grammers (https://codeberg.org/Lonami/grammers.git).
//
// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

use servmers_crypto::{
    DequeBuffer, ObfuscatedCipher, ObfuscatedCipherDecryptor, ObfuscatedCipherEncryptor,
};

use super::{Error, IntoSplit, Packer, Tagged, UnpackedOffset, Unpacker};

/// Obfuscation layer for other MTProto transport protocols.
///
/// This was made by Telegram to avoid ISP blocks.
/// This is needed to connect to the Telegram servers
/// using websockets or when conecting to MTProto proxies.
///
/// This wrapper encrypts the data using AES-256-CTR with a randomly
/// generated key that is then sent at the beginning of the connection.
///
/// Obfuscated transport can only be used with "tagged" transports, which
/// provide a way to get the obfuscated tag that is used in the encryption.
///
/// See [Transport Obfuscation](https://core.telegram.org/mtproto/mtproto-transports#transport-obfuscation)
/// for more information.
pub struct Obfuscated<T>
where
    T: IntoSplit,
    T::PackerHalf: Tagged,
{
    packer: ObfuscatedPacker<T::PackerHalf>,
    unpacker: ObfuscatedUnpacker<T::UnpackerHalf>,
}

pub struct ObfuscatedPacker<T: Packer + Tagged> {
    inner: T,
    cipher: ObfuscatedCipherEncryptor,
}

pub struct ObfuscatedUnpacker<T: Unpacker> {
    inner: T,
    cipher: ObfuscatedCipherDecryptor,
    decrypt_tail: usize,
}

impl<T> Obfuscated<T>
where
    T: IntoSplit,
    T::PackerHalf: Tagged,
{
    pub fn new(inner: T, cipher: ObfuscatedCipher) -> Self {
        let (packer, unpacker) = inner.into_split();
        let (encryptor, decryptor) = cipher.into_split();

        Self {
            packer: ObfuscatedPacker {
                inner: packer,
                cipher: encryptor,
            },
            unpacker: ObfuscatedUnpacker {
                inner: unpacker,
                cipher: decryptor,
                decrypt_tail: 0,
            },
        }
    }
}

impl<T> Packer for Obfuscated<T>
where
    T: IntoSplit,
    T::PackerHalf: Tagged,
{
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        self.packer.pack(buffer);
    }
}

impl<T> Unpacker for Obfuscated<T>
where
    T: IntoSplit,
    T::PackerHalf: Tagged,
{
    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        self.unpacker.unpack(buffer)
    }
}

impl<T> IntoSplit for Obfuscated<T>
where
    T: IntoSplit,
    T::PackerHalf: Tagged,
{
    type PackerHalf = ObfuscatedPacker<T::PackerHalf>;
    type UnpackerHalf = ObfuscatedUnpacker<T::UnpackerHalf>;

    fn into_split(self) -> (Self::PackerHalf, Self::UnpackerHalf) {
        (self.packer, self.unpacker)
    }
}

impl<T: Packer + Tagged> Packer for ObfuscatedPacker<T> {
    fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        self.inner.pack(buffer);
        self.cipher.encrypt(buffer.as_mut());
    }
}

impl<T: Unpacker> Unpacker for ObfuscatedUnpacker<T> {
    fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        if buffer.len() < self.decrypt_tail {
            panic!("buffer is smaller than what was decrypted");
        }

        self.cipher.decrypt(&mut buffer[self.decrypt_tail..]);
        self.decrypt_tail = buffer.len();

        match self.inner.unpack(buffer) {
            Ok(offset) => {
                self.decrypt_tail -= offset.next_offset;
                Ok(offset)
            }
            Err(e) => Err(e),
        }
    }
}
