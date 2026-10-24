// This code is modified from grammers-crypto (https://codeberg.org/Lonami/grammers.git).
//
// Copyright 2020 - developers of the `grammers` project.
//
// Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
// https://www.apache.org/licenses/LICENSE-2.0> or the MIT license
// <LICENSE-MIT or https://opensource.org/licenses/MIT>, at your
// option. This file may not be copied, modified, or distributed
// except according to those terms.

//! This library contains a collection of functions that relate to
//! encrypting and decryption values when exchanging messages with Telegram.

#![deny(unsafe_code)]

mod auth_key;
mod obfuscated;
mod sha;

pub use auth_key::AuthKey;
pub use grammers_crypto::{DequeBuffer, Error, aes};
pub use obfuscated::{ObfuscatedCipher, ObfuscatedCipherDecryptor, ObfuscatedCipherEncryptor};

enum Side {
    Client,
    Server,
}

impl Side {
    // "where x = 0 for messages from client to server and x = 8 for those from server to client."
    fn x(&self) -> usize {
        match *self {
            Side::Client => 0,
            Side::Server => 8,
        }
    }
}

/// Calculate the key based on Telegram [guidelines for MTProto 2],
/// returning the pair `(key, iv)` for use in AES-IGE mode.
///
/// [guidelines for MTProto 2]: https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector
fn calc_key(auth_key: &AuthKey, msg_key: &[u8; 16], side: Side) -> ([u8; 32], [u8; 32]) {
    let x = side.x();

    // sha256_a = SHA256 (msg_key + substr (auth_key, x, 36));
    let sha256_a = sha256!(msg_key, &auth_key.data[x..x + 36]);

    // sha256_b = SHA256 (substr (auth_key, 40+x, 36) + msg_key);
    let sha256_b = sha256!(&auth_key.data[40 + x..40 + x + 36], msg_key);

    // aes_key = substr (sha256_a, 0, 8) + substr (sha256_b, 8, 16) + substr (sha256_a, 24, 8);
    let aes_key = {
        let mut buffer = [0; 32];
        buffer[0..8].copy_from_slice(&sha256_a[0..8]);
        buffer[8..8 + 16].copy_from_slice(&sha256_b[8..8 + 16]);
        buffer[24..24 + 8].copy_from_slice(&sha256_a[24..24 + 8]);
        buffer
    };

    // aes_iv = substr (sha256_b, 0, 8) + substr (sha256_a, 8, 16) + substr (sha256_b, 24, 8);
    let aes_iv = {
        let mut buffer = [0; 32];
        buffer[0..8].copy_from_slice(&sha256_b[0..8]);
        buffer[8..8 + 16].copy_from_slice(&sha256_a[8..8 + 16]);
        buffer[24..24 + 8].copy_from_slice(&sha256_b[24..24 + 8]);
        buffer
    };

    (aes_key, aes_iv)
}

/// Determines the padding length needed for a plaintext of a certain length,
/// according to the following citation:
///
/// > Note that MTProto 2.0 requires from 12 to 1024 bytes of padding
/// > [...] the resulting message length be divisible by 16 bytes
fn determine_padding_v2_length(len: usize) -> usize {
    16 + (16 - (len % 16))
}

/// This function implements the [MTProto 2.0 algorithm] for computing
/// `aes_key` and `aes_iv` from `auth_key` and `msg_key` as specified
///
/// [MTProto 2.0 algorithm]: https://core.telegram.org/mtproto/description#defining-aes-key-and-initialization-vector
pub fn encrypt_data_v2(buffer: &mut DequeBuffer<u8>, auth_key: &AuthKey) {
    let random_padding = {
        let mut rnd = [0; 32];
        getrandom::fill(&mut rnd).expect("failed to generate a secure padding");
        rnd
    };

    // "Note that MTProto 2.0 requires from 12 to 1024 bytes of padding"
    // "[...] the resulting message length be divisible by 16 bytes"
    let padding_len = determine_padding_v2_length(buffer.len());
    buffer.extend_back(&random_padding[0..padding_len]);

    // Encryption is done by the server
    let side = Side::Server;
    let x = side.x();

    // msg_key_large = SHA256 (substr (auth_key, 88+x, 32) + plaintext + random_padding);
    let msg_key_large = sha256!(&auth_key.data[88 + x..88 + x + 32], &buffer[..]);

    // msg_key = substr (msg_key_large, 8, 16);
    let msg_key = {
        let mut buffer = [0; 16];
        buffer.copy_from_slice(&msg_key_large[8..8 + 16]);
        buffer
    };

    // Calculate the key
    let (key, iv) = calc_key(auth_key, &msg_key, side);

    aes::ige_encrypt(&mut buffer[..], &key, &iv);

    buffer.extend_front(&msg_key);
    buffer.extend_front(&auth_key.key_id);
}

/// This method is the inverse of `encrypt_data_v2`.
/// Returns the slice of the input buffer that contains the decrypted plaintext.
pub fn decrypt_data_v2<'b>(
    buffer: &'b mut [u8],
    auth_key: &AuthKey,
) -> Result<&'b mut [u8], Error> {
    // Decryption is done from the client
    let side = Side::Client;
    let x = side.x();

    if buffer.len() < 24 || !(buffer.len() - 24).is_multiple_of(16) {
        return Err(Error::InvalidBuffer);
    }

    // TODO Check salt, session_id and sequence_number
    let key_id = &buffer[..8];
    if auth_key.key_id != *key_id {
        return Err(Error::AuthKeyMismatch);
    }

    let mut msg_key = [0; 16];
    msg_key.copy_from_slice(&buffer[8..8 + 16]);

    let (key, iv) = calc_key(auth_key, &msg_key, side);

    aes::ige_decrypt(&mut buffer[8 + 16..], &key, &iv);
    let plaintext = &buffer[8 + 16..];

    // https://core.telegram.org/mtproto/security_guidelines#mtproto-encrypted-messages
    let our_key = sha256!(&auth_key.data[88 + x..88 + x + 32], &plaintext);

    if msg_key != our_key[8..8 + 16] {
        return Err(Error::MessageKeyMismatch);
    }

    Ok(&mut buffer[8 + 16..])
}
