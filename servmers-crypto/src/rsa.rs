//! Contains the function to RSA-encrypt hashed data as expected by Telegram.
//!
//! Not intended as a general implementation of RSA.

use std::path::Path;

use num_bigint::BigUint;

use crate::{aes, sha256};

/// RSA private key.
pub struct PrivateKey {
    n: BigUint,
    d: BigUint,
}

impl PrivateKey {
    pub fn new(n: &str, d: &str) -> Option<Self> {
        Some(Self {
            n: BigUint::parse_bytes(n.as_bytes(), 10)?,
            d: BigUint::parse_bytes(d.as_bytes(), 10)?,
        })
    }

    pub fn from_pem(path: impl AsRef<Path>) -> rsa::pkcs8::Result<Self> {
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::traits::{PrivateKeyParts, PublicKeyParts};

        let key = rsa::RsaPrivateKey::read_pkcs8_pem_file(path)?;
        Ok(Self {
            n: BigUint::from_bytes_be(&key.n().to_be_bytes()),
            d: BigUint::from_bytes_be(&key.d().to_be_bytes()),
        })
    }
}

/// Decrypt the given data and check hash.
pub fn decrypt_hashed(ciphertext: &[u8], key: &PrivateKey) -> Option<[u8; 192]> {
    if ciphertext.len() != 256 {
        return None;
    }

    // encrypted_data := RSA(key_aes_encrypted, server_pubkey)
    // m := ciphertext^d mod n
    let c = BigUint::from_bytes_be(ciphertext);
    if c >= key.n {
        return None;
    }

    let m = c.modpow(&key.d, &key.n);

    let mut key_aes_encrypted = m.to_bytes_be();
    if key_aes_encrypted.len() > 256 {
        return None;
    }
    while key_aes_encrypted.len() < 256 {
        key_aes_encrypted.insert(0, 0);
    }

    // key_aes_encrypted := temp_key_xor + aes_encrypted
    let (temp_key_xor_slice, aes_encrypted) = key_aes_encrypted.split_at(32);

    let mut temp_key_xor = [0u8; 32];
    temp_key_xor.copy_from_slice(temp_key_xor_slice);

    // temp_key := temp_key_xor XOR SHA256(aes_encrypted)
    let aes_hash = sha256!(aes_encrypted);
    let mut temp_key = temp_key_xor;
    for (a, b) in temp_key.iter_mut().zip(aes_hash.iter()) {
        *a ^= *b;
    }

    // aes_encrypted := AES256_IGE(data_with_hash, temp_key, 0)
    let mut data_with_hash = Vec::with_capacity(224);
    data_with_hash.extend_from_slice(aes_encrypted);

    aes::ige_decrypt(data_with_hash.as_mut(), &temp_key, &[0u8; 32]);

    // data_with_hash := data_pad_reversed + SHA256(temp_key + data_with_padding)
    let (data_pad_reversed, expected_hash_slice) = data_with_hash.split_at(192);

    let mut expected_hash = [0u8; 32];
    expected_hash.copy_from_slice(expected_hash_slice);

    // data_with_padding := BYTE_REVERSE(data_pad_reversed)
    let mut data_with_padding = data_pad_reversed.to_vec();
    data_with_padding.reverse();

    // check SHA256(temp_key + data_with_padding)
    let computed_hash = sha256!(&temp_key, &data_with_padding);
    if &computed_hash[..] != &expected_hash[..] {
        return None;
    }

    let mut out = [0u8; 192];
    out.copy_from_slice(&data_with_padding);
    Some(out)
}
