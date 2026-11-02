//! Sans-IO implementation of the process to generate an Authorization Key.

use std::fmt;

use grammers_tl_types::{self as tl, Deserializable, Serializable, deserialize::Cursor};
use jiff::Timestamp;
use num_bigint::BigUint;
use servmers_crypto::{AuthKey, aes, generate_key_data_from_nonce, rsa};
use sha1::{Digest, Sha1};
use tracing::debug;

use crate::DequeBuffer;

/// Private key pem file path.
const PRIVATE_PEM: &str = "server_private.pem";

/// public key fingerprints
const FINGERPRINTS: [i64; 1] = [4724578571238727662];

/// Client is expected to check whether dh_prime is a safe 2048-bit prime.
const DH_PRIME: [u8; 256] = [
    0xC7, 0x1C, 0xAE, 0xB9, 0xC6, 0xB1, 0xC9, 0x04, 0x8E, 0x6C, 0x52, 0x2F, 0x70, 0xF1, 0x3F, 0x73,
    0x98, 0x0D, 0x40, 0x23, 0x8E, 0x3E, 0x21, 0xC1, 0x49, 0x34, 0xD0, 0x37, 0x56, 0x3D, 0x93, 0x0F,
    0x48, 0x19, 0x8A, 0x0A, 0xA7, 0xC1, 0x40, 0x58, 0x22, 0x94, 0x93, 0xD2, 0x25, 0x30, 0xF4, 0xDB,
    0xFA, 0x33, 0x6F, 0x6E, 0x0A, 0xC9, 0x25, 0x13, 0x95, 0x43, 0xAE, 0xD4, 0x4C, 0xCE, 0x7C, 0x37,
    0x20, 0xFD, 0x51, 0xF6, 0x94, 0x58, 0x70, 0x5A, 0xC6, 0x8C, 0xD4, 0xFE, 0x6B, 0x6B, 0x13, 0xAB,
    0xDC, 0x97, 0x46, 0x51, 0x29, 0x69, 0x32, 0x84, 0x54, 0xF1, 0x8F, 0xAF, 0x8C, 0x59, 0x5F, 0x64,
    0x24, 0x77, 0xFE, 0x96, 0xBB, 0x2A, 0x94, 0x1D, 0x5B, 0xCD, 0x1D, 0x4A, 0xC8, 0xCC, 0x49, 0x88,
    0x07, 0x08, 0xFA, 0x9B, 0x37, 0x8E, 0x3C, 0x4F, 0x3A, 0x90, 0x60, 0xBE, 0xE6, 0x7C, 0xF9, 0xA4,
    0xA4, 0xA6, 0x95, 0x81, 0x10, 0x51, 0x90, 0x7E, 0x16, 0x27, 0x53, 0xB5, 0x6B, 0x0F, 0x6B, 0x41,
    0x0D, 0xBA, 0x74, 0xD8, 0xA8, 0x4B, 0x2A, 0x14, 0xB3, 0x14, 0x4E, 0x0E, 0xF1, 0x28, 0x47, 0x54,
    0xFD, 0x17, 0xED, 0x95, 0x0D, 0x59, 0x65, 0xB4, 0xB9, 0xDD, 0x46, 0x58, 0x2D, 0xB1, 0x17, 0x8D,
    0x16, 0x9C, 0x6B, 0xC4, 0x65, 0xB0, 0xD6, 0xFF, 0x9C, 0xA3, 0x92, 0x8F, 0xEF, 0x5B, 0x9A, 0xE4,
    0xE4, 0x18, 0xFC, 0x15, 0xE8, 0x3E, 0xBE, 0xA0, 0xF8, 0x7F, 0xA9, 0xFF, 0x5E, 0xED, 0x70, 0x05,
    0x0D, 0xED, 0x28, 0x49, 0xF4, 0x7B, 0xF9, 0x59, 0xD9, 0x56, 0x85, 0x0C, 0xE9, 0x29, 0x85, 0x1F,
    0x0D, 0x81, 0x15, 0xF6, 0x35, 0xB1, 0x05, 0xEE, 0x2E, 0x4E, 0x15, 0xD0, 0x4B, 0x24, 0x54, 0xBF,
    0x6F, 0x4F, 0xAD, 0xF0, 0x34, 0xB1, 0x04, 0x03, 0x11, 0x9C, 0xD8, 0xE3, 0xB9, 0x2F, 0xCC, 0x5B,
];

/// g is always equal to 2, 3, 4, 5, 6 or 7 (p = dh_prime):
///
/// - p mod 8 = 7 for g = 2;
/// - p mod 3 = 2 for g = 3;
/// - no extra condition for g = 4;
/// - p mod 5 = 1 or 4 for g = 5;
/// - p mod 24 = 19 or 23 for g = 6;
/// - p mod 7 = 3, 5 or 6 for g = 7.
const G: u32 = 3;

#[derive(Debug, Clone)]
pub enum Error {
    /// The client's nonce did not match ours.
    InvalidNonce {
        /// The unexpected nonce that we got.
        got: [u8; 16],

        /// The expected nonce.
        expected: [u8; 16],
    },

    /// The client's nonce has changed during the key exchange.
    InvalidServerNonce {
        /// The unexpected nonce that we got.
        got: [u8; 16],

        /// The expected nonce.
        expected: [u8; 16],
    },

    /// The client's PQ was not right.
    InvalidPq {
        /// The unexpected p that we got.
        p: Vec<u8>,

        /// The unexpected q that we got.
        q: Vec<u8>,
    },

    /// The client's fingerprint is not known to us.
    InvalidFingerprint {
        /// The fingerprint that we got.
        fingerprint: i64,
    },

    /// Failed to rsa decrypt.
    RsaDecryptFailed,

    /// The server's `encrypted_data` is not correctly padded.
    EncryptedResponseNotPadded {
        /// The non-padded length of the response.
        len: usize,
    },

    /// An error occured while trying to read the DH inner data.
    InvalidDhInnerData {
        /// The inner error that occured when reading the data.
        error: tl::deserialize::Error,
    },

    /// Some parameter (`g_a` or `g_b`) was out of range.
    GParameterOutOfRange {
        value: BigUint,
        low: BigUint,
        high: BigUint,
    },

    /// The plaintext answer hash did not match.
    InvalidAnswerHash {
        /// The unexpected hash that we got.
        got: [u8; 20],

        /// The expected hash.
        expected: [u8; 20],
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNonce { got, expected } => {
                write!(f, "invalid nonce: got {got:?}, expected {expected:?}")
            }
            Self::InvalidServerNonce { got, expected } => write!(
                f,
                "invalid server nonce: got {got:?}, expected {expected:?}"
            ),
            Self::InvalidPq { p, q } => write!(f, "invalid p: {p:?}, q: {q:?}"),
            Self::InvalidFingerprint { fingerprint } => {
                write!(f, "invalid client fingerprint: {fingerprint}")
            }
            Self::RsaDecryptFailed => write!(f, "failed to rsa decrypt"),
            Self::EncryptedResponseNotPadded { len } => write!(
                f,
                "the encrypted server response was {len} bytes long, which is not correctly padded"
            ),
            Self::InvalidDhInnerData { error } => {
                write!(f, "could not deserialize DH inner data: {error}")
            }
            Self::GParameterOutOfRange { low, high, value } => write!(
                f,
                "the parameter g = {value} was not in the range {low}..{high}"
            ),
            Self::InvalidAnswerHash { got, expected } => {
                write!(f, "invalid answer hash: got {got:?}, expected {expected:?}")
            }
        }
    }
}

pub struct DhData {
    pub nonce: [u8; 16],
    pub server_nonce: [u8; 16],
    pub p: u32,
    pub q: u32,
}

pub struct DhGenData {
    pub new_nonce: [u8; 32],
    pub a: BigUint,
    pub dc: Option<i32>,
    pub expires_in: Option<i32>,
}

impl DhData {
    pub fn new(
        nonce: [u8; 16],
        server_nonce: [u8; 16],
        raw_p: Vec<u8>,
        raw_q: Vec<u8>,
    ) -> Result<Self, Error> {
        let err = Error::InvalidPq {
            p: raw_p.clone(),
            q: raw_q.clone(),
        };
        let p = u32::from_be_bytes(match raw_p.try_into() {
            Ok(p) => p,
            Err(_) => return Err(err),
        });
        let q = u32::from_be_bytes(match raw_q.try_into() {
            Ok(q) => q,
            Err(_) => return Err(err),
        });
        Ok(Self {
            nonce,
            server_nonce,
            p,
            q,
        })
    }

    pub fn check(&self, got: DhData) -> Result<(), Error> {
        check_nonce(&got.nonce, &self.nonce)?;
        check_server_nonce(&got.server_nonce, &self.server_nonce)?;
        check_pq(got.p, got.q, self.p, self.q)?;

        Ok(())
    }
}

pub fn step1(request: tl::functions::ReqPqMulti) -> Result<(tl::enums::ResPq, DhData), Error> {
    let tl::functions::ReqPqMulti { nonce } = request;

    let server_nonce = generate_nonce();
    let (pq, p, q) = generate_pq();

    Ok((
        tl::enums::ResPq::Pq(tl::types::ResPq {
            nonce,
            server_nonce,
            pq: pq.to_vec(),
            server_public_key_fingerprints: FINGERPRINTS.to_vec(),
        }),
        DhData {
            nonce,
            server_nonce,
            p: p,
            q: q,
        },
    ))
}

pub fn step2(
    dh: &DhData,
    request: tl::functions::ReqDhParams,
) -> Result<(tl::enums::ServerDhParams, DhGenData), Error> {
    let tl::functions::ReqDhParams {
        nonce,
        server_nonce,
        p,
        q,
        public_key_fingerprint,
        encrypted_data,
    } = request;

    let new_dh = DhData::new(nonce, server_nonce, p, q)?;
    dh.check(new_dh)?;

    let key = key_for_fingerprint(public_key_fingerprint).ok_or(Error::InvalidFingerprint {
        fingerprint: public_key_fingerprint,
    })?;
    let decrypted_data =
        rsa::decrypt_hashed(&encrypted_data, &key).ok_or(Error::RsaDecryptFailed)?;

    let (pq, new_dh, new_nonce, dc, expires_in) =
        match tl::enums::PQInnerData::from_bytes(&decrypted_data)
            .map_err(|error| Error::InvalidDhInnerData { error })?
        {
            tl::enums::PQInnerData::Data(tl::types::PQInnerData {
                pq,
                p,
                q,
                nonce,
                server_nonce,
                new_nonce,
            }) => (
                pq,
                DhData::new(nonce, server_nonce, p, q)?,
                new_nonce,
                None,
                None,
            ),
            tl::enums::PQInnerData::Dc(tl::types::PQInnerDataDc {
                pq,
                p,
                q,
                nonce,
                server_nonce,
                new_nonce,
                dc,
            }) => (
                pq,
                DhData::new(nonce, server_nonce, p, q)?,
                new_nonce,
                Some(dc),
                None,
            ),
            tl::enums::PQInnerData::Temp(tl::types::PQInnerDataTemp {
                pq,
                p,
                q,
                nonce,
                server_nonce,
                new_nonce,
                expires_in,
            }) => (
                pq,
                DhData::new(nonce, server_nonce, p, q)?,
                new_nonce,
                None,
                Some(expires_in),
            ),
            tl::enums::PQInnerData::TempDc(tl::types::PQInnerDataTempDc {
                pq,
                p,
                q,
                nonce,
                server_nonce,
                new_nonce,
                dc,
                expires_in,
            }) => (
                pq,
                DhData::new(nonce, server_nonce, p, q)?,
                new_nonce,
                Some(dc),
                Some(expires_in),
            ),
        };
    if dh.p as u64 * dh.q as u64
        != u64::from_be_bytes(pq.try_into().map_err(|_| Error::InvalidPq {
            p: dh.p.to_be_bytes().to_vec(),
            q: dh.q.to_be_bytes().to_vec(),
        })?)
    {
        return Err(Error::InvalidPq {
            p: dh.p.to_be_bytes().to_vec(),
            q: dh.q.to_be_bytes().to_vec(),
        });
    }
    dh.check(new_dh)?;

    let server_time = Timestamp::now().as_second() as i32;

    // Complete DH Exchange
    let (key, iv) = generate_key_data_from_nonce(&dh.server_nonce, &new_nonce);

    let safety_range = BigUint::ONE << (2048 - 64);
    let g = BigUint::new_const(G);
    let dh_prime = BigUint::from_bytes_be(&DH_PRIME);
    let (a, g_a) = loop {
        let mut a_bytes = [0; 256];
        getrandom::fill(&mut a_bytes).expect("failed to generate g_a for auth key");
        if a_bytes[0] == 0 {
            continue;
        }

        let a = BigUint::from_bytes_be(&a_bytes);
        let g_a = g.modpow(&a, &dh_prime);
        if safety_range < g_a && g_a < &dh_prime - &safety_range {
            break (a, g_a);
        }
    };

    let inner = tl::enums::ServerDhInnerData::Data(tl::types::ServerDhInnerData {
        nonce: dh.nonce,
        server_nonce: dh.server_nonce,
        g: G as i32,
        dh_prime: DH_PRIME.to_vec(),
        g_a: g_a.to_bytes_be(),
        server_time,
    });
    let mut plain = DequeBuffer::with_capacity(608, 20);
    inner.serialize(&mut plain);

    let sha = {
        let mut h = Sha1::new();
        h.update(plain.as_ref());
        h.finalize()
    };
    plain.extend_front(&sha[..]);

    debug!(len = ?plain.len());
    let pad_len = (16 - (plain.len() % 16)) % 16;
    plain.extend_back(&[0u8; 15][..pad_len]);

    aes::ige_encrypt(&mut plain[..], &key, &iv);

    Ok((
        tl::enums::ServerDhParams::Ok(tl::types::ServerDhParamsOk {
            nonce: dh.nonce,
            server_nonce: dh.server_nonce,
            encrypted_answer: (&plain[..]).to_vec(),
        }),
        DhGenData {
            new_nonce,
            a,
            dc,
            expires_in,
        },
    ))
}

pub fn step3(
    dh: &DhData,
    dh_gen: &DhGenData,
    request: tl::functions::SetClientDhParams,
) -> Result<(tl::enums::SetClientDhParamsAnswer, AuthKey), Error> {
    let tl::functions::SetClientDhParams {
        nonce,
        server_nonce,
        mut encrypted_data,
    } = request;

    check_nonce(&nonce, &dh.nonce)?;
    check_server_nonce(&server_nonce, &dh.server_nonce)?;

    if !encrypted_data.len().is_multiple_of(16) {
        return Err(Error::EncryptedResponseNotPadded {
            len: encrypted_data.len(),
        });
    }

    // Complete DH Exchange
    let (key, iv) = generate_key_data_from_nonce(&dh.server_nonce, &dh_gen.new_nonce);
    aes::ige_decrypt(&mut encrypted_data, &key, &iv);
    let decrypted_data = encrypted_data;

    let mut cursor = Cursor::from_slice(&decrypted_data[20..]);
    let tl::enums::ClientDhInnerData::Data(tl::types::ClientDhInnerData {
        nonce,
        server_nonce,
        retry_id,
        g_b,
    }) = tl::enums::ClientDhInnerData::deserialize(&mut cursor)
        .map_err(|error| Error::InvalidDhInnerData { error })?;

    let sha = {
        let mut hasher = Sha1::new();
        hasher.update(&decrypted_data[20..20 + cursor.pos()]);
        hasher.finalize()
    };
    if decrypted_data[0..20] != *sha {
        return Err(Error::InvalidAnswerHash {
            got: decrypted_data[0..20].try_into().unwrap(),
            expected: sha.into(),
        });
    }

    check_nonce(&nonce, &dh.nonce)?;
    check_server_nonce(&server_nonce, &dh.server_nonce)?;

    if retry_id != 0 {
        // TODO: handle retry
    }

    let dh_prime = BigUint::from_bytes_be(&DH_PRIME);
    let g_b = BigUint::from_bytes_be(&g_b);
    let safety_range = BigUint::ONE << (2048 - 64);
    check_g_in_range(&g_b, &safety_range, &(&dh_prime - &safety_range))?;

    let auth_key = {
        let mut buffer = [0; 256];
        let gab = g_b.modpow(&dh_gen.a, &dh_prime);
        let gab_bytes = gab.to_bytes_be();
        let skip = buffer.len() - gab_bytes.len(); // gab might need less than 256 bytes
        buffer[skip..].copy_from_slice(&gab_bytes);
        AuthKey::from_bytes(buffer)
    };

    let nonce_number = 1;
    let new_nonce_hash = auth_key.calc_new_nonce_hash(&dh_gen.new_nonce, nonce_number);

    Ok((
        tl::enums::SetClientDhParamsAnswer::DhGenOk(tl::types::DhGenOk {
            nonce,
            server_nonce,
            new_nonce_hash1: new_nonce_hash,
        }),
        auth_key,
    ))
}

fn generate_nonce() -> [u8; 16] {
    let mut rnd = [0; 16];
    getrandom::fill(&mut rnd).expect("failed to generate a secure padding");
    rnd
}

fn generate_pq() -> ([u8; 8], u32, u32) {
    use num_prime::RandPrime;

    let mut rng = rand::thread_rng();

    let p: u32 = rng.gen_prime(31, None);
    let q: u32 = rng.gen_prime(31, None);

    let pq = p as u64 * q as u64;

    (pq.to_be_bytes(), p, q)
}

/// Helper function to avoid the boilerplate of checking for invalid nonce.
fn check_nonce(got: &[u8; 16], expected: &[u8; 16]) -> Result<(), Error> {
    if got == expected {
        Ok(())
    } else {
        Err(Error::InvalidNonce {
            got: *got,
            expected: *expected,
        })
    }
}

/// Helper function to avoid the boilerplate of checking for invalid
/// server nonce.
fn check_server_nonce(got: &[u8; 16], expected: &[u8; 16]) -> Result<(), Error> {
    if got == expected {
        Ok(())
    } else {
        Err(Error::InvalidServerNonce {
            got: *got,
            expected: *expected,
        })
    }
}

/// Helper function to avoid the boilerplate of checking for invalid
/// p and q.
fn check_pq(got_p: u32, got_q: u32, expected_p: u32, expected_q: u32) -> Result<(), Error> {
    if (got_p == expected_p && got_q == expected_q) || (got_p == expected_q && got_q == expected_p)
    {
        Ok(())
    } else {
        Err(Error::InvalidPq {
            p: got_p.to_be_bytes().to_vec(),
            q: got_q.to_be_bytes().to_vec(),
        })
    }
}

/// Helper function to avoid the boilerplate of checking for `g` not being
/// inside a valid range.
fn check_g_in_range(value: &BigUint, low: &BigUint, high: &BigUint) -> Result<(), Error> {
    if low < value && value < high {
        Ok(())
    } else {
        Err(Error::GParameterOutOfRange {
            value: value.clone(),
            low: low.clone(),
            high: high.clone(),
        })
    }
}

/// Find the RSA key's `(n, e)` pair for a certain fingerprint.
fn key_for_fingerprint(fingerprint: i64) -> Option<rsa::PrivateKey> {
    Some(match fingerprint {
        val if val == FINGERPRINTS[0] => {
            rsa::PrivateKey::from_pem(PRIVATE_PEM).expect("server private key needed")
        }
        _ => return None,
    })
}
