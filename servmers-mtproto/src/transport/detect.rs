use grammers_mtproto::transport::{Abridged, Full, Intermediate};
use servmers_crypto::ObfuscatedCipher;

use super::Transport;

const ABRIDGED_TAG: [u8; 4] = [0xef, 0xef, 0xef, 0xef];
const INTERMEDIATE_TAG: [u8; 4] = [0xee, 0xee, 0xee, 0xee];
const PADDED_INTERMEDIATE_TAG: [u8; 4] = [0xdd, 0xdd, 0xdd, 0xdd];

/// The maximum data that we're willing to send or receive at once.
///
/// By having a fixed-size buffer, we can avoid unnecessary allocations
/// and trivially prevent allocating more than this limit if we ever
/// received invalid data.
///
/// Telegram will close the connection with roughly a megabyte of data,
/// so to account for the transports' own overhead, we add a few extra
/// kilobytes to the maximum data size.
const MAX_PACKET_LEN: i32 = (1024 * 1024) + (8 * 1024);

const FORBIDDEN_FIRST_INTS: [&[u8; 4]; 5] = [
    b"HEAD",                   // HTTP HEAD
    b"POST",                   // HTTP POST
    b"GET ",                   // HTTP GET
    b"OPTI",                   // HTTP OPTIONS
    &[0x16, 0x03, 0x01, 0x02], // TLS handshake
];

/// The error of [`detect`].
pub enum DetectError {
    NeedMore(usize),
    Unsupported,
}

/// The result of [`detect`].
pub struct Detected {
    /// The result Transport.
    pub transport: Transport,
    /// Need to skip bytes before unpack.
    pub preamble: usize,
}

/// Detect transport from inbound bytes.
pub fn detect(buf: &[u8]) -> Result<Detected, DetectError> {
    // 1. Abridged: 1 byte tag
    if let Some(&b) = buf.first() {
        if b == ABRIDGED_TAG[0] {
            return Ok(Detected {
                transport: Transport::Abridged(Abridged::new()),
                preamble: 1,
            });
        }
    } else {
        return Err(DetectError::NeedMore(1));
    }

    // 2. Intermediate / Padded intermediate: 4 bytes tag
    if buf.len() < 4 {
        return Err(DetectError::NeedMore(4));
    }
    if buf[..4] == INTERMEDIATE_TAG {
        return Ok(Detected {
            transport: Transport::Intermediate(Intermediate::new()),
            preamble: 4,
        });
    }
    if buf[..4] == PADDED_INTERMEDIATE_TAG {
        return Err(DetectError::Unsupported);
    }

    // 3. Full: seq == 0
    if buf.len() >= 8 {
        let len = i32::from_le_bytes(buf[0..4].try_into().unwrap());
        let seq = i32::from_le_bytes(buf[4..8].try_into().unwrap());
        if (12..=MAX_PACKET_LEN).contains(&len) && len % 4 == 0 && seq == 0 {
            return Ok(Detected {
                transport: Transport::Full(Full::new()),
                preamble: 0,
            });
        }
    } else {
        return Err(DetectError::NeedMore(8));
    }

    // 4. Obfuscated
    for http in FORBIDDEN_FIRST_INTS {
        if buf.starts_with(http) {
            return Err(DetectError::Unsupported);
        }
    }
    if buf.len() < 64 {
        return Err(DetectError::NeedMore(64));
    }

    let mut header: [u8; 64] = buf[..64].try_into().unwrap();
    let mut cipher = ObfuscatedCipher::new(&header);
    cipher.decrypt(&mut header);

    let inner_tag: [u8; 4] = buf[56..60].try_into().unwrap();
    let inner = match inner_tag {
        INTERMEDIATE_TAG => Transport::Intermediate(Intermediate::new()),
        ABRIDGED_TAG => Transport::Abridged(Abridged::new()),
        PADDED_INTERMEDIATE_TAG => return Err(DetectError::Unsupported),
        _ => return Err(DetectError::Unsupported),
    };

    Ok(Detected {
        transport: Transport::Obfuscated {
            cipher: Box::new(cipher),
            inner: Box::new(inner),
            decrypted: 0,
        },
        preamble: 64,
    })
}
