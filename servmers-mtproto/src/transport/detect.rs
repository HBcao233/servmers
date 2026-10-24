use servmers_crypto::ObfuscatedCipher;

use super::{Abridged, Full, Intermediate, IntoSplit, Obfuscated, Packer, Unpacker};

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
    pub packer: Box<dyn Packer>,
    pub unpacker: Box<dyn Unpacker>,
    /// Need to skip bytes before unpack.
    pub preamble: usize,
}

/// Detect transport from inbound bytes.
pub fn detect(buf: &[u8]) -> Result<Detected, DetectError> {
    // 1. Abridged: 1 byte tag
    if let Some(&b) = buf.first() {
        if b == ABRIDGED_TAG[0] {
            let (packer, unpacker) = Abridged::new().into_split();
            return Ok(Detected {
                packer: Box::new(packer),
                unpacker: Box::new(unpacker),
                preamble: 1,
            });
        }
    } else {
        return Err(DetectError::NeedMore(1));
    }

    // 2. Intermediate: 4 bytes tag
    if buf.len() < 4 {
        return Err(DetectError::NeedMore(4));
    }
    if buf[..4] == INTERMEDIATE_TAG {
        let (packer, unpacker) = Intermediate::new().into_split();
        return Ok(Detected {
            packer: Box::new(packer),
            unpacker: Box::new(unpacker),
            preamble: 4,
        });
    }

    // 3. Padded intermediate
    if buf[..4] == PADDED_INTERMEDIATE_TAG {
        return Err(DetectError::Unsupported);
    }

    // 4. Full: seq == 0 and len is suitable
    if buf.len() >= 8 {
        if buf[4..8] == [0; 4] {
            let len = i32::from_le_bytes(buf[0..4].try_into().unwrap());
            return if (12..=MAX_PACKET_LEN).contains(&len) && len % 4 == 0 {
                let (packer, unpacker) = Full::new().into_split();
                Ok(Detected {
                    packer: Box::new(packer),
                    unpacker: Box::new(unpacker),
                    preamble: 0,
                })
            } else {
                Err(DetectError::Unsupported)
            };
        }
    } else {
        return Err(DetectError::NeedMore(8));
    }

    // 5. Obfuscated
    for http in FORBIDDEN_FIRST_INTS {
        if buf.starts_with(http) {
            return Err(DetectError::Unsupported);
        }
    }
    if buf.len() < 64 {
        return Err(DetectError::NeedMore(64));
    }

    let mut header: [u8; 64] = buf[..64].try_into().unwrap();
    let mut cipher = ObfuscatedCipher::new_server(&header);
    cipher.decrypt(&mut header);

    let inner_tag: [u8; 4] = header[56..60].try_into().unwrap();
    let (packer, unpacker): (Box<dyn Packer>, Box<dyn Unpacker>) = match inner_tag {
        INTERMEDIATE_TAG => {
            let (packer, unpacker) = Obfuscated::new(Intermediate::new(), cipher).into_split();
            (Box::new(packer), Box::new(unpacker))
        }
        ABRIDGED_TAG => {
            let (packer, unpacker) = Obfuscated::new(Abridged::new(), cipher).into_split();
            (Box::new(packer), Box::new(unpacker))
        }
        PADDED_INTERMEDIATE_TAG => return Err(DetectError::Unsupported),
        _ => return Err(DetectError::Unsupported),
    };

    Ok(Detected {
        packer,
        unpacker,
        preamble: 64,
    })
}
