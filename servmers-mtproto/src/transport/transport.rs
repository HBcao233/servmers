use grammers_mtproto::transport::{Abridged, Full, Intermediate, Transport as _};
pub use grammers_mtproto::transport::{Error, UnpackedOffset};
use servmers_crypto::{DequeBuffer, ObfuscatedCipher};

/// The enum of supported transports.
pub enum Transport {
    Abridged(Abridged),
    Intermediate(Intermediate),
    Full(Full),
    Obfuscated {
        cipher: Box<ObfuscatedCipher>,
        inner: Box<Transport>,
        decrypted: usize,
    },
}

impl Transport {
    /// Unpacks the input buffer in-place.
    ///
    /// Subsequent calls to `unpack` should be made with the same buffer,
    /// with the data on the ranges from previous `UnpackedOffset` removed.
    /// Failing to do so will cause transports such as [`Obfuscated`] to misbehave.
    pub fn unpack(&mut self, buffer: &mut [u8]) -> Result<UnpackedOffset, Error> {
        match self {
            Self::Abridged(t) => t.unpack(buffer),
            Self::Intermediate(t) => t.unpack(buffer),
            Self::Full(t) => t.unpack(buffer),
            Self::Obfuscated {
                cipher,
                inner,
                decrypted,
            } => {
                assert!(
                    buffer.len() >= *decrypted,
                    "buffer is smaller than what was decrypted"
                );

                cipher.decrypt(&mut buffer[*decrypted..]);
                *decrypted = buffer.len();

                match inner.unpack(buffer) {
                    Ok(offset) => {
                        *decrypted -= offset.next_offset;
                        Ok(offset)
                    }
                    Err(e) => Err(e),
                }
            }
        }
    }

    /// Packs the input buffer in-place.
    ///
    /// Panics if `buffer.len()` is not divisible by 4.
    pub fn pack(&mut self, buffer: &mut DequeBuffer<u8>) {
        match self {
            Self::Abridged(t) => t.pack(buffer),
            Self::Intermediate(t) => t.pack(buffer),
            Self::Full(t) => t.pack(buffer),
            Self::Obfuscated {
                cipher,
                inner,
                decrypted: _,
            } => {
                inner.pack(buffer);
                cipher.encrypt(buffer.as_mut());
            }
        }
    }
}
