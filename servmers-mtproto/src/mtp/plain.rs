use grammers_tl_types::{Cursor, Deserializable, Serializable};
use servmers_crypto::DequeBuffer;

use super::{ClientRequest, DeserializeError};
use crate::MsgId;
use crate::utils::MsgIdGenerator;

/// An implementation of the [Mobile Transport Protocol] for plaintext
/// (unencrypted) messages.
///
/// The reason to separate the plaintext and encrypted implementations
/// for serializing messages is that, even though they are similar, the
/// benefits outweight some minor code reuse.
///
/// This way, the encryption key for [`Mtp`] is mandatory so errors
/// for trying to encrypt data without a key are completely eliminated.
///
/// Also, the plaintext part of the protocol does not need to deal with
/// the complexity of the full protocol once encrypted messages are used,
/// so being able to keep a simpler implementation separate is a bonus.
///
/// [Mobile Transport Protocol]: https://core.telegram.org/mtproto
pub struct Plain {
    msg_id_generator: MsgIdGenerator,
}

impl Plain {
    /// Creates a new instance of the plain (unencrypted) MTP.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            msg_id_generator: MsgIdGenerator::new(),
        }
    }
}

impl Plain {
    /// Validates that the returned data is a correct plain message, and
    /// if it is, the method returns the inner contents of the message.
    pub(super) fn deserialize(
        &mut self,
        payload: &mut [u8],
    ) -> Result<Vec<ClientRequest>, DeserializeError> {
        crate::utils::check_message_buffer(payload)?;

        let mut buf = Cursor::from_slice(payload);
        let auth_key_id = i64::deserialize(&mut buf)?;
        if auth_key_id != 0 {
            return Err(DeserializeError::BadAuthKey {
                got: auth_key_id,
                expected: 0,
            });
        }

        let msg_id = i64::deserialize(&mut buf)?;
        // We can't validate it's close to our system time because our sytem
        // time may be wrong at this point (it only matters once encrypted
        // communication begins). However, we can validate the following:
        //
        // > Client message identifiers are divisible by 4
        // https://core.telegram.org/mtproto/description#message-identifier-msg-id
        if msg_id < 0 || (msg_id % 4) != 0 {
            return Err(DeserializeError::BadMessageId { got: msg_id });
        }

        let len = i32::deserialize(&mut buf)?;
        if len <= 0 {
            return Err(DeserializeError::NegativeMessageLength { got: len });
        }
        if (20 + len) as usize > payload.len() {
            return Err(DeserializeError::TooLongMessageLength {
                got: len as usize,
                max_length: payload.len() - 20,
            });
        }

        Ok(vec![ClientRequest {
            msg_id: MsgId(msg_id),
            body: payload[20..20 + len as usize].into(),
        }])
    }

    /// Wraps a response's data into a plain message (also known as
    /// [unencrypted messages]), and returns its serialized contents.
    ///
    /// Plain messages may be used for requests that don't require an
    /// Authorization Key to be present, such as those needed to generate
    /// the Authorization Key itself.
    ///
    /// [unencrypted messages]: https://core.telegram.org/mtproto/description#unencrypted-message
    pub(super) fn push(&mut self, buffer: &mut DequeBuffer<u8>, response: &[u8]) -> Option<MsgId> {
        if !buffer.is_empty() {
            return None;
        }

        0i64.serialize(buffer); // auth_key_id = 0

        let msg_id = self.msg_id_generator.get_new_msg_id(false);
        msg_id.serialize(buffer);

        (response.len() as i32).serialize(buffer); // message_data_length
        buffer.extend(response); // message_data

        Some(MsgId(msg_id))
    }

    pub(super) fn finalize(&mut self, buffer: &mut DequeBuffer<u8>) -> Option<MsgId> {
        (!buffer.is_empty()).then_some(MsgId(self.msg_id_generator.last_msg_id as i64))
    }
}
