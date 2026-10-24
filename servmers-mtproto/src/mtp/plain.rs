use grammers_tl_types::{Cursor, Deserializable, Serializable};
use servmers_crypto::DequeBuffer;

use super::{ClientMessages, Error, Message};
use crate::MsgId;

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
pub struct Plain;

impl Plain {
    /// Validates that the returned data is a correct plain message, and
    /// if it is, the method returns the inner contents of the message.
    pub fn deserialize(payload: &mut [u8]) -> Result<ClientMessages, Error> {
        crate::utils::check_message_buffer(payload)?;

        let mut buf = Cursor::from_slice(payload);

        let msg_id = i64::deserialize(&mut buf)?;
        // We can't validate it's close to our system time because our sytem
        // time may be wrong at this point (it only matters once encrypted
        // communication begins). However, we can validate the following:
        //
        // > Client message identifiers are divisible by 4
        // https://core.telegram.org/mtproto/description#message-identifier-msg-id
        if (msg_id % 4) != 0 {
            return Err(Error::BadMessageId { got: msg_id });
        }

        let len = i32::deserialize(&mut buf)?;
        if len <= 0 {
            return Err(Error::NegativeMessageLength { got: len });
        }
        if (20 + len) as usize > payload.len() {
            return Err(Error::TooLongMessageLength {
                got: len as usize,
                max_length: payload.len() - 20,
            });
        }

        Ok(ClientMessages::Plain(Message {
            msg_id: MsgId(msg_id),
            body: payload[20..20 + len as usize].into(),
        }))
    }

    /// Wraps a response's data into a plain message (also known as
    /// [unencrypted messages]), and returns its serialized contents.
    ///
    /// Plain messages may be used for requests that don't require an
    /// Authorization Key to be present, such as those needed to generate
    /// the Authorization Key itself.
    ///
    /// [unencrypted messages]: https://core.telegram.org/mtproto/description#unencrypted-message
    pub fn push(buffer: &mut DequeBuffer<u8>, response: &[u8]) -> Option<MsgId> {
        if !buffer.is_empty() {
            return None;
        }

        0i64.serialize(buffer); // auth_key_id = 0
        1i64.serialize(buffer); // msg_id

        (response.len() as i32).serialize(buffer); // message_data_length
        buffer.extend(response); // message_data

        Some(MsgId(1))
    }

    pub fn finalize(buffer: &mut DequeBuffer<u8>) -> Option<MsgId> {
        (!buffer.is_empty()).then_some(MsgId(1))
    }
}
