use std::mem;
use std::time::{SystemTime, UNIX_EPOCH};

use grammers_tl_types::{self as tl, Identifiable, Serializable};
use servmers_crypto::{DequeBuffer, encrypt_data_v2};

use super::{MESSAGE_CONTAINER_HEADER_LEN, Mtp, Outbound, PLAIN_PACKET_HEADER_LEN, Plain};
use crate::utils::StackBuffer;
use crate::{MsgId, manual_tl};

impl Mtp {
    pub fn push(&mut self, buffer: &mut DequeBuffer<u8>, outbound: Outbound) -> Option<MsgId> {
        let content_related = outbound.content_related();
        let response = outbound.to_bytes();

        if self.auth_key.is_some() {
            // TODO rather than taking in bytes, take requests, serialize them in place, and if too large drop the last part of the buffer

            // If we need to acknowledge messages, this notification goes in with the rest of requests
            // so that we can also include it. It has priority over user requests because these should
            // be sent out as soon as possible.
            if !self.pending_ack.is_empty() {
                // TODO avoid to_bytes here, serialize it in-place
                let body = tl::enums::MsgsAck::Ack(tl::types::MsgsAck {
                    msg_ids: mem::take(&mut self.pending_ack),
                })
                .to_bytes();
                self.serialize_msg(buffer, &body, false);
            }

            // Serialize `MAXIMUM_LENGTH` requests at most.
            if self.msg_count == manual_tl::MessageContainer::MAXIMUM_LENGTH {
                return None;
            }

            // Requests that are too large would cause Telegram to close the
            // connection but are so uncommon it's not worth returning `Err`.
            assert!(
                response.len() + manual_tl::Message::SIZE_OVERHEAD
                    <= manual_tl::MessageContainer::MAXIMUM_SIZE
            );

            // Serialized requests will always be correctly padded.
            assert!(response.len().is_multiple_of(4));

            // Payload provided by the user is always considered to be
            // content-related, which means we can apply compression.
            let mut body = &response;
            let compressed;
            if let Some(threshold) = self.compression_threshold
                && response.len() >= threshold
            {
                compressed = manual_tl::GzipPacked::new(&response).to_bytes();
                if compressed.len() < response.len() {
                    body = &compressed;
                }
            }

            let new_size = buffer.len() + body.len() + manual_tl::Message::SIZE_OVERHEAD;
            if new_size >= manual_tl::MessageContainer::MAXIMUM_SIZE {
                // No more messages fit in this container.
                return None;
            }

            // This request still fits in the container, so give it a message ID.
            Some(self.serialize_msg(buffer, body, content_related))
        } else {
            Plain::push(buffer, &response)
        }
    }

    pub fn finalize(&mut self, buffer: &mut DequeBuffer<u8>) -> Option<MsgId> {
        if self.auth_key.is_some() {
            self.finalize_plain(buffer);
            if buffer.is_empty() {
                None
            } else {
                encrypt_data_v2(buffer, self.auth_key.as_ref().unwrap());
                Some(MsgId(self.last_msg_id as i64))
            }
        } else {
            Plain::finalize(buffer)
        }
    }
}

impl Mtp {
    pub fn get_new_msg_id(&mut self, content_related: bool) -> i64 {
        // server message identifiers modulo 4 yield 1 if the message is a response to a client message, and 3 otherwise.
        let flag = if content_related { 3 } else { 1 };

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time is before epoch");

        let seconds = now.as_secs();
        let nanoseconds = now.subsec_nanos() as u64;
        let mut new_base = (seconds << 32) | (nanoseconds << 2);

        let last_base = self.last_msg_id & !3;
        if last_base >= new_base {
            new_base = last_base + 4;
        }

        let new_msg_id = new_base + flag;
        self.last_msg_id = new_msg_id;
        new_msg_id as i64
    }

    /// Generates the next sequence number depending on whether
    /// it should be for a content-related query or not.
    fn get_seq_no(&mut self, content_related: bool) -> i32 {
        if content_related {
            self.sequence += 2;
            self.sequence - 1
        } else {
            self.sequence
        }
    }

    fn serialize_msg(
        &mut self,
        buffer: &mut DequeBuffer<u8>,
        body: &[u8],
        content_related: bool,
    ) -> MsgId {
        let msg_id = self.get_new_msg_id(false);
        msg_id.serialize(buffer);

        self.get_seq_no(content_related).serialize(buffer);
        (body.len() as i32).serialize(buffer);
        buffer.extend(body);

        self.msg_count += 1;
        MsgId(msg_id)
    }

    fn get_current_salt(&self) -> i64 {
        // TODO: changed every 30 minutes
        // old salt are still accepted for a further 1800 seconds
        0
    }

    /// `finalize`, but without encryption.
    ///
    /// The buffer is *not* cleared, but is instead returned.
    fn finalize_plain(&mut self, buffer: &mut DequeBuffer<u8>) {
        if self.msg_count == 0 {
            return;
        }

        if self.msg_count != 1 {
            // Prepend a container, setting its message ID and sequence number.
            // + 8 because it has to include the constructor ID and length (4 bytes each).
            let len = (buffer.len() + 8) as i32;
            let mut header = StackBuffer::<MESSAGE_CONTAINER_HEADER_LEN>::new();

            // Manually `serialize_msg` because the container body was already written.
            let msg_id = self.get_new_msg_id(false);
            msg_id.serialize(&mut header);

            self.get_seq_no(false).serialize(&mut header);

            len.serialize(&mut header);

            manual_tl::MessageContainer::CONSTRUCTOR_ID.serialize(&mut header);
            (self.msg_count as i32).serialize(&mut header);
            buffer.extend_front(&header.into_inner());
        }

        {
            // Prepend the message header
            let mut header = StackBuffer::<PLAIN_PACKET_HEADER_LEN>::new();
            self.get_current_salt().serialize(&mut header); // 8 bytes

            self.session_id.serialize(&mut header); // 8 bytes
            buffer.extend_front(&header.into_inner());
        }

        self.msg_count = 0;
    }
}
