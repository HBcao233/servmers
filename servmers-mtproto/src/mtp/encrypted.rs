use std::mem;

pub use grammers_mtproto::mtp::{
    ENCRYPTED_PACKET_HEADER_LEN, MAX_TRANSPORT_HEADER_LEN, MESSAGE_CONTAINER_HEADER_LEN,
    PLAIN_PACKET_HEADER_LEN,
};
use grammers_tl_types::{self as tl, Cursor, Deserializable, Identifiable};
use servmers_crypto::{AuthKey, decrypt_data_v2};

use super::{ClientMessage, DecryptedMessages, Error};
// use crate::utils::StackBuffer;
use crate::{MsgId, manual_tl};

/// An implementation of the [Mobile Transport Protocol] for ciphertext
/// (encrypted) messages.
///
/// [Mobile Transport Protocol]: https://core.telegram.org/mtproto
pub struct Encrypted<'a> {
    /// The Authorization Key used for encryption and decryption.
    auth_key: &'a AuthKey,

    /// The current message sequence number.
    sequence: i32,

    /// Identifiers that need to be acknowledged to the server.
    ///
    /// A [Content-related Message] is "a message requiring an explicit
    /// acknowledgment. These include all the user and many service messages,
    /// virtually all with the exception of containers and acknowledgments."
    ///
    /// [Content-related Message]: https://core.telegram.org/mtproto/description#content-related-message
    pending_ack: Vec<i64>,

    /// If present, the threshold in bytes at which a message will be
    /// considered large enough to attempt compressing it. Otherwise,
    /// outgoing messages will never be compressed.
    compression_threshold: Option<usize>,

    /// Temporary deserialization results.
    deserialization: Vec<ClientMessage>,

    /// How many messages are there in the buffer.
    msg_count: usize,
}

impl<'a> Encrypted<'a> {
    pub fn new(auth_key: &'a AuthKey) -> Self {
        Self {
            auth_key,
            sequence: 0,
            pending_ack: Vec::new(),
            compression_threshold: crate::DEFAULT_COMPRESSION_THRESHOLD,
            deserialization: Vec::new(),
            msg_count: 0,
        }
    }

    /*
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
        let msg_id = self.msg_id_generator.get_new_msg_id(false);

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
            let msg_id = self.msg_id_generator.get_new_msg_id(false);
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
    */

    fn process_message(&mut self, message: manual_tl::Message) -> Result<(), Error> {
        if message.requires_ack() {
            self.pending_ack.push(message.msg_id);
        }

        // Handle all the possible Service Messages:
        // * https://core.telegram.org/mtproto/service_messages
        // * https://core.telegram.org/mtproto/service_messages_about_messages
        //
        // The order of the `match` here is the same as the order in which the
        // items appear in the documentation (to make it easier to review).
        // TODO verify what needs ack and what doesn't
        let id = message.constructor_id()?;
        match id {
            // Types only send from server to client
            manual_tl::RpcResult::CONSTRUCTOR_ID
            | tl::types::FutureSalt::CONSTRUCTOR_ID
            | tl::types::FutureSalts::CONSTRUCTOR_ID
            | tl::types::Pong::CONSTRUCTOR_ID
            | tl::types::DestroySessionOk::CONSTRUCTOR_ID
            | tl::types::DestroySessionNone::CONSTRUCTOR_ID
            | tl::types::NewSessionCreated::CONSTRUCTOR_ID
            | tl::types::BadMsgNotification::CONSTRUCTOR_ID
            | tl::types::BadServerSalt::CONSTRUCTOR_ID => Err(Error::UnexpectedConstructor { id }),

            // Service Messages about Messages
            // Acknowledgment of Receipt
            tl::types::MsgsAck::CONSTRUCTOR_ID => self.handle_ack(message),

            // Request for Message Status Information
            tl::types::MsgsStateReq::CONSTRUCTOR_ID => self.handle_state_req(message),
            // Informational Message regarding Status of Messages
            tl::types::MsgsStateInfo::CONSTRUCTOR_ID => self.handle_state_info(message),
            // Voluntary Communication of Status of Messages
            tl::types::MsgsAllInfo::CONSTRUCTOR_ID => self.handle_msg_all(message),
            // Extended Voluntary Communication of Status of One Message
            tl::types::MsgDetailedInfo::CONSTRUCTOR_ID
            | tl::types::MsgNewDetailedInfo::CONSTRUCTOR_ID => self.handle_detailed_info(message),
            // Explicit Request to Re-Send Messages & Explicit Request to Re-Send Answers
            tl::types::MsgResendReq::CONSTRUCTOR_ID
            | tl::types::MsgResendAnsReq::CONSTRUCTOR_ID => self.handle_msg_resend(message),

            // Containers (Simple Container)
            manual_tl::MessageContainer::CONSTRUCTOR_ID => self.handle_container(message),
            // Message Copies
            manual_tl::MessageCopy::CONSTRUCTOR_ID => self.handle_msg_copy(message),
            // Packed Object
            manual_tl::GzipPacked::CONSTRUCTOR_ID => self.handle_gzip_packed(message),
            // HTTP Wait/Long Poll
            tl::types::HttpWait::CONSTRUCTOR_ID => self.handle_http_wait(message),
            _ => self.handle_request(message),
        }
    }

    /// [Acknowledgment of Receipt]: https://core.telegram.org/mtproto/service_messages_about_messages#acknowledgment-of-receipt
    fn handle_ack(&self, message: manual_tl::Message) -> Result<(), Error> {
        // TODO notify about this somehow
        let _ack = tl::enums::MsgsAck::from_bytes(&message.body)?;
        Ok(())
    }

    /// **[Request for Message Status Information]**
    ///
    /// If either party has not received information on the status of its
    /// outgoing messages for a while, it may explicitly request it from the
    /// other party:
    ///
    /// ```tl
    /// msgs_state_req#da69fb52 msg_ids:Vector long = MsgsStateReq;
    /// ```
    ///
    /// [Request for Message Status Information]: https://core.telegram.org/mtproto/service_messages_about_messages#request-for-message-status-information
    fn handle_state_req(&self, _message: manual_tl::Message) -> Result<(), Error> {
        // TODO implement
        Ok(())
    }

    /// **[Informational Message regarding Status of Messages]**
    ///
    /// ```tl
    /// msgs_state_info#04deb57d req_msg_id:long info:string = MsgsStateInfo;
    /// ```
    ///
    /// Here, `info` is a string that contains exactly one byte of message
    /// status for each message from the incoming `msg_ids` list:
    ///
    /// * 1 = nothing is known about the message (`msg_id` too low, the other
    ///   party may have forgotten it)
    /// * 2 = message not received (`msg_id` falls within the range of stored
    ///   identifiers; however, the other party has certainly not received a
    ///   message like that)
    /// * 3 = message not received (`msg_id` too high; however, the other
    ///   party has certainly not received it yet)
    /// * 4 = message received (note that this response is also at the same
    ///   time a receipt acknowledgment)
    /// * +8 = message already acknowledged
    /// * +16 = message not requiring acknowledgment
    /// * +32 = RPC query contained in message being processed or processing
    ///   already complete
    /// * +64 = content-related response to message already generated
    /// * +128 = other party knows for a fact that message is already received
    ///
    /// This response does not require an acknowledgment. It is an
    /// acknowledgment of the relevant `msgs_state_req`, in and of itself.
    ///
    /// Note that if it turns out suddenly that the other party does not have
    /// a message that looks like it has been sent to it, the message can
    /// simply be re-sent. Even if the other party should receive two copies
    /// of the message at the same time, the duplicate will be ignored.
    /// (If too much time has passed, and the original `msg_id` is not longer
    /// valid, the message is to be wrapped in `msg_copy`).
    ///
    /// [Informational Message regarding Status of Messages]: https://core.telegram.org/mtproto/service_messages_about_messages#informational-message-regarding-status-of-messages
    fn handle_state_info(&mut self, _message: manual_tl::Message) -> Result<(), Error> {
        // TODO implement
        Ok(())
    }

    /// **[Voluntary Communication of Status of Messages]**
    ///
    /// Either party may voluntarily inform the other party of the status of
    /// the messages transmitted by the other party.
    ///
    /// ```tl
    /// msgs_all_info#8cc0d131 msg_ids:Vector long info:string = MsgsAllInfo;
    /// ```
    ///
    /// All message codes known to this party are enumerated, with the
    /// exception of those for which the +128 and the +16 flags are set.
    /// However, if the +32 flag is set but not +64, then the message status
    /// will still be communicated.
    ///
    /// This message does not require an acknowledgment.
    ///
    /// [Voluntary Communication of Status of Messages]: https://core.telegram.org/mtproto/service_messages_about_messages#voluntary-communication-of-status-of-messages
    fn handle_msg_all(&mut self, _message: manual_tl::Message) -> Result<(), Error> {
        // TODO implement
        Ok(())
    }

    /// **[Extended Voluntary Communication of Status of One Message]**
    ///
    /// Normally used by the server to respond to the receipt of a duplicate
    /// `msg_id`, especially if a response to the message has already been
    /// generated and the response is large. If the response is small, the
    /// server may re-send the answer itself instead. This message can also
    /// be used as a notification instead of resending a large message.
    ///
    /// ```tl
    /// msg_detailed_info#276d3ec6 msg_id:long answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
    /// msg_new_detailed_info#809db6df answer_msg_id:long bytes:int status:int = MsgDetailedInfo;
    /// ```
    ///
    /// The second version is used to notify of messages that were created on
    /// the server not in response to an RPC query (such as notifications of
    /// new messages) and were transmitted to the client some time ago, but
    /// not acknowledged.
    ///
    /// Currently, `status` is always zero. This may change in future.
    ///
    /// This message does not require an acknowledgment.
    ///
    /// [Extended Voluntary Communication of Status of One Message]: https://core.telegram.org/mtproto/service_messages_about_messages#extended-voluntary-communication-of-status-of-one-message
    fn handle_detailed_info(&mut self, message: manual_tl::Message) -> Result<(), Error> {
        // TODO https://github.com/telegramdesktop/tdesktop/blob/8f82880b938e06b7a2a27685ef9301edb12b4648/Telegram/SourceFiles/mtproto/connection.cpp#L1790-L1820
        // TODO https://github.com/telegramdesktop/tdesktop/blob/8f82880b938e06b7a2a27685ef9301edb12b4648/Telegram/SourceFiles/mtproto/connection.cpp#L1822-L1845
        let msg_detailed = tl::enums::MsgDetailedInfo::from_bytes(&message.body)?;
        match msg_detailed {
            tl::enums::MsgDetailedInfo::Info(x) => {
                self.pending_ack.push(x.answer_msg_id);
            }
            tl::enums::MsgDetailedInfo::MsgNewDetailedInfo(x) => {
                self.pending_ack.push(x.answer_msg_id);
            }
        }
        Ok(())
    }

    /// **[Explicit Request to Re-Send Messages]**
    ///
    /// ```tl
    /// msg_resend_req#7d861a08 msg_ids:Vector long = MsgResendReq;
    /// ```
    ///
    /// The remote party immediately responds by re-sending the requested
    /// messages, normally using the same connection that was used to transmit
    /// the query. If at least one message with requested msg_id does not
    /// exist or has already been forgotten, or has been sent by the
    /// requesting party (known from parity), `MsgsStateInfo` is returned for
    /// all messages requested as if the `MsgResendReq` query had been a
    /// `MsgsStateReq` query as well.
    ///
    /// **[Explicit Request to Re-Send Answers]**
    ///
    /// ```tl
    /// msg_resend_ans_req#8610baeb msg_ids:Vector long = MsgResendReq;
    /// ```
    ///
    /// The remote party immediately responds by re-sending answers to the
    /// requested messages, normally using the same connection that was used
    /// to transmit the query. `MsgsStateInfo` is returned for all messages
    /// requested as if the `MsgResendReq` query had been a MsgsStateReq query
    /// as well.
    ///
    /// [Explicit Request to Re-Send Answers]: https://core.telegram.org/mtproto/service_messages_about_messages#explicit-request-to-re-send-answers
    /// [Explicit Request to Re-Send Messages]: https://core.telegram.org/mtproto/service_messages_about_messages#explicit-request-to-re-send-messages
    fn handle_msg_resend(&self, _message: manual_tl::Message) -> Result<(), Error> {
        // TODO implement
        // `msg_resend_ans_req` seems to never occur (it was even missing from `mtproto.tl`)
        Ok(())
    }

    /// **[Containers]**
    ///
    /// *Containers* are messages containing several other messages. Used
    /// for the ability to transmit several RPC queries and/or service
    /// messages at the same time, using HTTP or even TCP or UDP protocol.
    /// A container may only be accepted or rejected by the other party as
    /// a whole.
    ///
    /// **[Simple Container]**
    ///
    /// A simple container carries several messages as follows:
    ///
    /// ```tl
    /// msg_container#73f1f8dc messages:vector message = MessageContainer;
    /// ```
    ///
    /// Here message refers to any message together with its length and
    /// `msg_id`:
    ///
    /// ```tl
    /// message msg_id:long seqno:int bytes:int body:Object = Message;
    /// ```
    ///
    /// `bytes` is the number of bytes in the body serialization.
    ///
    /// All messages in a container must have `msg_id` lower than that of the
    /// container itself. A container does not require an acknowledgment and
    /// may not carry other simple containers. When messages are re-sent,
    /// they may be combined into a container in a different manner or sent
    /// individually.
    ///
    /// Empty containers are also allowed. They are used by the server,
    /// for example, to respond to an HTTP request when the timeout specified
    /// in `http_wait` expires, and there are no messages to transmit.
    ///
    /// [Containers]: https://core.telegram.org/mtproto/service_messages#containers
    /// [Simple Container]: https://core.telegram.org/mtproto/service_messages#simple-container
    fn handle_container(&mut self, message: manual_tl::Message) -> Result<(), Error> {
        let container = manual_tl::MessageContainer::from_bytes(&message.body)?;
        for inner_message in container.messages {
            self.process_message(inner_message)?;
        }

        Ok(())
    }

    /// **[Message Copies]**
    ///
    /// In some situations, an old message with a `msg_id` that is no longer
    /// valid needs to be re-sent. Then, it is wrapped in a copy container:
    ///
    /// ```tl
    /// msg_copy#e06046b2 orig_message:Message = MessageCopy;
    /// ```
    ///
    /// Once received, the message is processed as if the wrapper were not
    /// there. However, if it is known for certain that the message
    /// `orig_message.msg_id` was received, then the new message is not
    /// processed (while at the same time, it and `orig_message.msg_id`
    /// are acknowledged). The value of `orig_message.msg_id` must be lower
    /// than the container's `msg_id`.
    ///
    /// This is not used at this time, because an old message can be wrapped
    /// in a simple container with the same result.
    ///
    /// [Message Copies]: https://core.telegram.org/mtproto/service_messages#message-copies
    fn handle_msg_copy(&self, _message: manual_tl::Message) -> Result<(), Error> {
        panic!("msg_copy should not be used")
    }

    /// **[Packed Object]**
    ///
    /// Used to replace any other object (or rather, a serialization thereof)
    /// with its archived (gzipped) representation:
    ///
    /// ```tl
    /// gzip_packed#3072cfa1 packed_data:string = Object;
    /// ```
    ///
    /// At the present time, it is supported in the body of an RPC response
    /// (i.e., as result in rpc_result) and generated by the server for a
    /// limited number of high-level queries. In addition, in the future it
    /// may be used to transmit non-service messages (i.e. RPC queries) from
    /// client to server.
    ///
    /// [Packed Object]: https://core.telegram.org/mtproto/service_messages#packed-object
    fn handle_gzip_packed(&mut self, message: manual_tl::Message) -> Result<(), Error> {
        let container = manual_tl::GzipPacked::from_bytes(&message.body)?;
        self.process_message(manual_tl::Message {
            body: container.decompress()?,
            ..message
        })
        .map(|_| ())
    }

    /// **[HTTP Wait/Long Poll]**
    ///
    /// The following special service query not requiring an acknowledgement
    /// (which must be transmitted only through an HTTP connection) is used to
    /// enable the server to send messages in the future to the client using
    /// HTTP protocol:
    ///
    /// ```tl
    /// http_wait#9299359f max_delay:int wait_after:int max_wait:int = HttpWait;
    /// ```
    ///
    /// When such a message (or a container carrying such a message) is
    /// received, the server either waits `max_delay` milliseconds, whereupon
    /// it forwards all the messages that it is holding on to the client if
    /// there is at least one message queued in session (if needed, by placing
    /// them into a container to which acknowledgments may also be added); or
    /// else waits no more than `max_wait` milliseconds until such a message
    /// is available. If a message never appears, an empty container is
    /// transmitted.
    ///
    /// The `max_delay` parameter denotes the maximum number of milliseconds
    /// that has elapsed between the first message for this session and the
    /// transmission of an HTTP response. The wait_after parameter works as
    /// follows: after the receipt of the latest message for a particular
    /// session, the server waits another wait_after milliseconds in case
    /// there are more messages. If there are no additional messages, the
    /// result is transmitted (a container with all the messages). If more
    /// messages appear, the `wait_after` timer is reset.
    ///
    /// At the same time, the max_delay parameter has higher priority than
    /// `wait_after`, and `max_wait` has higher priority than `max_delay`.
    ///
    /// This message does not require a response or an acknowledgement. If
    /// the container transmitted over HTTP carries several such messages,
    /// the behavior is undefined (in fact, the latest parameter will be
    /// used).
    ///
    /// If no `http_wait` is present in container, default values
    /// `max_delay=0` (milliseconds), `wait_after=0` (milliseconds), and
    /// `max_wait=25000` (milliseconds) are used.
    ///
    /// If the client's ping of the server takes a long time, it may make
    /// sense to set `max_delay` to a value that is comparable in magnitude
    /// to ping time.
    ///
    /// [HTTP Wait/Long Poll]: https://core.telegram.org/mtproto/service_messages#http-wait-long-poll
    fn handle_http_wait(&mut self, _message: manual_tl::Message) -> Result<(), Error> {
        // TODO implement
        Ok(())
    }

    /// Anything else that's not Service Message will be `Requests`.
    ///
    /// Since we handle all the possible service messages, we can
    /// safely treat whatever message body we received as `Requests`.
    fn handle_request(&mut self, message: manual_tl::Message) -> Result<(), Error> {
        self.deserialization.push(ClientMessage {
            msg_id: MsgId(message.msg_id),
            body: message.body,
        });
        Ok(())
    }
}

impl<'a> Encrypted<'a> {
    pub fn deserialize(&mut self, payload: &mut [u8]) -> Result<DecryptedMessages, Error> {
        crate::utils::check_message_buffer(payload)?;

        let plaintext = decrypt_data_v2(payload, self.auth_key)?;

        let mut buffer = Cursor::from_slice(plaintext);

        let salt = i64::deserialize(&mut buffer)?;
        let session_id = i64::deserialize(&mut buffer)?;

        self.process_message(manual_tl::Message::deserialize(&mut buffer)?)?;

        // For simplicity, and to avoid passing too much stuff around (RPC results, updates),
        // the processing result is stored in self. After processing is done, that temporary
        // state is cleaned and returned with `mem::take`.
        Ok(DecryptedMessages {
            salt,
            session_id,
            messages: mem::take(&mut self.deserialization),
        })
    }

    /*
    pub(super) fn push(&mut self, buffer: &mut DequeBuffer<u8>, response: &[u8]) -> Option<MsgId> {
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
        let mut body = response;
        let compressed;
        if let Some(threshold) = self.compression_threshold
            && response.len() >= threshold
        {
            compressed = manual_tl::GzipPacked::new(response).to_bytes();
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
        Some(self.serialize_msg(buffer, body, true))
    }

    pub(super) fn finalize(&mut self, buffer: &mut DequeBuffer<u8>) -> Option<MsgId> {
        self.finalize_plain(buffer);
        if buffer.is_empty() {
            None
        } else {
            encrypt_data_v2(buffer, &self.auth_key);
            Some(MsgId(self.msg_id_generator.last_msg_id as i64))
        }
    }
    */
}
