use std::time::{SystemTime, UNIX_EPOCH};

use crate::mtp::DeserializeError;

/// Checks a message buffer for common errors
pub(crate) fn check_message_buffer(message: &[u8]) -> Result<(), DeserializeError> {
    if message.len() < 20 {
        Err(DeserializeError::MessageBufferTooSmall)
    } else {
        Ok(())
    }
}

/// Stack buffer to support extending from an iterator.
pub(crate) struct StackBuffer<const N: usize> {
    array: [u8; N],
    pos: usize,
}

impl<const N: usize> StackBuffer<N> {
    pub(crate) fn new() -> Self {
        Self {
            array: [0; N],
            pos: 0,
        }
    }

    pub(crate) fn into_inner(self) -> [u8; N] {
        self.array
    }
}

impl<const N: usize> Extend<u8> for StackBuffer<N> {
    fn extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) {
        iter.into_iter().for_each(|x| {
            self.array[self.pos] = x;
            self.pos += 1;
        });
    }
}

pub struct MsgIdGenerator {
    /// The ID of the last message which the lower 2 bits are set to 0.
    pub(crate) last_msg_id: u64,
}

impl MsgIdGenerator {
    pub fn new() -> Self {
        Self { last_msg_id: 0 }
    }

    pub fn get_new_msg_id(&mut self, is_update: bool) -> i64 {
        // server message identifiers modulo 4 yield 1 if the message is a response to a client message, and 3 otherwise.
        let flag = if is_update { 3 } else { 1 };

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
}
