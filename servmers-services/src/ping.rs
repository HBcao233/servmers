use async_trait::async_trait;
use grammers_tl_types::{self as tl, Deserializable, Identifiable, Serializable};
use servmers_core::{Service, Session};
use servmers_mtproto::mtp::{Error, Message, Outbound};

#[derive(Debug, Default, Clone, Copy)]
pub struct PingService;

impl PingService {
    pub fn pong(&self, msg_id: i64, ping: tl::functions::Ping) -> tl::enums::Pong {
        tl::enums::Pong::Pong(tl::types::Pong {
            msg_id,
            ping_id: ping.ping_id,
        })
    }
}

#[async_trait]
impl Service for PingService {
    fn constructors(&self) -> &[u32] {
        &[tl::functions::Ping::CONSTRUCTOR_ID]
    }

    async fn handle(
        &self,
        _session: &Session,
        message: &Message,
    ) -> Result<Option<Outbound>, Error> {
        let ping = tl::functions::Ping::from_bytes(&message.body[4..])?;
        let pong = self.pong(message.msg_id.into_inner(), ping);

        // pong is a service message, not an rpc_result wrapper.
        Ok(Some(Outbound::Other(pong.to_bytes())))
    }
}
