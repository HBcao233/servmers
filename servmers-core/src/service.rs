use async_trait::async_trait;
use servmers_mtproto::mtp::{Error, Message, Outbound};

use crate::Session;

#[async_trait]
pub trait Service: Send + Sync {
    fn constructors(&self) -> &[u32];

    async fn handle(&self, session: &Session, message: &Message)
    -> Result<Option<Outbound>, Error>;
}
