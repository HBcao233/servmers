use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use dashmap::DashMap;
use grammers_tl_types::deserialize::{Cursor, Deserializable};
use grammers_tl_types::{self as tl, Identifiable, Serializable};
use servmers_mtproto::DequeBuffer;
use servmers_mtproto::authentication;
use servmers_mtproto::mtp::{self, ClientMessages, DecryptedMessages, Message, Mtp, Outbound};
use servmers_mtproto::transport::{
    Drive, NegotiateError, NegotiateResult, Packer, TransportDriver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, tcp::OwnedWriteHalf};
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};
use tracing::{debug, info, instrument, trace, warn};

use crate::errors::ConnectionError;
use crate::server::AuthKeyCache;
use crate::{Registry, Service, SessionKey};

/// Maximum handshake time.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// After how long should the server close the connection when we send a ping?
///
/// What this value essentially means is that we have `NO_PING_DISCONNECT - PING_DELAY` seconds
/// to keep sending pings, or the server will close the connection.
///
/// Pings ensure the connection is kept active, and the delayed disconnect ensures the messages
/// are getting through consistently enough.
const IDLE_TIMEOUT: Duration = Duration::from_secs(75);

/// How much leading space should be reserved in a buffer to avoid moving memory.
const LEADING_BUFFER_SPACE: usize = mtp::MAX_TRANSPORT_HEADER_LEN
    + mtp::ENCRYPTED_PACKET_HEADER_LEN
    + mtp::PLAIN_PACKET_HEADER_LEN
    + mtp::MESSAGE_CONTAINER_HEADER_LEN;

/// Initial capacity of read buffer.
const INITIAL_CAPACITY: usize = 8 * 1024;

/// The maximum data that we're willing to send or receive at once.
///
/// Server will close the connection with roughly a megabyte of data,
/// so to account for the transports' own overhead, we add a few extra
/// kilobytes to the maximum data size.
pub const MAX_FRAME_BYTES: usize = (1024 * 1024) + (8 * 1024);

pub struct Connection {
    auth_key_id: [u8; 8],
    dh: Option<authentication::DHData>,
}

#[derive(Debug)]
enum WriteCommand {
    Outbound(Outbound),
    Raw(Vec<u8>),
}

impl Connection {
    pub fn new() -> Self {
        Self {
            auth_key_id: [0; 8],
            dh: None,
        }
    }

    #[instrument(skip(self, stream, auth_keys, registry, services))]
    pub async fn handle(
        &mut self,
        stream: TcpStream,
        addr: SocketAddr,
        auth_keys: Arc<AuthKeyCache>,
        registry: Arc<Registry>,
        services: Arc<DashMap<u32, Arc<dyn Service>>>,
    ) -> Result<(), ConnectionError> {
        let (mut reader, writer) = stream.into_split();
        let mut driver = TransportDriver::new();

        let mut read_buffer = BytesMut::with_capacity(INITIAL_CAPACITY);
        let mut packets = Vec::new();

        let packer = loop {
            match driver.negotiate(&mut read_buffer) {
                Ok(NegotiateResult::Negotiated { packer }) => break packer,
                Ok(NegotiateResult::NeedMore) => {}
                Err(NegotiateError::UnsupportedTransport) => {
                    return Err(ConnectionError::UnsupportedTransport);
                }
            }

            if read_buffer.len() > MAX_FRAME_BYTES {
                warn!(len = read_buffer.len(), "recv buffer overflow");
                return Err(ConnectionError::Overflow);
            }

            match timeout(HANDSHAKE_TIMEOUT, reader.read_buf(&mut read_buffer)).await {
                Err(_) => {
                    debug!("handshake timeout");
                    return Err(ConnectionError::Timeout);
                }
                Ok(Ok(0)) => {
                    return Err(ConnectionError::Io(
                        std::io::ErrorKind::ConnectionReset.into(),
                    ));
                }
                Ok(Ok(n)) => {
                    trace!(n, "read");
                }
                Ok(Err(e)) => return Err(e.into()),
            }
        };

        let (write_tx, write_rx) = mpsc::channel(100);
        let mtp = Arc::new(Mutex::new(Mtp::new()));
        let write_task = tokio::task::spawn(write_loop(writer, write_rx, packer, Arc::clone(&mtp)));

        let result = 'outer: loop {
            loop {
                match driver.drive(&mut read_buffer, &mut packets) {
                    Ok(Drive::Progress) => {}
                    Ok(Drive::NeedMore) => break,
                    Err(e) => {
                        break 'outer Err(e.into());
                    }
                }
            }

            match self.on_packets(&mut packets, Arc::clone(&auth_keys), &mtp) {
                Ok(messages) => {
                    self.on_messages(
                        messages,
                        write_tx.clone(),
                        Arc::clone(&registry),
                        Arc::clone(&services),
                    )
                    .await?
                }
                Err(e) => break Err(e),
            };

            if read_buffer.len() > MAX_FRAME_BYTES {
                warn!(len = read_buffer.len(), "recv buffer overflow");
                break Err(ConnectionError::Overflow);
            }

            match timeout(IDLE_TIMEOUT, reader.read_buf(&mut read_buffer)).await {
                Err(_) => {
                    debug!("idle timeout");
                    break Ok(());
                }
                Ok(Ok(0)) => break Ok(()),
                Ok(Ok(n)) => {
                    trace!(n, "read");
                }
                Ok(Err(e)) => break Err(e.into()),
            }
        };

        write_task.abort();
        let _ = write_task.await;
        info!("connection closed");

        result
    }

    fn on_packets(
        &mut self,
        packets: &mut Vec<BytesMut>,
        auth_keys: Arc<AuthKeyCache>,
        mtp: &Mutex<Mtp>,
    ) -> Result<Vec<ClientMessages>, ConnectionError> {
        let mut result = Vec::new();
        let mut guard = mtp.lock().unwrap();
        let mut is_auth_key_configured = guard.is_auth_key_configured();

        for mut packet in packets.drain(..) {
            if packet.len() < 8 {
                return Err(ConnectionError::Mtp(mtp::Error::MessageBufferTooSmall));
            }

            if packet[..8] == [0; 8] {
                if is_auth_key_configured {
                    return Err(ConnectionError::InvalidPacket);
                }

                let message = guard.deserialize(&mut packet[8..])?;

                result.push(message);
            } else {
                let auth_key_id = packet[..8].try_into().unwrap();
                self.auth_key_id = auth_key_id;

                let auth_key = auth_keys
                    .get(&auth_key_id)
                    .ok_or(ConnectionError::Forbidden)?;
                if !is_auth_key_configured {
                    guard.set_auth_key(auth_key.clone());
                    is_auth_key_configured = true;
                }

                let message = guard.deserialize(&mut packet)?;

                match message {
                    ClientMessages::Encrypted(DecryptedMessages { session_id, .. }) => {
                        guard.set_session_id(session_id)?
                    }
                    _ => {}
                }

                result.push(message);
            }
        }

        Ok(result)
    }

    async fn on_messages(
        &mut self,
        messages: Vec<ClientMessages>,
        tx: mpsc::Sender<WriteCommand>,
        registry: Arc<Registry>,
        services: Arc<DashMap<u32, Arc<dyn Service>>>,
    ) -> Result<(), ConnectionError> {
        for message in messages {
            match message {
                ClientMessages::Plain(msg) => self.on_plain_message(msg, tx.clone()).await?,
                ClientMessages::Encrypted(DecryptedMessages {
                    salt,
                    session_id,
                    messages,
                }) => {
                    self.on_encryted_messages(
                        session_id,
                        salt,
                        messages,
                        tx.clone(),
                        Arc::clone(&registry),
                        Arc::clone(&services),
                    )
                    .await?
                }
            }
        }

        Ok(())
    }

    async fn on_encryted_messages(
        &mut self,
        session_id: i64,
        salt: i64,
        messages: Vec<Message>,
        tx: mpsc::Sender<WriteCommand>,
        registry: Arc<Registry>,
        services: Arc<DashMap<u32, Arc<dyn Service>>>,
    ) -> Result<(), ConnectionError> {
        let session = registry.get_or_create(SessionKey {
            auth_key_id: self.auth_key_id,
            session_id,
        });
        info!(salt, session_id, ?messages);

        for message in messages {
            if message.body.len() < 4 {
                return Err(mtp::Error::MessageBufferTooSmall.into());
            }

            let id = u32::from_le_bytes(message.body[..4].try_into().unwrap());
            let response = match services.get(&id) {
                Some(service) => service.handle(&session, &message).await?,
                None => Some(Outbound::RpcError {
                    req_msg_id: message.msg_id.into_inner(),
                    code: 400,
                    message: "METHOD_INVALID".to_string(),
                }),
            };
            debug!(?response);

            if let Some(resp) = response {
                tx.send(WriteCommand::Outbound(resp))
                    .await
                    .map_err(|_| ConnectionError::Io(std::io::ErrorKind::BrokenPipe.into()))?;
            }
        }

        Ok(())
    }

    async fn on_plain_message(
        &mut self,
        message: Message,
        tx: mpsc::Sender<WriteCommand>,
    ) -> Result<(), ConnectionError> {
        info!(?message);

        let mut buf = Cursor::from_slice(&message.body);
        let response = match u32::deserialize(&mut buf)? {
            tl::functions::ReqPqMulti::CONSTRUCTOR_ID => {
                let request = tl::functions::ReqPqMulti::deserialize(&mut buf)?;
                let (response, dh) = authentication::step1(request)?;

                self.dh = Some(dh);

                WriteCommand::Outbound(Outbound::Other(response.to_bytes()))
            }
            tl::functions::ReqDhParams::CONSTRUCTOR_ID => {
                let request = tl::functions::ReqDhParams::deserialize(&mut buf)?;
                let (new_dh, decrypted_data) = authentication::step2(request)?;
                match self.dh {
                    Some(ref dh) => {
                        dh.check(new_dh)?;

                        let data = tl::enums::PQInnerData::from_bytes(&decrypted_data)?;
                        let response = authentication::do_step2(dh, data)?;

                        WriteCommand::Outbound(Outbound::Other(response.to_bytes()))
                    }
                    None => WriteCommand::Raw((-404i32).to_le_bytes().to_vec()),
                }
            }
            tl::functions::SetClientDhParams::CONSTRUCTOR_ID => {
                todo!();
            }
            _ => WriteCommand::Outbound(Outbound::RpcError {
                req_msg_id: message.msg_id.into_inner(),
                code: 400,
                message: "METHOD_INVALID".to_string(),
            }),
        };
        debug!(?response);

        tx.send(response)
            .await
            .map_err(|_| ConnectionError::Io(std::io::ErrorKind::BrokenPipe.into()))?;

        Ok(())
    }
}

async fn write_loop(
    mut writer: OwnedWriteHalf,
    mut rx: mpsc::Receiver<WriteCommand>,
    mut packer: Box<dyn Packer>,
    mtp: Arc<Mutex<Mtp>>,
) -> Result<(), ConnectionError> {
    let mut buf: DequeBuffer<u8> =
        DequeBuffer::with_capacity(INITIAL_CAPACITY, LEADING_BUFFER_SPACE);
    let mut peek = None;

    while let Some(first) = match peek.take() {
        Some(peek) => Some(peek),
        None => rx.recv().await,
    } {
        let outbound = match first {
            WriteCommand::Outbound(outbound) => outbound,
            WriteCommand::Raw(raw) => {
                write_bytes(&mut writer, &raw).await?;
                continue;
            }
        };

        {
            let mut guard = mtp.lock().unwrap();
            guard.push(&mut buf, outbound);
            while let Ok(next) = rx.try_recv() {
                let outbound = match next {
                    WriteCommand::Outbound(outbound) => outbound,
                    WriteCommand::Raw(raw) => {
                        peek = Some(WriteCommand::Raw(raw));
                        break;
                    }
                };

                if buf.len() > MAX_FRAME_BYTES / 2 {
                    break;
                }
                guard.push(&mut buf, outbound);
            }

            guard.finalize(&mut buf);
        }

        packer.pack(&mut buf);

        write_bytes(&mut writer, &buf[..]).await?;

        buf.clear();
    }

    Ok(())
}

async fn write_bytes(writer: &mut OwnedWriteHalf, bytes: &[u8]) -> Result<(), ConnectionError> {
    writer.write_all(bytes).await.map_err(|error| {
        warn!(%error, "write failed");
        ConnectionError::Io(error)
    })
}
