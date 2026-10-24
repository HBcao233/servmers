use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::BytesMut;
use servmers_crypto::DequeBuffer;
use servmers_mtproto::mtp::{self, ClientMessages, DecryptedMessages, Mtp, Outbound};
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

#[instrument(skip(stream, auth_keys))]
pub async fn handle_connection(
    stream: TcpStream,
    addr: SocketAddr,
    auth_keys: Arc<AuthKeyCache>,
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

        if let Err(e) = on_packets(&mut packets, Arc::clone(&auth_keys), &write_tx, &mtp) {
            break Err(e);
        }

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
    packets: &mut Vec<BytesMut>,
    auth_keys: Arc<AuthKeyCache>,
    write_tx: &mpsc::Sender<Outbound>,
    mtp: &Mutex<Mtp>,
) -> Result<(), ConnectionError> {
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

            let ClientMessages::Plain(message) = guard.deserialize(&mut packet)? else {
                return Err(ConnectionError::InvalidPacket);
            };

            info!(?message);
        } else {
            let auth_key_id = packet[..8].try_into().unwrap();
            let auth_key = auth_keys.get(&auth_key_id).expect("TODO");
            if !is_auth_key_configured {
                guard.set_auth_key(auth_key.clone());
                is_auth_key_configured = true;
            }

            let ClientMessages::Encrypted(DecryptedMessages {
                salt,
                session_id,
                messages,
            }) = guard.deserialize(&mut packet)?
            else {
                return Err(ConnectionError::InvalidPacket);
            };

            guard.set_session_id(session_id)?;

            info!(salt, session_id, ?messages);
        }
    }

    Ok(())
}

async fn write_loop(
    mut writer: OwnedWriteHalf,
    mut rx: mpsc::Receiver<Outbound>,
    mut packer: Box<dyn Packer>,
    mtp: Arc<Mutex<Mtp>>,
) -> Result<(), ConnectionError> {
    let mut buf: DequeBuffer<u8> =
        DequeBuffer::with_capacity(INITIAL_CAPACITY, LEADING_BUFFER_SPACE);

    while let Some(first) = rx.recv().await {
        {
            let mut guard = mtp.lock().unwrap();
            guard.push(&mut buf, first);
            while let Ok(next) = rx.try_recv() {
                if buf.len() > MAX_FRAME_BYTES / 2 {
                    break;
                }
                guard.push(&mut buf, next);
            }

            guard.finalize(&mut buf);
        }

        packer.pack(&mut buf);

        writer.write_all(&buf[..]).await.map_err(|error| {
            warn!(%error, "write failed");
            ConnectionError::Io(error)
        })?;

        buf.clear();
    }

    Ok(())
}
