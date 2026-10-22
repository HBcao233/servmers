use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use servmers_crypto::DequeBuffer;
use servmers_mtproto::mtp;
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
    let (mut reader, mut writer) = stream.into_split();
    let mut driver = TransportDriver::new();

    let mut read_buffer = BytesMut::with_capacity(INITIAL_CAPACITY);
    let mut packets = Vec::new();

    let packer = 'outer: loop {
        loop {
            match driver.negotiate(&mut read_buffer) {
                Ok(NegotiateResult::Negotiated { packer }) => break 'outer Ok(packer),
                Ok(NegotiateResult::NeedMore) => break,
                Err(NegotiateError::UnsupportedTransport) => {
                    break 'outer Err(ConnectionError::UnsupportedTransport);
                }
            }
        }

        if read_buffer.len() > MAX_FRAME_BYTES {
            warn!(len = read_buffer.len(), "recv buffer overflow");
            break Err(ConnectionError::Overflow);
        }

        match timeout(HANDSHAKE_TIMEOUT, reader.read_buf(&mut read_buffer)).await {
            Err(_) => {
                debug!("handshake timeout");
                break Err(ConnectionError::Timeout);
            }
            Ok(Ok(0)) => {
                break Err(ConnectionError::Io(
                    std::io::ErrorKind::ConnectionReset.into(),
                ));
            }
            Ok(Ok(n)) => {
                trace!(n, "read");
            }
            Ok(Err(e)) => break Err(e.into()),
        }
    };
    let packer = match packer {
        Ok(packer) => packer,
        Err(e) => return Err(e),
    };

    let (write_tx, write_rx) = mpsc::channel(100);
    let write_task = tokio::task::spawn(write_loop(writer, write_rx, packer));

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

        on_packets(&mut packets, Arc::clone(&auth_keys))?;

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
) -> Result<(), ConnectionError> {
    for mut packet in packets.drain(..) {
        if packet.len() < 8 {
            return Err(ConnectionError::Mtp(mtp::Error::MessageBufferTooSmall));
        }

        if &packet[..8] == &[0; 8] {
            let messages = mtp::Plain::deserialize(&mut packet)?;
            info!(?messages);
        } else {
            let auth_key_id = packet[..8].try_into().unwrap();
            let auth_key = auth_keys.get(&auth_key_id).expect("TODO");
            let mtp::DecryptedMessages {
                salt,
                session_id,
                messages,
            } = mtp::Encrypted::new(&auth_key).deserialize(&mut packet)?;
            info!(salt, session_id, ?messages);
        }
    }

    Ok(())
}

async fn write_loop(
    mut writer: OwnedWriteHalf,
    rx: mpsc::Receiver<Outbound>,
    packer: Box<dyn Packer>,
) -> Result<(), ConnectionError> {
    let buf: DequeBuffer<u8> = DequeBuffer::with_capacity(INITIAL_CAPACITY, LEADING_BUFFER_SPACE);
    let peeked = None;

    while let Some(first) = rx.recv().await {
        push(first, &mut buf);
        while let Ok(next) = rx.try_recv() {
            if buf.len() > MAX_FRAME_BYTES / 2 {
                break;
            }
            push(&next, &mut buf)?;
        }

        finishize(&mut buf);

        packer.pack(&mut buf);

        writer.write_all(&buf[..]).await.map_err(|error| {
            warn!(%error, "write failed");
            ConnectionError::Io(error)
        })?;

        buf.clear();
    }

    Ok(())
}
