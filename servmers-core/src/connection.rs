use std::net::SocketAddr;
use std::sync::Arc;

use bytes::BytesMut;
use servmers_mtproto::mtp;
use servmers_mtproto::transport::{Drive, TransportDriver};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::{debug, info, instrument, trace, warn};

use crate::errors::ConnectionError;
use crate::server::AuthKeyCache;

/// After how many seconds should the server close the connection when we send a ping?
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

    loop {
        loop {
            match driver.drive(&mut read_buffer, &mut packets) {
                Ok(Drive::Progress) => {}
                Ok(Drive::NeedMore) => break,
                Err(e) => {
                    // writer.abort();
                    return Err(e.into());
                }
            }
        }

        on_packets(&mut packets, Arc::clone(&auth_keys))?;

        if read_buffer.len() > MAX_FRAME_BYTES {
            warn!(len = read_buffer.len(), "recv buffer overflow",);
            return Err(ConnectionError::Overflow);
        }

        match timeout(IDLE_TIMEOUT, reader.read_buf(&mut read_buffer)).await {
            Err(_) => {
                debug!("idle timeout");
                break;
            }
            Ok(Ok(0)) => break,
            Ok(Ok(n)) => {
                trace!(n, "read")
            }
            Ok(Err(e)) => {
                return Err(e.into());
            }
        }
    }

    info!("connection closed");
    Ok(())
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
