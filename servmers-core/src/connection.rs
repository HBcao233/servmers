use std::net::SocketAddr;

use bytes::BytesMut;
use servmers_mtproto::decode::{Decoder, Drive, Payload};
use servmers_mtproto::mtp;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};
use tracing::{debug, info, instrument, trace, warn};

use crate::errors::ReadError;
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

#[instrument(skip(stream))]
pub async fn handle_connection(stream: TcpStream, addr: SocketAddr) -> Result<(), ReadError> {
    let (mut reader, mut writer) = stream.into_split();
    let mut decoder = Decoder::new();
    let mut read_buffer = BytesMut::with_capacity(INITIAL_CAPACITY);
    let mut payloads = Vec::new();

    loop {
        loop {
            match decoder.drive(&mut read_buffer, &mut payloads) {
                Ok(Drive::Progress) => {}
                Ok(Drive::NeedMore) => break,
                Err(e) => {
                    // writer.abort();
                    return Err(e.into());
                }
            }
        }

        on_payloads(&mut payloads);

        if read_buffer.len() > MAX_FRAME_BYTES {
            warn!(len = read_buffer.len(), "recv buffer overflow",);
            return Err(ReadError::Overflow);
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

/*
/// Handle `n` more read bytes being ready to process by the transport.
///
/// This won't cause `ReadError::Io`, but yet another enum would be overkill.
fn on_net_read(&mut self, n: usize) -> Result<Vec<ClientRequest>, ReadError> {
    if n == 0 {
        return Err(ReadError::Io(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "read 0 bytes",
        )));
    }

    self.read_tail += n;
    trace!("read {} bytes from the network", n);
    trace!("trying to unpack buffer of {} bytes...", self.read_tail);

    // TODO the buffer might have multiple transport packets, what should happen with the
    // updates successfully read if subsequent packets fail to be deserialized properly?
    let mut requests = Vec::new();
    let mut next_offset = 0;
    while next_offset != self.read_tail {

    }

    self.read_buffer.copy_within(next_offset..self.read_tail, 0);
    self.read_tail -= next_offset;

    Ok(requests)
}*/

fn on_payloads(payloads: &mut Vec<Payload>) {
    for payload in payloads.drain(..) {
        info!(?payload);
    }
}
