use std::net::SocketAddr;
use std::sync::Arc;

use servmers_crypto::DequeBuffer;
use servmers_mtproto::mtp::{self, ClientRequest, DeserializeError, Encrypted, Mtp, Plain};
use servmers_mtproto::transport::{self, DetectError, Detected, Transport};
use tokio::io::{self, AsyncReadExt};
use tokio::net::TcpStream;
use tokio::time::{sleep, Duration};
use tracing::{debug, info, trace};

use crate::errors::ReadError;
use crate::server::AuthKeyCache;

/// After how many seconds should the server close the connection when we send a ping?
///
/// What this value essentially means is that we have `NO_PING_DISCONNECT - PING_DELAY` seconds
/// to keep sending pings, or the server will close the connection.
///
/// Pings ensure the connection is kept active, and the delayed disconnect ensures the messages
/// are getting through consistently enough.
const NO_PING_DISCONNECT: Duration = Duration::from_secs(75);

/// The maximum data that we're willing to send or receive at once.
///
/// By having a fixed-size buffer, we can avoid unnecessary allocations
/// and trivially prevent allocating more than this limit if we ever
/// received invalid data.
///
/// Telegram will close the connection with roughly a megabyte of data,
/// so to account for the transports' own overhead, we add a few extra
/// kilobytes to the maximum data size.
const MAXIMUM_DATA: usize = (1024 * 1024) + (8 * 1024);

/// How much leading space should be reserved in a buffer to avoid moving memory.
const LEADING_BUFFER_SPACE: usize = mtp::MAX_TRANSPORT_HEADER_LEN
    + mtp::ENCRYPTED_PACKET_HEADER_LEN
    + mtp::PLAIN_PACKET_HEADER_LEN
    + mtp::MESSAGE_CONTAINER_HEADER_LEN;

pub struct Connection {
    stream: TcpStream,
    transport: Option<Transport>,
    mtp: Option<Mtp>,
    addr: SocketAddr,
    auth_keys: Arc<AuthKeyCache>,

    // Transport-level buffers and positions
    read_buffer: Vec<u8>,
    read_tail: usize,
    write_buffer: DequeBuffer<u8>,
    write_head: usize,
}

impl Connection {
    /// Create a new connection using the stream and server address.
    pub fn new(stream: TcpStream, addr: SocketAddr, auth_keys: Arc<AuthKeyCache>) -> Self {
        info!("new connection from {addr}");

        Self {
            stream,
            transport: None,
            mtp: None,
            addr,
            auth_keys,

            read_buffer: vec![0; MAXIMUM_DATA],
            read_tail: 0,
            write_buffer: DequeBuffer::with_capacity(MAXIMUM_DATA, LEADING_BUFFER_SPACE),
            write_head: 0,
        }
    }

    pub async fn handle(mut self) -> Result<(), ReadError> {
        self.negotiate_transport().await?;

        loop {
            let step = self.step().await?;
            info!(?step);
        }
    }

    async fn negotiate_transport(&mut self) -> Result<(), ReadError> {
        let mut buf = [0u8; 64];
        let mut need_more = 0;
        loop {
            let n = self.stream.peek(&mut buf).await?;
            if n == 0 {
                return Err(ReadError::Io(io::ErrorKind::UnexpectedEof.into()));
            }
            if n < need_more {
                continue;
            }

            match transport::detect(&buf[..n]) {
                Ok(Detected {
                    transport,
                    preamble,
                }) => {
                    if preamble > 0 {
                        let mut skip = vec![0u8; preamble];
                        self.stream.read_exact(&mut skip).await?;
                    }
                    info!(addr = %self.addr, "transport negotiated");
                    self.transport = Some(transport);
                    return Ok(());
                }
                Err(DetectError::NeedMore(more)) => {
                    need_more = more;
                    continue;
                }
                Err(DetectError::Unsupported) => {
                    return Err(ReadError::UnsupportedTransport);
                }
            }
        }
    }

    /// Step network events, writing and reading at the same time.
    ///
    /// Updates received during this step, if any, are returned.
    ///
    /// If an error is returned, the connection should be treated
    /// as dead and the sender instance recreated.
    async fn step(&mut self) -> Result<Vec<ClientRequest>, ReadError> {
        /*self.try_fill_write();
        let write_len = self.write_buffer.len() - self.write_head;
        trace!(
            "reading bytes and sending up to {} bytes via network",
            write_len
        );*/

        let (mut reader, mut _writer) = self.stream.split();

        tokio::select! {
            n = reader.read(&mut self.read_buffer[self.read_tail..]) => {
                n.map_err(ReadError::Io).and_then(|n| self.on_net_read(n))
            }
            /*n = writer.write(&self.write_buffer[self.write_head..]), if !self.write_buffer.is_empty() => {
                n.map_err(ReadError::Io).map(|n| {
                    self.on_net_write(n);
                    Vec::new()
                })
            }*/
            _ = sleep(NO_PING_DISCONNECT) => {
                Err(ReadError::Timeout)
            }
        }
    }

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
            match self
                .transport
                .as_mut()
                .unwrap()
                .unpack(&mut self.read_buffer[next_offset..self.read_tail])
            {
                Ok(offset) => {
                    debug!("deserializing valid transport packet...");
                    let buf = &mut self.read_buffer[next_offset..][offset.data_range];
                    let result =
                        detect_mtp(buf, Arc::clone(&self.auth_keys))?.deserialize(buf)?;

                    requests.extend(result);
                    next_offset += offset.next_offset;
                }
                Err(transport::Error::MissingBytes) => break,
                Err(err) => return Err(err.into()),
            }
        }

        self.read_buffer.copy_within(next_offset..self.read_tail, 0);
        self.read_tail -= next_offset;

        Ok(requests)
    }

    /*
    /// Handle `n` more written bytes being ready to process by the transport.
    fn on_net_write(&mut self, n: usize) {
        self.write_head += n;
        trace!(
            "written {} bytes to the network ({}/{})",
            n,
            self.write_head,
            self.write_buffer.len()
        );
        assert!(self.write_head <= self.write_buffer.len());
        if self.write_head != self.write_buffer.len() {
            return;
        }

        self.write_buffer.clear();
        self.write_head = 0;
        for req in self.requests.iter_mut() {
            match &req.state {
                RequestState::NotSerialized | RequestState::Sent(_) => {}
                RequestState::Serialized(pair) => {
                    debug!(?pair, "sent request with");
                    req.state = RequestState::Sent(pair.clone());
                }
            }
        }
    }*/
}

fn detect_mtp(payload: &[u8], auth_keys: Arc<AuthKeyCache>) -> Result<Mtp, ReadError> {
    if payload.len() < 8 {
        return Err(ReadError::Deserialize(
            DeserializeError::MessageBufferTooSmall,
        ));
    }

    debug!(payload = ?payload[..64]);
    if payload[..8] == [0u8; 8] {
        Ok(Mtp::Plain(Plain::new()))
    } else if let Some(auth_key) = auth_keys.get(&payload[..8].try_into().unwrap()) {
        Ok(Mtp::Encrypted(Box::new(Encrypted::new(auth_key.to_bytes(), 0))))
    } else {
        Err(ReadError::Forbidden)
    }
}
