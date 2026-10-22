use std::sync::Arc;

use dashmap::DashMap;
use servmers_crypto::AuthKey;
use tokio::io;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn};

use crate::connection::handle_connection;

/// Maximum connection count.
const MAX_CONNECTION: usize = 1000;

pub struct AuthKeyCache {
    map: DashMap<[u8; 8], AuthKey>,
}

impl AuthKeyCache {
    pub fn new(auth_keys: Vec<AuthKey>) -> Self {
        let map = DashMap::new();
        for auth_key in auth_keys {
            map.insert(auth_key.id(), auth_key);
        }
        Self { map }
    }

    pub fn get(&self, id: &[u8; 8]) -> Option<dashmap::mapref::one::Ref<'_, [u8; 8], AuthKey>> {
        self.map.get(id)
    }
}

pub struct Server {
    listener: TcpListener,
    auth_keys: Arc<AuthKeyCache>,
    semaphore: Arc<Semaphore>,
}

impl Server {
    pub async fn bind(listen: &str, auth_keys: Vec<AuthKey>) -> io::Result<Self> {
        let listener = TcpListener::bind(listen).await?;
        info!("listening on {}", listen);
        Ok(Self {
            listener,
            auth_keys: Arc::new(AuthKeyCache::new(auth_keys)),
            semaphore: Arc::new(Semaphore::new(MAX_CONNECTION)),
        })
    }

    pub async fn run(&self) -> io::Result<()> {
        loop {
            let (stream, addr) = self.listener.accept().await?;
            stream.set_nodelay(true)?;

            let auth_keys = Arc::clone(&self.auth_keys);
            let permit = Arc::clone(&self.semaphore)
                .acquire_owned()
                .await
                .expect("semaphore closed");

            tokio::spawn(async move {
                let _permit = permit;

                match handle_connection(stream, addr, auth_keys).await {
                    Ok(()) => {}
                    Err(e) => warn!(%addr, "{e}"),
                }
            });
        }
    }
}
