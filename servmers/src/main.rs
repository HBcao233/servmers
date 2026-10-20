mod connection;
mod errors;
mod server;

use std::path::PathBuf;

use servmers_crypto::AuthKey;
use tracing::info;

use crate::server::Server;

const PORT: u16 = 2391;
const AUTH_KEY_BIN: &str = "auth_key.bin";

fn load_auth_keys() -> Result<Vec<AuthKey>, String> {
    if PathBuf::from(AUTH_KEY_BIN).exists() {
        let v = std::fs::read(AUTH_KEY_BIN).map_err(|e| e.to_string())?;
        if v.len() != 256 {
            return Err(format!("auth_key bin len !=256, got {}", v.len()));
        }
        Ok(vec![AuthKey::from_bytes(v.try_into().unwrap())])
    } else {
        Err("auth_key file not found.".to_string())
    }
}

async fn async_main() {
    let auth_keys = load_auth_keys().unwrap();
    info!("{:?}", auth_keys[0].id());

    let listen = format!("0.0.0.0:{}", PORT);
    let server = Server::bind(&listen, auth_keys).await.unwrap();
    server.run().await.unwrap();
}

fn main() {
    tracing_subscriber::fmt()
        .without_time()
        .with_max_level(tracing::Level::TRACE)
        .init();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main());
}
