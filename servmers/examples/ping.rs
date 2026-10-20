use std::path::PathBuf;
use std::str::FromStr;
use std::time::Duration;

use grammers_mtproto::transport;
use grammers_mtsender::connect_with_auth;
use grammers_tl_types::functions;
use tokio::net::TcpStream;

const PORT: u16 = 2391;

fn load_auth_key() -> Result<[u8; 256], String> {
    if PathBuf::from("auth_key.bin").exists() {
        let v = std::fs::read("auth_key.bin").map_err(|e| e.to_string())?;
        if v.len() != 256 {
            return Err(format!("auth_key bin len !=256, got {}", v.len()));
        }
        Ok(v.try_into().unwrap())
    } else {
        Err("auth_key file not found.".to_string())
    }
}

async fn async_main() -> Result<(), Box<dyn std::error::Error>> {
    let auth_key = load_auth_key()?;

    let addr = format!("127.0.0.1:{}", PORT);
    let mut stream = TcpStream::connect(&addr).await?;
    let mut sender = connect_with_auth(
        transport::Full::new(),
        grammers_mtsender::ServerAddr::Tcp {
            address: std::net::SocketAddr::from_str(&addr).unwrap(),
        },
        auth_key,
    )
    .await?;
    println!("connected");

    for i in 0..2 {
        println!("\n-> ping #{i}");

        let response = sender.invoke(&functions::Ping { ping_id: i }).await;

        println!("  <- got {:?}", response);

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    Ok(())
}

fn main() {
    tracing_subscriber::fmt().init();

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async_main());
}
