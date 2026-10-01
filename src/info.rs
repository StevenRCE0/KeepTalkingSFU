//! A tiny plain-HTTP listener that tells clients how to reach the hub, so
//! apps configure only the relay's domain. A reverse proxy (Caddy) serves it
//! under TLS at `https://<relay>/kt/hub`; the web certificate is what vouches
//! for the hub id.
//!
//! `GET /kt/hub` returns
//! `{"hub":"<hex id>","relay":"<url>","alpn":"keeptalking/hub/1","qad_port":7842}`.
//! Anything else is a 404. Hand-rolled on purpose: one route, no framework.

use anyhow::Result;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};
use tracing::debug;

use crate::proto::HUB_ALPN;

/// The JSON document served at `/kt/hub`.
pub fn hub_info_json(hub: &str, relay: &str, qad_port: Option<u16>) -> String {
    let qad = qad_port.map_or_else(|| "null".to_string(), |port| port.to_string());
    format!(
        r#"{{"hub":"{hub}","relay":"{relay}","alpn":"{}","qad_port":{qad}}}"#,
        String::from_utf8_lossy(HUB_ALPN)
    )
}

/// Serves `body` at `GET /kt/hub` until the listener fails.
pub async fn serve(listener: TcpListener, body: String) -> Result<()> {
    loop {
        let (mut stream, peer) = listener.accept().await?;
        let body = body.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            let mut filled = 0;
            // Read until the end of the request head (or give up at 4 KiB).
            while filled < buf.len() {
                match stream.read(&mut buf[filled..]).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => filled += n,
                }
                if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf[..filled]);
            let request_line = head.lines().next().unwrap_or_default();
            let mut parts = request_line.split_whitespace();
            let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
            let path = path.split('?').next().unwrap_or(path);
            let response = if (method == "GET" || method == "HEAD") && path == "/kt/hub" {
                let payload = if method == "HEAD" { "" } else { body.as_str() };
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
                    body.len()
                )
            } else {
                "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            };
            if let Err(err) = stream.write_all(response.as_bytes()).await {
                debug!(%peer, "info write failed: {err}");
            }
            let _ = stream.shutdown().await;
        });
    }
}
