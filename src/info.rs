//! A tiny plain-HTTP listener that tells clients how to reach the SFU, so
//! apps configure only the relay's domain. A reverse proxy (Caddy) serves it
//! under TLS at `https://<relay>/kt/sfu`; the web certificate is what vouches
//! for the SFU id.
//!
//! `GET /kt/sfu` returns
//! `{"sfu":"<hex id>","relay":"<url>","alpn":"keeptalking/sfu/1","qad_port":7842}`.
//! Anything else is a 404. Hand-rolled on purpose: one route, no framework.

use std::time::Duration;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, warn};

use crate::proto::SFU_ALPN;

/// Path of the info document.
pub const INFO_PATH: &str = "/kt/sfu";
/// Time a client has to send its request head.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Bounds of the retry delay after a failed accept.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(2);

/// The JSON document served at [`INFO_PATH`].
pub fn sfu_info_json(sfu: &str, relay: &str, qad_port: Option<u16>) -> String {
    let qad = qad_port.map_or_else(|| "null".to_string(), |port| port.to_string());
    format!(
        r#"{{"sfu":"{sfu}","relay":"{relay}","alpn":"{}","qad_port":{qad}}}"#,
        String::from_utf8_lossy(SFU_ALPN)
    )
}

/// Serves `body` at `GET /kt/sfu`, forever. A failed accept (EMFILE,
/// ECONNABORTED, ...) is logged and retried after a short backoff, so the
/// listener never dies while the process looks healthy.
pub async fn serve(listener: TcpListener, body: String) {
    let mut backoff = ACCEPT_BACKOFF_MIN;
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => {
                backoff = ACCEPT_BACKOFF_MIN;
                accepted
            }
            Err(err) => {
                warn!("info accept failed, retrying in {backoff:?}: {err}");
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                continue;
            }
        };
        let body = body.clone();
        tokio::spawn(async move {
            if let Err(err) = respond(stream, &body).await {
                debug!(%peer, "info request failed: {err}");
            }
        });
    }
}

async fn respond(mut stream: TcpStream, body: &str) -> std::io::Result<()> {
    let mut buf = vec![0u8; 4096];
    let mut filled = 0;
    // Read until the end of the request head (or give up at 4 KiB or
    // REQUEST_TIMEOUT).
    let head = tokio::time::timeout(REQUEST_TIMEOUT, async {
        while filled < buf.len() {
            match stream.read(&mut buf[filled..]).await? {
                0 => break,
                n => filled += n,
            }
            if buf[..filled].windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    })
    .await;
    match head {
        Ok(result) => result?,
        Err(_) => return Err(std::io::ErrorKind::TimedOut.into()),
    }
    let head = String::from_utf8_lossy(&buf[..filled]);
    let request_line = head.lines().next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let (method, path) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let path = path.split('?').next().unwrap_or(path);
    let response = if (method == "GET" || method == "HEAD") && path == INFO_PATH {
        let payload = if method == "HEAD" { "" } else { body };
        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{payload}",
            body.len()
        )
    } else {
        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string()
    };
    stream.write_all(response.as_bytes()).await?;
    stream.shutdown().await
}
