//! A tiny plain-HTTP listener that tells clients how to reach the SFU, so
//! apps configure only the relay's domain. A reverse proxy (Caddy) serves it
//! under TLS at `https://<relay>/kt/sfu`; the web certificate is what vouches
//! for the SFU id.
//!
//! `GET /kt/sfu` returns
//! `{"sfu":"<hex id>","relay":"<url>","alpn":"keeptalking/sfu/1","qad_port":7842}`.
//! Anything else is a 404. Hand-rolled on purpose: one route, no framework.
//! [`fetch_info`] is the matching client (used by `kt-probe --info`).

use std::{str::FromStr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail, ensure};
use iroh::{EndpointId, RelayUrl, tls::CaTlsConfig};
use rustls::pki_types::ServerName;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, warn};
use url::Url;

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

/// What `GET /kt/sfu` tells a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfuInfo {
    pub sfu: EndpointId,
    pub relay: RelayUrl,
    pub alpn: String,
    pub qad_port: Option<u16>,
}

impl SfuInfo {
    /// Parses the document [`sfu_info_json`] writes. Not a general JSON
    /// parser: string values without escapes, numbers and `null`.
    pub fn parse(json: &str) -> Result<Self> {
        let sfu = json_field(json, "sfu").context("info has no \"sfu\"")?;
        let relay = json_field(json, "relay").context("info has no \"relay\"")?;
        let alpn = json_field(json, "alpn").context("info has no \"alpn\"")?;
        let qad_port = match json_field(json, "qad_port") {
            None | Some("null") => None,
            Some(port) => Some(port.parse().context("bad qad_port")?),
        };
        Ok(Self {
            sfu: EndpointId::from_str(sfu).context("bad sfu id")?,
            relay: relay.parse().context("bad relay url")?,
            alpn: alpn.to_string(),
            qad_port,
        })
    }
}

fn json_field<'a>(json: &'a str, key: &str) -> Option<&'a str> {
    let at = json.find(&format!("\"{key}\""))? + key.len() + 2;
    let rest = json[at..].trim_start().strip_prefix(':')?.trim_start();
    match rest.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next(),
        None => rest.split([',', '}']).next().map(str::trim),
    }
}

/// Fetches and parses the info document at `url` (`http` or `https`;
/// `ca` overrides the web PKI roots, e.g. for a `kt-sfu --dev` proxy).
/// Fails if the SFU speaks a different protocol than this build.
pub async fn fetch_info(url: &Url, ca: Option<&CaTlsConfig>) -> Result<SfuInfo> {
    let host = url.host_str().context("info url has no host")?;
    let port = url
        .port_or_known_default()
        .context("info url has no port")?;
    let bare_host = host.trim_start_matches('[').trim_end_matches(']');
    let path = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
    );
    let tcp = tokio::time::timeout(REQUEST_TIMEOUT, TcpStream::connect((bare_host, port)))
        .await
        .context("info connect timed out")??;
    let request_future = async {
        match url.scheme() {
            "http" => exchange(tcp, &request).await,
            "https" => {
                let provider = Arc::new(rustls::crypto::ring::default_provider());
                let config = ca.cloned().unwrap_or_default().client_config(provider)?;
                let name = ServerName::try_from(bare_host.to_string())?;
                let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
                    .connect(name, tcp)
                    .await?;
                exchange(tls, &request).await
            }
            other => bail!("unsupported info url scheme {other}"),
        }
    };
    let response = tokio::time::timeout(REQUEST_TIMEOUT, request_future)
        .await
        .context("info request timed out")??;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .context("malformed HTTP response")?;
    let status = head.lines().next().unwrap_or_default();
    ensure!(
        status.split_whitespace().nth(1) == Some("200"),
        "GET {url}: {status}"
    );
    let info = SfuInfo::parse(body)?;
    ensure!(
        info.alpn.as_bytes() == SFU_ALPN,
        "the SFU speaks {}, this build speaks {}",
        info.alpn,
        String::from_utf8_lossy(SFU_ALPN)
    );
    Ok(info)
}

/// Sends `request` and reads the response until the peer closes (tolerating
/// a TLS peer that closes without close_notify), at most 64 KiB.
async fn exchange<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    request: &str,
) -> Result<String> {
    stream.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let mut chunk = [0u8; 4096];
    while response.len() < 64 * 1024 {
        match stream.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&chunk[..n]),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof && !response.is_empty() => {
                break;
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(String::from_utf8_lossy(&response).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn info_json_roundtrips() {
        let id = iroh::SecretKey::from_bytes(&[3; 32]).public();
        let json = sfu_info_json(&id.to_string(), "https://relay.example/", Some(7842));
        assert_eq!(
            SfuInfo::parse(&json).unwrap(),
            SfuInfo {
                sfu: id,
                relay: "https://relay.example/".parse().unwrap(),
                alpn: "keeptalking/sfu/1".into(),
                qad_port: Some(7842),
            }
        );
        let json = sfu_info_json(&id.to_string(), "https://relay.example/", None);
        assert_eq!(SfuInfo::parse(&json).unwrap().qad_port, None);
        assert!(SfuInfo::parse(r#"{"hub":"x"}"#).is_err());
    }
}
