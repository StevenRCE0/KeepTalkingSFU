//! Reference client for the presence protocol, used by `kt-probe` and the
//! tests. The Swift SDK should implement the same thing on `iroh-ffi`.

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, SecretKey,
    endpoint::{Connection, SendStream, presets},
    tls::CaTlsConfig,
};
use tokio::sync::{Mutex, mpsc};
use uuid::Uuid;

use crate::proto::{ClientFrame, PRESENCE_ALPN, ServerFrame, read_frame, write_frame};

/// How a client endpoint is configured: our relay only, no DNS/DHT address
/// lookup, and an ephemeral key unless one is supplied.
pub struct ClientOptions {
    pub relay_map: RelayMap,
    pub ca: Option<CaTlsConfig>,
    pub alpns: Vec<Vec<u8>>,
    pub secret_key: Option<SecretKey>,
    /// Drop IP transports so every connection stays on the relay.
    pub relay_only: bool,
}

pub async fn bind_client(options: ClientOptions) -> Result<Endpoint> {
    let mut builder = Endpoint::builder(presets::Minimal)
        .relay_mode(RelayMode::Custom(options.relay_map))
        .alpns(options.alpns);
    if let Some(ca) = options.ca {
        builder = builder.ca_tls_config(ca);
    }
    if let Some(key) = options.secret_key {
        builder = builder.secret_key(key);
    }
    if options.relay_only {
        builder = builder.clear_ip_transports();
    }
    builder
        .bind()
        .await
        .map_err(|err| anyhow!("bind endpoint: {err:?}"))
}

/// A presence session with the hub over one QUIC connection.
pub struct PresenceClient {
    conn: Connection,
    send: Mutex<SendStream>,
}

impl PresenceClient {
    /// Connects and returns the client plus the stream of server frames.
    /// The receiver closes when the connection ends.
    pub async fn connect(
        endpoint: &Endpoint,
        hub: EndpointAddr,
    ) -> Result<(Self, mpsc::Receiver<ServerFrame>)> {
        let conn = endpoint
            .connect(hub, PRESENCE_ALPN)
            .await
            .map_err(|err| anyhow!("connect to hub: {err:?}"))?;
        let (send, mut recv) = conn.open_bi().await.context("open presence stream")?;
        let (tx, rx) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Ok(Some((tag, body))) = read_frame(&mut recv).await {
                match ServerFrame::decode(tag, body) {
                    Ok(frame) => {
                        if tx.send(frame).await.is_err() {
                            break;
                        }
                    }
                    Err(err) => tracing::warn!("bad server frame: {err:#}"),
                }
            }
        });
        Ok((
            Self {
                conn,
                send: Mutex::new(send),
            },
            rx,
        ))
    }

    pub async fn join(&self, context: Uuid) -> Result<()> {
        self.send(ClientFrame::Join { context }).await
    }

    pub async fn leave(&self, context: Uuid) -> Result<()> {
        self.send(ClientFrame::Leave { context }).await
    }

    pub async fn publish(&self, context: Uuid, blob: Bytes) -> Result<()> {
        self.send(ClientFrame::Publish { context, blob }).await
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
    }

    async fn send(&self, frame: ClientFrame) -> Result<()> {
        let mut send = self.send.lock().await;
        if self.conn.close_reason().is_some() {
            bail!("presence connection closed");
        }
        write_frame(&mut *send, &frame.encode()).await
    }
}
