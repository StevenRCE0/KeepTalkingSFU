//! Reference client for the SFU protocol, used by `kt-probe` and the tests.
//! The Swift SDK implements the same thing on `iroh-ffi`
//! (`Transport/Iroh/KeepTalkingIrohTransportHost.swift`).

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, SecretKey,
    endpoint::{Connection, SendStream, presets},
    tls::CaTlsConfig,
};
use tokio::sync::{Mutex, mpsc};

use crate::proto::{
    ClientFrame, SFU_ALPN, ServerFrame, Topic, datagram, read_frame, split_datagram, write_frame,
};

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

/// A session with the SFU over one QUIC connection: subscriptions,
/// presence, SFU-delivered publishes and datagrams.
pub struct SfuClient {
    conn: Connection,
    send: Mutex<SendStream>,
}

impl SfuClient {
    /// Connects and returns the client plus the stream of server frames.
    /// The receiver closes when the connection ends.
    pub async fn connect(
        endpoint: &Endpoint,
        sfu: EndpointAddr,
    ) -> Result<(Self, mpsc::Receiver<ServerFrame>)> {
        let conn = endpoint
            .connect(sfu, SFU_ALPN)
            .await
            .map_err(|err| anyhow!("connect to sfu: {err:?}"))?;
        let (send, mut recv) = conn.open_bi().await.context("open sfu stream")?;
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

    pub async fn subscribe(&self, topic: Topic) -> Result<()> {
        self.send(ClientFrame::Subscribe { topic }).await
    }

    pub async fn unsubscribe(&self, topic: Topic) -> Result<()> {
        self.send(ClientFrame::Unsubscribe { topic }).await
    }

    pub async fn announce(&self, topic: Topic, blob: Bytes) -> Result<()> {
        self.send(ClientFrame::Announce { topic, blob }).await
    }

    /// Reliable fan-out to every other subscriber of `topic`.
    pub async fn publish(&self, topic: Topic, payload: Bytes) -> Result<()> {
        self.send(ClientFrame::Publish { topic, payload }).await
    }

    /// Best-effort fan-out of one datagram to every other subscriber.
    pub fn send_datagram(&self, topic: &Topic, payload: &[u8]) -> Result<()> {
        self.conn
            .send_datagram(datagram(topic, payload))
            .map_err(|err| anyhow!("sfu datagram: {err:?}"))
    }

    /// Next datagram forwarded by the SFU.
    pub async fn read_datagram(&self) -> Result<(Topic, Bytes)> {
        loop {
            let raw = self.conn.read_datagram().await?;
            if let Some(split) = split_datagram(raw) {
                return Ok(split);
            }
        }
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
            bail!("sfu connection closed");
        }
        write_frame(&mut *send, &frame.encode()).await
    }
}
