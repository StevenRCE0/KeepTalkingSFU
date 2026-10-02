//! Reference client for the SFU protocol, used by `kt-probe` and the tests.
//! The Swift SDK implements the same thing on `iroh-ffi`
//! (`Transport/Iroh/KeepTalkingIrohTransportHost.swift`).

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, anyhow, bail};
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, RelayMap, RelayMode, SecretKey,
    endpoint::{Connection, SendStream, presets},
    tls::CaTlsConfig,
};
use tokio::{
    io::AsyncRead,
    sync::{Mutex, mpsc},
};
use tracing::debug;

use crate::proto::{
    ClientFrame, MAX_MEMBERS_PER_TOPIC, Member, SFU_ALPN, ServerFrame, Topic, datagram, read_frame,
    split_datagram, write_frame,
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
    skipped: Arc<AtomicU64>,
}

impl SfuClient {
    /// Connects and returns the client plus the stream of server frames.
    /// Snapshots arrive assembled (every chunk merged, `more == false`).
    /// The receiver closes when the connection ends.
    pub async fn connect(
        endpoint: &Endpoint,
        sfu: EndpointAddr,
    ) -> Result<(Self, mpsc::Receiver<ServerFrame>)> {
        let conn = endpoint
            .connect(sfu, SFU_ALPN)
            .await
            .map_err(|err| anyhow!("connect to sfu: {err:?}"))?;
        let (send, recv) = conn.open_bi().await.context("open sfu stream")?;
        let (tx, rx) = mpsc::channel(256);
        let skipped = Arc::new(AtomicU64::new(0));
        tokio::spawn(pump_frames(recv, tx, skipped.clone()));
        Ok((
            Self {
                conn,
                send: Mutex::new(send),
                skipped,
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

    /// Server frames skipped so far because they were unknown or malformed.
    pub fn skipped_frames(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
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

/// Reads server frames into `tx` until the stream ends, the framing breaks
/// or the receiver goes away. Unknown or malformed frames are skipped and
/// counted in `skipped`; snapshot chunks are merged per topic and handed
/// out once the chunk without MORE arrives.
pub async fn pump_frames<R: AsyncRead + Unpin>(
    mut recv: R,
    tx: mpsc::Sender<ServerFrame>,
    skipped: Arc<AtomicU64>,
) {
    let mut partial: HashMap<Topic, Vec<Member>> = HashMap::new();
    loop {
        let (tag, body) = match read_frame(&mut recv).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(err) => {
                debug!("sfu stream ended: {err:#}");
                break;
            }
        };
        let frame = match ServerFrame::decode(tag, body) {
            Ok(ServerFrame::Snapshot {
                topic,
                more,
                members,
            }) => {
                let pending = partial.entry(topic).or_default();
                pending.extend(members);
                if pending.len() > 2 * MAX_MEMBERS_PER_TOPIC {
                    debug!(topic = %topic.fmt_short(), "dropping oversized snapshot");
                    partial.remove(&topic);
                    skipped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                if more {
                    continue;
                }
                ServerFrame::Snapshot {
                    topic,
                    more: false,
                    members: partial.remove(&topic).unwrap_or_default(),
                }
            }
            Ok(frame) => frame,
            Err(err) => {
                skipped.fetch_add(1, Ordering::Relaxed);
                debug!("skipping server frame 0x{tag:02x}: {err:#}");
                continue;
            }
        };
        if tx.send(frame).await.is_err() {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use bytes::BufMut;

    use super::*;
    use crate::proto::{SNAPSHOT_CHUNK_BYTES, encode_snapshot, tag};

    fn member(seed: u8) -> Member {
        Member {
            id: SecretKey::from_bytes(&[seed; 32]).public(),
            blob: Bytes::from(vec![seed; 8]),
        }
    }

    /// Unknown tags and malformed bodies are skipped; chunked snapshots
    /// arrive merged; a bad length prefix ends the stream.
    #[tokio::test]
    async fn pump_skips_garbage_and_merges_snapshots() {
        let topic = Topic([5; 32]);
        let other = Topic([6; 32]);
        let members: Vec<Member> = (1..=5).map(member).collect();
        let mut wire = Vec::new();
        // Unknown tag.
        wire.extend_from_slice(&[0, 0, 0, 4, 0x7E, 1, 2, 3]);
        // A JOINED that is too short.
        wire.extend_from_slice(&[0, 0, 0, 3, tag::JOINED, 1, 2]);
        for chunk in encode_snapshot(topic, &members, 2, SNAPSHOT_CHUNK_BYTES) {
            wire.extend_from_slice(&chunk);
        }
        for chunk in encode_snapshot(other, &[], 2, SNAPSHOT_CHUNK_BYTES) {
            wire.extend_from_slice(&chunk);
        }
        wire.extend_from_slice(
            &ServerFrame::Error {
                topic: Some(topic),
                reason: "room full".into(),
            }
            .encode(),
        );
        // Fatal: zero length. Nothing after it is read.
        wire.put_u32(0);
        wire.extend_from_slice(
            &ServerFrame::Joined {
                topic,
                id: member(9).id,
            }
            .encode(),
        );

        let (tx, mut rx) = mpsc::channel(16);
        let skipped = Arc::new(AtomicU64::new(0));
        pump_frames(&wire[..], tx, skipped.clone()).await;

        assert_eq!(
            rx.recv().await,
            Some(ServerFrame::Snapshot {
                topic,
                more: false,
                members
            })
        );
        assert_eq!(
            rx.recv().await,
            Some(ServerFrame::Snapshot {
                topic: other,
                more: false,
                members: vec![]
            })
        );
        assert_eq!(
            rx.recv().await,
            Some(ServerFrame::Error {
                topic: Some(topic),
                reason: "room full".into()
            })
        );
        assert_eq!(rx.recv().await, None);
        assert_eq!(skipped.load(Ordering::Relaxed), 2);
    }
}
