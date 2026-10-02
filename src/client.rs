//! Reference client for the SFU protocol, used by `kt-probe` and the tests.
//! The Swift SDK implements the same thing on `iroh-ffi`
//! (`Transport/Iroh/KeepTalkingIrohTransportHost.swift`).
//!
//! One connection carries the session stream (opened first, room
//! management), a long-lived control and interactive lane stream each
//! (opened on first use), one stream per bulk publish, and the SFU's own
//! lane streams, whose DELIVERs come out of [`Inbox::deliveries`] tagged
//! with their lane.

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
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, SecretKey,
    endpoint::{Connection, QuicTransportConfig, SendStream, presets},
    tls::CaTlsConfig,
};
use tokio::{
    io::AsyncRead,
    sync::{Mutex, mpsc},
};
use tracing::debug;

use crate::proto::{
    ClientFrame, Lane, MAX_MEMBERS_PER_TOPIC, Member, SFU_ALPN, ServerFrame, Topic, datagram,
    priority, read_frame, read_lane_byte, split_datagram, write_frame,
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
    /// QUIC transport settings; `None` keeps iroh's defaults. An SFU client
    /// must accept at least 18 concurrent incoming uni streams (the SFU's
    /// two long-lived lanes plus its 16 bulk streams); the default is 100.
    pub transport: Option<QuicTransportConfig>,
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
    if let Some(transport) = options.transport {
        builder = builder.transport_config(transport);
    }
    builder
        .bind()
        .await
        .map_err(|err| anyhow!("bind endpoint: {err:?}"))
}

/// A DELIVER and the lane it arrived on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Delivery {
    pub lane: Lane,
    pub topic: Topic,
    pub payload: Bytes,
}

/// What the SFU sends a client, by where it arrives. Both receivers close
/// when the connection ends.
pub struct Inbox {
    /// Session-stream frames: SNAPSHOT (assembled from its chunks, `more ==
    /// false`), JOINED, LEFT, PRESENCE and ERROR.
    pub frames: mpsc::Receiver<ServerFrame>,
    /// DELIVERs from every SFU lane stream.
    pub deliveries: mpsc::Receiver<Delivery>,
}

/// A session with the SFU over one QUIC connection: subscriptions,
/// presence, SFU-delivered publishes and datagrams.
pub struct SfuClient {
    conn: Connection,
    session: Mutex<SendStream>,
    /// The long-lived control and interactive lane streams, opened on first
    /// use and replaced if a write on one fails.
    lanes: [Mutex<Option<SendStream>>; 2],
    skipped: Arc<AtomicU64>,
}

impl SfuClient {
    /// Connects, opens the session stream and starts accepting the SFU's
    /// lane streams. The SFU only sees the session stream once a frame is
    /// sent on it, so subscribe within its open timeout (10 s).
    pub async fn connect(endpoint: &Endpoint, sfu: EndpointAddr) -> Result<(Self, Inbox)> {
        let conn = endpoint
            .connect(sfu, SFU_ALPN)
            .await
            .map_err(|err| anyhow!("connect to sfu: {err:?}"))?;
        let (send, recv) = conn.open_bi().await.context("open sfu session stream")?;
        let _ = send.set_priority(priority::SESSION);
        let (frames_tx, frames) = mpsc::channel(256);
        let (deliveries_tx, deliveries) = mpsc::channel(256);
        let skipped = Arc::new(AtomicU64::new(0));
        tokio::spawn(pump_frames(recv, frames_tx, skipped.clone()));
        tokio::spawn(accept_lanes(conn.clone(), deliveries_tx, skipped.clone()));
        Ok((
            Self {
                conn,
                session: Mutex::new(send),
                lanes: [Mutex::new(None), Mutex::new(None)],
                skipped,
            },
            Inbox { frames, deliveries },
        ))
    }

    pub async fn subscribe(&self, topic: Topic) -> Result<()> {
        self.send_session(ClientFrame::Subscribe { topic }).await
    }

    pub async fn unsubscribe(&self, topic: Topic) -> Result<()> {
        self.send_session(ClientFrame::Unsubscribe { topic }).await
    }

    pub async fn announce(&self, topic: Topic, blob: Bytes) -> Result<()> {
        self.send_session(ClientFrame::Announce { topic, blob })
            .await
    }

    /// Reliable fan-out on `lane` to every other subscriber of `topic`.
    /// Publish only once the topic's SNAPSHOT has arrived: lane streams are
    /// not ordered against the session stream.
    pub async fn publish(&self, lane: Lane, topic: Topic, payload: Bytes) -> Result<()> {
        self.send_lane(lane, ClientFrame::Publish { topic, payload })
            .await
    }

    /// Reliable delivery on `lane` to `recipient` alone, which must be
    /// another subscriber of `topic` (else `ERROR(topic, "no such
    /// recipient")`).
    pub async fn publish_to(
        &self,
        lane: Lane,
        topic: Topic,
        recipient: EndpointId,
        payload: Bytes,
    ) -> Result<()> {
        self.send_lane(
            lane,
            ClientFrame::PublishTo {
                topic,
                recipient,
                payload,
            },
        )
        .await
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

    /// Server frames (and lane streams) skipped so far because they were
    /// unknown, malformed or on the wrong kind of stream.
    pub fn skipped_frames(&self) -> u64 {
        self.skipped.load(Ordering::Relaxed)
    }

    pub fn connection(&self) -> &Connection {
        &self.conn
    }

    pub fn close(&self) {
        self.conn.close(0u32.into(), b"bye");
    }

    fn ensure_open(&self) -> Result<()> {
        if self.conn.close_reason().is_some() {
            bail!("sfu connection closed");
        }
        Ok(())
    }

    async fn send_session(&self, frame: ClientFrame) -> Result<()> {
        let mut send = self.session.lock().await;
        self.ensure_open()?;
        write_frame(&mut *send, &frame.encode()).await
    }

    async fn send_lane(&self, lane: Lane, frame: ClientFrame) -> Result<()> {
        self.ensure_open()?;
        let frame = frame.encode();
        if lane == Lane::Bulk {
            // One stream per bulk frame, finished right after it.
            let mut send = self.conn.open_uni().await.context("open bulk stream")?;
            let _ = send.set_priority(lane.priority());
            send.write_all_chunks(&mut [lane.prefix(), frame])
                .await
                .context("write bulk stream")?;
            send.finish().context("finish bulk stream")?;
            return Ok(());
        }
        let mut slot = self.lanes[lane.index()].lock().await;
        let written = match slot.as_mut() {
            Some(send) => send.write_chunk(frame).await,
            None => {
                let mut send = self
                    .conn
                    .open_uni()
                    .await
                    .with_context(|| format!("open {lane} stream"))?;
                let _ = send.set_priority(lane.priority());
                let written = send.write_all_chunks(&mut [lane.prefix(), frame]).await;
                *slot = Some(send);
                written
            }
        };
        if written.is_err() {
            *slot = None;
        }
        written.with_context(|| format!("write {lane} stream"))
    }
}

/// Reads session frames into `tx` until the stream ends, the framing breaks
/// or the receiver goes away. Unknown or malformed frames, and DELIVERs
/// (which belong on lane streams), are skipped and counted in `skipped`;
/// snapshot chunks are merged per topic and handed out once the chunk
/// without MORE arrives.
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
                debug!("sfu session stream ended: {err:#}");
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
            Ok(ServerFrame::Deliver { .. }) => {
                skipped.fetch_add(1, Ordering::Relaxed);
                debug!("skipping a DELIVER on the session stream");
                continue;
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

/// Accepts the SFU's lane streams until the connection ends.
async fn accept_lanes(conn: Connection, tx: mpsc::Sender<Delivery>, skipped: Arc<AtomicU64>) {
    while let Ok(recv) = conn.accept_uni().await {
        tokio::spawn(pump_lane(recv, tx.clone(), skipped.clone()));
    }
}

/// Reads one SFU lane stream: its lane byte, then DELIVERs into `tx` (one,
/// on a bulk stream). A stream with an unknown lane is dropped, and frames
/// other than DELIVER are skipped; both count in `skipped`.
pub async fn pump_lane<R: AsyncRead + Unpin>(
    mut recv: R,
    tx: mpsc::Sender<Delivery>,
    skipped: Arc<AtomicU64>,
) {
    let lane = match read_lane_byte(&mut recv).await {
        Ok(Some(byte)) => match Lane::from_byte(byte) {
            Some(lane) => lane,
            None => {
                skipped.fetch_add(1, Ordering::Relaxed);
                return debug!("dropping an sfu stream with unknown lane 0x{byte:02x}");
            }
        },
        _ => return,
    };
    loop {
        let (tag, body) = match read_frame(&mut recv).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(err) => {
                debug!("sfu {lane} stream ended: {err:#}");
                break;
            }
        };
        match ServerFrame::decode(tag, body) {
            Ok(ServerFrame::Deliver { topic, payload }) => {
                let delivery = Delivery {
                    lane,
                    topic,
                    payload,
                };
                if tx.send(delivery).await.is_err() {
                    break;
                }
            }
            Ok(_) => {
                skipped.fetch_add(1, Ordering::Relaxed);
                debug!("skipping a session frame on the {lane} lane");
            }
            Err(err) => {
                skipped.fetch_add(1, Ordering::Relaxed);
                debug!("skipping server frame 0x{tag:02x}: {err:#}");
            }
        }
        if lane == Lane::Bulk {
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

    /// Unknown tags, malformed bodies and DELIVERs are skipped; chunked
    /// snapshots arrive merged; a bad length prefix ends the stream.
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
        // A DELIVER belongs on a lane stream.
        wire.extend_from_slice(
            &ServerFrame::Deliver {
                topic,
                payload: Bytes::from_static(b"misrouted"),
            }
            .encode(),
        );
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
        assert_eq!(skipped.load(Ordering::Relaxed), 3);
    }

    fn deliver(topic: Topic, payload: &'static [u8]) -> Bytes {
        ServerFrame::Deliver {
            topic,
            payload: Bytes::from_static(payload),
        }
        .encode()
    }

    /// Lane streams yield their DELIVERs tagged with the lane; a bulk stream
    /// yields one; other frames and unknown lanes are skipped.
    #[tokio::test]
    async fn pump_lane_tags_deliveries() {
        let topic = Topic([7; 32]);
        let mut control = vec![Lane::Control.byte()];
        control.extend_from_slice(&deliver(topic, b"one"));
        control.extend_from_slice(
            &ServerFrame::Joined {
                topic,
                id: member(1).id,
            }
            .encode(),
        );
        control.extend_from_slice(&deliver(topic, b"two"));
        let mut bulk = vec![Lane::Bulk.byte()];
        bulk.extend_from_slice(&deliver(topic, b"big"));
        bulk.extend_from_slice(&deliver(topic, b"ignored"));

        let (tx, mut rx) = mpsc::channel(16);
        let skipped = Arc::new(AtomicU64::new(0));
        pump_lane(&control[..], tx.clone(), skipped.clone()).await;
        pump_lane(&bulk[..], tx.clone(), skipped.clone()).await;
        pump_lane(&[0x09, 1, 2][..], tx.clone(), skipped.clone()).await;
        drop(tx);

        let got: Vec<(Lane, Bytes)> = std::iter::from_fn(|| rx.try_recv().ok())
            .map(|d| (d.lane, d.payload))
            .collect();
        assert_eq!(
            got,
            vec![
                (Lane::Control, Bytes::from_static(b"one")),
                (Lane::Control, Bytes::from_static(b"two")),
                (Lane::Bulk, Bytes::from_static(b"big")),
            ]
        );
        assert_eq!(skipped.load(Ordering::Relaxed), 2);
    }
}
