//! The service: an embedded iroh relay plus an SFU endpoint that keeps one
//! room per topic. The SFU relays presence blobs and, for senders that pick
//! SFU delivery, fans each published payload (and datagram) out to the rest
//! of the room. Peers that pick mesh delivery talk over their own iroh
//! connections, relayed through the embedded relay until they go direct.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, presets},
    tls::CaTlsConfig,
};
use iroh_relay::{
    RelayQuicConfig,
    server::{CertConfig, QuicConfig, RelayConfig, Server as RelayServer, ServerConfig, TlsConfig},
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, info, warn};

use crate::proto::{
    ClientFrame, FrameLengthError, MAX_ANNOUNCE_LEN, MAX_MEMBERS_PER_TOPIC, MAX_PUBLISH_LEN,
    MAX_TOPICS_PER_CONNECTION, Member, SFU_ALPN, SNAPSHOT_CHUNK_BYTES, SNAPSHOT_CHUNK_ENTRIES,
    ServerFrame, Topic, close, encode_snapshot, read_frame, reason, split_datagram, write_frame,
};

/// Frames queued towards one client before it is dropped as too slow.
const OUTBOX_CAPACITY: usize = 1024;

/// Per-room and per-connection bounds. The defaults are the protocol's;
/// tests lower them.
#[derive(Debug, Clone)]
pub struct Limits {
    pub max_members_per_topic: usize,
    pub max_topics_per_connection: usize,
    pub snapshot_chunk_entries: usize,
    pub snapshot_chunk_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_members_per_topic: MAX_MEMBERS_PER_TOPIC,
            max_topics_per_connection: MAX_TOPICS_PER_CONNECTION,
            snapshot_chunk_entries: SNAPSHOT_CHUNK_ENTRIES,
            snapshot_chunk_bytes: SNAPSHOT_CHUNK_BYTES,
        }
    }
}

pub struct SfuConfig {
    /// Plain-HTTP listener (captive-portal probes; everything when TLS is off).
    pub relay_http_bind: SocketAddr,
    /// HTTPS listener serving `/relay`.
    pub relay_https_bind: SocketAddr,
    /// QUIC address-discovery listener. `None` disables QAD.
    pub relay_quic_bind: Option<SocketAddr>,
    pub cert: CertConfig,
    /// URL clients use for the relay. Defaults to `https://<https addr>`,
    /// which only makes sense for local development.
    pub public_relay_url: Option<RelayUrl>,
    /// QAD port clients use. Defaults to the bound QUIC port.
    pub public_quic_port: Option<u16>,
    /// UDP sockets for the SFU endpoint. Empty = OS default.
    pub sfu_bind: Vec<SocketAddr>,
    pub sfu_secret: SecretKey,
    /// Trust anchors the SFU uses to reach its own relay. `None` = web PKI.
    pub sfu_ca: Option<CaTlsConfig>,
    pub limits: Limits,
}

pub struct Sfu {
    relay: RelayServer,
    endpoint: Endpoint,
    relay_url: RelayUrl,
    relay_map: RelayMap,
    rooms: Arc<Rooms>,
    stats: Arc<Stats>,
    accept_task: JoinHandle<()>,
}

/// Running totals since start, for logs and diagnostics.
#[derive(Default)]
pub struct Stats {
    pub published: AtomicU64,
    pub delivered: AtomicU64,
    pub datagrams_in: AtomicU64,
    pub datagrams_out: AtomicU64,
    /// Client frames skipped for an unknown tag or a malformed body.
    pub malformed: AtomicU64,
}

impl Sfu {
    pub async fn spawn(config: SfuConfig) -> Result<Self> {
        let mut relay = RelayConfig::new(config.relay_http_bind);
        relay.tls = Some(TlsConfig::new(config.relay_https_bind, config.cert));
        relay.key_cache_capacity = Some(4096);
        let mut server = ServerConfig::default();
        server.relay = Some(relay);
        server.quic = config.relay_quic_bind.map(QuicConfig::new);
        let relay = RelayServer::spawn(server)
            .await
            .map_err(|err| anyhow!("relay: {err:?}"))?;

        let relay_url = match config.public_relay_url {
            Some(url) => url,
            None => {
                let addr = relay.https_addr().context("relay has no https listener")?;
                format!("https://{addr}").parse()?
            }
        };
        let quic_port = config
            .public_quic_port
            .or(relay.quic_addr().map(|addr| addr.port()));
        let relay_map: RelayMap =
            iroh::RelayConfig::new(relay_url.clone(), quic_port.map(RelayQuicConfig::new)).into();

        let mut endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(config.sfu_secret)
            .alpns(vec![SFU_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()));
        if let Some(ca) = config.sfu_ca {
            endpoint = endpoint.ca_tls_config(ca);
        }
        for addr in config.sfu_bind {
            endpoint = endpoint
                .bind_addr(addr)
                .map_err(|err| anyhow!("sfu bind {addr}: {err:?}"))?;
        }
        let endpoint = endpoint
            .bind()
            .await
            .map_err(|err| anyhow!("sfu endpoint: {err:?}"))?;

        let rooms = Arc::new(Rooms::new(config.limits));
        let stats = Arc::new(Stats::default());
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), rooms.clone(), stats.clone()));
        info!(sfu = %endpoint.id(), relay = %relay_url, "sfu up");
        Ok(Self {
            relay,
            endpoint,
            relay_url,
            relay_map,
            rooms,
            stats,
            accept_task,
        })
    }

    pub fn sfu_id(&self) -> EndpointId {
        self.endpoint.id()
    }

    /// The SFU address clients dial: its id plus the relay. Direct paths
    /// are discovered by iroh once connected.
    pub fn sfu_addr(&self) -> EndpointAddr {
        EndpointAddr::new(self.endpoint.id()).with_relay_url(self.relay_url.clone())
    }

    pub fn relay_url(&self) -> &RelayUrl {
        &self.relay_url
    }

    pub fn relay_map(&self) -> &RelayMap {
        &self.relay_map
    }

    pub fn relay_https_addr(&self) -> Option<SocketAddr> {
        self.relay.https_addr()
    }

    pub fn relay_quic_addr(&self) -> Option<SocketAddr> {
        self.relay.quic_addr()
    }

    pub fn sfu_sockets(&self) -> Vec<SocketAddr> {
        self.endpoint.bound_sockets()
    }

    /// Current subscribers of a topic, for diagnostics and tests.
    pub fn members(&self, topic: Topic) -> Vec<EndpointId> {
        self.rooms.members(topic)
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// A shared handle on the running totals, for background reporting.
    pub fn stats_handle(&self) -> Arc<Stats> {
        self.stats.clone()
    }

    /// (rooms, subscriptions) right now.
    pub fn occupancy(&self) -> (usize, usize) {
        self.rooms.occupancy()
    }

    /// Resolves when the relay stops on its own (it should not).
    pub async fn relay_stopped(&mut self) {
        let _ = self.relay.join().await;
    }

    pub async fn shutdown(self) -> Result<()> {
        self.accept_task.abort();
        self.endpoint.close().await;
        self.relay
            .shutdown()
            .await
            .map_err(|err| anyhow!("relay shutdown: {err:?}"))
    }
}

async fn accept_loop(endpoint: Endpoint, rooms: Arc<Rooms>, stats: Arc<Stats>) {
    while let Some(incoming) = endpoint.accept().await {
        let rooms = rooms.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    debug!("handshake failed: {err:?}");
                    return;
                }
            };
            let peer = conn.remote_id();
            if let Err(err) = serve_connection(conn, &rooms, &stats).await {
                debug!(peer = %peer.fmt_short(), "connection ended: {err:#}");
            }
        });
    }
}

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

async fn serve_connection(conn: Connection, rooms: &Arc<Rooms>, stats: &Arc<Stats>) -> Result<()> {
    let peer = conn.remote_id();
    let conn_id = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
    let (mut send, mut recv) = conn.accept_bi().await?;
    debug!(peer = %peer.fmt_short(), conn_id, "sfu stream open");

    let (tx, mut rx) = mpsc::channel::<Bytes>(OUTBOX_CAPACITY);
    let writer = tokio::spawn(async move {
        while let Some(frame) = rx.recv().await {
            if write_frame(&mut send, &frame).await.is_err() {
                break;
            }
        }
        let _ = send.finish();
    });

    let handle = MemberHandle {
        peer,
        conn_id,
        tx,
        conn: conn.clone(),
    };
    let datagrams = tokio::spawn(datagram_loop(handle.clone(), rooms.clone(), stats.clone()));
    let mut subscribed = HashSet::new();
    let result = read_loop(&mut recv, &handle, &mut subscribed, rooms, stats).await;

    datagrams.abort();
    for topic in subscribed {
        rooms.leave(topic, &handle);
    }
    drop(handle);
    if let Err(err) = &result
        && let Some(bad) = err.downcast_ref::<FrameLengthError>()
    {
        // The stream cannot be resynchronised after a bad length prefix.
        conn.close(close::PROTOCOL.into(), bad.to_string().as_bytes());
    }
    let _ = writer.await;
    result
}

async fn read_loop(
    recv: &mut iroh::endpoint::RecvStream,
    handle: &MemberHandle,
    subscribed: &mut HashSet<Topic>,
    rooms: &Rooms,
    stats: &Stats,
) -> Result<()> {
    while let Some((tag, body)) = read_frame(recv).await? {
        let frame = match ClientFrame::decode(tag, body) {
            Ok(frame) => frame,
            Err(err) => {
                // Skip it; the stream is still in sync.
                stats.malformed.fetch_add(1, Ordering::Relaxed);
                debug!(peer = %handle.peer.fmt_short(), "skipping client frame 0x{tag:02x}: {err:#}");
                handle.error(None, format!("malformed frame 0x{tag:02x}: {err:#}"));
                continue;
            }
        };
        match frame {
            ClientFrame::Subscribe { topic } => {
                if subscribed.contains(&topic) {
                    // Already subscribed: no second snapshot.
                } else if topic.is_zero() {
                    handle.error(Some(topic), reason::RESERVED_TOPIC.into());
                } else if subscribed.len() >= rooms.limits.max_topics_per_connection {
                    handle.error(Some(topic), reason::TOO_MANY_TOPICS.into());
                } else if rooms.join(topic, handle) {
                    subscribed.insert(topic);
                } else {
                    handle.error(Some(topic), reason::ROOM_FULL.into());
                }
            }
            ClientFrame::Unsubscribe { topic } => {
                if subscribed.remove(&topic) {
                    rooms.leave(topic, handle);
                }
            }
            ClientFrame::Announce { topic, blob } => {
                if blob.len() > MAX_ANNOUNCE_LEN {
                    handle.error(Some(topic), reason::ANNOUNCE_TOO_LARGE.into());
                } else if !subscribed.contains(&topic) {
                    handle.error(Some(topic), reason::NOT_SUBSCRIBED.into());
                } else {
                    rooms.announce(topic, handle, blob);
                }
            }
            ClientFrame::Publish { topic, payload } => {
                if payload.len() > MAX_PUBLISH_LEN {
                    handle.error(Some(topic), reason::PUBLISH_TOO_LARGE.into());
                } else if !subscribed.contains(&topic) {
                    handle.error(Some(topic), reason::NOT_SUBSCRIBED.into());
                } else {
                    let fanout = rooms.publish(topic, handle, payload);
                    stats.published.fetch_add(1, Ordering::Relaxed);
                    stats.delivered.fetch_add(fanout as u64, Ordering::Relaxed);
                }
            }
        }
    }
    Ok(())
}

/// Forwards each `topic ‖ payload` datagram to the topic's other
/// subscribers, best effort. Datagrams for topics the sender is not
/// subscribed to are dropped.
async fn datagram_loop(handle: MemberHandle, rooms: Arc<Rooms>, stats: Arc<Stats>) {
    while let Ok(datagram) = handle.conn.read_datagram().await {
        stats.datagrams_in.fetch_add(1, Ordering::Relaxed);
        let Some((topic, _)) = split_datagram(datagram.clone()) else {
            continue;
        };
        for conn in rooms.datagram_targets(topic, &handle) {
            if conn.send_datagram(datagram.clone()).is_ok() {
                stats.datagrams_out.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The sending half of one client connection.
#[derive(Clone)]
struct MemberHandle {
    peer: EndpointId,
    conn_id: u64,
    tx: mpsc::Sender<Bytes>,
    conn: Connection,
}

impl MemberHandle {
    /// Queues a frame without blocking. A client that stops reading is
    /// disconnected rather than allowed to stall the room.
    fn deliver(&self, frame: Bytes) {
        match self.tx.try_send(frame) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                warn!(peer = %self.peer.fmt_short(), "outbox full, dropping slow client");
                self.conn.close(1u32.into(), b"slow consumer");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    }

    fn error(&self, topic: Option<Topic>, reason: String) {
        self.deliver(ServerFrame::Error { topic, reason }.encode());
    }
}

struct Slot {
    handle: MemberHandle,
    blob: Bytes,
}

type Room = HashMap<EndpointId, Slot>;

/// Rooms keyed by topic, members keyed by endpoint id. Every mutation and
/// the frames it causes happen under one lock, so each client sees a room's
/// events in a consistent order (snapshot first).
struct Rooms {
    inner: Mutex<HashMap<Topic, Room>>,
    limits: Limits,
}

impl Rooms {
    fn new(mut limits: Limits) -> Self {
        limits.max_members_per_topic = limits.max_members_per_topic.max(1);
        Self {
            inner: Mutex::default(),
            limits,
        }
    }

    /// Adds the connection to the room and sends it the snapshot. Returns
    /// false, changing nothing, if the room is full.
    fn join(&self, topic: Topic, handle: &MemberHandle) -> bool {
        let mut rooms = self.inner.lock().expect("rooms lock");
        let room = rooms.entry(topic).or_default();
        // A newer connection from the same endpoint takes its slot over;
        // that does not grow the room. (A new room is never full: the limit
        // is at least 1.)
        if !room.contains_key(&handle.peer) && room.len() >= self.limits.max_members_per_topic {
            return false;
        }
        room.insert(
            handle.peer,
            Slot {
                handle: handle.clone(),
                blob: Bytes::new(),
            },
        );
        let members: Vec<Member> = room
            .iter()
            .filter(|(id, _)| **id != handle.peer)
            .map(|(id, slot)| Member {
                id: *id,
                blob: slot.blob.clone(),
            })
            .collect();
        for chunk in encode_snapshot(
            topic,
            &members,
            self.limits.snapshot_chunk_entries,
            self.limits.snapshot_chunk_bytes,
        ) {
            handle.deliver(chunk);
        }
        broadcast(
            room,
            handle.peer,
            &ServerFrame::Joined {
                topic,
                id: handle.peer,
            },
        );
        info!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), size = room.len(), "joined");
        true
    }

    fn leave(&self, topic: Topic, handle: &MemberHandle) {
        let mut rooms = self.inner.lock().expect("rooms lock");
        let Some(room) = rooms.get_mut(&topic) else {
            return;
        };
        // Only the connection that owns the slot may vacate it.
        if room
            .get(&handle.peer)
            .is_none_or(|slot| slot.handle.conn_id != handle.conn_id)
        {
            return;
        }
        room.remove(&handle.peer);
        broadcast(
            room,
            handle.peer,
            &ServerFrame::Left {
                topic,
                id: handle.peer,
            },
        );
        info!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), size = room.len(), "left");
        if room.is_empty() {
            rooms.remove(&topic);
        }
    }

    fn announce(&self, topic: Topic, handle: &MemberHandle, blob: Bytes) {
        let mut rooms = self.inner.lock().expect("rooms lock");
        let Some(room) = rooms.get_mut(&topic) else {
            return;
        };
        match room.get_mut(&handle.peer) {
            Some(slot) if slot.handle.conn_id == handle.conn_id => slot.blob = blob.clone(),
            _ => return,
        }
        broadcast(
            room,
            handle.peer,
            &ServerFrame::Presence {
                topic,
                id: handle.peer,
                blob,
            },
        );
    }

    /// Fans a payload out to the room; returns how many members it reached.
    fn publish(&self, topic: Topic, handle: &MemberHandle, payload: Bytes) -> usize {
        let rooms = self.inner.lock().expect("rooms lock");
        let Some(room) = rooms.get(&topic) else {
            return 0;
        };
        if !owns_slot(room, handle) {
            return 0;
        }
        broadcast(room, handle.peer, &ServerFrame::Deliver { topic, payload })
    }

    /// Connections of the room's other members, if `handle` is subscribed.
    fn datagram_targets(&self, topic: Topic, handle: &MemberHandle) -> Vec<Connection> {
        let rooms = self.inner.lock().expect("rooms lock");
        let Some(room) = rooms.get(&topic) else {
            return Vec::new();
        };
        if !owns_slot(room, handle) {
            return Vec::new();
        }
        room.iter()
            .filter(|(id, _)| **id != handle.peer)
            .map(|(_, slot)| slot.handle.conn.clone())
            .collect()
    }

    fn members(&self, topic: Topic) -> Vec<EndpointId> {
        let rooms = self.inner.lock().expect("rooms lock");
        rooms
            .get(&topic)
            .map(|room| room.keys().copied().collect())
            .unwrap_or_default()
    }

    fn occupancy(&self) -> (usize, usize) {
        let rooms = self.inner.lock().expect("rooms lock");
        (rooms.len(), rooms.values().map(HashMap::len).sum())
    }
}

fn owns_slot(room: &Room, handle: &MemberHandle) -> bool {
    room.get(&handle.peer)
        .is_some_and(|slot| slot.handle.conn_id == handle.conn_id)
}

/// Sends `frame` to everyone in `room` but `except`; returns the count.
fn broadcast(room: &Room, except: EndpointId, frame: &ServerFrame) -> usize {
    let frame = frame.encode();
    let mut sent = 0;
    for (id, slot) in room {
        if *id != except {
            slot.handle.deliver(frame.clone());
            sent += 1;
        }
    }
    sent
}
