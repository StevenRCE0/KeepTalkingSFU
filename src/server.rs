//! The service: an embedded iroh relay plus an SFU endpoint that keeps one
//! room per topic. The SFU relays presence blobs and, for senders that pick
//! SFU delivery, fans each published payload (and datagram) out to the rest
//! of the room. Peers that pick mesh delivery talk over their own iroh
//! connections, relayed through the embedded relay until they go direct.
//!
//! # Resource bounds
//!
//! Anyone can connect with any key, so every per-connection resource is
//! bounded (see [`Limits`] for the numbers):
//!
//! - **Connections.** At most `max_connections` at once; beyond that new
//!   handshakes are refused. A connection must finish its handshake and open
//!   its one bidirectional stream in time or it is closed. The QUIC transport
//!   allows one bidi stream, no uni streams, and finite receive windows.
//! - **Inbound.** Frames are read incrementally (a peer must send bytes to
//!   make us allocate them). PUBLISH+ANNOUNCE, room joins and datagrams each
//!   go through a token bucket per connection.
//! - **Outbound.** Each connection has a queue bounded in bytes. A frame is
//!   encoded once and the same [`Bytes`] is queued for every recipient; a
//!   DELIVER reuses the publisher's received body. A connection whose queue
//!   goes over budget, or whose stream accepts no bytes for `stall_timeout`,
//!   is closed, so a slow reader never holds a room back.
//! - **Rooms.** Sharded by topic. A lock is held only to update membership
//!   and enqueue already-encoded frames (snapshots are encoded later, by the
//!   receiving connection's writer); logging happens outside it.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    num::NonZeroU32,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{Connection, QuicTransportConfig, RecvStream, SendStream, VarInt, presets},
    tls::CaTlsConfig,
};
use iroh_relay::{
    RelayQuicConfig,
    server::{
        CertConfig, ClientRateLimit, QuicConfig, RelayConfig, Server as RelayServer, ServerConfig,
        TlsConfig,
    },
};
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, info, warn};

use crate::proto::{
    ClientFrame, FrameLengthError, MAX_ANNOUNCE_LEN, MAX_MEMBERS_PER_TOPIC, MAX_PUBLISH_LEN,
    MAX_TOPICS_PER_CONNECTION, Member, SFU_ALPN, SNAPSHOT_CHUNK_BYTES, SNAPSHOT_CHUNK_ENTRIES,
    ServerFrame, Topic, close, encode_snapshot, frame_header, read_frame, reason,
    snapshot_wire_len, split_datagram, tag,
};

const MIB: u64 = 1024 * 1024;

/// QUIC connection receive window: unread bytes a client may have in flight
/// towards us across the connection.
const QUIC_RECEIVE_WINDOW: u32 = 4 * MIB as u32;
/// QUIC stream receive window; above one maximal frame.
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 2 * MIB as u32;
/// Unacknowledged bytes we keep in flight towards one client.
const QUIC_SEND_WINDOW: u64 = 4 * MIB;
/// Received datagrams buffered per connection before QUIC drops them.
const QUIC_DATAGRAM_RECEIVE_BUFFER: usize = 512 * 1024;
/// Room shards; topics are uniformly random, so any byte picks a shard.
const SHARDS: usize = 64;

/// A token-bucket rate: bytes and frames per second, each with a burst.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    pub bytes_per_second: f64,
    pub burst_bytes: f64,
    pub frames_per_second: f64,
    pub burst_frames: f64,
}

impl Rate {
    /// A rate on frames only.
    pub const fn frames(per_second: f64, burst: f64) -> Self {
        Self {
            bytes_per_second: f64::INFINITY,
            burst_bytes: f64::INFINITY,
            frames_per_second: per_second,
            burst_frames: burst,
        }
    }
}

/// Per-room, per-connection and global bounds. The defaults are the
/// production values; tests lower them.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Members one room may hold ([`MAX_MEMBERS_PER_TOPIC`]).
    pub max_members_per_topic: usize,
    /// Topics one connection may hold ([`MAX_TOPICS_PER_CONNECTION`]).
    pub max_topics_per_connection: usize,
    /// SNAPSHOT chunk cut points ([`SNAPSHOT_CHUNK_ENTRIES`],
    /// [`SNAPSHOT_CHUNK_BYTES`]).
    pub snapshot_chunk_entries: usize,
    pub snapshot_chunk_bytes: usize,
    /// Concurrent connections (including handshakes in progress).
    pub max_connections: usize,
    /// Time a connection has to finish its QUIC handshake.
    pub handshake_timeout: Duration,
    /// Time a connection has to open its bidirectional stream.
    pub stream_open_timeout: Duration,
    /// Bytes queued towards one connection before it is closed as a slow
    /// consumer. An empty queue always takes one frame.
    pub outbox_bytes: usize,
    /// Time the stream may accept no bytes before the connection is closed.
    pub stall_timeout: Duration,
    /// PUBLISH and ANNOUNCE a connection may send.
    pub publish_rate: Rate,
    /// Room joins (SUBSCRIBE) a connection may make. Each join costs the
    /// room a JOINED, so this bounds subscribe/unsubscribe churn.
    pub join_rate: Rate,
    /// Datagrams a connection may send for fan-out.
    pub datagram_rate: Rate,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_members_per_topic: MAX_MEMBERS_PER_TOPIC,
            max_topics_per_connection: MAX_TOPICS_PER_CONNECTION,
            snapshot_chunk_entries: SNAPSHOT_CHUNK_ENTRIES,
            snapshot_chunk_bytes: SNAPSHOT_CHUNK_BYTES,
            max_connections: 10_000,
            handshake_timeout: Duration::from_secs(15),
            stream_open_timeout: Duration::from_secs(10),
            outbox_bytes: 8 * MIB as usize,
            stall_timeout: Duration::from_secs(20),
            // The burst is half the outbox budget, so one publisher's burst
            // alone cannot push a healthy reader over it.
            publish_rate: Rate {
                bytes_per_second: (4 * MIB) as f64,
                burst_bytes: (4 * MIB) as f64,
                frames_per_second: 200.0,
                burst_frames: 400.0,
            },
            // The burst covers re-subscribing every topic after a reconnect.
            join_rate: Rate::frames(50.0, (MAX_TOPICS_PER_CONNECTION + 88) as f64),
            datagram_rate: Rate {
                bytes_per_second: MIB as f64,
                burst_bytes: (2 * MIB) as f64,
                frames_per_second: 1000.0,
                burst_frames: 2000.0,
            },
        }
    }
}

/// Per-client receive rate limit on the embedded relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRateLimit {
    pub bytes_per_second: NonZeroU32,
    pub burst_bytes: NonZeroU32,
}

impl Default for RelayRateLimit {
    /// 2 MiB/s with a 4 MiB burst.
    fn default() -> Self {
        Self {
            bytes_per_second: NonZeroU32::new(2 * MIB as u32).expect("nonzero"),
            burst_bytes: NonZeroU32::new(4 * MIB as u32).expect("nonzero"),
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
    /// Rate limit on what the relay reads from each client connection.
    /// `None` = unlimited. It applies to the SFU's own relay connection
    /// too, which carries its fan-out to relay-only clients.
    pub relay_rate_limit: Option<RelayRateLimit>,
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
    shared: Arc<Shared>,
    accept_task: JoinHandle<()>,
}

/// Counters since start (and two gauges), for logs and diagnostics.
#[derive(Default, Debug)]
pub struct Stats {
    /// Open connections right now, including handshakes in progress.
    pub connections: AtomicU64,
    /// Connections refused at the connection cap.
    pub connections_refused: AtomicU64,
    /// Connections closed for not opening their stream in time.
    pub no_stream: AtomicU64,
    /// Connections closed because their outbound queue went over budget.
    pub slow_consumers: AtomicU64,
    /// Connections closed because their stream stopped accepting bytes.
    pub stalled: AtomicU64,
    pub published: AtomicU64,
    pub delivered: AtomicU64,
    /// PUBLISH/ANNOUNCE/SUBSCRIBE refused by a rate limit.
    pub rate_limited: AtomicU64,
    /// Client frames skipped for an unknown tag or a malformed body.
    pub malformed: AtomicU64,
    pub datagrams_in: AtomicU64,
    pub datagrams_out: AtomicU64,
    /// Datagrams not forwarded: over the rate limit, malformed, or for a
    /// topic the sender has not joined.
    pub datagrams_dropped: AtomicU64,
}

impl Stats {
    fn bump(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// The current values, for logging.
    pub fn snapshot(&self) -> StatsSnapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        StatsSnapshot {
            connections: get(&self.connections),
            connections_refused: get(&self.connections_refused),
            no_stream: get(&self.no_stream),
            slow_consumers: get(&self.slow_consumers),
            stalled: get(&self.stalled),
            published: get(&self.published),
            delivered: get(&self.delivered),
            rate_limited: get(&self.rate_limited),
            malformed: get(&self.malformed),
            datagrams_in: get(&self.datagrams_in),
            datagrams_out: get(&self.datagrams_out),
            datagrams_dropped: get(&self.datagrams_dropped),
        }
    }
}

/// [`Stats`] read at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StatsSnapshot {
    pub connections: u64,
    pub connections_refused: u64,
    pub no_stream: u64,
    pub slow_consumers: u64,
    pub stalled: u64,
    pub published: u64,
    pub delivered: u64,
    pub rate_limited: u64,
    pub malformed: u64,
    pub datagrams_in: u64,
    pub datagrams_out: u64,
    pub datagrams_dropped: u64,
}

/// State every connection task shares.
struct Shared {
    rooms: Rooms,
    stats: Arc<Stats>,
    limits: Limits,
}

impl Sfu {
    pub async fn spawn(config: SfuConfig) -> Result<Self> {
        let mut relay = RelayConfig::new(config.relay_http_bind);
        relay.tls = Some(TlsConfig::new(config.relay_https_bind, config.cert));
        relay.key_cache_capacity = Some(4096);
        if let Some(limit) = config.relay_rate_limit {
            let mut client_rx = ClientRateLimit::new(limit.bytes_per_second);
            client_rx.max_burst_bytes = Some(limit.burst_bytes);
            relay.limits.client_rx = Some(client_rx);
        }
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

        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(1))
            .max_concurrent_uni_streams(VarInt::from_u32(0))
            .receive_window(VarInt::from_u32(QUIC_RECEIVE_WINDOW))
            .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
            .send_window(QUIC_SEND_WINDOW)
            .datagram_receive_buffer_size(Some(QUIC_DATAGRAM_RECEIVE_BUFFER))
            .build();
        let mut endpoint = Endpoint::builder(presets::Minimal)
            .secret_key(config.sfu_secret)
            .alpns(vec![SFU_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()))
            .transport_config(transport);
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

        let shared = Arc::new(Shared {
            rooms: Rooms::new(&config.limits),
            stats: Arc::new(Stats::default()),
            limits: config.limits,
        });
        let accept_task = tokio::spawn(accept_loop(endpoint.clone(), shared.clone()));
        info!(sfu = %endpoint.id(), relay = %relay_url, "sfu up");
        Ok(Self {
            relay,
            endpoint,
            relay_url,
            relay_map,
            shared,
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
        self.shared.rooms.members(topic)
    }

    pub fn stats(&self) -> &Stats {
        &self.shared.stats
    }

    /// A shared handle on the running totals, for background reporting.
    pub fn stats_handle(&self) -> Arc<Stats> {
        self.shared.stats.clone()
    }

    /// (rooms, subscriptions) right now.
    pub fn occupancy(&self) -> (usize, usize) {
        self.shared.rooms.occupancy()
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

/// Counts a connection against `max_connections` until dropped.
struct ConnectionSlot(Arc<Shared>);

impl ConnectionSlot {
    fn acquire(shared: &Arc<Shared>) -> Option<Self> {
        let open = shared.stats.connections.fetch_add(1, Ordering::AcqRel);
        if open >= shared.limits.max_connections as u64 {
            shared.stats.connections.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Self(shared.clone()))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.stats.connections.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn accept_loop(endpoint: Endpoint, shared: Arc<Shared>) {
    while let Some(incoming) = endpoint.accept().await {
        let Some(slot) = ConnectionSlot::acquire(&shared) else {
            Stats::bump(&shared.stats.connections_refused);
            debug!("at the connection cap, refusing a handshake");
            incoming.refuse();
            continue;
        };
        tokio::spawn(async move {
            let shared = slot.0.clone();
            let conn = match tokio::time::timeout(shared.limits.handshake_timeout, incoming).await {
                Ok(Ok(conn)) => conn,
                Ok(Err(err)) => return debug!("handshake failed: {err:?}"),
                Err(_) => return debug!("handshake timed out"),
            };
            serve_connection(conn, &shared).await;
            drop(slot);
        });
    }
}

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

async fn serve_connection(conn: Connection, shared: &Arc<Shared>) {
    let peer = conn.remote_id();
    let conn_id = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
    let limits = &shared.limits;
    let stats = &shared.stats;
    let (send, mut recv) =
        match tokio::time::timeout(limits.stream_open_timeout, conn.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(err)) => return debug!(peer = %peer.fmt_short(), "no stream: {err}"),
            Err(_) => {
                Stats::bump(&stats.no_stream);
                conn.close(close::NO_STREAM.into(), b"no stream opened");
                return debug!(peer = %peer.fmt_short(), "closed: no stream opened");
            }
        };
    debug!(peer = %peer.fmt_short(), conn_id, "sfu stream open");

    let (tx, rx) = mpsc::unbounded_channel();
    let outbox = Arc::new(Outbox {
        queued: AtomicUsize::new(0),
        budget: limits.outbox_bytes,
        overflowed: AtomicBool::new(false),
    });
    let mut writer = tokio::spawn(write_loop(
        send,
        rx,
        outbox.clone(),
        conn.clone(),
        shared.clone(),
    ));
    let handle = MemberHandle {
        peer,
        conn_id,
        tx,
        outbox: outbox.clone(),
        conn: conn.clone(),
    };
    let datagrams = tokio::spawn(datagram_loop(handle.clone(), shared.clone()));
    let mut session = Session {
        handle,
        shared,
        subscribed: HashSet::new(),
        publish_rate: Bucket::new(limits.publish_rate),
        join_rate: Bucket::new(limits.join_rate),
    };
    let result = session.read_loop(&mut recv).await;

    datagrams.abort();
    let _ = datagrams.await;
    session.leave_all();
    // Every queue handle is gone now, so the writer drains and finishes.
    drop(session);
    match &result {
        Err(err) if err.downcast_ref::<FrameLengthError>().is_some() => {
            // The stream cannot be resynchronised after a bad length prefix.
            conn.close(close::PROTOCOL.into(), err.to_string().as_bytes());
        }
        _ => {}
    }
    if tokio::time::timeout(limits.stall_timeout, &mut writer)
        .await
        .is_err()
    {
        writer.abort();
    }
    if outbox.overflowed.load(Ordering::Acquire) {
        Stats::bump(&stats.slow_consumers);
        warn!(peer = %peer.fmt_short(), conn_id, "dropped a slow consumer (outbox over budget)");
    }
    match result {
        Ok(()) => debug!(peer = %peer.fmt_short(), conn_id, "connection finished"),
        Err(err) => debug!(peer = %peer.fmt_short(), conn_id, "connection ended: {err:#}"),
    }
}

/// One connection's view: what it subscribed to and its rate budgets.
struct Session<'a> {
    handle: MemberHandle,
    shared: &'a Shared,
    subscribed: HashSet<Topic>,
    publish_rate: Bucket,
    join_rate: Bucket,
}

impl Session<'_> {
    async fn read_loop(&mut self, recv: &mut RecvStream) -> Result<()> {
        while let Some((tag, body)) = read_frame(recv).await? {
            let frame_len = 5 + body.len();
            // PUBLISH's body is `topic ‖ payload`, exactly DELIVER's body:
            // keep it to forward without copying.
            let raw = body.clone();
            match ClientFrame::decode(tag, body) {
                Ok(frame) => self.handle_frame(frame, raw, frame_len),
                Err(err) => {
                    // Skip it; the stream is still in sync.
                    Stats::bump(&self.shared.stats.malformed);
                    debug!(peer = %self.handle.peer.fmt_short(), "skipping client frame 0x{tag:02x}: {err:#}");
                    self.handle
                        .error(None, format!("malformed frame 0x{tag:02x}: {err:#}"));
                }
            }
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: ClientFrame, raw: Bytes, frame_len: usize) {
        let (rooms, stats, limits) = (&self.shared.rooms, &self.shared.stats, &self.shared.limits);
        let handle = &self.handle;
        match frame {
            ClientFrame::Subscribe { topic } => {
                if self.subscribed.contains(&topic) {
                    // Already subscribed: no second snapshot.
                } else if topic.is_zero() {
                    handle.error(Some(topic), reason::RESERVED_TOPIC);
                } else if self.subscribed.len() >= limits.max_topics_per_connection {
                    handle.error(Some(topic), reason::TOO_MANY_TOPICS);
                } else if !self.join_rate.try_take(0) {
                    Stats::bump(&stats.rate_limited);
                    handle.error(Some(topic), reason::RATE_LIMITED);
                } else {
                    match rooms.join(topic, handle) {
                        Some(size) => {
                            self.subscribed.insert(topic);
                            debug!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), size, "joined");
                        }
                        None => handle.error(Some(topic), reason::ROOM_FULL),
                    }
                }
            }
            ClientFrame::Unsubscribe { topic } => {
                if self.subscribed.remove(&topic)
                    && let Some(size) = rooms.leave(topic, handle)
                {
                    debug!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), size, "left");
                }
            }
            ClientFrame::Announce { topic, blob } => {
                if blob.len() > MAX_ANNOUNCE_LEN {
                    handle.error(Some(topic), reason::ANNOUNCE_TOO_LARGE);
                } else if !self.subscribed.contains(&topic) {
                    handle.error(Some(topic), reason::NOT_SUBSCRIBED);
                } else if !self.publish_rate.try_take(frame_len) {
                    Stats::bump(&stats.rate_limited);
                    handle.error(Some(topic), reason::RATE_LIMITED);
                } else if rooms.announce(topic, handle, blob) {
                    debug!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), "announced");
                }
            }
            ClientFrame::Publish { topic, payload } => {
                if payload.len() > MAX_PUBLISH_LEN {
                    handle.error(Some(topic), reason::PUBLISH_TOO_LARGE);
                } else if !self.subscribed.contains(&topic) {
                    handle.error(Some(topic), reason::NOT_SUBSCRIBED);
                } else if !self.publish_rate.try_take(frame_len) {
                    Stats::bump(&stats.rate_limited);
                    handle.error(Some(topic), reason::RATE_LIMITED);
                } else {
                    let fanout = rooms.publish(topic, handle, raw);
                    Stats::bump(&stats.published);
                    stats.delivered.fetch_add(fanout as u64, Ordering::Relaxed);
                }
            }
        }
    }

    fn leave_all(&mut self) {
        for topic in self.subscribed.drain() {
            self.shared.rooms.leave(topic, &self.handle);
        }
    }
}

/// Forwards each `topic ‖ payload` datagram to the topic's other
/// subscribers, best effort. Datagrams over the rate limit or for topics the
/// sender has not joined are dropped.
async fn datagram_loop(handle: MemberHandle, shared: Arc<Shared>) {
    let stats = &shared.stats;
    let mut rate = Bucket::new(shared.limits.datagram_rate);
    while let Ok(datagram) = handle.conn.read_datagram().await {
        Stats::bump(&stats.datagrams_in);
        let targets = if rate.try_take(datagram.len()) {
            split_datagram(datagram.clone())
                .and_then(|(topic, _)| shared.rooms.datagram_targets(topic, &handle))
        } else {
            None
        };
        let Some(targets) = targets else {
            Stats::bump(&stats.datagrams_dropped);
            continue;
        };
        for conn in targets {
            if conn.send_datagram(datagram.clone()).is_ok() {
                Stats::bump(&stats.datagrams_out);
            }
        }
    }
}

/// Something queued towards one client.
enum Outgoing {
    /// An encoded frame, shared with every other recipient.
    Frame(Bytes),
    /// A frame as header plus a body shared with the sender's read buffer.
    Parts(Bytes, Bytes),
    /// A room snapshot, encoded into chunks by the writer.
    Snapshot { topic: Topic, members: Vec<Member> },
}

struct Queued {
    item: Outgoing,
    /// What the item counts against the byte budget.
    size: usize,
}

/// Byte accounting for one connection's queue.
struct Outbox {
    queued: AtomicUsize,
    budget: usize,
    overflowed: AtomicBool,
}

/// The sending half of one client connection, as rooms hold it.
#[derive(Clone)]
struct MemberHandle {
    peer: EndpointId,
    conn_id: u64,
    tx: mpsc::UnboundedSender<Queued>,
    outbox: Arc<Outbox>,
    conn: Connection,
}

impl MemberHandle {
    /// Queues an item without blocking. A client whose queue goes over its
    /// byte budget is disconnected rather than allowed to stall the room.
    /// Never logs: callers may hold a room lock.
    fn push(&self, item: Outgoing, size: usize) {
        let outbox = &*self.outbox;
        if outbox.overflowed.load(Ordering::Acquire) {
            return;
        }
        let before = outbox.queued.fetch_add(size, Ordering::AcqRel);
        if before > 0 && before + size > outbox.budget {
            outbox.queued.fetch_sub(size, Ordering::AcqRel);
            if !outbox.overflowed.swap(true, Ordering::AcqRel) {
                self.conn
                    .close(close::SLOW_CONSUMER.into(), b"slow consumer");
            }
            return;
        }
        if self.tx.send(Queued { item, size }).is_err() {
            outbox.queued.fetch_sub(size, Ordering::AcqRel);
        }
    }

    fn push_frame(&self, frame: Bytes) {
        let size = frame.len();
        self.push(Outgoing::Frame(frame), size);
    }

    fn error(&self, topic: Option<Topic>, reason: impl Into<String>) {
        self.push_frame(
            ServerFrame::Error {
                topic,
                reason: reason.into(),
            }
            .encode(),
        );
    }
}

/// Writes queued items to the stream until every queue handle is gone. A
/// write that makes no progress for `stall_timeout` closes the connection.
async fn write_loop(
    mut send: SendStream,
    mut rx: mpsc::UnboundedReceiver<Queued>,
    outbox: Arc<Outbox>,
    conn: Connection,
    shared: Arc<Shared>,
) {
    let limits = &shared.limits;
    while let Some(Queued { item, size }) = rx.recv().await {
        let written = match item {
            Outgoing::Frame(frame) => write_chunks(&mut send, &mut [frame], limits).await,
            Outgoing::Parts(head, body) => write_chunks(&mut send, &mut [head, body], limits).await,
            Outgoing::Snapshot { topic, members } => {
                let mut chunks = encode_snapshot(
                    topic,
                    &members,
                    limits.snapshot_chunk_entries,
                    limits.snapshot_chunk_bytes,
                );
                drop(members);
                write_chunks(&mut send, &mut chunks, limits).await
            }
        };
        outbox.queued.fetch_sub(size, Ordering::AcqRel);
        match written {
            Ok(()) => {}
            Err(WriteFailure::Closed) => return,
            Err(WriteFailure::Stalled) => {
                Stats::bump(&shared.stats.stalled);
                conn.close(close::STALLED.into(), b"stalled");
                warn!(peer = %conn.remote_id().fmt_short(), "dropped a stalled consumer (no write progress)");
                return;
            }
        }
    }
    let _ = send.finish();
}

enum WriteFailure {
    Closed,
    Stalled,
}

async fn write_chunks(
    send: &mut SendStream,
    chunks: &mut [Bytes],
    limits: &Limits,
) -> Result<(), WriteFailure> {
    let mut rest = chunks;
    while !rest.is_empty() {
        // Cancel-safe: on timeout nothing more was written.
        match tokio::time::timeout(limits.stall_timeout, send.write_many_chunks(&mut rest)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return Err(WriteFailure::Closed),
            Err(_) => return Err(WriteFailure::Stalled),
        }
    }
    Ok(())
}

struct Slot {
    handle: MemberHandle,
    blob: Bytes,
}

type Room = HashMap<EndpointId, Slot>;

/// Rooms keyed by topic, members keyed by endpoint id, sharded by topic.
/// Every membership change and the frames it causes are queued under the
/// room's shard lock, so each client sees a room's events in a consistent
/// order (snapshot first). Frames are encoded before taking the lock (a
/// snapshot by the receiving writer) and nothing logs under it.
struct Rooms {
    shards: Box<[Mutex<HashMap<Topic, Room>>]>,
    max_members: usize,
    chunk_entries: usize,
}

impl Rooms {
    fn new(limits: &Limits) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            max_members: limits.max_members_per_topic.max(1),
            chunk_entries: limits.snapshot_chunk_entries.max(1),
        }
    }

    fn shard(&self, topic: &Topic) -> MutexGuard<'_, HashMap<Topic, Room>> {
        let index = usize::from(u16::from_le_bytes([topic.0[0], topic.0[1]])) % SHARDS;
        self.shards[index].lock().expect("rooms lock")
    }

    /// Adds the connection to the room and queues its snapshot. Returns the
    /// new room size, or `None` (changing nothing) if the room is full.
    fn join(&self, topic: Topic, handle: &MemberHandle) -> Option<usize> {
        let joined = ServerFrame::Joined {
            topic,
            id: handle.peer,
        }
        .encode();
        let mut shard = self.shard(&topic);
        let room = shard.entry(topic).or_default();
        // A newer connection from the same endpoint takes its slot over;
        // that does not grow the room. (A new room is never full: the limit
        // is at least 1.)
        if !room.contains_key(&handle.peer) && room.len() >= self.max_members {
            return None;
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
        let size = snapshot_wire_len(&members, self.chunk_entries);
        handle.push(Outgoing::Snapshot { topic, members }, size);
        broadcast(room, handle.peer, &joined);
        Some(room.len())
    }

    /// Removes the connection's slot (if it still owns it) and tells the
    /// room. Returns the remaining size if it left.
    fn leave(&self, topic: Topic, handle: &MemberHandle) -> Option<usize> {
        let left = ServerFrame::Left {
            topic,
            id: handle.peer,
        }
        .encode();
        let mut shard = self.shard(&topic);
        let room = shard.get_mut(&topic)?;
        // Only the connection that owns the slot may vacate it.
        if !owns_slot(room, handle) {
            return None;
        }
        room.remove(&handle.peer);
        broadcast(room, handle.peer, &left);
        let size = room.len();
        if size == 0 {
            shard.remove(&topic);
        }
        Some(size)
    }

    /// Stores the blob and relays it as PRESENCE. False if the connection
    /// no longer owns its slot.
    fn announce(&self, topic: Topic, handle: &MemberHandle, blob: Bytes) -> bool {
        let presence = ServerFrame::Presence {
            topic,
            id: handle.peer,
            blob: blob.clone(),
        }
        .encode();
        let mut shard = self.shard(&topic);
        let Some(room) = shard.get_mut(&topic) else {
            return false;
        };
        match room.get_mut(&handle.peer) {
            Some(slot) if slot.handle.conn_id == handle.conn_id => slot.blob = blob,
            _ => return false,
        }
        broadcast(room, handle.peer, &presence);
        true
    }

    /// Fans a PUBLISH body (`topic ‖ payload`) out as DELIVER, sharing the
    /// bytes; returns how many members it reached.
    fn publish(&self, topic: Topic, handle: &MemberHandle, body: Bytes) -> usize {
        let head = frame_header(tag::DELIVER, body.len());
        let size = head.len() + body.len();
        let shard = self.shard(&topic);
        let Some(room) = shard.get(&topic) else {
            return 0;
        };
        if !owns_slot(room, handle) {
            return 0;
        }
        let mut sent = 0;
        for (id, slot) in room {
            if *id != handle.peer {
                slot.handle
                    .push(Outgoing::Parts(head.clone(), body.clone()), size);
                sent += 1;
            }
        }
        sent
    }

    /// Connections of the room's other members, if `handle` is subscribed.
    fn datagram_targets(&self, topic: Topic, handle: &MemberHandle) -> Option<Vec<Connection>> {
        let shard = self.shard(&topic);
        let room = shard.get(&topic)?;
        if !owns_slot(room, handle) {
            return None;
        }
        Some(
            room.iter()
                .filter(|(id, _)| **id != handle.peer)
                .map(|(_, slot)| slot.handle.conn.clone())
                .collect(),
        )
    }

    fn members(&self, topic: Topic) -> Vec<EndpointId> {
        self.shard(&topic)
            .get(&topic)
            .map(|room| room.keys().copied().collect())
            .unwrap_or_default()
    }

    fn occupancy(&self) -> (usize, usize) {
        self.shards.iter().fold((0, 0), |(rooms, members), shard| {
            let shard = shard.lock().expect("rooms lock");
            (
                rooms + shard.len(),
                members + shard.values().map(HashMap::len).sum::<usize>(),
            )
        })
    }
}

fn owns_slot(room: &Room, handle: &MemberHandle) -> bool {
    room.get(&handle.peer)
        .is_some_and(|slot| slot.handle.conn_id == handle.conn_id)
}

/// Queues `frame` for everyone in `room` but `except`.
fn broadcast(room: &Room, except: EndpointId, frame: &Bytes) {
    for (id, slot) in room {
        if *id != except {
            slot.handle.push_frame(frame.clone());
        }
    }
}

/// Byte and frame token buckets, refilled continuously.
struct Bucket {
    rate: Rate,
    bytes: f64,
    frames: f64,
    last: Instant,
}

impl Bucket {
    fn new(rate: Rate) -> Self {
        Self {
            rate,
            bytes: rate.burst_bytes,
            frames: rate.burst_frames,
            last: Instant::now(),
        }
    }

    /// Takes one frame of `len` bytes if both buckets allow it. A frame
    /// larger than the byte burst needs a full bucket and leaves it in debt.
    fn try_take(&mut self, len: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        let rate = self.rate;
        self.bytes = refill(self.bytes, rate.bytes_per_second, rate.burst_bytes, elapsed);
        self.frames = refill(
            self.frames,
            rate.frames_per_second,
            rate.burst_frames,
            elapsed,
        );
        let len = len as f64;
        if self.frames < 1.0 || self.bytes < len.min(self.rate.burst_bytes) {
            return false;
        }
        self.frames -= 1.0;
        self.bytes -= len;
        true
    }
}

fn refill(level: f64, per_second: f64, burst: f64, elapsed: f64) -> f64 {
    if burst.is_infinite() {
        return f64::INFINITY;
    }
    (level + elapsed * per_second).min(burst)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_limits_frames_and_bytes() {
        let mut frames = Bucket::new(Rate::frames(1.0, 3.0));
        assert!((0..3).all(|_| frames.try_take(1_000_000)));
        assert!(!frames.try_take(0));

        let mut bytes = Bucket::new(Rate {
            bytes_per_second: 1.0,
            burst_bytes: 100.0,
            frames_per_second: 1000.0,
            burst_frames: 1000.0,
        });
        assert!(bytes.try_take(60));
        assert!(!bytes.try_take(60));
        assert!(bytes.try_take(40));
        assert!(!bytes.try_take(1));
    }

    #[test]
    fn bucket_admits_an_oversized_frame_from_a_full_bucket() {
        let mut bucket = Bucket::new(Rate {
            bytes_per_second: 1000.0,
            burst_bytes: 100.0,
            frames_per_second: 1000.0,
            burst_frames: 1000.0,
        });
        assert!(bucket.try_take(500));
        // Now in debt: nothing passes until it is repaid.
        assert!(!bucket.try_take(1));
    }

    #[test]
    fn bucket_refills_over_time() {
        let mut bucket = Bucket::new(Rate::frames(1000.0, 1.0));
        assert!(bucket.try_take(0));
        assert!(!bucket.try_take(0));
        std::thread::sleep(Duration::from_millis(5));
        assert!(bucket.try_take(0));
    }
}
