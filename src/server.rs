//! The service: an embedded iroh relay plus an SFU endpoint that keeps one
//! room per topic. The SFU relays presence blobs and, for senders that pick
//! SFU delivery, fans each published payload (and datagram) out to the rest
//! of the room or hands it to one member. Peers that pick mesh delivery talk
//! over their own iroh connections, relayed through the embedded relay
//! until they go direct.
//!
//! # Streams
//!
//! Each connection has one session stream (room management) plus lane
//! streams in both directions (see [`crate::proto`]). Inbound, the session
//! stream and every lane stream get their own reader task; outbound, the
//! session stream, the control lane and the interactive lane each get a
//! writer task, and bulk deliveries get a dispatcher that opens one stream
//! per delivery. Stream priorities make the QUIC scheduler send control
//! before interactive before bulk.
//!
//! # Resource bounds
//!
//! Anyone can connect with any key, so every per-connection resource is
//! bounded (see [`Limits`] for the numbers):
//!
//! - **Connections.** At most `max_connections` at once; beyond that new
//!   handshakes are refused. A connection must finish its handshake and open
//!   its session stream in time or it is closed. The QUIC transport allows
//!   one bidi stream, `max_lane_streams` uni streams, and finite receive
//!   windows.
//! - **Inbound.** Frames are read incrementally (a peer must send bytes to
//!   make us allocate them), so partly received frames take at most one
//!   frame per open stream. PUBLISH+PUBLISH_TO+ANNOUNCE (all lanes), room
//!   joins and datagrams each go through a token bucket per connection.
//! - **Outbound.** A DELIVER is encoded once and the same [`Bytes`] are
//!   queued for every recipient, sliced from the publisher's received body.
//!   The session stream and the control and interactive lanes share one
//!   byte budget per connection: a connection that goes over it, or whose
//!   stream accepts no bytes for `stall_timeout`, is closed, so a slow
//!   reader never holds a room back. Bulk has its own budget, counting
//!   deliveries until the client acknowledges them: over it the oldest
//!   queued bulk deliveries are dropped, and a bulk stream that makes no
//!   progress for `stall_timeout` is reset; the connection stays.
//! - **Rooms.** Sharded by topic. A lock is held only to update membership
//!   and enqueue already-encoded frames (snapshots are encoded later, by the
//!   receiving connection's writer); logging happens outside it.

use std::{
    collections::{HashMap, HashSet, VecDeque},
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
use tokio::{
    sync::{Notify, Semaphore, mpsc},
    task::{JoinHandle, JoinSet},
};
use tracing::{debug, info, warn};

use crate::proto::{
    ClientFrame, FrameLengthError, Lane, MAX_ANNOUNCE_LEN, MAX_MEMBERS_PER_TOPIC, MAX_PUBLISH_LEN,
    MAX_TOPICS_PER_CONNECTION, Member, SFU_ALPN, SNAPSHOT_CHUNK_BYTES, SNAPSHOT_CHUNK_ENTRIES,
    ServerFrame, Topic, close, encode_snapshot, frame_header, priority, read_frame, read_lane_byte,
    reason, snapshot_wire_len, split_datagram, stream_error, tag,
};

const MIB: usize = 1024 * 1024;

/// QUIC connection receive window: unread bytes a client may have in flight
/// towards us across the connection. Every stream is read eagerly, so this
/// only has to cover the bandwidth-delay product.
const QUIC_RECEIVE_WINDOW: u32 = 4 * MIB as u32;
/// QUIC stream receive window; above one maximal frame.
const QUIC_STREAM_RECEIVE_WINDOW: u32 = 2 * MIB as u32;
/// Send window on top of the bulk budget. Bulk bytes count against that
/// budget until the client acknowledges them, so bulk alone never fills the
/// window; this headroom covers the session stream and the two long-lived
/// lanes (each held to the client's stream window, 1.25 MB by default). With
/// the window never full, priorities alone decide what is sent first.
const QUIC_SEND_WINDOW_HEADROOM: usize = 8 * MIB;
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
    /// Time a connection has to open its session stream.
    pub stream_open_timeout: Duration,
    /// Lane streams a client may have open at once: its control and
    /// interactive lanes plus concurrent bulk publishes. Each holds at most
    /// one partly received frame, so this × [`crate::proto::MAX_FRAME_LEN`]
    /// bounds what a connection's lane readers buffer.
    pub max_lane_streams: u32,
    /// Bytes queued towards one connection on its session stream and its
    /// control and interactive lanes before it is closed as a slow consumer.
    /// An empty budget always takes one frame.
    pub outbox_bytes: usize,
    /// Bulk bytes queued or unacknowledged towards one connection. A bulk
    /// delivery that does not fit drops the oldest queued ones (or itself).
    pub bulk_outbox_bytes: usize,
    /// Bulk streams the SFU has open towards one connection at once; more
    /// bulk deliveries wait in the queue.
    pub max_bulk_streams: usize,
    /// Time a stream may accept no bytes before its connection is closed
    /// (session, control, interactive) or it is reset (bulk).
    pub stall_timeout: Duration,
    /// PUBLISH, PUBLISH_TO (every lane) and ANNOUNCE a connection may send.
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
            // Two long-lived lanes plus 14 bulk uploads in flight, far more
            // than the publish burst lets through anyway.
            max_lane_streams: 16,
            outbox_bytes: 8 * MIB,
            bulk_outbox_bytes: 8 * MIB,
            max_bulk_streams: 16,
            stall_timeout: Duration::from_secs(20),
            // The burst is half the disconnecting outbox budget, so one
            // publisher's burst alone cannot push a healthy reader over it,
            // even on the interactive lane.
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

/// Counters since start (and one gauge), for logs and diagnostics.
#[derive(Default, Debug)]
pub struct Stats {
    /// Open connections right now, including handshakes in progress.
    pub connections: AtomicU64,
    /// Connections refused at the connection cap.
    pub connections_refused: AtomicU64,
    /// Connections closed for not opening their session stream in time.
    pub no_stream: AtomicU64,
    /// Connections closed because their session/control/interactive queue
    /// went over budget.
    pub slow_consumers: AtomicU64,
    /// Connections closed because their session, control or interactive
    /// stream stopped accepting bytes.
    pub stalled: AtomicU64,
    /// Accepted PUBLISH and PUBLISH_TO, per lane ([`Lane::index`]).
    pub published: [AtomicU64; 3],
    /// DELIVERs queued, per lane.
    pub delivered: [AtomicU64; 3],
    /// Accepted PUBLISH_TO (also counted in `published`).
    pub directed: AtomicU64,
    /// Bulk deliveries dropped because the receiver's bulk budget was full.
    pub bulk_dropped: AtomicU64,
    /// Bulk streams reset (or never opened) for making no progress.
    pub bulk_stalled: AtomicU64,
    /// Client streams stopped because their first byte is not a lane.
    pub bad_lanes: AtomicU64,
    /// Client bulk streams stopped for data after their frame or a
    /// malformed frame.
    pub bulk_stopped: AtomicU64,
    /// PUBLISH/PUBLISH_TO/ANNOUNCE/SUBSCRIBE refused by a rate limit.
    pub rate_limited: AtomicU64,
    /// Client frames skipped (or bulk streams stopped) for an unknown tag,
    /// a malformed body, or a frame on the wrong kind of stream.
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
        let lanes = |counters: &[AtomicU64; 3]| LaneCounts {
            control: get(&counters[Lane::Control.index()]),
            interactive: get(&counters[Lane::Interactive.index()]),
            bulk: get(&counters[Lane::Bulk.index()]),
        };
        StatsSnapshot {
            connections: get(&self.connections),
            connections_refused: get(&self.connections_refused),
            no_stream: get(&self.no_stream),
            slow_consumers: get(&self.slow_consumers),
            stalled: get(&self.stalled),
            published: lanes(&self.published),
            delivered: lanes(&self.delivered),
            directed: get(&self.directed),
            bulk_dropped: get(&self.bulk_dropped),
            bulk_stalled: get(&self.bulk_stalled),
            bad_lanes: get(&self.bad_lanes),
            bulk_stopped: get(&self.bulk_stopped),
            rate_limited: get(&self.rate_limited),
            malformed: get(&self.malformed),
            datagrams_in: get(&self.datagrams_in),
            datagrams_out: get(&self.datagrams_out),
            datagrams_dropped: get(&self.datagrams_dropped),
        }
    }
}

/// A counter per lane.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LaneCounts {
    pub control: u64,
    pub interactive: u64,
    pub bulk: u64,
}

impl LaneCounts {
    pub fn total(&self) -> u64 {
        self.control + self.interactive + self.bulk
    }

    pub fn get(&self, lane: Lane) -> u64 {
        match lane {
            Lane::Control => self.control,
            Lane::Interactive => self.interactive,
            Lane::Bulk => self.bulk,
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
    pub published: LaneCounts,
    pub delivered: LaneCounts,
    pub directed: u64,
    pub bulk_dropped: u64,
    pub bulk_stalled: u64,
    pub bad_lanes: u64,
    pub bulk_stopped: u64,
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

        let limits = &config.limits;
        let transport = QuicTransportConfig::builder()
            .max_concurrent_bidi_streams(VarInt::from_u32(1))
            .max_concurrent_uni_streams(VarInt::from_u32(limits.max_lane_streams))
            .receive_window(VarInt::from_u32(QUIC_RECEIVE_WINDOW))
            .stream_receive_window(VarInt::from_u32(QUIC_STREAM_RECEIVE_WINDOW))
            .send_window((limits.bulk_outbox_bytes + QUIC_SEND_WINDOW_HEADROOM) as u64)
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
    let _ = send.set_priority(priority::SESSION);
    debug!(peer = %peer.fmt_short(), conn_id, "sfu session open");

    let budget = Arc::new(Budget {
        queued: AtomicUsize::new(0),
        limit: limits.outbox_bytes,
        overflowed: AtomicBool::new(false),
    });
    let bulk = Arc::new(BulkQueue::new(limits.bulk_outbox_bytes));
    let (session_tx, session_rx) = mpsc::unbounded_channel();
    let (control_tx, control_rx) = mpsc::unbounded_channel();
    let (interactive_tx, interactive_rx) = mpsc::unbounded_channel();
    let mut writers = JoinSet::new();
    writers.spawn(session_writer(
        send,
        session_rx,
        budget.clone(),
        conn.clone(),
        shared.clone(),
    ));
    writers.spawn(lane_writer(
        Lane::Control,
        control_rx,
        budget.clone(),
        conn.clone(),
        shared.clone(),
    ));
    writers.spawn(lane_writer(
        Lane::Interactive,
        interactive_rx,
        budget.clone(),
        conn.clone(),
        shared.clone(),
    ));
    writers.spawn(bulk_dispatcher(bulk.clone(), conn.clone(), shared.clone()));

    let handle = MemberHandle {
        peer,
        conn_id,
        out: Arc::new(Outbound {
            budget: budget.clone(),
            session: session_tx,
            lanes: [control_tx, interactive_tx],
            bulk,
            stats: stats.clone(),
        }),
        conn: conn.clone(),
    };
    let datagrams = tokio::spawn(datagram_loop(handle.clone(), shared.clone()));
    let readers = Arc::new(Readers {
        handle,
        shared: shared.clone(),
        publish_rate: Mutex::new(Bucket::new(limits.publish_rate)),
    });
    let lanes = tokio::spawn(accept_lanes(conn.clone(), readers.clone()));
    let mut session = Session {
        readers,
        subscribed: HashSet::new(),
        join_rate: Bucket::new(limits.join_rate),
    };
    let result = session.read_loop(&mut recv).await;

    datagrams.abort();
    lanes.abort();
    let _ = datagrams.await;
    let _ = lanes.await;
    session.leave_all();
    // Every queue handle is gone now (the lane readers went with their
    // acceptor), so the writers drain and finish.
    drop(session);
    match &result {
        Err(err) if err.downcast_ref::<FrameLengthError>().is_some() => {
            // The stream cannot be resynchronised after a bad length prefix.
            conn.close(close::PROTOCOL.into(), err.to_string().as_bytes());
        }
        _ => {}
    }
    let drained = tokio::time::timeout(limits.stall_timeout, async {
        while writers.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        writers.abort_all();
    }
    if budget.overflowed.load(Ordering::Acquire) {
        Stats::bump(&stats.slow_consumers);
        warn!(peer = %peer.fmt_short(), conn_id, "dropped a slow consumer (outbox over budget)");
    }
    match result {
        Ok(()) => debug!(peer = %peer.fmt_short(), conn_id, "connection finished"),
        Err(err) => debug!(peer = %peer.fmt_short(), conn_id, "connection ended: {err:#}"),
    }
}

/// What every reader of one connection shares: the queues towards it and
/// the publish budget, which spans the session stream (ANNOUNCE) and every
/// lane (PUBLISH, PUBLISH_TO).
struct Readers {
    handle: MemberHandle,
    shared: Arc<Shared>,
    publish_rate: Mutex<Bucket>,
}

impl Readers {
    fn take_publish(&self, frame_len: usize) -> bool {
        self.publish_rate
            .lock()
            .expect("publish rate lock")
            .try_take(frame_len)
    }

    fn rate_limited(&self, topic: Topic) {
        Stats::bump(&self.shared.stats.rate_limited);
        self.handle.error(Some(topic), reason::RATE_LIMITED);
    }

    /// Answers a frame that could not be decoded (or does not belong on its
    /// stream) with a general ERROR; the stream carries on.
    fn skip_malformed(&self, tag: u8, err: &anyhow::Error) {
        Stats::bump(&self.shared.stats.malformed);
        debug!(peer = %self.handle.peer.fmt_short(), "skipping client frame 0x{tag:02x}: {err:#}");
        self.handle
            .error(None, format!("malformed frame 0x{tag:02x}: {err:#}"));
    }

    /// A PUBLISH or PUBLISH_TO from a lane stream. `topic` is the first 32
    /// bytes of the frame body, kept to build the DELIVER without copying.
    fn publish(&self, lane: Lane, frame: ClientFrame, topic_bytes: Bytes, frame_len: usize) {
        let (topic, recipient, payload) = match frame {
            ClientFrame::Publish { topic, payload } => (topic, None, payload),
            ClientFrame::PublishTo {
                topic,
                recipient,
                payload,
            } => (topic, Some(recipient), payload),
            _ => unreachable!("only lane frames are published"),
        };
        let (rooms, stats, handle) = (&self.shared.rooms, &self.shared.stats, &self.handle);
        if payload.len() > MAX_PUBLISH_LEN {
            return handle.error(Some(topic), reason::PUBLISH_TOO_LARGE);
        }
        if !rooms.is_member(topic, handle) {
            return handle.error(Some(topic), reason::NOT_SUBSCRIBED);
        }
        if !self.take_publish(frame_len) {
            return self.rate_limited(topic);
        }
        let deliver = Deliver::new(topic_bytes, payload);
        let result = match recipient {
            None => rooms.publish(topic, handle, lane, &deliver),
            Some(recipient) => rooms.publish_to(topic, handle, recipient, lane, &deliver),
        };
        match result {
            Ok(fanout) => {
                Stats::bump(&stats.published[lane.index()]);
                stats.delivered[lane.index()].fetch_add(fanout as u64, Ordering::Relaxed);
                if recipient.is_some() {
                    Stats::bump(&stats.directed);
                }
            }
            Err(Refusal::NotSubscribed) => handle.error(Some(topic), reason::NOT_SUBSCRIBED),
            Err(Refusal::NoSuchRecipient) => handle.error(Some(topic), reason::NO_SUCH_RECIPIENT),
        }
    }
}

/// The session stream's reader: subscriptions and presence.
struct Session {
    readers: Arc<Readers>,
    subscribed: HashSet<Topic>,
    join_rate: Bucket,
}

impl Session {
    async fn read_loop(&mut self, recv: &mut RecvStream) -> Result<()> {
        while let Some((tag, body)) = read_frame(recv).await? {
            let frame_len = 5 + body.len();
            match ClientFrame::decode(tag, body) {
                Ok(frame) => self.handle_frame(frame, frame_len),
                // Skip it; the stream is still in sync.
                Err(err) => self.readers.skip_malformed(tag, &err),
            }
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: ClientFrame, frame_len: usize) {
        let readers = &*self.readers;
        let (rooms, stats, limits) = (
            &readers.shared.rooms,
            &readers.shared.stats,
            &readers.shared.limits,
        );
        let handle = &readers.handle;
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
                } else if !readers.take_publish(frame_len) {
                    readers.rate_limited(topic);
                } else if rooms.announce(topic, handle, blob) {
                    debug!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), "announced");
                }
            }
            ClientFrame::Publish { topic, .. } | ClientFrame::PublishTo { topic, .. } => {
                handle.error(Some(topic), reason::PUBLISH_ON_SESSION);
            }
        }
    }

    fn leave_all(&mut self) {
        for topic in self.subscribed.drain() {
            self.readers.shared.rooms.leave(topic, &self.readers.handle);
        }
    }
}

/// Accepts the client's lane streams, one reader task each, until the
/// connection ends. Aborting it aborts every reader.
async fn accept_lanes(conn: Connection, readers: Arc<Readers>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = conn.accept_uni() => {
                let Ok(recv) = accepted else { break };
                let readers = readers.clone();
                tasks.spawn(async move {
                    if let Err(err) = read_lane(recv, &readers).await {
                        if err.downcast_ref::<FrameLengthError>().is_some() {
                            readers
                                .handle
                                .conn
                                .close(close::PROTOCOL.into(), err.to_string().as_bytes());
                        }
                        debug!(peer = %readers.handle.peer.fmt_short(), "lane stream ended: {err:#}");
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

/// Reads one client lane stream: its lane byte, then PUBLISH/PUBLISH_TO
/// frames (exactly one on a bulk stream). A bad length prefix is returned
/// as a [`FrameLengthError`]; everything else ends the stream quietly.
async fn read_lane(mut recv: RecvStream, readers: &Readers) -> Result<()> {
    let stats = &readers.shared.stats;
    let peer = readers.handle.peer.fmt_short();
    let Some(byte) = read_lane_byte(&mut recv).await? else {
        return Ok(());
    };
    let Some(lane) = Lane::from_byte(byte) else {
        Stats::bump(&stats.bad_lanes);
        let _ = recv.stop(stream_error::UNKNOWN_LANE.into());
        debug!(%peer, "stopped a stream with unknown lane 0x{byte:02x}");
        return Ok(());
    };
    if lane == Lane::Bulk {
        let Some((tag, body)) = read_frame(&mut recv).await? else {
            return Ok(());
        };
        let frame_len = 5 + body.len();
        match decode_lane_frame(tag, body) {
            Ok((frame, topic)) => readers.publish(lane, frame, topic, frame_len),
            Err(err) => {
                Stats::bump(&stats.malformed);
                Stats::bump(&stats.bulk_stopped);
                let _ = recv.stop(stream_error::MALFORMED.into());
                debug!(%peer, "stopped a bulk stream: frame 0x{tag:02x}: {err:#}");
                return Ok(());
            }
        }
        // One frame per bulk stream: the next thing must be its end.
        if let Ok(Some(_)) = recv.read(&mut [0u8; 1]).await {
            Stats::bump(&stats.bulk_stopped);
            let _ = recv.stop(stream_error::BULK_TRAILING.into());
            debug!(%peer, "stopped a bulk stream with data after its frame");
        }
        return Ok(());
    }
    while let Some((tag, body)) = read_frame(&mut recv).await? {
        let frame_len = 5 + body.len();
        match decode_lane_frame(tag, body) {
            Ok((frame, topic)) => readers.publish(lane, frame, topic, frame_len),
            Err(err) => readers.skip_malformed(tag, &err),
        }
    }
    Ok(())
}

/// Decodes a lane frame and also returns the body's topic bytes (a slice of
/// the received buffer, which the DELIVER reuses).
fn decode_lane_frame(tag: u8, body: Bytes) -> Result<(ClientFrame, Bytes)> {
    let topic = body.slice(..body.len().min(32));
    let frame = ClientFrame::decode(tag, body)?;
    anyhow::ensure!(frame.is_lane_frame(), "not a lane frame");
    Ok((frame, topic))
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

/// A DELIVER frame, encoded once and shared by every recipient: a fresh
/// header plus the topic and payload sliced from the publisher's received
/// body.
#[derive(Clone)]
struct Deliver {
    head: Bytes,
    topic: Bytes,
    payload: Bytes,
}

impl Deliver {
    fn new(topic: Bytes, payload: Bytes) -> Self {
        debug_assert_eq!(topic.len(), 32);
        Self {
            head: frame_header(tag::DELIVER, topic.len() + payload.len()),
            topic,
            payload,
        }
    }

    fn len(&self) -> usize {
        self.head.len() + self.topic.len() + self.payload.len()
    }

    fn chunks(&self) -> [Bytes; 3] {
        [self.head.clone(), self.topic.clone(), self.payload.clone()]
    }
}

/// Something queued on the session stream.
enum SessionItem {
    /// An encoded frame, shared with every other recipient.
    Frame(Bytes),
    /// A room snapshot, encoded into chunks by the writer.
    Snapshot { topic: Topic, members: Vec<Member> },
}

struct Queued<T> {
    item: T,
    /// What the item counts against the byte budget.
    size: usize,
}

/// Byte accounting for the queues that drop a slow consumer: the session
/// stream and the control and interactive lanes.
struct Budget {
    queued: AtomicUsize,
    limit: usize,
    overflowed: AtomicBool,
}

impl Budget {
    fn release(&self, size: usize) {
        self.queued.fetch_sub(size, Ordering::AcqRel);
    }
}

/// Bulk deliveries waiting for a stream, plus the accounting for those on
/// a stream and not yet acknowledged.
struct BulkQueue {
    state: Mutex<BulkState>,
    budget: usize,
    ready: Notify,
}

#[derive(Default)]
struct BulkState {
    waiting: VecDeque<Deliver>,
    /// Bytes in `waiting`.
    waiting_bytes: usize,
    /// Bytes in `waiting` plus bytes on streams not yet acknowledged.
    bytes: usize,
    closed: bool,
}

impl BulkQueue {
    fn new(budget: usize) -> Self {
        Self {
            state: Mutex::default(),
            budget,
            ready: Notify::new(),
        }
    }

    fn lock(&self) -> MutexGuard<'_, BulkState> {
        self.state.lock().expect("bulk queue lock")
    }

    /// Queues a delivery within the budget, dropping the oldest waiting ones
    /// to make room, or this one if the deliveries already on streams leave
    /// no room. An empty budget always takes one. Returns how many
    /// deliveries were dropped. Never logs: callers may hold a room lock.
    fn push(&self, frame: Deliver) -> u64 {
        let size = frame.len();
        let mut state = self.lock();
        if state.closed {
            return 0;
        }
        let on_streams = state.bytes - state.waiting_bytes;
        if on_streams > 0 && on_streams + size > self.budget {
            return 1;
        }
        let mut dropped = 0;
        while state.bytes > 0 && state.bytes + size > self.budget {
            let Some(oldest) = state.waiting.pop_front() else {
                break;
            };
            state.waiting_bytes -= oldest.len();
            state.bytes -= oldest.len();
            dropped += 1;
        }
        state.waiting.push_back(frame);
        state.waiting_bytes += size;
        state.bytes += size;
        drop(state);
        self.ready.notify_one();
        dropped
    }

    /// The oldest waiting delivery, moved onto a stream (it keeps counting
    /// until [`Self::done`]). `None` once closed and empty.
    async fn next(&self) -> Option<Deliver> {
        loop {
            let ready = self.ready.notified();
            {
                let mut state = self.lock();
                if let Some(frame) = state.waiting.pop_front() {
                    state.waiting_bytes -= frame.len();
                    return Some(frame);
                }
                if state.closed {
                    return None;
                }
            }
            ready.await;
        }
    }

    /// A delivery left its stream (acknowledged, reset or failed).
    fn done(&self, size: usize) {
        self.lock().bytes -= size;
    }

    fn close(&self) {
        self.lock().closed = true;
        self.ready.notify_one();
    }
}

/// The queues towards one client. Dropping the last handle closes them, so
/// the writers drain and finish.
struct Outbound {
    budget: Arc<Budget>,
    session: mpsc::UnboundedSender<Queued<SessionItem>>,
    /// Control, then interactive.
    lanes: [mpsc::UnboundedSender<Queued<Deliver>>; 2],
    bulk: Arc<BulkQueue>,
    stats: Arc<Stats>,
}

impl Drop for Outbound {
    fn drop(&mut self) {
        self.bulk.close();
    }
}

/// The sending half of one client connection, as rooms hold it.
#[derive(Clone)]
struct MemberHandle {
    peer: EndpointId,
    conn_id: u64,
    out: Arc<Outbound>,
    conn: Connection,
}

impl MemberHandle {
    /// Counts `size` bytes against the session/control/interactive budget.
    /// A client that would go over it is disconnected rather than allowed to
    /// stall the room. Never logs: callers may hold a room lock.
    fn reserve(&self, size: usize) -> bool {
        let budget = &*self.out.budget;
        if budget.overflowed.load(Ordering::Acquire) {
            return false;
        }
        let before = budget.queued.fetch_add(size, Ordering::AcqRel);
        if before > 0 && before + size > budget.limit {
            budget.release(size);
            if !budget.overflowed.swap(true, Ordering::AcqRel) {
                self.conn
                    .close(close::SLOW_CONSUMER.into(), b"slow consumer");
            }
            return false;
        }
        true
    }

    fn push_session(&self, item: SessionItem, size: usize) {
        if self.reserve(size) && self.out.session.send(Queued { item, size }).is_err() {
            self.out.budget.release(size);
        }
    }

    fn push_frame(&self, frame: Bytes) {
        let size = frame.len();
        self.push_session(SessionItem::Frame(frame), size);
    }

    /// Queues a DELIVER on `lane`. Never logs: callers hold a room lock.
    fn deliver(&self, lane: Lane, frame: &Deliver) {
        match lane {
            Lane::Bulk => {
                let dropped = self.out.bulk.push(frame.clone());
                if dropped > 0 {
                    self.out
                        .stats
                        .bulk_dropped
                        .fetch_add(dropped, Ordering::Relaxed);
                }
            }
            Lane::Control | Lane::Interactive => {
                let size = frame.len();
                let item = Queued {
                    item: frame.clone(),
                    size,
                };
                if self.reserve(size) && self.out.lanes[lane.index()].send(item).is_err() {
                    self.out.budget.release(size);
                }
            }
        }
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

/// Writes the session stream until every queue handle is gone. A write that
/// makes no progress for `stall_timeout` closes the connection.
async fn session_writer(
    mut send: SendStream,
    mut rx: mpsc::UnboundedReceiver<Queued<SessionItem>>,
    budget: Arc<Budget>,
    conn: Connection,
    shared: Arc<Shared>,
) {
    let limits = &shared.limits;
    while let Some(Queued { item, size }) = rx.recv().await {
        let written = match item {
            SessionItem::Frame(frame) => write_chunks(&mut send, &mut [frame], limits).await,
            SessionItem::Snapshot { topic, members } => {
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
        budget.release(size);
        match written {
            Ok(()) => {}
            Err(WriteFailure::Closed) => return,
            Err(WriteFailure::Stalled) => return stalled(&conn, &shared, "session"),
        }
    }
    let _ = send.finish();
}

/// Writes one long-lived lane (control or interactive) towards the client,
/// opening its stream on the first DELIVER. A write that makes no progress
/// for `stall_timeout` closes the connection; a stream the client stopped
/// is replaced on the next DELIVER.
async fn lane_writer(
    lane: Lane,
    mut rx: mpsc::UnboundedReceiver<Queued<Deliver>>,
    budget: Arc<Budget>,
    conn: Connection,
    shared: Arc<Shared>,
) {
    let limits = &shared.limits;
    let mut stream: Option<SendStream> = None;
    while let Some(Queued { item, size }) = rx.recv().await {
        let [head, topic, payload] = item.chunks();
        let written = match stream.as_mut() {
            Some(send) => write_chunks(send, &mut [head, topic, payload], limits).await,
            None => match open_lane(&conn, lane, limits).await {
                Ok(mut send) => {
                    let written = write_chunks(
                        &mut send,
                        &mut [lane.prefix(), head, topic, payload],
                        limits,
                    )
                    .await;
                    stream = Some(send);
                    written
                }
                Err(failure) => Err(failure),
            },
        };
        budget.release(size);
        match written {
            Ok(()) => {}
            Err(WriteFailure::Closed) if conn.close_reason().is_none() => stream = None,
            Err(WriteFailure::Closed) => return,
            Err(WriteFailure::Stalled) => return stalled(&conn, &shared, lane.name()),
        }
    }
    if let Some(mut send) = stream {
        let _ = send.finish();
    }
}

fn stalled(conn: &Connection, shared: &Shared, stream: &str) {
    Stats::bump(&shared.stats.stalled);
    conn.close(close::STALLED.into(), b"stalled");
    warn!(peer = %conn.remote_id().fmt_short(), stream, "dropped a stalled consumer (no write progress)");
}

/// Opens a server → client lane stream at the lane's priority. Waiting for
/// stream credit counts as a stall.
async fn open_lane(
    conn: &Connection,
    lane: Lane,
    limits: &Limits,
) -> Result<SendStream, WriteFailure> {
    let send = match tokio::time::timeout(limits.stall_timeout, conn.open_uni()).await {
        Ok(Ok(send)) => send,
        Ok(Err(_)) => return Err(WriteFailure::Closed),
        Err(_) => return Err(WriteFailure::Stalled),
    };
    let _ = send.set_priority(lane.priority());
    Ok(send)
}

/// Sends queued bulk deliveries, each on its own stream, at most
/// `max_bulk_streams` at a time, until the queue closes and drains.
async fn bulk_dispatcher(queue: Arc<BulkQueue>, conn: Connection, shared: Arc<Shared>) {
    let slots = Arc::new(Semaphore::new(shared.limits.max_bulk_streams.max(1)));
    let mut streams = JoinSet::new();
    loop {
        // Take a delivery off the queue only once a stream slot is free, so
        // waiting deliveries stay droppable.
        let Ok(slot) = slots.clone().acquire_owned().await else {
            break;
        };
        let Some(frame) = queue.next().await else {
            break;
        };
        let (queue, conn, shared) = (queue.clone(), conn.clone(), shared.clone());
        streams.spawn(async move {
            let size = frame.len();
            send_bulk(&conn, frame, &shared).await;
            queue.done(size);
            drop(slot);
        });
        while streams.try_join_next().is_some() {}
    }
    while streams.join_next().await.is_some() {}
}

/// One bulk delivery: a new stream, the lane byte, one DELIVER, FIN, then
/// the client's acknowledgement. A stream that makes no progress for
/// `stall_timeout` (writing or waiting for the acknowledgement) is reset.
async fn send_bulk(conn: &Connection, frame: Deliver, shared: &Shared) {
    let limits = &shared.limits;
    let stats = &shared.stats;
    let mut send = match open_lane(conn, Lane::Bulk, limits).await {
        Ok(send) => send,
        Err(WriteFailure::Closed) => return,
        Err(WriteFailure::Stalled) => return Stats::bump(&stats.bulk_stalled),
    };
    let [head, topic, payload] = frame.chunks();
    let mut chunks = [Lane::Bulk.prefix(), head, topic, payload];
    match write_chunks(&mut send, &mut chunks, limits).await {
        Ok(()) => {}
        Err(WriteFailure::Closed) => return,
        Err(WriteFailure::Stalled) => {
            Stats::bump(&stats.bulk_stalled);
            let _ = send.reset(stream_error::STALLED.into());
            return debug!(peer = %conn.remote_id().fmt_short(), "reset a stalled bulk stream");
        }
    }
    let _ = send.finish();
    // Resolves once the client has every byte (or stopped the stream).
    if tokio::time::timeout(limits.stall_timeout, send.stopped())
        .await
        .is_err()
    {
        Stats::bump(&stats.bulk_stalled);
        let _ = send.reset(stream_error::STALLED.into());
        debug!(peer = %conn.remote_id().fmt_short(), "reset an unacknowledged bulk stream");
    }
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
    loop {
        // An empty chunk needs no write (and must not wait for window).
        while rest.first().is_some_and(Bytes::is_empty) {
            rest = &mut rest[1..];
        }
        if rest.is_empty() {
            return Ok(());
        }
        // Cancel-safe: on timeout nothing more was written.
        match tokio::time::timeout(limits.stall_timeout, send.write_many_chunks(&mut rest)).await {
            Ok(Ok(_)) => {}
            Ok(Err(_)) => return Err(WriteFailure::Closed),
            Err(_) => return Err(WriteFailure::Stalled),
        }
    }
}

struct Slot {
    handle: MemberHandle,
    blob: Bytes,
}

type Room = HashMap<EndpointId, Slot>;

/// Why a publish was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refusal {
    NotSubscribed,
    NoSuchRecipient,
}

/// Rooms keyed by topic, members keyed by endpoint id, sharded by topic.
/// Every membership change and the frames it causes are queued under the
/// room's shard lock, so each client sees a room's session events in a
/// consistent order (snapshot first). Frames are encoded before taking the
/// lock (a snapshot by the receiving writer) and nothing logs under it.
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
        handle.push_session(SessionItem::Snapshot { topic, members }, size);
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

    /// Whether the connection holds its slot in the topic's room.
    fn is_member(&self, topic: Topic, handle: &MemberHandle) -> bool {
        self.shard(&topic)
            .get(&topic)
            .is_some_and(|room| owns_slot(room, handle))
    }

    /// Queues the DELIVER on `lane` for every other member; returns how many
    /// members it reached.
    fn publish(
        &self,
        topic: Topic,
        handle: &MemberHandle,
        lane: Lane,
        frame: &Deliver,
    ) -> Result<usize, Refusal> {
        let shard = self.shard(&topic);
        let room = shard
            .get(&topic)
            .filter(|room| owns_slot(room, handle))
            .ok_or(Refusal::NotSubscribed)?;
        let mut sent = 0;
        for (id, slot) in room {
            if *id != handle.peer {
                slot.handle.deliver(lane, frame);
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Queues the DELIVER on `lane` for `recipient` alone, if it is another
    /// member of the room.
    fn publish_to(
        &self,
        topic: Topic,
        handle: &MemberHandle,
        recipient: EndpointId,
        lane: Lane,
        frame: &Deliver,
    ) -> Result<usize, Refusal> {
        let shard = self.shard(&topic);
        let room = shard
            .get(&topic)
            .filter(|room| owns_slot(room, handle))
            .ok_or(Refusal::NotSubscribed)?;
        if recipient == handle.peer {
            return Err(Refusal::NoSuchRecipient);
        }
        let slot = room.get(&recipient).ok_or(Refusal::NoSuchRecipient)?;
        slot.handle.deliver(lane, frame);
        Ok(1)
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

/// Queues `frame` on the session stream of everyone in `room` but `except`.
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

    fn deliver(payload_len: usize) -> Deliver {
        Deliver::new(
            Bytes::from_static(&[1; 32]),
            Bytes::from(vec![0; payload_len]),
        )
    }

    /// Frame size of [`deliver`]: 5-byte header plus the topic.
    const OVERHEAD: usize = 37;

    fn waiting(queue: &BulkQueue) -> Vec<usize> {
        queue
            .lock()
            .waiting
            .iter()
            .map(|frame| frame.payload.len())
            .collect()
    }

    #[tokio::test]
    async fn bulk_queue_drops_the_oldest_waiting() {
        let queue = BulkQueue::new(3 * (100 + OVERHEAD));
        for len in [100, 100, 100] {
            assert_eq!(queue.push(deliver(len)), 0);
        }
        // A fourth of the same size pushes the first out.
        assert_eq!(queue.push(deliver(100)), 1);
        assert_eq!(waiting(&queue), [100, 100, 100]);
        // A larger one pushes out as many as it needs.
        assert_eq!(queue.push(deliver(200)), 2);
        assert_eq!(waiting(&queue), [100, 200]);
        assert_eq!(queue.lock().bytes, 300 + 2 * OVERHEAD);
    }

    #[tokio::test]
    async fn bulk_queue_counts_deliveries_on_streams() {
        let queue = BulkQueue::new(2 * (100 + OVERHEAD));
        queue.push(deliver(100));
        queue.push(deliver(100));
        let on_stream = queue.next().await.unwrap();
        // One on a stream, one waiting: a third drops the waiting one.
        assert_eq!(queue.push(deliver(100)), 1);
        let second = queue.next().await.unwrap();
        // Both on streams: nothing waiting can make room, so the new one
        // is dropped.
        assert_eq!(queue.push(deliver(100)), 1);
        assert!(waiting(&queue).is_empty());
        queue.done(on_stream.len());
        assert_eq!(queue.push(deliver(100)), 0);
        queue.done(second.len());
        // An empty budget takes one delivery of any size.
        let big = BulkQueue::new(10);
        assert_eq!(big.push(deliver(1000)), 0);
        assert_eq!(big.push(deliver(1)), 1);
        // Closing ends `next` once the queue is drained.
        big.close();
        assert!(big.next().await.is_some());
        assert!(big.next().await.is_none());
        assert_eq!(big.push(deliver(1)), 0);
    }
}
