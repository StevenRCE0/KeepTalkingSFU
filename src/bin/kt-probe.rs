//! `kt-probe`: subscribes to a topic on `kt-sfu` and measures both
//! delivery paths with every other probe in it:
//!
//! - **Mesh:** a direct iroh connection per peer — time to connect,
//!   relay → direct upgrade, RTT, pings and datagram echoes.
//! - **SFU:** pings published through the SFU on the control lane (every
//!   other probe answers with a pong directed back to the pinger with
//!   PUBLISH_TO), datagrams fanned out by the SFU, and one 256 KiB bulk-lane
//!   publish per run, which every receiver acknowledges with a directed
//!   control message.
//!
//! Run the same command on two or more machines with the same `--context`.

use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use bytes::{Buf, BufMut, BytesMut};
use clap::Parser;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayUrl,
    endpoint::{Connection, PathEvent},
};
use iroh_relay::RelayQuicConfig;
use keeptalking_sfu::{
    client::{ClientOptions, Delivery, SfuClient, bind_client},
    info,
    proto::{Lane, ServerFrame, Topic},
    tls::ca_from_pem_file,
};
use n0_future::StreamExt;
use sha2::{Digest, Sha256};
use url::Url;
use uuid::Uuid;

const PROBE_ALPN: &[u8] = b"keeptalking/probe/1";
/// Presence blob a probe announces. The SDK announces a context-sealed blob
/// here instead; the probe keeps it readable.
const BLOB_MAGIC: &[u8] = b"kt-probe/1:";
/// Size of the one bulk publish a probe makes per run.
const BULK_PROBE_LEN: usize = 256 * 1024;

#[derive(Parser, Debug)]
#[command(
    name = "kt-probe",
    about = "Probe a kt-sfu: SFU fan-out + full-mesh peer connections"
)]
enum Command {
    /// Subscribe to a topic and connect to every other probe in it.
    Room(RoomArgs),
}

#[derive(Parser, Debug)]
struct RoomArgs {
    /// SFU endpoint id printed by kt-sfu.
    #[arg(long, required_unless_present = "info")]
    sfu: Option<EndpointId>,
    /// Relay URL printed by kt-sfu.
    #[arg(long, required_unless_present = "info")]
    relay: Option<RelayUrl>,
    /// Look the SFU id, relay URL and QAD port up at the info endpoint
    /// instead, e.g. https://signal.rcex.live/kt/sfu.
    #[arg(long, conflicts_with_all = ["sfu", "relay"])]
    info: Option<Url>,
    /// QUIC address-discovery port of the relay (kt-sfu prints it).
    #[arg(long)]
    qad_port: Option<u16>,
    /// PEM root to trust for the relay and the info URL (the file
    /// `kt-sfu --dev` writes).
    #[arg(long)]
    relay_ca: Option<PathBuf>,
    /// Context to join; the topic is SHA-256("kt-probe/" ‖ context). A random
    /// one is generated and printed if omitted.
    #[arg(long)]
    context: Option<Uuid>,
    /// Use this topic (64 hex digits) instead of deriving one from --context.
    #[arg(long, conflicts_with = "context")]
    topic: Option<String>,
    /// Keep every connection on the relay (no IP transports).
    #[arg(long)]
    relay_only: bool,
    /// Seconds between pings and status lines.
    #[arg(long, default_value_t = 2.0)]
    interval: f64,
    /// Exit after this many seconds and print a summary (0 = until ctrl-c).
    #[arg(long, default_value_t = 0.0)]
    duration: f64,
    /// Log every path opened/closed, not just path selection.
    #[arg(long)]
    paths: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();
    match Command::parse() {
        Command::Room(args) => room(args).await,
    }
}

async fn room(args: RoomArgs) -> Result<()> {
    let started = Instant::now();
    let ca = args.relay_ca.as_deref().map(ca_from_pem_file).transpose()?;
    let (sfu_id, relay, qad_port) = match &args.info {
        Some(url) => {
            let info = info::fetch_info(url, ca.as_ref()).await?;
            println!(
                "info     {url}: sfu {} relay {}",
                info.sfu.fmt_short(),
                info.relay
            );
            (info.sfu, info.relay, args.qad_port.or(info.qad_port))
        }
        None => (
            args.sfu.context("--sfu is required without --info")?,
            args.relay
                .clone()
                .context("--relay is required without --info")?,
            args.qad_port,
        ),
    };
    let relay_map: iroh::RelayMap =
        iroh::RelayConfig::new(relay.clone(), qad_port.map(RelayQuicConfig::new)).into();
    let endpoint = bind_client(ClientOptions {
        relay_map,
        ca,
        alpns: vec![PROBE_ALPN.to_vec()],
        secret_key: None,
        relay_only: args.relay_only,
        transport: None,
    })
    .await?;
    let me = endpoint.id();
    let topic = match &args.topic {
        Some(hex) => Topic::from_hex(hex)?,
        None => {
            let context = args.context.unwrap_or_else(Uuid::new_v4);
            println!("context  {context}");
            Topic(Sha256::digest([b"kt-probe/".as_slice(), context.as_bytes()].concat()).into())
        }
    };
    println!("me       {me}");
    println!("topic    {topic}");

    let sfu_addr = EndpointAddr::new(sfu_id).with_relay_url(relay.clone());
    let (sfu, mut inbox) = SfuClient::connect(&endpoint, sfu_addr).await?;
    let sfu = Arc::new(sfu);
    println!("sfu      connected in {:?}", started.elapsed());
    sfu.subscribe(topic).await?;
    let mut blob = BytesMut::from(BLOB_MAGIC);
    blob.put_slice(me.as_bytes());
    sfu.announce(topic, blob.freeze()).await?;

    let mesh = Arc::new(Mesh {
        endpoint: endpoint.clone(),
        me,
        relay,
        interval: Duration::from_secs_f64(args.interval),
        log_paths: args.paths,
        started,
        peers: Mutex::new(HashMap::new()),
        joined: tokio::sync::watch::Sender::new(false),
        bulk_sent: Mutex::new(None),
    });
    tokio::spawn(accept_loop(mesh.clone()));
    tokio::spawn(status_loop(mesh.clone()));
    tokio::spawn(sfu_ping_loop(mesh.clone(), sfu.clone(), topic));
    tokio::spawn(sfu_datagram_reader(mesh.clone(), sfu.clone()));

    let deadline = async {
        if args.duration > 0.0 {
            tokio::time::sleep(Duration::from_secs_f64(args.duration)).await
        } else {
            std::future::pending().await
        }
    };
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            frame = inbox.frames.recv() => {
                let Some(frame) = frame else {
                    println!("sfu      connection closed");
                    break;
                };
                mesh.session_frame(frame);
            }
            Some(delivery) = inbox.deliveries.recv() => {
                mesh.sfu_message(&sfu, topic, delivery).await;
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = &mut deadline => break,
        }
    }

    sfu.close();
    endpoint.close().await;
    mesh.print_summary();
    Ok(())
}

struct Mesh {
    endpoint: Endpoint,
    me: EndpointId,
    relay: RelayUrl,
    interval: Duration,
    log_paths: bool,
    started: Instant,
    /// Every peer ever seen; entries stay after a peer leaves so the
    /// summary covers them.
    peers: Mutex<HashMap<EndpointId, Arc<PeerStats>>>,
    /// Set once our SNAPSHOT arrived: only then may we publish (lane
    /// streams are not ordered against our SUBSCRIBE).
    joined: tokio::sync::watch::Sender<bool>,
    /// When our bulk publish went out, and to how many peers.
    bulk_sent: Mutex<Option<(Duration, usize)>>,
}

#[derive(Default)]
struct PeerStats {
    learned_at: Mutex<Option<Instant>>,
    connected_after: Mutex<Option<Duration>>,
    direct_after: Mutex<Option<Duration>>,
    conn: Mutex<Option<Connection>>,
    initiator: AtomicBool,
    /// QUIC's RTT estimate on the selected path, sampled by the status loop.
    last_rtt: Mutex<Option<Duration>>,
    /// Application-level ping round trip (initiator only).
    last_ping: Mutex<Option<Duration>>,
    pings_ok: AtomicU64,
    dgrams_sent: AtomicU64,
    dgrams_echoed: AtomicU64,
    /// Round trip of our latest SFU ping, answered by this peer via the SFU.
    sfu_rtt: Mutex<Option<Duration>>,
    sfu_pongs: AtomicU64,
    /// SFU-forwarded datagrams received from this peer.
    sfu_dgrams: AtomicU64,
    /// Our bulk publish, from sending it to this peer's directed ack.
    bulk_rtt: Mutex<Option<Duration>>,
    /// Bulk payload bytes received from this peer.
    bulk_in: AtomicU64,
}

impl Mesh {
    fn session_frame(self: &Arc<Self>, frame: ServerFrame) {
        match frame {
            ServerFrame::Snapshot { members, .. } => {
                println!("room     snapshot: {} other member(s)", members.len());
                for member in members {
                    self.learn(member.id, &member.blob);
                }
                self.joined.send_replace(true);
            }
            ServerFrame::Joined { id, .. } => println!("room     + {}", id.fmt_short()),
            ServerFrame::Presence { id, blob, .. } => self.learn(id, &blob),
            ServerFrame::Left { id, .. } => {
                println!("room     - {}", id.fmt_short());
                self.forget(id);
            }
            // DELIVERs arrive on lane streams, as `Delivery`.
            ServerFrame::Deliver { .. } => {}
            ServerFrame::Error { topic, reason } => match topic {
                Some(topic) => println!("sfu      error on {}: {reason}", topic.fmt_short()),
                None => println!("sfu      error: {reason}"),
            },
        }
    }

    /// Peers whose presence we have seen.
    fn known_peers(&self) -> usize {
        self.peers
            .lock()
            .unwrap()
            .values()
            .filter(|stats| stats.learned_at.lock().unwrap().is_some())
            .count()
    }

    fn stats(&self, id: EndpointId) -> Arc<PeerStats> {
        self.peers.lock().unwrap().entry(id).or_default().clone()
    }

    /// A peer's presence arrived. Its id is taken from the blob (the SDK's
    /// sealed envelope), never from the server; the lower id dials.
    fn learn(self: &Arc<Self>, reported: EndpointId, blob: &[u8]) {
        let Some(id) = parse_blob(blob) else {
            if !blob.is_empty() {
                println!(
                    "room     {} published a non-probe blob",
                    reported.fmt_short()
                );
            }
            return;
        };
        if id != reported {
            println!(
                "room     ! blob id {} != server id {}",
                id.fmt_short(),
                reported.fmt_short()
            );
            return;
        }
        // SFU traffic can create a peer's entry before its presence arrives,
        // so "learned" is the presence timestamp, not the entry.
        let stats = {
            let mut peers = self.peers.lock().unwrap();
            let stats = peers.entry(id).or_default().clone();
            let mut learned = stats.learned_at.lock().unwrap();
            if learned.is_some() {
                return;
            }
            *learned = Some(Instant::now());
            drop(learned);
            stats
        };
        println!("peer     {} learned", id.fmt_short());
        if self.me < id {
            let mesh = self.clone();
            tokio::spawn(async move {
                let addr = EndpointAddr::new(id).with_relay_url(mesh.relay.clone());
                match mesh.endpoint.connect(addr, PROBE_ALPN).await {
                    Ok(conn) => mesh.run_peer(conn, stats, true).await,
                    Err(err) => println!("peer     {} dial failed: {err:?}", id.fmt_short()),
                }
            });
        }
    }

    /// A payload the SFU delivered to us:
    ///
    /// - `P ‖ from ‖ seq ‖ t_ns` (control, broadcast): a ping, answered
    ///   with `Q ‖ from ‖ me ‖ seq ‖ t_ns` directed to `from`.
    /// - `Q ‖ to ‖ from ‖ seq ‖ t_ns` (control, directed): a pong to time.
    /// - `B ‖ from ‖ seq ‖ t_ns ‖ padding` (bulk, broadcast): a bulk probe,
    ///   acknowledged with `A ‖ from ‖ me ‖ t_ns ‖ u32 len` directed to `from`.
    /// - `A ‖ to ‖ from ‖ t_ns ‖ u32 len` (control, directed): a bulk ack.
    async fn sfu_message(&self, sfu: &SfuClient, topic: Topic, delivery: Delivery) {
        let Delivery { lane, payload, .. } = delivery;
        let total = payload.len();
        let mut payload = payload;
        if payload.remaining() < 1 {
            return;
        }
        let kind = payload.get_u8();
        let expected = if kind == b'B' {
            Lane::Bulk
        } else {
            Lane::Control
        };
        if lane != expected {
            println!("lane     ! '{}' arrived on {lane}", kind.escape_ascii());
        }
        match kind {
            b'P' if payload.remaining() >= 48 => {
                let Some(from) = take_id(&mut payload) else {
                    return;
                };
                let mut pong = BytesMut::with_capacity(81);
                pong.put_u8(b'Q');
                pong.put_slice(from.as_bytes());
                pong.put_slice(self.me.as_bytes());
                pong.put_slice(&payload);
                let _ = sfu
                    .publish_to(Lane::Control, topic, from, pong.freeze())
                    .await;
            }
            b'Q' if payload.remaining() >= 80 => {
                let (Some(to), Some(from)) = (take_id(&mut payload), take_id(&mut payload)) else {
                    return;
                };
                if to != self.me {
                    println!("sfu      ! pong for {} reached us", to.fmt_short());
                    return;
                }
                let _seq = payload.get_u64();
                let rtt = self.since(payload.get_u64());
                let stats = self.stats(from);
                *stats.sfu_rtt.lock().unwrap() = Some(rtt);
                stats.sfu_pongs.fetch_add(1, Ordering::Relaxed);
            }
            b'B' if payload.remaining() >= 48 => {
                let Some(from) = take_id(&mut payload) else {
                    return;
                };
                let _seq = payload.get_u64();
                let sent_ns = payload.get_u64();
                self.stats(from)
                    .bulk_in
                    .fetch_add(total as u64, Ordering::Relaxed);
                println!(
                    "bulk     {} KiB from {} on {lane}",
                    total / 1024,
                    from.fmt_short()
                );
                let mut ack = BytesMut::with_capacity(77);
                ack.put_u8(b'A');
                ack.put_slice(from.as_bytes());
                ack.put_slice(self.me.as_bytes());
                ack.put_u64(sent_ns);
                ack.put_u32(total as u32);
                let _ = sfu
                    .publish_to(Lane::Control, topic, from, ack.freeze())
                    .await;
            }
            b'A' if payload.remaining() >= 76 => {
                let (Some(to), Some(from)) = (take_id(&mut payload), take_id(&mut payload)) else {
                    return;
                };
                if to != self.me {
                    return;
                }
                let rtt = self.since(payload.get_u64());
                let len = payload.get_u32() as usize;
                if len != BULK_PROBE_LEN {
                    println!(
                        "bulk     ! {} got {len} of {BULK_PROBE_LEN} bytes",
                        from.fmt_short()
                    );
                }
                *self.stats(from).bulk_rtt.lock().unwrap() = Some(rtt);
            }
            _ => {}
        }
    }

    /// Time since a `t_ns` stamp taken from [`Self::since_start`].
    fn since(&self, sent_ns: u64) -> Duration {
        self.since_start()
            .saturating_sub(Duration::from_nanos(sent_ns))
    }

    fn since_start(&self) -> Duration {
        self.started.elapsed()
    }

    fn forget(&self, id: EndpointId) {
        let stats = self.peers.lock().unwrap().get(&id).cloned();
        if let Some(conn) = stats.and_then(|stats| stats.conn.lock().unwrap().take()) {
            conn.close(0u32.into(), b"left");
        }
    }

    async fn run_peer(self: Arc<Self>, conn: Connection, stats: Arc<PeerStats>, initiator: bool) {
        let id = conn.remote_id();
        let since = stats
            .learned_at
            .lock()
            .unwrap()
            .unwrap_or_else(Instant::now);
        *stats.connected_after.lock().unwrap() = Some(since.elapsed());
        *stats.conn.lock().unwrap() = Some(conn.clone());
        stats.initiator.store(initiator, Ordering::Relaxed);
        println!(
            "peer     {} connected ({}) after {:?} via {}",
            id.fmt_short(),
            if initiator { "dialed" } else { "accepted" },
            since.elapsed(),
            selected_path(&conn),
        );

        tokio::spawn(watch_paths(
            conn.clone(),
            stats.clone(),
            since,
            self.log_paths,
        ));
        let result = if initiator {
            ping_loop(&conn, &stats, self.interval).await
        } else {
            echo_loop(&conn).await
        };
        if let Err(err) = result {
            println!("peer     {} ended: {err:#}", id.fmt_short());
        }
    }

    fn print_summary(&self) {
        let peers = self.peers.lock().unwrap();
        println!("\nsummary  {} peer(s)", peers.len());
        match *self.bulk_sent.lock().unwrap() {
            Some((at, to)) => {
                let acked: Vec<Duration> = peers
                    .values()
                    .filter_map(|stats| *stats.bulk_rtt.lock().unwrap())
                    .collect();
                println!(
                    "  bulk {} KiB at {at:.1?} to {to} peer(s): acked by {}, slowest {}",
                    BULK_PROBE_LEN / 1024,
                    acked.len(),
                    fmt_opt(acked.iter().max().copied()),
                );
            }
            None => println!("  bulk not sent (no peer seen)"),
        }
        for (id, stats) in peers.iter() {
            println!(
                "  {}  connect {}  direct {}  rtt {}  {}",
                id.fmt_short(),
                fmt_opt(*stats.connected_after.lock().unwrap()),
                fmt_opt(*stats.direct_after.lock().unwrap()),
                fmt_opt(*stats.last_rtt.lock().unwrap()),
                stats.traffic(),
            );
        }
    }
}

/// Every tick: one ping published through the SFU on the control lane (all
/// other probes answer with a directed pong) and one datagram the SFU fans
/// out. Once there is a peer, one bulk-lane publish per run.
async fn sfu_ping_loop(mesh: Arc<Mesh>, sfu: Arc<SfuClient>, topic: Topic) {
    if mesh
        .joined
        .subscribe()
        .wait_for(|joined| *joined)
        .await
        .is_err()
    {
        return;
    }
    let mut tick = tokio::time::interval(mesh.interval);
    let mut seq = 0u64;
    loop {
        tick.tick().await;
        seq += 1;
        if mesh.bulk_sent.lock().unwrap().is_none() {
            let peers = mesh.known_peers();
            if peers > 0 {
                let sent = mesh.since_start();
                let mut bulk = BytesMut::with_capacity(BULK_PROBE_LEN);
                bulk.put_u8(b'B');
                bulk.put_slice(mesh.me.as_bytes());
                bulk.put_u64(seq);
                bulk.put_u64(sent.as_nanos() as u64);
                bulk.resize(BULK_PROBE_LEN, 0);
                *mesh.bulk_sent.lock().unwrap() = Some((sent, peers));
                println!(
                    "bulk     publishing {} KiB to {peers} peer(s)",
                    BULK_PROBE_LEN / 1024
                );
                if let Err(err) = sfu.publish(Lane::Bulk, topic, bulk.freeze()).await {
                    println!("bulk     publish failed: {err:#}");
                }
            }
        }
        let sent_ns = mesh.since_start().as_nanos() as u64;
        let mut ping = BytesMut::with_capacity(49);
        ping.put_u8(b'P');
        ping.put_slice(mesh.me.as_bytes());
        ping.put_u64(seq);
        ping.put_u64(sent_ns);
        if sfu
            .publish(Lane::Control, topic, ping.freeze())
            .await
            .is_err()
        {
            return;
        }
        let mut dg = BytesMut::with_capacity(40);
        dg.put_slice(mesh.me.as_bytes());
        dg.put_u64(seq);
        let _ = sfu.send_datagram(&topic, &dg);
    }
}

async fn sfu_datagram_reader(mesh: Arc<Mesh>, sfu: Arc<SfuClient>) {
    while let Ok((_, payload)) = sfu.read_datagram().await {
        if payload.len() < 32 {
            continue;
        }
        let from: [u8; 32] = payload[..32].try_into().expect("32 bytes");
        let Ok(from) = EndpointId::from_bytes(&from) else {
            continue;
        };
        let stats = mesh.peers.lock().unwrap().entry(from).or_default().clone();
        stats.sfu_dgrams.fetch_add(1, Ordering::Relaxed);
    }
}

async fn accept_loop(mesh: Arc<Mesh>) {
    while let Some(incoming) = mesh.endpoint.accept().await {
        let mesh = mesh.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => return println!("peer     incoming failed: {err:?}"),
            };
            let id = conn.remote_id();
            let stats = mesh.peers.lock().unwrap().entry(id).or_default().clone();
            stats
                .learned_at
                .lock()
                .unwrap()
                .get_or_insert_with(Instant::now);
            mesh.run_peer(conn, stats, false).await;
        });
    }
}

async fn status_loop(mesh: Arc<Mesh>) {
    let mut tick = tokio::time::interval(mesh.interval.max(Duration::from_secs(1)) * 2);
    loop {
        tick.tick().await;
        let peers: Vec<_> = mesh
            .peers
            .lock()
            .unwrap()
            .iter()
            .map(|(id, s)| (*id, s.clone()))
            .collect();
        for (id, stats) in peers {
            let Some(conn) = stats.conn.lock().unwrap().clone() else {
                continue;
            };
            if conn.close_reason().is_some() {
                continue;
            }
            let rtt = conn
                .paths()
                .iter()
                .find(|p| p.is_selected())
                .map(|p| p.rtt());
            if rtt.is_some() {
                *stats.last_rtt.lock().unwrap() = rtt;
            }
            println!(
                "status   {}  {}  rtt {}  {}",
                id.fmt_short(),
                selected_path(&conn),
                fmt_opt(rtt),
                stats.traffic(),
            );
        }
    }
}

async fn watch_paths(conn: Connection, stats: Arc<PeerStats>, since: Instant, log_all: bool) {
    let id = conn.remote_id().fmt_short();
    let mut events = conn.path_events();
    while let Some(event) = events.next().await {
        match event {
            PathEvent::Selected { remote_addr, .. } => {
                if remote_addr.is_ip() {
                    stats
                        .direct_after
                        .lock()
                        .unwrap()
                        .get_or_insert(since.elapsed());
                }
                println!(
                    "path     {id} selected {remote_addr:?} at {:?}",
                    since.elapsed()
                );
            }
            PathEvent::Opened { remote_addr, .. } if log_all => {
                println!("path     {id} opened {remote_addr:?}")
            }
            PathEvent::Closed { remote_addr, .. } if log_all => {
                println!("path     {id} closed {remote_addr:?}")
            }
            PathEvent::Lagged { missed, .. } => println!("path     {id} missed {missed} event(s)"),
            _ => {}
        }
    }
}

/// Initiator side: a ping on a bidirectional stream plus one datagram per
/// tick. Ping and datagram payloads are `seq: u64`.
async fn ping_loop(conn: &Connection, stats: &PeerStats, interval: Duration) -> Result<()> {
    let (mut send, mut recv) = conn.open_bi().await?;
    let dgram_conn = conn.clone();
    let echoed = Arc::new(AtomicU64::new(0));
    let dgram_reader = {
        let echoed = echoed.clone();
        tokio::spawn(async move {
            while dgram_conn.read_datagram().await.is_ok() {
                echoed.fetch_add(1, Ordering::Relaxed);
            }
        })
    };
    let mut tick = tokio::time::interval(interval);
    let mut seq = 0u64;
    let result: Result<()> = async {
        loop {
            tick.tick().await;
            seq += 1;
            let mut payload = BytesMut::with_capacity(8);
            payload.put_u64(seq);
            let payload = payload.freeze();
            if conn.send_datagram(payload.clone()).is_ok() {
                stats.dgrams_sent.fetch_add(1, Ordering::Relaxed);
            }
            let sent = Instant::now();
            send.write_all(&payload).await?;
            let mut back = [0u8; 8];
            tokio::time::timeout(Duration::from_secs(10), recv.read_exact(&mut back))
                .await
                .context("ping timed out")??;
            if (&back[..]).get_u64() != seq {
                return Err(anyhow!("ping sequence mismatch"));
            }
            *stats.last_ping.lock().unwrap() = Some(sent.elapsed());
            stats.pings_ok.fetch_add(1, Ordering::Relaxed);
            stats
                .dgrams_echoed
                .store(echoed.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
    .await;
    dgram_reader.abort();
    result
}

/// Responder side: echo the ping stream and every datagram.
async fn echo_loop(conn: &Connection) -> Result<()> {
    let (mut send, mut recv) = conn.accept_bi().await?;
    let dgram_conn = conn.clone();
    let dgrams = tokio::spawn(async move {
        while let Ok(datagram) = dgram_conn.read_datagram().await {
            let _ = dgram_conn.send_datagram(datagram);
        }
    });
    let result = async {
        let mut buf = [0u8; 8];
        loop {
            recv.read_exact(&mut buf).await?;
            send.write_all(&buf).await?;
        }
    }
    .await;
    dgrams.abort();
    result
}

impl PeerStats {
    fn traffic(&self) -> String {
        let sfu = format!(
            "sfu rtt {} x{} dgrams {} bulk rtt {} in {} KiB",
            fmt_opt(*self.sfu_rtt.lock().unwrap()),
            self.sfu_pongs.load(Ordering::Relaxed),
            self.sfu_dgrams.load(Ordering::Relaxed),
            fmt_opt(*self.bulk_rtt.lock().unwrap()),
            self.bulk_in.load(Ordering::Relaxed) / 1024,
        );
        if !self.initiator.load(Ordering::Relaxed) {
            return format!("echoing  {sfu}");
        }
        format!(
            "ping {} x{}  dgrams {}/{}  {sfu}",
            fmt_opt(*self.last_ping.lock().unwrap()),
            self.pings_ok.load(Ordering::Relaxed),
            self.dgrams_echoed.load(Ordering::Relaxed),
            self.dgrams_sent.load(Ordering::Relaxed),
        )
    }
}

/// Splits a 32-byte endpoint id off the front of `payload`.
fn take_id(payload: &mut bytes::Bytes) -> Option<EndpointId> {
    if payload.remaining() < 32 {
        return None;
    }
    let bytes: [u8; 32] = payload.split_to(32)[..].try_into().ok()?;
    EndpointId::from_bytes(&bytes).ok()
}

fn parse_blob(blob: &[u8]) -> Option<EndpointId> {
    let rest = blob.strip_prefix(BLOB_MAGIC)?;
    let bytes: [u8; 32] = rest.try_into().ok()?;
    EndpointId::from_bytes(&bytes).ok()
}

fn selected_path(conn: &Connection) -> String {
    match conn.paths().iter().find(|path| path.is_selected()) {
        Some(path) if path.is_relay() => "relay".into(),
        Some(path) => format!("direct {:?}", path.remote_addr()),
        None => "no path".into(),
    }
}

fn fmt_opt(duration: Option<Duration>) -> String {
    duration
        .map(|d| format!("{:.1?}", d))
        .unwrap_or_else(|| "-".into())
}
