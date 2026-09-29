//! `kt-probe`: joins a presence room on a `kt-sfu` and forms a full mesh
//! with every other probe in it, reporting how each peer connection behaves:
//! time to connect, relay → direct upgrade, RTT, and datagram delivery.
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
    client::{ClientOptions, PresenceClient, bind_client},
    proto::ServerFrame,
    tls::ca_from_pem_file,
};
use n0_future::StreamExt;
use uuid::Uuid;

const PROBE_ALPN: &[u8] = b"keeptalking/probe/1";
/// Presence blob a probe publishes. The SDK will publish a context-sealed
/// envelope here instead; the probe keeps it readable.
const BLOB_MAGIC: &[u8] = b"kt-probe/1:";

#[derive(Parser, Debug)]
#[command(
    name = "kt-probe",
    about = "Probe a kt-sfu: presence + full-mesh peer connections"
)]
enum Command {
    /// Join a context and connect to every other probe in it.
    Room(RoomArgs),
}

#[derive(Parser, Debug)]
struct RoomArgs {
    /// Hub endpoint id printed by kt-sfu.
    #[arg(long)]
    hub: EndpointId,
    /// Relay URL printed by kt-sfu.
    #[arg(long)]
    relay: RelayUrl,
    /// QUIC address-discovery port of the relay (kt-sfu prints it).
    #[arg(long)]
    qad_port: Option<u16>,
    /// PEM root to trust for the relay (the file `kt-sfu --dev` writes).
    #[arg(long)]
    relay_ca: Option<PathBuf>,
    /// Context to join. A random one is generated and printed if omitted.
    #[arg(long)]
    context: Option<Uuid>,
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
    let relay_map: iroh::RelayMap =
        iroh::RelayConfig::new(args.relay.clone(), args.qad_port.map(RelayQuicConfig::new)).into();
    let ca = args.relay_ca.as_deref().map(ca_from_pem_file).transpose()?;
    let endpoint = bind_client(ClientOptions {
        relay_map,
        ca,
        alpns: vec![PROBE_ALPN.to_vec()],
        secret_key: None,
        relay_only: args.relay_only,
    })
    .await?;
    let me = endpoint.id();
    let context = args.context.unwrap_or_else(Uuid::new_v4);
    println!("me       {me}");
    println!("context  {context}");

    let hub = EndpointAddr::new(args.hub).with_relay_url(args.relay.clone());
    let (presence, mut frames) = PresenceClient::connect(&endpoint, hub).await?;
    println!("hub      connected in {:?}", started.elapsed());
    presence.join(context).await?;
    let mut blob = BytesMut::from(BLOB_MAGIC);
    blob.put_slice(me.as_bytes());
    presence.publish(context, blob.freeze()).await?;

    let mesh = Arc::new(Mesh {
        endpoint: endpoint.clone(),
        me,
        relay: args.relay.clone(),
        interval: Duration::from_secs_f64(args.interval),
        log_paths: args.paths,
        peers: Mutex::new(HashMap::new()),
    });
    tokio::spawn(accept_loop(mesh.clone()));
    tokio::spawn(status_loop(mesh.clone()));

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
            frame = frames.recv() => {
                let Some(frame) = frame else {
                    println!("hub      presence connection closed");
                    break;
                };
                handle_frame(&mesh, frame);
            }
            _ = tokio::signal::ctrl_c() => break,
            _ = &mut deadline => break,
        }
    }

    presence.close();
    endpoint.close().await;
    mesh.print_summary();
    Ok(())
}

fn handle_frame(mesh: &Arc<Mesh>, frame: ServerFrame) {
    match frame {
        ServerFrame::Snapshot { members, .. } => {
            println!("room     snapshot: {} other member(s)", members.len());
            for member in members {
                mesh.learn(member.id, &member.blob);
            }
        }
        ServerFrame::Joined { id, .. } => println!("room     + {}", id.fmt_short()),
        ServerFrame::Presence { id, blob, .. } => mesh.learn(id, &blob),
        ServerFrame::Left { id, .. } => {
            println!("room     - {}", id.fmt_short());
            mesh.forget(id);
        }
        ServerFrame::Error { reason } => println!("hub      error: {reason}"),
    }
}

struct Mesh {
    endpoint: Endpoint,
    me: EndpointId,
    relay: RelayUrl,
    interval: Duration,
    log_paths: bool,
    /// Every peer ever seen; entries stay after a peer leaves so the
    /// summary covers them.
    peers: Mutex<HashMap<EndpointId, Arc<PeerStats>>>,
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
}

impl Mesh {
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
        let stats = {
            let mut peers = self.peers.lock().unwrap();
            if peers.contains_key(&id) {
                return;
            }
            let stats = Arc::new(PeerStats::default());
            *stats.learned_at.lock().unwrap() = Some(Instant::now());
            peers.insert(id, stats.clone());
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
        if !self.initiator.load(Ordering::Relaxed) {
            return "echoing".into();
        }
        format!(
            "ping {} x{}  dgrams {}/{}",
            fmt_opt(*self.last_ping.lock().unwrap()),
            self.pings_ok.load(Ordering::Relaxed),
            self.dgrams_echoed.load(Ordering::Relaxed),
            self.dgrams_sent.load(Ordering::Relaxed),
        )
    }
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
