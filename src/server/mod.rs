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
//! - **Outbound.** A DELIVER is encoded once and the same [`Bytes`](bytes::Bytes) are
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

mod connection;
mod data_channels;
mod limits;
mod rooms;
mod stats;
mod voice;

use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey,
    endpoint::{QuicTransportConfig, VarInt, presets},
    tls::CaTlsConfig,
};
use iroh_relay::{
    RelayQuicConfig,
    server::{
        CertConfig, ClientRateLimit, QuicConfig, RelayConfig, Server as RelayServer, ServerConfig,
        TlsConfig,
    },
};
use tokio::task::JoinHandle;
use tracing::info;

pub use limits::config::{Limits, Rate, RelayRateLimit};
pub use stats::{LaneCounts, Stats, StatsSnapshot};

use crate::proto::{SFU_ALPN, Topic};
use connection::accept_loop;
use limits::config::MIB;
use rooms::registry::Rooms;

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
