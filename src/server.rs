//! The service: an embedded iroh relay plus a hub endpoint that keeps
//! per-context presence rooms. It never carries message traffic; peers talk
//! over their own iroh connections, relayed through the embedded relay until
//! they punch through to a direct path.

use std::{
    collections::{HashMap, HashSet, hash_map::Entry},
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
use uuid::Uuid;

use crate::proto::{
    ClientFrame, MAX_PRESENCE_LEN, Member, PRESENCE_ALPN, ServerFrame, read_frame, write_frame,
};

/// Contexts one connection may be joined to at once.
pub const MAX_CONTEXTS_PER_CONNECTION: usize = 512;
/// Frames queued towards one client before it is dropped as too slow.
const OUTBOX_CAPACITY: usize = 1024;

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
    /// UDP sockets for the hub endpoint. Empty = OS default.
    pub hub_bind: Vec<SocketAddr>,
    pub hub_secret: SecretKey,
    /// Trust anchors the hub uses to reach its own relay. `None` = web PKI.
    pub hub_ca: Option<CaTlsConfig>,
}

pub struct Sfu {
    relay: RelayServer,
    hub: Endpoint,
    relay_url: RelayUrl,
    relay_map: RelayMap,
    rooms: Arc<Rooms>,
    accept_task: JoinHandle<()>,
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

        let mut hub = Endpoint::builder(presets::Minimal)
            .secret_key(config.hub_secret)
            .alpns(vec![PRESENCE_ALPN.to_vec()])
            .relay_mode(RelayMode::Custom(relay_map.clone()));
        if let Some(ca) = config.hub_ca {
            hub = hub.ca_tls_config(ca);
        }
        for addr in config.hub_bind {
            hub = hub
                .bind_addr(addr)
                .map_err(|err| anyhow!("hub bind {addr}: {err:?}"))?;
        }
        let hub = hub
            .bind()
            .await
            .map_err(|err| anyhow!("hub endpoint: {err:?}"))?;

        let rooms = Arc::new(Rooms::default());
        let accept_task = tokio::spawn(accept_loop(hub.clone(), rooms.clone()));
        info!(hub = %hub.id(), relay = %relay_url, "sfu up");
        Ok(Self {
            relay,
            hub,
            relay_url,
            relay_map,
            rooms,
            accept_task,
        })
    }

    pub fn hub_id(&self) -> EndpointId {
        self.hub.id()
    }

    /// The hub address clients dial: its id plus the relay. Direct paths
    /// are discovered by iroh once connected.
    pub fn hub_addr(&self) -> EndpointAddr {
        EndpointAddr::new(self.hub.id()).with_relay_url(self.relay_url.clone())
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

    pub fn hub_sockets(&self) -> Vec<SocketAddr> {
        self.hub.bound_sockets()
    }

    /// Current members of a context, for diagnostics and tests.
    pub fn members(&self, context: Uuid) -> Vec<EndpointId> {
        self.rooms.members(context)
    }

    /// Resolves when the relay stops on its own (it should not).
    pub async fn relay_stopped(&mut self) {
        let _ = self.relay.join().await;
    }

    pub async fn shutdown(self) -> Result<()> {
        self.accept_task.abort();
        self.hub.close().await;
        self.relay
            .shutdown()
            .await
            .map_err(|err| anyhow!("relay shutdown: {err:?}"))
    }
}

async fn accept_loop(hub: Endpoint, rooms: Arc<Rooms>) {
    while let Some(incoming) = hub.accept().await {
        let rooms = rooms.clone();
        tokio::spawn(async move {
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    debug!("handshake failed: {err:?}");
                    return;
                }
            };
            let peer = conn.remote_id();
            if let Err(err) = serve_connection(conn, &rooms).await {
                debug!(peer = %peer.fmt_short(), "connection ended: {err:#}");
            }
        });
    }
}

static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

async fn serve_connection(conn: Connection, rooms: &Rooms) -> Result<()> {
    let peer = conn.remote_id();
    let conn_id = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
    let (mut send, mut recv) = conn.accept_bi().await?;
    debug!(peer = %peer.fmt_short(), conn_id, "presence stream open");

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
    let mut joined = HashSet::new();
    let result = read_loop(&mut recv, &handle, &mut joined, rooms).await;

    for context in joined {
        rooms.leave(context, &handle);
    }
    drop(handle);
    let _ = writer.await;
    result
}

async fn read_loop(
    recv: &mut iroh::endpoint::RecvStream,
    handle: &MemberHandle,
    joined: &mut HashSet<Uuid>,
    rooms: &Rooms,
) -> Result<()> {
    while let Some((tag, body)) = read_frame(recv).await? {
        let frame = match ClientFrame::decode(tag, body) {
            Ok(frame) => frame,
            Err(err) => {
                handle.error(format!("{err:#}"));
                continue;
            }
        };
        match frame {
            ClientFrame::Join { context } => {
                if !joined.contains(&context) && joined.len() >= MAX_CONTEXTS_PER_CONNECTION {
                    handle.error(format!(
                        "too many contexts (max {MAX_CONTEXTS_PER_CONNECTION})"
                    ));
                    continue;
                }
                joined.insert(context);
                rooms.join(context, handle);
            }
            ClientFrame::Leave { context } => {
                if joined.remove(&context) {
                    rooms.leave(context, handle);
                }
            }
            ClientFrame::Publish { context, blob } => {
                if blob.len() > MAX_PRESENCE_LEN {
                    handle.error(format!("presence too large (max {MAX_PRESENCE_LEN} bytes)"));
                } else if !joined.contains(&context) {
                    handle.error(format!("publish to unjoined context {context}"));
                } else {
                    rooms.publish(context, handle, blob);
                }
            }
        }
    }
    Ok(())
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

    fn error(&self, reason: String) {
        self.deliver(ServerFrame::Error { reason }.encode());
    }
}

struct Slot {
    handle: MemberHandle,
    blob: Bytes,
}

/// Presence rooms keyed by context, members keyed by endpoint id. Every
/// mutation and the frames it causes happen under one lock, so each client
/// sees a room's events in a consistent order (snapshot first).
#[derive(Default)]
struct Rooms {
    inner: Mutex<HashMap<Uuid, HashMap<EndpointId, Slot>>>,
}

impl Rooms {
    fn join(&self, context: Uuid, handle: &MemberHandle) {
        let mut rooms = self.inner.lock().expect("rooms lock");
        let room = rooms.entry(context).or_default();
        let announce = match room.entry(handle.peer) {
            // Same connection joining twice: just resend the snapshot.
            Entry::Occupied(slot) if slot.get().handle.conn_id == handle.conn_id => false,
            // A newer connection from the same endpoint takes the slot over.
            Entry::Occupied(mut slot) => {
                slot.insert(Slot {
                    handle: handle.clone(),
                    blob: Bytes::new(),
                });
                true
            }
            Entry::Vacant(slot) => {
                slot.insert(Slot {
                    handle: handle.clone(),
                    blob: Bytes::new(),
                });
                true
            }
        };
        let members = room
            .iter()
            .filter(|(id, _)| **id != handle.peer)
            .map(|(id, slot)| Member {
                id: *id,
                blob: slot.blob.clone(),
            })
            .collect();
        handle.deliver(ServerFrame::Snapshot { context, members }.encode());
        if announce {
            broadcast(
                room,
                handle.peer,
                &ServerFrame::Joined {
                    context,
                    id: handle.peer,
                },
            );
            info!(context = %context, peer = %handle.peer.fmt_short(), size = room.len(), "joined");
        }
    }

    fn leave(&self, context: Uuid, handle: &MemberHandle) {
        let mut rooms = self.inner.lock().expect("rooms lock");
        let Some(room) = rooms.get_mut(&context) else {
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
                context,
                id: handle.peer,
            },
        );
        info!(context = %context, peer = %handle.peer.fmt_short(), size = room.len(), "left");
        if room.is_empty() {
            rooms.remove(&context);
        }
    }

    fn publish(&self, context: Uuid, handle: &MemberHandle, blob: Bytes) {
        let mut rooms = self.inner.lock().expect("rooms lock");
        let Some(room) = rooms.get_mut(&context) else {
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
                context,
                id: handle.peer,
                blob,
            },
        );
    }

    fn members(&self, context: Uuid) -> Vec<EndpointId> {
        let rooms = self.inner.lock().expect("rooms lock");
        rooms
            .get(&context)
            .map(|room| room.keys().copied().collect())
            .unwrap_or_default()
    }
}

fn broadcast(room: &HashMap<EndpointId, Slot>, except: EndpointId, frame: &ServerFrame) {
    let frame = frame.encode();
    for (id, slot) in room {
        if *id != except {
            slot.handle.deliver(frame.clone());
        }
    }
}
