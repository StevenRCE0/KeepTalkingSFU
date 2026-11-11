//! Connection lifecycle: the accept loop, the connection cap, and wiring one
//! connection's readers, writers and queues together until it ends.

use std::{
    collections::HashSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use iroh::{Endpoint, endpoint::Connection};
use tokio::{sync::mpsc, task::JoinSet};
use tracing::{debug, warn};

use super::{
    Shared, Stats,
    data_channels::{
        bulk::{BulkQueue, bulk_dispatcher},
        queues::{Budget, MemberHandle, Outbound},
        readers::{Readers, accept_lanes},
        writers::lane_writer,
    },
    limits::rate_limiter::Bucket,
    rooms::{session::Session, session_writer::session_writer},
    voice::datagrams::datagram_loop,
    wake::serve_wake,
};
use crate::{
    proto::{FrameLengthError, Lane, close, priority},
    wake::WAKE_ALPN,
};

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

pub(super) async fn accept_loop(endpoint: Endpoint, shared: Arc<Shared>) {
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
            match (conn.alpn() == WAKE_ALPN, shared.wake.clone()) {
                (true, Some(wake)) => serve_wake(conn, wake, &shared).await,
                _ => serve_connection(conn, &shared).await,
            }
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
