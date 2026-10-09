//! Writer tasks for the long-lived control and interactive lanes, plus the
//! stall-bounded write (and stall handling) the session writer and bulk
//! share.

use std::sync::Arc;

use bytes::Bytes;
use iroh::endpoint::{Connection, SendStream};
use tokio::sync::mpsc;
use tracing::warn;

use super::queues::{Budget, Deliver, Queued};
use crate::proto::{Lane, close};
use crate::server::{Limits, Shared, Stats};

/// Writes one long-lived lane (control or interactive) towards the client,
/// opening its stream on the first DELIVER. A write that makes no progress
/// for `stall_timeout` closes the connection; a stream the client stopped
/// is replaced on the next DELIVER.
pub(crate) async fn lane_writer(
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

pub(crate) fn stalled(conn: &Connection, shared: &Shared, stream: &str) {
    Stats::bump(&shared.stats.stalled);
    conn.close(close::STALLED.into(), b"stalled");
    warn!(peer = %conn.remote_id().fmt_short(), stream, "dropped a stalled consumer (no write progress)");
}

/// Opens a server → client lane stream at the lane's priority. Waiting for
/// stream credit counts as a stall.
pub(crate) async fn open_lane(
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

pub(crate) enum WriteFailure {
    Closed,
    Stalled,
}

pub(crate) async fn write_chunks(
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
