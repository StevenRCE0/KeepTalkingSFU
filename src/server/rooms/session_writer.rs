//! The session stream's writer: ERROR, JOINED, LEFT and PRESENCE frames, and
//! room snapshots encoded into chunks here, off the room lock.

use std::sync::Arc;

use iroh::endpoint::{Connection, SendStream};
use tokio::sync::mpsc;

use crate::proto::encode_snapshot;
use crate::server::{
    Shared,
    data_channels::{
        queues::{Budget, Queued, SessionItem},
        writers::{WriteFailure, stalled, write_chunks},
    },
};

/// Writes the session stream until every queue handle is gone. A write that
/// makes no progress for `stall_timeout` closes the connection.
pub(crate) async fn session_writer(
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
