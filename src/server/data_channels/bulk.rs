//! The bulk lane: a dropping queue per connection and a dispatcher that
//! sends each delivery on its own stream until the client acknowledges it.

use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, MutexGuard},
};

use iroh::endpoint::Connection;
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
};
use tracing::debug;

use super::{
    queues::Deliver,
    writers::{WriteFailure, open_lane, write_chunks},
};
use crate::proto::{Lane, stream_error};
use crate::server::{Shared, Stats};

/// Bulk deliveries waiting for a stream, plus the accounting for those on
/// a stream and not yet acknowledged.
pub(crate) struct BulkQueue {
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
    pub(crate) fn new(budget: usize) -> Self {
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
    pub(crate) fn push(&self, frame: Deliver) -> u64 {
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

    pub(crate) fn close(&self) {
        self.lock().closed = true;
        self.ready.notify_one();
    }
}

/// Sends queued bulk deliveries, each on its own stream, at most
/// `max_bulk_streams` at a time, until the queue closes and drains.
pub(crate) async fn bulk_dispatcher(queue: Arc<BulkQueue>, conn: Connection, shared: Arc<Shared>) {
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

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

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
