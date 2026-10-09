//! The queues towards one client and the handle rooms hold to fill them:
//! the shared DELIVER encoding, the session/control/interactive byte
//! budget, and the hand-off to the bulk queue.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

use bytes::Bytes;
use iroh::{EndpointId, endpoint::Connection};
use tokio::sync::mpsc;

use super::bulk::BulkQueue;
use crate::proto::{Lane, Member, ServerFrame, Topic, close, frame_header, tag};
use crate::server::Stats;

/// A DELIVER frame, encoded once and shared by every recipient: a fresh
/// header plus the topic and payload sliced from the publisher's received
/// body.
#[derive(Clone)]
pub(crate) struct Deliver {
    head: Bytes,
    topic: Bytes,
    pub(crate) payload: Bytes,
}

impl Deliver {
    pub(crate) fn new(topic: Bytes, payload: Bytes) -> Self {
        debug_assert_eq!(topic.len(), 32);
        Self {
            head: frame_header(tag::DELIVER, topic.len() + payload.len()),
            topic,
            payload,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.head.len() + self.topic.len() + self.payload.len()
    }

    pub(crate) fn chunks(&self) -> [Bytes; 3] {
        [self.head.clone(), self.topic.clone(), self.payload.clone()]
    }
}

/// Something queued on the session stream.
pub(crate) enum SessionItem {
    /// An encoded frame, shared with every other recipient.
    Frame(Bytes),
    /// A room snapshot, encoded into chunks by the writer.
    Snapshot { topic: Topic, members: Vec<Member> },
}

pub(crate) struct Queued<T> {
    pub(crate) item: T,
    /// What the item counts against the byte budget.
    pub(crate) size: usize,
}

/// Byte accounting for the queues that drop a slow consumer: the session
/// stream and the control and interactive lanes.
pub(crate) struct Budget {
    pub(crate) queued: AtomicUsize,
    pub(crate) limit: usize,
    pub(crate) overflowed: AtomicBool,
}

impl Budget {
    pub(crate) fn release(&self, size: usize) {
        self.queued.fetch_sub(size, Ordering::AcqRel);
    }
}

/// The queues towards one client. Dropping the last handle closes them, so
/// the writers drain and finish.
pub(crate) struct Outbound {
    pub(crate) budget: Arc<Budget>,
    pub(crate) session: mpsc::UnboundedSender<Queued<SessionItem>>,
    /// Control, then interactive.
    pub(crate) lanes: [mpsc::UnboundedSender<Queued<Deliver>>; 2],
    pub(crate) bulk: Arc<BulkQueue>,
    pub(crate) stats: Arc<Stats>,
}

impl Drop for Outbound {
    fn drop(&mut self) {
        self.bulk.close();
    }
}

/// The sending half of one client connection, as rooms hold it.
#[derive(Clone)]
pub(crate) struct MemberHandle {
    pub(crate) peer: EndpointId,
    pub(crate) conn_id: u64,
    pub(crate) out: Arc<Outbound>,
    pub(crate) conn: Connection,
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

    pub(crate) fn push_session(&self, item: SessionItem, size: usize) {
        if self.reserve(size) && self.out.session.send(Queued { item, size }).is_err() {
            self.out.budget.release(size);
        }
    }

    pub(crate) fn push_frame(&self, frame: Bytes) {
        let size = frame.len();
        self.push_session(SessionItem::Frame(frame), size);
    }

    /// Queues a DELIVER on `lane`. Never logs: callers hold a room lock.
    pub(crate) fn deliver(&self, lane: Lane, frame: &Deliver) {
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

    pub(crate) fn error(&self, topic: Option<Topic>, reason: impl Into<String>) {
        self.push_frame(
            ServerFrame::Error {
                topic,
                reason: reason.into(),
            }
            .encode(),
        );
    }
}
