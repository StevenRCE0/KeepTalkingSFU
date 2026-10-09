//! Running counters, read as a [`StatsSnapshot`] for logs.

use std::sync::atomic::{AtomicU64, Ordering};

use crate::proto::Lane;

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
    pub(super) fn bump(counter: &AtomicU64) {
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
