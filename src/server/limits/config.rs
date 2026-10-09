//! Tunable bounds: token-bucket rates, the per-room, per-connection and
//! global [`Limits`], and the embedded relay's rate limit.

use std::{num::NonZeroU32, time::Duration};

use crate::proto::{
    MAX_MEMBERS_PER_TOPIC, MAX_TOPICS_PER_CONNECTION, SNAPSHOT_CHUNK_BYTES, SNAPSHOT_CHUNK_ENTRIES,
};

pub(crate) const MIB: usize = 1024 * 1024;

/// A token-bucket rate: bytes and frames per second, each with a burst.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Rate {
    pub bytes_per_second: f64,
    pub burst_bytes: f64,
    pub frames_per_second: f64,
    pub burst_frames: f64,
}

impl Rate {
    /// A rate on frames only.
    pub const fn frames(per_second: f64, burst: f64) -> Self {
        Self {
            bytes_per_second: f64::INFINITY,
            burst_bytes: f64::INFINITY,
            frames_per_second: per_second,
            burst_frames: burst,
        }
    }
}

/// Per-room, per-connection and global bounds. The defaults are the
/// production values; tests lower them.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Members one room may hold ([`MAX_MEMBERS_PER_TOPIC`]).
    pub max_members_per_topic: usize,
    /// Topics one connection may hold ([`MAX_TOPICS_PER_CONNECTION`]).
    pub max_topics_per_connection: usize,
    /// SNAPSHOT chunk cut points ([`SNAPSHOT_CHUNK_ENTRIES`],
    /// [`SNAPSHOT_CHUNK_BYTES`]).
    pub snapshot_chunk_entries: usize,
    pub snapshot_chunk_bytes: usize,
    /// Concurrent connections (including handshakes in progress).
    pub max_connections: usize,
    /// Time a connection has to finish its QUIC handshake.
    pub handshake_timeout: Duration,
    /// Time a connection has to open its session stream.
    pub stream_open_timeout: Duration,
    /// Lane streams a client may have open at once: its control and
    /// interactive lanes plus concurrent bulk publishes. Each holds at most
    /// one partly received frame, so this × [`crate::proto::MAX_FRAME_LEN`]
    /// bounds what a connection's lane readers buffer.
    pub max_lane_streams: u32,
    /// Bytes queued towards one connection on its session stream and its
    /// control and interactive lanes before it is closed as a slow consumer.
    /// An empty budget always takes one frame.
    pub outbox_bytes: usize,
    /// Bulk bytes queued or unacknowledged towards one connection. A bulk
    /// delivery that does not fit drops the oldest queued ones (or itself).
    pub bulk_outbox_bytes: usize,
    /// Bulk streams the SFU has open towards one connection at once; more
    /// bulk deliveries wait in the queue.
    pub max_bulk_streams: usize,
    /// Time a stream may accept no bytes before its connection is closed
    /// (session, control, interactive) or it is reset (bulk).
    pub stall_timeout: Duration,
    /// PUBLISH, PUBLISH_TO (every lane) and ANNOUNCE a connection may send.
    pub publish_rate: Rate,
    /// Room joins (SUBSCRIBE) a connection may make. Each join costs the
    /// room a JOINED, so this bounds subscribe/unsubscribe churn.
    pub join_rate: Rate,
    /// Datagrams a connection may send for fan-out.
    pub datagram_rate: Rate,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_members_per_topic: MAX_MEMBERS_PER_TOPIC,
            max_topics_per_connection: MAX_TOPICS_PER_CONNECTION,
            snapshot_chunk_entries: SNAPSHOT_CHUNK_ENTRIES,
            snapshot_chunk_bytes: SNAPSHOT_CHUNK_BYTES,
            max_connections: 10_000,
            handshake_timeout: Duration::from_secs(15),
            stream_open_timeout: Duration::from_secs(10),
            // Two long-lived lanes plus 14 bulk uploads in flight, far more
            // than the publish burst lets through anyway.
            max_lane_streams: 16,
            outbox_bytes: 8 * MIB,
            bulk_outbox_bytes: 8 * MIB,
            max_bulk_streams: 16,
            stall_timeout: Duration::from_secs(20),
            // The burst is half the disconnecting outbox budget, so one
            // publisher's burst alone cannot push a healthy reader over it,
            // even on the interactive lane.
            publish_rate: Rate {
                bytes_per_second: (4 * MIB) as f64,
                burst_bytes: (4 * MIB) as f64,
                frames_per_second: 200.0,
                burst_frames: 400.0,
            },
            // The burst covers re-subscribing every topic after a reconnect.
            join_rate: Rate::frames(50.0, (MAX_TOPICS_PER_CONNECTION + 88) as f64),
            datagram_rate: Rate {
                bytes_per_second: MIB as f64,
                burst_bytes: (2 * MIB) as f64,
                frames_per_second: 1000.0,
                burst_frames: 2000.0,
            },
        }
    }
}

/// Per-client receive rate limit on the embedded relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayRateLimit {
    pub bytes_per_second: NonZeroU32,
    pub burst_bytes: NonZeroU32,
}

impl Default for RelayRateLimit {
    /// 2 MiB/s with a 4 MiB burst.
    fn default() -> Self {
        Self {
            bytes_per_second: NonZeroU32::new(2 * MIB as u32).expect("nonzero"),
            burst_bytes: NonZeroU32::new(4 * MIB as u32).expect("nonzero"),
        }
    }
}
