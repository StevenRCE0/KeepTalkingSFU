//! Inbound lanes: what every reader of a connection shares, and the reader
//! for each client lane stream (PUBLISH and PUBLISH_TO).

use std::sync::{Arc, Mutex, atomic::Ordering};

use anyhow::Result;
use bytes::Bytes;
use iroh::endpoint::{Connection, RecvStream};
use tokio::task::JoinSet;
use tracing::debug;

use crate::proto::{
    ClientFrame, FrameLengthError, Lane, MAX_PUBLISH_LEN, Topic, close, read_frame, read_lane_byte,
    reason, stream_error,
};
use crate::server::{
    Shared, Stats,
    data_channels::queues::{Deliver, MemberHandle},
    limits::rate_limiter::Bucket,
    rooms::registry::Refusal,
};

/// What every reader of one connection shares: the queues towards it and
/// the publish budget, which spans the session stream (ANNOUNCE) and every
/// lane (PUBLISH, PUBLISH_TO).
pub(crate) struct Readers {
    pub(crate) handle: MemberHandle,
    pub(crate) shared: Arc<Shared>,
    pub(crate) publish_rate: Mutex<Bucket>,
}

impl Readers {
    pub(crate) fn take_publish(&self, frame_len: usize) -> bool {
        self.publish_rate
            .lock()
            .expect("publish rate lock")
            .try_take(frame_len)
    }

    pub(crate) fn rate_limited(&self, topic: Topic) {
        Stats::bump(&self.shared.stats.rate_limited);
        self.handle.error(Some(topic), reason::RATE_LIMITED);
    }

    /// Answers a frame that could not be decoded (or does not belong on its
    /// stream) with a general ERROR; the stream carries on.
    pub(crate) fn skip_malformed(&self, tag: u8, err: &anyhow::Error) {
        Stats::bump(&self.shared.stats.malformed);
        debug!(peer = %self.handle.peer.fmt_short(), "skipping client frame 0x{tag:02x}: {err:#}");
        self.handle
            .error(None, format!("malformed frame 0x{tag:02x}: {err:#}"));
    }

    /// A PUBLISH or PUBLISH_TO from a lane stream. `topic` is the first 32
    /// bytes of the frame body, kept to build the DELIVER without copying.
    fn publish(&self, lane: Lane, frame: ClientFrame, topic_bytes: Bytes, frame_len: usize) {
        let (topic, recipient, payload) = match frame {
            ClientFrame::Publish { topic, payload } => (topic, None, payload),
            ClientFrame::PublishTo {
                topic,
                recipient,
                payload,
            } => (topic, Some(recipient), payload),
            _ => unreachable!("only lane frames are published"),
        };
        let (rooms, stats, handle) = (&self.shared.rooms, &self.shared.stats, &self.handle);
        if payload.len() > MAX_PUBLISH_LEN {
            return handle.error(Some(topic), reason::PUBLISH_TOO_LARGE);
        }
        if !rooms.is_member(topic, handle) {
            return handle.error(Some(topic), reason::NOT_SUBSCRIBED);
        }
        if !self.take_publish(frame_len) {
            return self.rate_limited(topic);
        }
        let deliver = Deliver::new(topic_bytes, payload);
        let result = match recipient {
            None => rooms.publish(topic, handle, lane, &deliver),
            Some(recipient) => rooms.publish_to(topic, handle, recipient, lane, &deliver),
        };
        match result {
            Ok(fanout) => {
                Stats::bump(&stats.published[lane.index()]);
                stats.delivered[lane.index()].fetch_add(fanout as u64, Ordering::Relaxed);
                if recipient.is_some() {
                    Stats::bump(&stats.directed);
                }
            }
            Err(Refusal::NotSubscribed) => handle.error(Some(topic), reason::NOT_SUBSCRIBED),
            Err(Refusal::NoSuchRecipient) => handle.error(Some(topic), reason::NO_SUCH_RECIPIENT),
        }
    }
}

/// Accepts the client's lane streams, one reader task each, until the
/// connection ends. Aborting it aborts every reader.
pub(crate) async fn accept_lanes(conn: Connection, readers: Arc<Readers>) {
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            accepted = conn.accept_uni() => {
                let Ok(recv) = accepted else { break };
                let readers = readers.clone();
                tasks.spawn(async move {
                    if let Err(err) = read_lane(recv, &readers).await {
                        if err.downcast_ref::<FrameLengthError>().is_some() {
                            readers
                                .handle
                                .conn
                                .close(close::PROTOCOL.into(), err.to_string().as_bytes());
                        }
                        debug!(peer = %readers.handle.peer.fmt_short(), "lane stream ended: {err:#}");
                    }
                });
            }
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
        }
    }
}

/// Reads one client lane stream: its lane byte, then PUBLISH/PUBLISH_TO
/// frames (exactly one on a bulk stream). A bad length prefix is returned
/// as a [`FrameLengthError`]; everything else ends the stream quietly.
async fn read_lane(mut recv: RecvStream, readers: &Readers) -> Result<()> {
    let stats = &readers.shared.stats;
    let peer = readers.handle.peer.fmt_short();
    let Some(byte) = read_lane_byte(&mut recv).await? else {
        return Ok(());
    };
    let Some(lane) = Lane::from_byte(byte) else {
        Stats::bump(&stats.bad_lanes);
        let _ = recv.stop(stream_error::UNKNOWN_LANE.into());
        debug!(%peer, "stopped a stream with unknown lane 0x{byte:02x}");
        return Ok(());
    };
    if lane == Lane::Bulk {
        let Some((tag, body)) = read_frame(&mut recv).await? else {
            return Ok(());
        };
        let frame_len = 5 + body.len();
        match decode_lane_frame(tag, body) {
            Ok((frame, topic)) => readers.publish(lane, frame, topic, frame_len),
            Err(err) => {
                Stats::bump(&stats.malformed);
                Stats::bump(&stats.bulk_stopped);
                let _ = recv.stop(stream_error::MALFORMED.into());
                debug!(%peer, "stopped a bulk stream: frame 0x{tag:02x}: {err:#}");
                return Ok(());
            }
        }
        // One frame per bulk stream: the next thing must be its end.
        if let Ok(Some(_)) = recv.read(&mut [0u8; 1]).await {
            Stats::bump(&stats.bulk_stopped);
            let _ = recv.stop(stream_error::BULK_TRAILING.into());
            debug!(%peer, "stopped a bulk stream with data after its frame");
        }
        return Ok(());
    }
    while let Some((tag, body)) = read_frame(&mut recv).await? {
        let frame_len = 5 + body.len();
        match decode_lane_frame(tag, body) {
            Ok((frame, topic)) => readers.publish(lane, frame, topic, frame_len),
            Err(err) => readers.skip_malformed(tag, &err),
        }
    }
    Ok(())
}

/// Decodes a lane frame and also returns the body's topic bytes (a slice of
/// the received buffer, which the DELIVER reuses).
fn decode_lane_frame(tag: u8, body: Bytes) -> Result<(ClientFrame, Bytes)> {
    let topic = body.slice(..body.len().min(32));
    let frame = ClientFrame::decode(tag, body)?;
    anyhow::ensure!(frame.is_lane_frame(), "not a lane frame");
    Ok((frame, topic))
}
