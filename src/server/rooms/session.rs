//! The session stream's reader: SUBSCRIBE, UNSUBSCRIBE and ANNOUNCE.

use std::{collections::HashSet, sync::Arc};

use anyhow::Result;
use iroh::endpoint::RecvStream;
use tracing::debug;

use crate::proto::{ClientFrame, MAX_ANNOUNCE_LEN, Topic, read_frame, reason};
use crate::server::{Stats, data_channels::readers::Readers, limits::rate_limiter::Bucket};

/// The session stream's reader: subscriptions and presence.
pub(crate) struct Session {
    pub(crate) readers: Arc<Readers>,
    pub(crate) subscribed: HashSet<Topic>,
    pub(crate) join_rate: Bucket,
}

impl Session {
    pub(crate) async fn read_loop(&mut self, recv: &mut RecvStream) -> Result<()> {
        while let Some((tag, body)) = read_frame(recv).await? {
            let frame_len = 5 + body.len();
            match ClientFrame::decode(tag, body) {
                Ok(frame) => self.handle_frame(frame, frame_len),
                // Skip it; the stream is still in sync.
                Err(err) => self.readers.skip_malformed(tag, &err),
            }
        }
        Ok(())
    }

    fn handle_frame(&mut self, frame: ClientFrame, frame_len: usize) {
        let readers = &*self.readers;
        let (rooms, stats, limits) = (
            &readers.shared.rooms,
            &readers.shared.stats,
            &readers.shared.limits,
        );
        let handle = &readers.handle;
        match frame {
            ClientFrame::Subscribe { topic } => {
                if self.subscribed.contains(&topic) {
                    // Already subscribed: no second snapshot.
                } else if topic.is_zero() {
                    handle.error(Some(topic), reason::RESERVED_TOPIC);
                } else if self.subscribed.len() >= limits.max_topics_per_connection {
                    handle.error(Some(topic), reason::TOO_MANY_TOPICS);
                } else if !self.join_rate.try_take(0) {
                    Stats::bump(&stats.rate_limited);
                    handle.error(Some(topic), reason::RATE_LIMITED);
                } else {
                    match rooms.join(topic, handle) {
                        Some(size) => {
                            self.subscribed.insert(topic);
                            debug!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), size, "joined");
                        }
                        None => handle.error(Some(topic), reason::ROOM_FULL),
                    }
                }
            }
            ClientFrame::Unsubscribe { topic } => {
                if self.subscribed.remove(&topic)
                    && let Some(size) = rooms.leave(topic, handle)
                {
                    debug!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), size, "left");
                }
            }
            ClientFrame::Announce { topic, blob } => {
                if blob.len() > MAX_ANNOUNCE_LEN {
                    handle.error(Some(topic), reason::ANNOUNCE_TOO_LARGE);
                } else if !self.subscribed.contains(&topic) {
                    handle.error(Some(topic), reason::NOT_SUBSCRIBED);
                } else if !readers.take_publish(frame_len) {
                    readers.rate_limited(topic);
                } else if rooms.announce(topic, handle, blob) {
                    debug!(topic = %topic.fmt_short(), peer = %handle.peer.fmt_short(), "announced");
                }
            }
            ClientFrame::Publish { topic, .. } | ClientFrame::PublishTo { topic, .. } => {
                handle.error(Some(topic), reason::PUBLISH_ON_SESSION);
            }
        }
    }

    pub(crate) fn leave_all(&mut self) {
        for topic in self.subscribed.drain() {
            self.readers.shared.rooms.leave(topic, &self.readers.handle);
        }
    }
}
