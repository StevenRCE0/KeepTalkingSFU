//! Datagram fan-out.

use std::sync::Arc;

use crate::proto::split_datagram;
use crate::server::{
    Shared, Stats, data_channels::queues::MemberHandle, limits::rate_limiter::Bucket,
};

/// Forwards each `topic ‖ payload` datagram to the topic's other
/// subscribers, best effort. Datagrams over the rate limit or for topics the
/// sender has not joined are dropped.
pub(crate) async fn datagram_loop(handle: MemberHandle, shared: Arc<Shared>) {
    let stats = &shared.stats;
    let mut rate = Bucket::new(shared.limits.datagram_rate);
    while let Ok(datagram) = handle.conn.read_datagram().await {
        Stats::bump(&stats.datagrams_in);
        let targets = if rate.try_take(datagram.len()) {
            split_datagram(datagram.clone())
                .and_then(|(topic, _)| shared.rooms.datagram_targets(topic, &handle))
        } else {
            None
        };
        let Some(targets) = targets else {
            Stats::bump(&stats.datagrams_dropped);
            continue;
        };
        for conn in targets {
            if conn.send_datagram(datagram.clone()).is_ok() {
                Stats::bump(&stats.datagrams_out);
            }
        }
    }
}
