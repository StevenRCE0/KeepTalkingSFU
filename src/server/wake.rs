//! A wake connection: one bidirectional stream of requests, each answered in
//! order (see [`crate::wake`]).

use std::sync::Arc;

use iroh::endpoint::Connection;
use tracing::debug;

use super::{Shared, Stats, limits::rate_limiter::Bucket};
use crate::{
    proto::{FrameLengthError, close, read_frame_up_to, write_frame},
    wake::{MAX_WAKE_FRAME_LEN, Wake, WakeResponse, status},
};

pub(super) async fn serve_wake(conn: Connection, wake: Arc<Wake>, shared: &Arc<Shared>) {
    let peer = conn.remote_id();
    let limits = &shared.limits;
    let (mut send, mut recv) =
        match tokio::time::timeout(limits.stream_open_timeout, conn.accept_bi()).await {
            Ok(Ok(streams)) => streams,
            Ok(Err(err)) => return debug!(peer = %peer.fmt_short(), "no wake stream: {err}"),
            Err(_) => {
                Stats::bump(&shared.stats.no_stream);
                conn.close(close::NO_STREAM.into(), b"no stream opened");
                return;
            }
        };
    let mut rate = Bucket::new(limits.wake_rate);
    loop {
        let (tag, body) = match read_frame_up_to(&mut recv, MAX_WAKE_FRAME_LEN).await {
            Ok(Some(frame)) => frame,
            Ok(None) => break,
            Err(err) => {
                if err.downcast_ref::<FrameLengthError>().is_some() {
                    conn.close(close::PROTOCOL.into(), err.to_string().as_bytes());
                }
                debug!(peer = %peer.fmt_short(), "wake stream ended: {err:#}");
                break;
            }
        };
        let response = if rate.try_take(body.len()) {
            wake.respond(tag, body).await
        } else {
            WakeResponse::status(status::RATE_LIMITED, "rate limited")
        };
        if write_frame(&mut send, &response.encode()).await.is_err() {
            break;
        }
    }
    let _ = send.finish();
    let _ = conn.closed().await;
}
