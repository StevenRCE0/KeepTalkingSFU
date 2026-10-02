//! Lane streams against an in-process `Sfu`: routing by lane, directed
//! publishes, the rules for lane and bulk streams, bulk backpressure, and
//! no head-of-line blocking between lanes.

mod common;

use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use common::*;
use iroh::endpoint::{QuicTransportConfig, RecvStream, VarInt};
use keeptalking_sfu::{
    client::{Inbox, SfuClient},
    proto::{ClientFrame, Lane, ServerFrame, Topic, read_frame, stream_error, tag},
    server::Limits,
};
use tokio::sync::mpsc;

/// `a` and `b` (reference clients) subscribed to one topic, both past their
/// snapshot, `a` past b's JOINED.
async fn pair(h: &Harness) -> (Topic, [(SfuClient, Inbox); 2], [iroh::Endpoint; 2]) {
    let topic = random_topic();
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Joined { topic, id: eb.id() }
    );
    (topic, [(a, ra), (b, rb)], [ea, eb])
}

/// A publish on a lane is delivered on that lane, and a lane keeps its
/// order.
#[tokio::test]
async fn deliveries_keep_their_lane() {
    let h = Harness::start().await;
    let (topic, [(a, mut ra), (_b, mut rb)], _endpoints) = pair(&h).await;
    for lane in Lane::ALL {
        a.publish(lane, topic, Bytes::from(lane.name()))
            .await
            .unwrap();
        assert_eq!(delivery(&mut rb).await, deliver(lane, topic, lane.name()));
    }
    for i in 0..50u8 {
        a.publish(Lane::Control, topic, Bytes::from(vec![i]))
            .await
            .unwrap();
    }
    for i in 0..50u8 {
        assert_eq!(
            delivery(&mut rb).await,
            deliver(Lane::Control, topic, vec![i])
        );
    }
    assert_quiet(&mut ra).await;
    let stats = h.sfu.stats().snapshot();
    assert_eq!(
        (
            stats.published.control,
            stats.published.interactive,
            stats.published.bulk
        ),
        (51, 1, 1)
    );
    assert_eq!(stats.delivered, stats.published);
}

/// Towards a client, control and interactive each use one long-lived
/// stream; every bulk delivery gets a stream of its own that ends after it.
#[tokio::test]
async fn sfu_opens_one_stream_per_lane_and_per_bulk_delivery() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (er, ea) = (h.endpoint(false).await, h.endpoint(false).await);
    let mut receiver = h.raw(&er).await;
    receiver.send(ClientFrame::Subscribe { topic }).await;
    assert_eq!(receiver.next().await, snapshot(topic, vec![]));
    let (a, mut ra) = h.direct_client(&ea).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;

    for i in 0..3u8 {
        for lane in [Lane::Control, Lane::Interactive] {
            a.publish(lane, topic, Bytes::from(vec![i])).await.unwrap();
        }
    }
    for i in 0..2u8 {
        a.publish(Lane::Bulk, topic, Bytes::from(vec![i]))
            .await
            .unwrap();
    }

    let mut streams: HashMap<Lane, usize> = HashMap::new();
    let mut bulk_payloads = Vec::new();
    for _ in 0..4 {
        let (lane, mut recv) = receiver.accept_lane().await;
        *streams.entry(lane).or_default() += 1;
        if lane == Lane::Bulk {
            let ServerFrame::Deliver { payload, .. } = read_server_frame(&mut recv).await else {
                panic!("expected a DELIVER");
            };
            bulk_payloads.push(payload[0]);
            // One DELIVER, then the end of the stream.
            assert_eq!(
                tokio::time::timeout(WAIT, recv.read(&mut [0u8; 1]))
                    .await
                    .unwrap()
                    .unwrap(),
                None
            );
        } else {
            for i in 0..3u8 {
                assert_eq!(
                    read_server_frame(&mut recv).await,
                    ServerFrame::Deliver {
                        topic,
                        payload: Bytes::from(vec![i])
                    }
                );
            }
        }
    }
    assert_eq!(
        streams,
        HashMap::from([(Lane::Control, 1), (Lane::Interactive, 1), (Lane::Bulk, 2)])
    );
    bulk_payloads.sort();
    assert_eq!(bulk_payloads, [0, 1]);
    let more = tokio::time::timeout(Duration::from_millis(300), receiver.conn.accept_uni()).await;
    assert!(more.is_err(), "unexpected extra stream");
}

/// PUBLISH_TO reaches the named member only, on its lane, and never echoes.
#[tokio::test]
async fn directed_publish_reaches_only_the_recipient() {
    let h = Harness::start().await;
    let (topic, [(a, mut ra), (_b, mut rb)], [_ea, eb]) = pair(&h).await;
    let ec = h.endpoint(false).await;
    let (c, mut rc) = h.direct_client(&ec).await;
    c.subscribe(topic).await.unwrap();
    next(&mut rc).await;
    next(&mut ra).await; // joined c
    next(&mut rb).await; // joined c

    for lane in Lane::ALL {
        a.publish_to(lane, topic, eb.id(), Bytes::from_static(b"for b"))
            .await
            .unwrap();
        assert_eq!(delivery(&mut rb).await, deliver(lane, topic, &b"for b"[..]));
    }
    assert_quiet(&mut rc).await;
    assert_quiet(&mut ra).await;
    let stats = h.sfu.stats().snapshot();
    assert_eq!(stats.directed, 3);
    assert_eq!(stats.delivered.total(), 3);
}

/// PUBLISH_TO a non-member, an unknown id or yourself is refused with
/// ERROR(topic, "no such recipient"); from a non-member, "not subscribed".
#[tokio::test]
async fn directed_publish_needs_a_member_recipient() {
    let h = Harness::start().await;
    let (topic, [(a, mut ra), (_b, mut rb)], [ea, eb]) = pair(&h).await;
    let ed = h.endpoint(false).await;
    let (d, mut rd) = h.direct_client(&ed).await;
    let elsewhere = random_topic();
    d.subscribe(elsewhere).await.unwrap();
    next(&mut rd).await;

    let stranger = iroh::SecretKey::generate().public();
    for recipient in [ed.id(), stranger, ea.id()] {
        a.publish_to(Lane::Interactive, topic, recipient, bytes(8))
            .await
            .unwrap();
        assert_eq!(next(&mut ra).await, error(topic, "no such recipient"));
    }
    // d is a member of another room, not this one.
    d.publish_to(Lane::Control, topic, eb.id(), bytes(8))
        .await
        .unwrap();
    assert_eq!(next(&mut rd).await, error(topic, "not subscribed"));
    assert_quiet(&mut rb).await;
    assert_quiet(&mut rd).await;
    assert_eq!(h.sfu.stats().snapshot().directed, 0);
}

/// PUBLISH and PUBLISH_TO on the session stream are refused, not
/// forwarded.
#[tokio::test]
async fn publish_on_the_session_stream_is_refused() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (er, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (b, mut rb) = h.direct_client(&eb).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    let mut raw = h.raw(&er).await;
    raw.send(ClientFrame::Subscribe { topic }).await;
    assert!(matches!(raw.next().await, ServerFrame::Snapshot { .. }));
    next(&mut rb).await; // joined

    raw.send(ClientFrame::Publish {
        topic,
        payload: bytes(4),
    })
    .await;
    assert_eq!(raw.next().await, error(topic, "publish on a lane stream"));
    raw.send(ClientFrame::PublishTo {
        topic,
        recipient: eb.id(),
        payload: bytes(4),
    })
    .await;
    assert_eq!(raw.next().await, error(topic, "publish on a lane stream"));
    assert_quiet(&mut rb).await;

    // The same frame on a lane stream goes through.
    let mut control = raw.open_stream(Lane::Control.byte()).await;
    write_frames(
        &mut control,
        &[ClientFrame::Publish {
            topic,
            payload: bytes(4),
        }],
    )
    .await;
    assert_eq!(
        delivery(&mut rb).await,
        deliver(Lane::Control, topic, bytes(4))
    );
}

/// A raw publisher subscribed to a room with reference client `b`.
async fn raw_publisher(h: &Harness) -> (Topic, Raw, SfuClient, Inbox, Vec<iroh::Endpoint>) {
    let topic = random_topic();
    let (er, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (b, mut rb) = h.direct_client(&eb).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    let mut raw = h.raw(&er).await;
    raw.send(ClientFrame::Subscribe { topic }).await;
    assert!(matches!(raw.next().await, ServerFrame::Snapshot { .. }));
    next(&mut rb).await; // joined
    (topic, raw, b, rb, vec![er, eb])
}

/// A stream whose first byte is not a lane is stopped and counted; the
/// connection carries on.
#[tokio::test]
async fn unknown_lane_byte_stops_the_stream() {
    let h = Harness::start().await;
    let (topic, raw, _b, mut rb, _endpoints) = raw_publisher(&h).await;
    for first in [0x00, 0x04, tag::PUBLISH] {
        let mut send = raw.open_stream(first).await;
        write_frames(
            &mut send,
            &[ClientFrame::Publish {
                topic,
                payload: bytes(4),
            }],
        )
        .await;
        assert_eq!(stopped(&send).await, u64::from(stream_error::UNKNOWN_LANE));
    }
    assert_quiet(&mut rb).await;
    assert_eq!(h.sfu.stats().snapshot().bad_lanes, 3);

    let mut interactive = raw.open_stream(Lane::Interactive.byte()).await;
    write_frames(
        &mut interactive,
        &[ClientFrame::Publish {
            topic,
            payload: bytes(4),
        }],
    )
    .await;
    assert_eq!(
        delivery(&mut rb).await,
        deliver(Lane::Interactive, topic, bytes(4))
    );
}

/// A bulk stream carries one frame: it is forwarded, and anything after it
/// stops the stream.
#[tokio::test]
async fn bulk_stream_carries_one_frame() {
    let h = Harness::start().await;
    let (topic, raw, _b, mut rb, _endpoints) = raw_publisher(&h).await;
    let mut wire = Vec::new();
    for payload in [&b"first"[..], b"second"] {
        wire.extend_from_slice(
            &ClientFrame::Publish {
                topic,
                payload: Bytes::copy_from_slice(payload),
            }
            .encode(),
        );
    }
    let mut send = raw.open_stream(Lane::Bulk.byte()).await;
    send.write_all(&wire).await.unwrap();
    assert_eq!(
        delivery(&mut rb).await,
        deliver(Lane::Bulk, topic, &b"first"[..])
    );
    assert_eq!(stopped(&send).await, u64::from(stream_error::BULK_TRAILING));
    assert_quiet(&mut rb).await;
    let stats = h.sfu.stats().snapshot();
    assert_eq!((stats.published.bulk, stats.bulk_stopped), (1, 1));

    // One frame and FIN is the normal case.
    let mut send = raw.open_stream(Lane::Bulk.byte()).await;
    write_frames(
        &mut send,
        &[ClientFrame::Publish {
            topic,
            payload: bytes(3),
        }],
    )
    .await;
    send.finish().unwrap();
    assert_eq!(
        delivery(&mut rb).await,
        deliver(Lane::Bulk, topic, bytes(3))
    );
    assert_eq!(h.sfu.stats().snapshot().bulk_stopped, 1);
}

/// A malformed frame, or a session frame, on a control or interactive
/// stream is skipped with a general ERROR; on a bulk stream it stops the
/// stream.
#[tokio::test]
async fn malformed_lane_frames() {
    let h = Harness::start().await;
    let (topic, mut raw, _b, mut rb, _endpoints) = raw_publisher(&h).await;
    let mut control = raw.open_stream(Lane::Control.byte()).await;
    control
        .write_all(&[0, 0, 0, 4, 0x7E, 1, 2, 3])
        .await
        .unwrap();
    write_frames(
        &mut control,
        &[
            ClientFrame::Subscribe {
                topic: random_topic(),
            },
            ClientFrame::Publish {
                topic,
                payload: bytes(2),
            },
        ],
    )
    .await;
    for expected in ["malformed frame 0x7e", "malformed frame 0x21"] {
        let ServerFrame::Error {
            topic: None,
            reason,
        } = raw.next().await
        else {
            panic!("expected a general error");
        };
        assert!(reason.starts_with(expected), "{reason}");
    }
    assert_eq!(
        delivery(&mut rb).await,
        deliver(Lane::Control, topic, bytes(2))
    );

    let mut bulk = raw.open_stream(Lane::Bulk.byte()).await;
    bulk.write_all(&[0, 0, 0, 4, 0x7E, 1, 2, 3]).await.unwrap();
    assert_eq!(stopped(&bulk).await, u64::from(stream_error::MALFORMED));
    let mut bulk = raw.open_stream(Lane::Bulk.byte()).await;
    write_frames(&mut bulk, &[ClientFrame::Unsubscribe { topic }]).await;
    assert_eq!(stopped(&bulk).await, u64::from(stream_error::MALFORMED));
    assert_quiet(&mut rb).await;
    // Still subscribed: the UNSUBSCRIBE on the bulk stream did nothing.
    assert_eq!(h.sfu.members(topic).len(), 2);
    let stats = h.sfu.stats().snapshot();
    assert_eq!((stats.malformed, stats.bulk_stopped), (4, 2));
}

/// A client endpoint whose streams take only 64 KiB before the SFU must
/// wait for it to read.
async fn slow_reader_endpoint(h: &Harness) -> iroh::Endpoint {
    h.endpoint_with(
        QuicTransportConfig::builder()
            .stream_receive_window(VarInt::from_u32(64 * 1024))
            .build(),
    )
    .await
}

/// What a raw receiver's lane acceptor collects: DELIVERs from its control
/// and interactive streams (with arrival time) and its bulk streams, unread.
struct LaneSink {
    deliveries: mpsc::UnboundedReceiver<(Instant, Lane, ServerFrame)>,
    bulk: Arc<Mutex<Vec<RecvStream>>>,
}

/// Accepts every SFU stream on `raw`: control and interactive streams are
/// read promptly, bulk streams are kept unread.
fn sink(raw: &Raw) -> LaneSink {
    let (tx, deliveries) = mpsc::unbounded_channel();
    let bulk = Arc::new(Mutex::new(Vec::new()));
    let (conn, held) = (raw.conn.clone(), bulk.clone());
    tokio::spawn(async move {
        while let Ok(mut recv) = conn.accept_uni().await {
            let mut byte = [0u8; 1];
            recv.read_exact(&mut byte).await.unwrap();
            let lane = Lane::from_byte(byte[0]).unwrap();
            if lane == Lane::Bulk {
                held.lock().unwrap().push(recv);
                continue;
            }
            let tx = tx.clone();
            tokio::spawn(async move {
                while let Ok(Some((tag, body))) = read_frame(&mut recv).await {
                    let frame = ServerFrame::decode(tag, body).unwrap();
                    let _ = tx.send((Instant::now(), lane, frame));
                }
            });
        }
    });
    LaneSink { deliveries, bulk }
}

/// A receiver that never reads its bulk streams loses bulk deliveries to
/// its budget (oldest waiting first) but stays connected, and its control
/// lane keeps delivering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_bulk_consumer_gets_drops_not_disconnected() {
    let h = Harness::with_limits(Limits {
        bulk_outbox_bytes: 1024 * 1024,
        stall_timeout: Duration::from_secs(60),
        publish_rate: GENEROUS,
        ..Limits::default()
    })
    .await;
    let topic = random_topic();
    let (es, ea) = (slow_reader_endpoint(&h).await, h.endpoint(false).await);
    let mut slow = h.raw(&es).await;
    slow.send(ClientFrame::Subscribe { topic }).await;
    slow.next().await;
    let mut lanes = sink(&slow);
    let (a, mut ra) = h.direct_client(&ea).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;

    // 16 × 256 KiB against a 1 MiB budget: three fit on streams the
    // receiver never drains, the other 13 are dropped.
    for _ in 0..16 {
        a.publish(Lane::Bulk, topic, bytes(256 * 1024))
            .await
            .unwrap();
    }
    eventually("bulk drops", || h.sfu.stats().snapshot().bulk_dropped == 13).await;
    a.publish(Lane::Control, topic, Bytes::from_static(b"still here"))
        .await
        .unwrap();
    let (_, lane, frame) = tokio::time::timeout(WAIT, lanes.deliveries.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        (lane, frame),
        (
            Lane::Control,
            ServerFrame::Deliver {
                topic,
                payload: Bytes::from_static(b"still here")
            }
        )
    );
    eventually("three bulk streams", || {
        lanes.bulk.lock().unwrap().len() == 3
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(lanes.bulk.lock().unwrap().len(), 3);
    assert!(slow.conn.close_reason().is_none());
    let stats = h.sfu.stats().snapshot();
    assert_eq!(
        (stats.slow_consumers, stats.stalled, stats.bulk_stalled),
        (0, 0, 0)
    );
    assert_eq!(stats.delivered.bulk, 16);
    assert_eq!(h.sfu.members(topic).len(), 2);
}

/// A bulk stream the receiver never reads is reset after the stall
/// timeout; the connection stays and its other lanes keep delivering.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_bulk_stream_is_reset() {
    let h = Harness::with_limits(Limits {
        stall_timeout: Duration::from_secs(1),
        publish_rate: GENEROUS,
        ..Limits::default()
    })
    .await;
    let topic = random_topic();
    let (es, ea) = (slow_reader_endpoint(&h).await, h.endpoint(false).await);
    let mut slow = h.raw(&es).await;
    slow.send(ClientFrame::Subscribe { topic }).await;
    slow.next().await;
    let mut lanes = sink(&slow);
    let (a, mut ra) = h.direct_client(&ea).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;

    a.publish(Lane::Bulk, topic, bytes(256 * 1024))
        .await
        .unwrap();
    eventually("the bulk stream", || lanes.bulk.lock().unwrap().len() == 1).await;
    let mut held = lanes.bulk.lock().unwrap().pop().unwrap();
    let reset = tokio::time::timeout(WAIT, held.received_reset())
        .await
        .expect("bulk stream was not reset")
        .expect("reset");
    assert_eq!(reset, Some(VarInt::from_u32(stream_error::STALLED)));
    assert_eq!(h.sfu.stats().snapshot().bulk_stalled, 1);

    a.publish(Lane::Interactive, topic, Bytes::from_static(b"alive"))
        .await
        .unwrap();
    let (_, lane, _) = tokio::time::timeout(WAIT, lanes.deliveries.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(lane, Lane::Interactive);
    assert!(slow.conn.close_reason().is_none());
    let stats = h.sfu.stats().snapshot();
    assert_eq!((stats.stalled, stats.slow_consumers), (0, 0));
}

/// An interactive DELIVER overtakes a multi-MiB bulk fan-out that the same
/// receiver is still reading slowly. Queued behind it on one shared stream
/// (as in sfu/1) it would arrive only after all of it, ~2.6 s here.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interactive_is_not_delayed_behind_bulk() {
    const BULK: usize = 4;
    const PAYLOAD: usize = 1024 * 1024;
    let h = Harness::with_limits(Limits {
        publish_rate: GENEROUS,
        ..Limits::default()
    })
    .await;
    let topic = random_topic();
    let (er, ea) = (slow_reader_endpoint(&h).await, h.endpoint(false).await);
    let mut receiver = h.raw(&er).await;
    receiver.send(ClientFrame::Subscribe { topic }).await;
    receiver.next().await;

    // Each bulk stream is read at ~400 KB/s (~1.6 MB/s for all four);
    // interactive ones at once.
    let bulk_read = Arc::new(AtomicUsize::new(0));
    let bulk_done = Arc::new(AtomicUsize::new(0));
    let (tx, mut interactive) = mpsc::unbounded_channel();
    let conn = receiver.conn.clone();
    let (read, done) = (bulk_read.clone(), bulk_done.clone());
    tokio::spawn(async move {
        while let Ok(mut recv) = conn.accept_uni().await {
            let mut byte = [0u8; 1];
            recv.read_exact(&mut byte).await.unwrap();
            let (tx, read, done) = (tx.clone(), read.clone(), done.clone());
            tokio::spawn(async move {
                if Lane::from_byte(byte[0]) == Some(Lane::Bulk) {
                    let mut buf = vec![0u8; 16 * 1024];
                    while let Ok(Some(n)) = recv.read(&mut buf).await {
                        read.fetch_add(n, Ordering::Relaxed);
                        tokio::time::sleep(Duration::from_millis(40)).await;
                    }
                    done.fetch_add(1, Ordering::Relaxed);
                } else {
                    while let Ok(Some((tag, body))) = read_frame(&mut recv).await {
                        let frame = ServerFrame::decode(tag, body).unwrap();
                        let _ = tx.send((Instant::now(), frame));
                    }
                }
            });
        }
    });
    let (a, mut ra) = h.direct_client(&ea).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;

    for _ in 0..BULK {
        a.publish(Lane::Bulk, topic, bytes(PAYLOAD)).await.unwrap();
    }
    eventually("bulk to be in flight", || {
        bulk_read.load(Ordering::Relaxed) > 0
    })
    .await;
    let sent = Instant::now();
    a.publish(Lane::Interactive, topic, Bytes::from_static(b"urgent"))
        .await
        .unwrap();
    let (arrived, frame) = tokio::time::timeout(WAIT, interactive.recv())
        .await
        .expect("interactive delivery timed out")
        .unwrap();
    let in_flight = bulk_read.load(Ordering::Relaxed);
    assert_eq!(
        frame,
        ServerFrame::Deliver {
            topic,
            payload: Bytes::from_static(b"urgent")
        }
    );
    let latency = arrived - sent;
    assert!(
        latency < Duration::from_millis(500),
        "interactive took {latency:?}"
    );
    let total = BULK * (PAYLOAD + 32 + 5);
    assert!(
        in_flight < total / 2,
        "bulk was not in flight: {in_flight} of {total} bytes read"
    );
    // The bulk deliveries still complete, every byte of them.
    eventually("bulk to finish", || {
        bulk_done.load(Ordering::Relaxed) == BULK
    })
    .await;
    assert_eq!(bulk_read.load(Ordering::Relaxed), total);
}
