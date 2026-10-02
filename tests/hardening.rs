//! Resource bounds against an in-process `Sfu`: slow and stalled readers,
//! rate limits, connections that never open a stream, and the connection
//! cap.

mod common;

use std::{sync::atomic::Ordering, time::Duration};

use bytes::Bytes;
use common::*;
use iroh::endpoint::Connection;
use keeptalking_sfu::{
    client::{Inbox, SfuClient},
    proto::{ClientFrame, Lane, SFU_ALPN, ServerFrame, Topic, close},
    server::{Limits, Rate},
};

/// A publisher, a healthy reader and a reader that never reads, all in one
/// room. The non-reader's connection is open and subscribed.
struct SlowRoom {
    topic: Topic,
    publisher: SfuClient,
    healthy: SfuClient,
    healthy_rx: Inbox,
    slow: Raw,
    slow_id: iroh::EndpointId,
    _endpoints: Vec<iroh::Endpoint>,
}

async fn slow_room(h: &Harness) -> SlowRoom {
    let topic = random_topic();
    let (ea, ec, es) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );
    let (publisher, mut pa) = h.direct_client(&ea).await;
    let (healthy, mut healthy_rx) = h.direct_client(&ec).await;
    publisher.subscribe(topic).await.unwrap();
    next(&mut pa).await;
    healthy.subscribe(topic).await.unwrap();
    next(&mut healthy_rx).await;
    let mut slow = h.raw(&es).await;
    slow.send(ClientFrame::Subscribe { topic }).await;
    eventually("the slow reader to join", || {
        h.sfu.members(topic).len() == 3
    })
    .await;
    // The publisher's own frames are irrelevant; keep its queue drained.
    tokio::spawn(async move { while pa.frames.recv().await.is_some() {} });
    SlowRoom {
        topic,
        publisher,
        healthy,
        healthy_rx,
        slow,
        slow_id: es.id(),
        _endpoints: vec![ea, ec, es],
    }
}

/// Publishes `count` payloads of 64 KiB on `lane`, paced well below what a
/// healthy reader drains (~6 MB/s), and checks the healthy reader gets every
/// one of them, then sees the slow reader leave.
async fn publish_and_check_healthy(room: &mut SlowRoom, lane: Lane, count: usize) {
    let len = 64 * 1024;
    let mut tick = tokio::time::interval(Duration::from_millis(10));
    for _ in 0..count {
        tick.tick().await;
        room.publisher
            .publish(lane, room.topic, bytes(len))
            .await
            .unwrap();
    }
    let (mut delivered, mut slow_left) = (0, false);
    let closed = |delivered| {
        panic!(
            "healthy reader closed after {delivered} deliveries: {:?}",
            room.healthy.connection().close_reason()
        )
    };
    while delivered < count || !slow_left {
        tokio::select! {
            frame = room.healthy_rx.frames.recv() => match frame {
                Some(ServerFrame::Left { id, .. }) => {
                    assert_eq!(id, room.slow_id);
                    slow_left = true;
                }
                Some(ServerFrame::Joined { .. }) => {}
                Some(other) => panic!("unexpected {other:?}"),
                None => closed(delivered),
            },
            got = room.healthy_rx.deliveries.recv() => match got {
                Some(got) => {
                    assert_eq!((got.lane, got.payload.len()), (lane, len));
                    delivered += 1;
                }
                None => closed(delivered),
            },
            _ = tokio::time::sleep(WAIT) => panic!("timed out after {delivered} deliveries"),
        }
    }
    assert!(room.publisher.connection().close_reason().is_none());
    assert!(room.healthy.connection().close_reason().is_none());
}

/// A reader whose interactive queue outgrows the byte budget is
/// disconnected; the publisher and the other reader carry on with every
/// frame.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn slow_consumer_is_dropped_by_byte_budget() {
    // The non-reader buffers ~1.25 MB in QUIC (its interactive stream's
    // window) before its queue grows, so 64 publishes (4 MiB) overflow a
    // 1 MiB budget.
    let h = Harness::with_limits(Limits {
        outbox_bytes: 1024 * 1024,
        stall_timeout: Duration::from_secs(60),
        publish_rate: GENEROUS,
        ..Limits::default()
    })
    .await;
    let mut room = slow_room(&h).await;
    publish_and_check_healthy(&mut room, Lane::Interactive, 64).await;
    assert_eq!(
        room.slow.closed().await,
        (u64::from(close::SLOW_CONSUMER), "slow consumer".into())
    );
    eventually("the drop to be counted", || {
        h.sfu.stats().slow_consumers.load(Ordering::Relaxed) == 1
    })
    .await;
    assert_eq!(h.sfu.members(room.topic).len(), 2);
}

/// A reader whose control stream accepts no bytes for the stall timeout is
/// disconnected even though its queue is within budget.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_consumer_is_dropped() {
    let h = Harness::with_limits(Limits {
        outbox_bytes: 256 * 1024 * 1024,
        stall_timeout: Duration::from_secs(1),
        publish_rate: GENEROUS,
        ..Limits::default()
    })
    .await;
    let mut room = slow_room(&h).await;
    publish_and_check_healthy(&mut room, Lane::Control, 48).await;
    assert_eq!(
        room.slow.closed().await,
        (u64::from(close::STALLED), "stalled".into())
    );
    assert_eq!(h.sfu.stats().stalled.load(Ordering::Relaxed), 1);
    assert_eq!(h.sfu.stats().slow_consumers.load(Ordering::Relaxed), 0);
}

/// Collects DELIVERs on `deliveries` and ERRORs on `errors` until `total`
/// frames were accounted for.
async fn tally(
    deliveries: &mut Inbox,
    errors: &mut Inbox,
    topic: Topic,
    total: usize,
) -> (usize, usize) {
    let (mut delivered, mut refused) = (0, 0);
    while delivered + refused < total {
        tokio::select! {
            got = delivery(deliveries) => {
                assert_eq!(got.topic, topic);
                delivered += 1;
            }
            frame = next(errors) => {
                assert_eq!(frame, error(topic, "rate limited"));
                refused += 1;
            }
        }
    }
    (delivered, refused)
}

/// PUBLISH and PUBLISH_TO beyond the frame rate, on any lane, are refused
/// with ERROR(topic, "rate limited") and not forwarded.
#[tokio::test]
async fn publish_rate_limit_by_frames() {
    let h = Harness::with_limits(Limits {
        publish_rate: Rate {
            bytes_per_second: 1e9,
            burst_bytes: 1e9,
            frames_per_second: 2.0,
            burst_frames: 10.0,
        },
        ..Limits::default()
    })
    .await;
    let topic = random_topic();
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    next(&mut ra).await; // joined b

    // One bucket across lanes, broadcast and directed alike.
    for i in 0..30 {
        let lane = Lane::ALL[i % 3];
        if i % 2 == 0 {
            a.publish(lane, topic, Bytes::from_static(b"m"))
                .await
                .unwrap();
        } else {
            a.publish_to(lane, topic, eb.id(), Bytes::from_static(b"m"))
                .await
                .unwrap();
        }
    }
    let (delivered, refused) = tally(&mut rb, &mut ra, topic, 30).await;
    assert!((10..15).contains(&delivered), "{delivered} delivered");
    assert_eq!(delivered + refused, 30);
    assert_eq!(
        h.sfu.stats().rate_limited.load(Ordering::Relaxed),
        refused as u64
    );
    assert_quiet(&mut rb).await;
}

/// PUBLISH (lane streams) and ANNOUNCE (session stream) share a byte
/// budget.
#[tokio::test]
async fn publish_rate_limit_by_bytes() {
    let h = Harness::with_limits(Limits {
        publish_rate: Rate {
            bytes_per_second: 1024.0,
            burst_bytes: 128.0 * 1024.0,
            frames_per_second: 1e6,
            burst_frames: 1e6,
        },
        ..Limits::default()
    })
    .await;
    let topic = random_topic();
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    next(&mut ra).await; // joined b

    for lane in [Lane::Interactive, Lane::Bulk, Lane::Control] {
        a.publish(lane, topic, bytes(60 * 1024)).await.unwrap();
    }
    let (delivered, refused) = tally(&mut rb, &mut ra, topic, 3).await;
    assert_eq!((delivered, refused), (2, 1));
    // The bucket holds ~8 KiB now: a small announce passes, a large one
    // does not.
    a.announce(topic, bytes(512)).await.unwrap();
    assert!(matches!(next(&mut rb).await, ServerFrame::Presence { .. }));
    for _ in 0..20 {
        a.announce(topic, bytes(1024)).await.unwrap();
    }
    // The publisher only ever hears refusals.
    assert_eq!(next(&mut ra).await, error(topic, "rate limited"));
}

/// Room joins are rate limited too; a refused join does not subscribe.
#[tokio::test]
async fn join_rate_limit() {
    let h = Harness::with_limits(Limits {
        join_rate: Rate::frames(0.5, 3.0),
        ..Limits::default()
    })
    .await;
    let ea = h.endpoint(false).await;
    let (a, mut ra) = h.direct_client(&ea).await;
    let topics: Vec<Topic> = (0..5).map(|_| random_topic()).collect();
    for topic in &topics {
        a.subscribe(*topic).await.unwrap();
    }
    for topic in &topics[..3] {
        assert_eq!(next(&mut ra).await, snapshot(*topic, vec![]));
    }
    for topic in &topics[3..] {
        assert_eq!(next(&mut ra).await, error(*topic, "rate limited"));
        assert!(h.sfu.members(*topic).is_empty());
    }
    // A duplicate subscribe is free.
    a.subscribe(topics[0]).await.unwrap();
    assert_quiet(&mut ra).await;
}

/// Datagrams beyond the rate are dropped silently and counted.
#[tokio::test]
async fn datagram_rate_limit() {
    let h = Harness::with_limits(Limits {
        datagram_rate: Rate::frames(1.0, 5.0),
        ..Limits::default()
    })
    .await;
    let topic = random_topic();
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;

    for _ in 0..40 {
        a.send_datagram(&topic, b"voice").unwrap();
    }
    eventually("datagrams to arrive at the SFU", || {
        h.sfu.stats().datagrams_in.load(Ordering::Relaxed) >= 30
    })
    .await;
    let mut received = 0;
    while let Ok(Ok(_)) = tokio::time::timeout(Duration::from_millis(300), b.read_datagram()).await
    {
        received += 1;
    }
    assert!(received <= 6, "{received} datagrams got through");
    let stats = h.sfu.stats();
    assert!(stats.datagrams_dropped.load(Ordering::Relaxed) >= 24);
    assert!(stats.datagrams_out.load(Ordering::Relaxed) <= 6);
}

/// A connection that never opens its stream is closed.
#[tokio::test]
async fn connection_without_a_stream_is_closed() {
    let h = Harness::with_limits(Limits {
        stream_open_timeout: Duration::from_millis(300),
        ..Limits::default()
    })
    .await;
    let endpoint = h.endpoint(false).await;
    let conn = endpoint.connect(h.direct_addr(), SFU_ALPN).await.unwrap();
    assert_eq!(
        app_close(&conn).await,
        (u64::from(close::NO_STREAM), "no stream opened".into())
    );
    assert_eq!(h.sfu.stats().no_stream.load(Ordering::Relaxed), 1);
    assert_eq!(h.sfu.stats().connections.load(Ordering::Relaxed), 0);
}

async fn app_close(conn: &Connection) -> (u64, String) {
    match tokio::time::timeout(WAIT, conn.closed()).await.unwrap() {
        iroh::endpoint::ConnectionError::ApplicationClosed(close) => (
            close.error_code.into_inner(),
            String::from_utf8_lossy(&close.reason).into_owned(),
        ),
        other => panic!("unexpected close {other:?}"),
    }
}

/// Handshakes beyond the connection cap are refused; a slot frees up when
/// a connection ends.
#[tokio::test]
async fn connection_cap_refuses_handshakes() {
    let h = Harness::with_limits(Limits {
        max_connections: 2,
        ..Limits::default()
    })
    .await;
    let endpoints = [
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    ];
    let first = h.raw(&endpoints[0]).await;
    let _second = h.raw(&endpoints[1]).await;
    eventually("two connections", || {
        h.sfu.stats().connections.load(Ordering::Relaxed) == 2
    })
    .await;

    let refused = tokio::time::timeout(WAIT, endpoints[2].connect(h.direct_addr(), SFU_ALPN))
        .await
        .expect("refusal should be prompt");
    assert!(refused.is_err(), "third connection was accepted");
    assert!(h.sfu.stats().connections_refused.load(Ordering::Relaxed) >= 1);

    first.conn.close(0u32.into(), b"bye");
    eventually("a slot to free up", || {
        h.sfu.stats().connections.load(Ordering::Relaxed) == 1
    })
    .await;
    let mut third = h.raw(&endpoints[2]).await;
    let topic = random_topic();
    third.send(ClientFrame::Subscribe { topic }).await;
    assert_eq!(third.next().await, snapshot(topic, vec![]));
}
