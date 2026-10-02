//! Protocol rules against an in-process `Sfu`: chunked snapshots, room and
//! topic caps, duplicate subscribes, size limits, framing errors, room
//! cleanup and datagram admission.

mod common;

use std::{sync::atomic::Ordering, time::Duration};

use bytes::Bytes;
use common::*;
use iroh::EndpointId;
use keeptalking_sfu::{
    client::Inbox,
    proto::{
        ClientFrame, Lane, MAX_ANNOUNCE_LEN, MAX_FRAME_LEN, MAX_PUBLISH_LEN, Member, ServerFrame,
        Topic, close, tag,
    },
    server::Limits,
};

/// A second SUBSCRIBE for a topic the connection holds changes nothing: no
/// snapshot, no JOINED, and the announced blob stays.
#[tokio::test]
async fn duplicate_subscribe_is_a_noop() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (ea, eb, ec) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    a.subscribe(topic).await.unwrap();
    assert_eq!(next(&mut ra).await, snapshot(topic, vec![]));
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Joined { topic, id: eb.id() }
    );
    a.announce(topic, Bytes::from_static(b"blob-a"))
        .await
        .unwrap();
    next(&mut rb).await; // presence

    for _ in 0..3 {
        a.subscribe(topic).await.unwrap();
    }
    assert_quiet(&mut ra).await;
    assert_quiet(&mut rb).await;
    assert_eq!(h.sfu.members(topic).len(), 2);

    let (c, mut rc) = h.direct_client(&ec).await;
    c.subscribe(topic).await.unwrap();
    let ServerFrame::Snapshot { members, .. } = next(&mut rc).await else {
        panic!("expected snapshot");
    };
    assert_eq!(
        sorted(members),
        sorted(vec![
            Member {
                id: ea.id(),
                blob: Bytes::from_static(b"blob-a")
            },
            Member {
                id: eb.id(),
                blob: Bytes::new()
            },
        ])
    );
}

/// A full room refuses new members (but not a reconnect of an existing
/// one) and admits them again once someone leaves.
#[tokio::test]
async fn full_room_refuses_subscribe() {
    let h = Harness::with_limits(Limits {
        max_members_per_topic: 2,
        ..Limits::default()
    })
    .await;
    let topic = random_topic();
    let (ea, eb, ec) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    let (c, mut rc) = h.direct_client(&ec).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    next(&mut ra).await; // joined b

    c.subscribe(topic).await.unwrap();
    assert_eq!(next(&mut rc).await, error(topic, "room full"));
    assert_quiet(&mut ra).await;
    assert_quiet(&mut rb).await;
    assert_eq!(h.sfu.members(topic).len(), 2);
    // Refused means not subscribed.
    c.publish(Lane::Interactive, topic, Bytes::from_static(b"x"))
        .await
        .unwrap();
    assert_eq!(next(&mut rc).await, error(topic, "not subscribed"));

    // The same endpoint reconnecting takes its own slot over.
    let (a2, mut ra2) = h.direct_client(&ea).await;
    a2.subscribe(topic).await.unwrap();
    assert!(matches!(next(&mut ra2).await, ServerFrame::Snapshot { .. }));

    b.unsubscribe(topic).await.unwrap();
    assert_eq!(
        next(&mut ra2).await,
        ServerFrame::Left { topic, id: eb.id() }
    );
    c.subscribe(topic).await.unwrap();
    assert!(matches!(next(&mut rc).await, ServerFrame::Snapshot { .. }));
    assert_eq!(
        next(&mut ra2).await,
        ServerFrame::Joined { topic, id: ec.id() }
    );
}

/// One connection holds at most `max_topics_per_connection` topics.
#[tokio::test]
async fn topic_cap_refuses_subscribe() {
    let h = Harness::with_limits(Limits {
        max_topics_per_connection: 3,
        ..Limits::default()
    })
    .await;
    let ea = h.endpoint(false).await;
    let (a, mut ra) = h.direct_client(&ea).await;
    let topics: Vec<Topic> = (0..4).map(|_| random_topic()).collect();
    for topic in &topics[..3] {
        a.subscribe(*topic).await.unwrap();
        assert_eq!(next(&mut ra).await, snapshot(*topic, vec![]));
    }
    a.subscribe(topics[3]).await.unwrap();
    assert_eq!(next(&mut ra).await, error(topics[3], "too many topics"));
    assert!(h.sfu.members(topics[3]).is_empty());

    a.unsubscribe(topics[0]).await.unwrap();
    a.subscribe(topics[3]).await.unwrap();
    assert_eq!(next(&mut ra).await, snapshot(topics[3], vec![]));
}

/// Oversized announces and publishes are refused with an ERROR naming the
/// topic and reach nobody; the reserved all-zero topic cannot be joined.
#[tokio::test]
async fn oversized_frames_are_refused() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    next(&mut ra).await; // joined b

    a.announce(topic, bytes(MAX_ANNOUNCE_LEN + 1))
        .await
        .unwrap();
    assert_eq!(next(&mut ra).await, error(topic, "announce too large"));
    assert_quiet(&mut rb).await;
    a.announce(topic, bytes(MAX_ANNOUNCE_LEN)).await.unwrap();
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Presence {
            topic,
            id: ea.id(),
            blob: bytes(MAX_ANNOUNCE_LEN)
        }
    );

    for lane in Lane::ALL {
        a.publish(lane, topic, bytes(MAX_PUBLISH_LEN + 1))
            .await
            .unwrap();
        assert_eq!(next(&mut ra).await, error(topic, "publish too large"));
        assert_quiet(&mut rb).await;
        a.publish(lane, topic, bytes(MAX_PUBLISH_LEN))
            .await
            .unwrap();
        assert_eq!(
            delivery(&mut rb).await,
            deliver(lane, topic, bytes(MAX_PUBLISH_LEN))
        );
    }

    a.subscribe(Topic::ZERO).await.unwrap();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Error {
            topic: None,
            reason: "reserved topic".into()
        }
    );
    assert!(h.sfu.members(Topic::ZERO).is_empty());
}

/// Frames with a valid length but an unknown tag or a malformed body are
/// skipped and answered with a general ERROR; the connection carries on.
/// A bad length prefix closes the connection.
#[tokio::test]
async fn malformed_frames_are_skipped() {
    let h = Harness::start().await;
    let (topic, later) = (random_topic(), random_topic());
    let endpoint = h.endpoint(false).await;
    let mut raw = h.raw(&endpoint).await;
    raw.send(ClientFrame::Subscribe { topic }).await;
    assert_eq!(raw.next().await, snapshot(topic, vec![]));

    let malformed: [&[u8]; 3] = [
        // Unknown tag.
        &[0, 0, 0, 4, 0x7E, 1, 2, 3],
        // SUBSCRIBE with a 31-byte topic.
        &[&[0, 0, 0, 32, tag::SUBSCRIBE][..], &[1; 31]].concat(),
        // PUBLISH too short to hold a topic.
        &[0, 0, 0, 3, tag::PUBLISH, 9, 9],
    ];
    for frame in malformed {
        raw.send_bytes(frame).await;
        let ServerFrame::Error {
            topic: None,
            reason,
        } = raw.next().await
        else {
            panic!("expected a general error");
        };
        assert!(reason.starts_with("malformed frame"), "{reason}");
    }
    raw.send(ClientFrame::Subscribe { topic: later }).await;
    assert_eq!(raw.next().await, snapshot(later, vec![]));
    assert_eq!(h.sfu.stats().malformed.load(Ordering::Relaxed), 3);
    assert_eq!(h.sfu.members(topic), vec![endpoint.id()]);

    let mut zero = h.raw(&endpoint).await;
    zero.send_bytes(&[0, 0, 0, 0]).await;
    assert_eq!(zero.closed().await.0, u64::from(close::PROTOCOL));

    let mut huge = h.raw(&endpoint).await;
    huge.send_bytes(&((MAX_FRAME_LEN + 1) as u32).to_be_bytes())
        .await;
    assert_eq!(huge.closed().await.0, u64::from(close::PROTOCOL));
}

/// A room's snapshot is split into chunks with MORE on all but the last; the
/// reference client merges them into one snapshot.
#[tokio::test]
async fn snapshots_are_chunked() {
    let h = Harness::with_limits(Limits {
        snapshot_chunk_entries: 2,
        ..Limits::default()
    })
    .await;
    let topic = random_topic();

    // Five members join, then each announces a blob.
    let mut endpoints = Vec::new();
    let mut clients = Vec::new();
    for _ in 0..5 {
        let endpoint = h.endpoint(false).await;
        let (client, mut rx) = h.direct_client(&endpoint).await;
        client.subscribe(topic).await.unwrap();
        assert!(matches!(next(&mut rx).await, ServerFrame::Snapshot { .. }));
        endpoints.push(endpoint);
        clients.push((client, rx));
    }
    let expected: Vec<Member> = endpoints
        .iter()
        .enumerate()
        .map(|(i, e)| Member {
            id: e.id(),
            blob: Bytes::from(vec![b'm', i as u8]),
        })
        .collect();
    for ((client, _), member) in clients.iter().zip(&expected) {
        client.announce(topic, member.blob.clone()).await.unwrap();
    }
    // Every announce has landed once member 0 sees the others' presence
    // and member 1 sees member 0's.
    wait_for_blobs(&mut clients[0].1, &expected[1..]).await;
    wait_for_blobs(&mut clients[1].1, &expected[..1]).await;

    let watcher = h.endpoint(false).await;
    let mut raw = h.raw(&watcher).await;
    raw.send(ClientFrame::Subscribe { topic }).await;
    let (mut shape, mut union) = (Vec::new(), Vec::new());
    loop {
        let ServerFrame::Snapshot { more, members, .. } = raw.next().await else {
            panic!("expected snapshot chunk");
        };
        shape.push((more, members.len()));
        union.extend(members);
        if !more {
            break;
        }
    }
    assert_eq!(shape, vec![(true, 2), (true, 2), (false, 1)]);
    assert_eq!(sorted(union), sorted(expected.clone()));

    // The reference client hands out the union in one snapshot.
    let late = h.endpoint(false).await;
    let (client, mut rx) = h.direct_client(&late).await;
    client.subscribe(topic).await.unwrap();
    let ServerFrame::Snapshot { more, members, .. } = next(&mut rx).await else {
        panic!("expected snapshot");
    };
    assert!(!more);
    let mut want = expected.clone();
    want.push(Member {
        id: watcher.id(),
        blob: Bytes::new(),
    });
    assert_eq!(sorted(members), sorted(want));
    assert_eq!(client.skipped_frames(), 0);
}

/// Reads frames until every member in `want` has been seen with its blob,
/// in a snapshot or as presence.
async fn wait_for_blobs(rx: &mut Inbox, want: &[Member]) {
    let mut missing: Vec<(EndpointId, Bytes)> =
        want.iter().map(|m| (m.id, m.blob.clone())).collect();
    while !missing.is_empty() {
        let seen: Vec<(EndpointId, Bytes)> = match next(rx).await {
            ServerFrame::Snapshot { members, .. } => {
                members.into_iter().map(|m| (m.id, m.blob)).collect()
            }
            ServerFrame::Presence { id, blob, .. } => vec![(id, blob)],
            _ => continue,
        };
        missing.retain(|entry| !seen.contains(entry));
    }
}

/// Rooms disappear once their last member leaves, whether by UNSUBSCRIBE
/// or by disconnecting.
#[tokio::test]
async fn empty_rooms_are_removed() {
    let h = Harness::start().await;
    let (topic, other) = (random_topic(), random_topic());
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    for topic in [topic, other] {
        a.subscribe(topic).await.unwrap();
        assert_eq!(next(&mut ra).await, snapshot(topic, vec![]));
    }
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    assert_eq!(h.sfu.occupancy(), (2, 3));

    a.unsubscribe(topic).await.unwrap();
    eventually("a to leave", || h.sfu.occupancy() == (2, 2)).await;
    b.close();
    eventually("b's room to go", || h.sfu.occupancy() == (1, 1)).await;
    a.unsubscribe(other).await.unwrap();
    eventually("every room to go", || h.sfu.occupancy() == (0, 0)).await;
    assert!(h.sfu.members(topic).is_empty());
}

/// Datagrams for a topic the sender has not joined are dropped.
#[tokio::test]
async fn datagrams_from_non_subscribers_are_dropped() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (ea, eb, eo) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );
    let (a, mut ra) = h.direct_client(&ea).await;
    let (b, mut rb) = h.direct_client(&eb).await;
    let (outsider, mut ro) = h.direct_client(&eo).await;
    a.subscribe(topic).await.unwrap();
    next(&mut ra).await;
    b.subscribe(topic).await.unwrap();
    next(&mut rb).await;
    // The outsider is connected and in another room, just not this one.
    outsider.subscribe(random_topic()).await.unwrap();
    next(&mut ro).await;

    for _ in 0..20 {
        outsider.send_datagram(&topic, b"intruder").unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let leaked = tokio::time::timeout(Duration::from_millis(500), b.read_datagram()).await;
    assert!(
        leaked.is_err(),
        "outsider datagram was forwarded: {leaked:?}"
    );

    // A member's datagrams still go through.
    let got = tokio::time::timeout(WAIT, async {
        loop {
            a.send_datagram(&topic, b"member").unwrap();
            if let Ok(Ok((t, payload))) =
                tokio::time::timeout(Duration::from_millis(50), b.read_datagram()).await
            {
                return (t, payload);
            }
        }
    })
    .await
    .expect("member datagram not forwarded");
    assert_eq!(got, (topic, Bytes::from_static(b"member")));
}
