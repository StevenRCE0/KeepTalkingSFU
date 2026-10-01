//! End-to-end tests against an in-process `Sfu` on localhost: topic rooms,
//! hub fan-out of publishes and datagrams, the info endpoint, and peer
//! connections carried by the embedded relay.

use std::{net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::Connection};
use keeptalking_sfu::{
    client::{ClientOptions, HubClient, bind_client},
    info,
    proto::{Member, ServerFrame, Topic},
    server::{Sfu, SfuConfig},
    tls::DevCert,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

const TEST_ALPN: &[u8] = b"keeptalking/test/1";
const WAIT: Duration = Duration::from_secs(10);

struct Harness {
    sfu: Sfu,
    dev: DevCert,
}

impl Harness {
    async fn start() -> Self {
        let dev = DevCert::generate(&[]).unwrap();
        let local = |port| (Ipv4Addr::LOCALHOST, port).into();
        let sfu = Sfu::spawn(SfuConfig {
            relay_http_bind: local(0),
            relay_https_bind: local(0),
            relay_quic_bind: Some(local(0)),
            cert: dev.cert_config().unwrap(),
            public_relay_url: None,
            public_quic_port: None,
            hub_bind: vec![local(0)],
            hub_secret: SecretKey::generate(),
            hub_ca: Some(dev.ca()),
        })
        .await
        .unwrap();
        Self { sfu, dev }
    }

    async fn endpoint(&self, relay_only: bool) -> Endpoint {
        bind_client(ClientOptions {
            relay_map: self.sfu.relay_map().clone(),
            ca: Some(self.dev.ca()),
            alpns: vec![TEST_ALPN.to_vec()],
            secret_key: None,
            relay_only,
        })
        .await
        .unwrap()
    }

    async fn hub(&self, endpoint: &Endpoint) -> (HubClient, mpsc::Receiver<ServerFrame>) {
        HubClient::connect(endpoint, self.sfu.hub_addr())
            .await
            .unwrap()
    }
}

async fn next(rx: &mut mpsc::Receiver<ServerFrame>) -> ServerFrame {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("timed out waiting for frame")
        .expect("closed")
}

async fn assert_quiet(rx: &mut mpsc::Receiver<ServerFrame>) {
    if let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
        panic!("unexpected frame {frame:?}");
    }
}

fn random_topic() -> Topic {
    Topic(SecretKey::generate().to_bytes())
}

fn sorted(mut members: Vec<Member>) -> Vec<Member> {
    members.sort_by_key(|m| *m.id.as_bytes());
    members
}

#[tokio::test]
async fn room_lifecycle() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (ea, eb, ec) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );

    let (a, mut ra) = h.hub(&ea).await;
    a.subscribe(topic).await.unwrap();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Snapshot {
            topic,
            members: vec![]
        }
    );

    let (b, mut rb) = h.hub(&eb).await;
    b.subscribe(topic).await.unwrap();
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Snapshot {
            topic,
            members: vec![Member {
                id: ea.id(),
                blob: Bytes::new()
            }]
        }
    );
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Joined { topic, id: eb.id() }
    );

    a.announce(topic, Bytes::from_static(b"sealed-a"))
        .await
        .unwrap();
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Presence {
            topic,
            id: ea.id(),
            blob: Bytes::from_static(b"sealed-a")
        }
    );
    b.announce(topic, Bytes::from_static(b"sealed-b"))
        .await
        .unwrap();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Presence {
            topic,
            id: eb.id(),
            blob: Bytes::from_static(b"sealed-b")
        }
    );

    // A late joiner gets everyone's latest presence in its snapshot.
    let (c, mut rc) = h.hub(&ec).await;
    c.subscribe(topic).await.unwrap();
    let ServerFrame::Snapshot { members, .. } = next(&mut rc).await else {
        panic!("expected snapshot")
    };
    assert_eq!(
        sorted(members),
        sorted(vec![
            Member {
                id: ea.id(),
                blob: Bytes::from_static(b"sealed-a")
            },
            Member {
                id: eb.id(),
                blob: Bytes::from_static(b"sealed-b")
            },
        ])
    );
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Joined { topic, id: ec.id() }
    );
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Joined { topic, id: ec.id() }
    );

    // Explicit leave.
    c.unsubscribe(topic).await.unwrap();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Left { topic, id: ec.id() }
    );
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Left { topic, id: ec.id() }
    );

    // Announcing to a topic you are not subscribed to is refused, not forwarded.
    c.announce(topic, Bytes::from_static(b"nope"))
        .await
        .unwrap();
    assert!(matches!(next(&mut rc).await, ServerFrame::Error { .. }));
    assert_quiet(&mut ra).await;

    // Dropping the connection leaves every subscribed room.
    b.close();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Left { topic, id: eb.id() }
    );
    assert_eq!(h.sfu.members(topic), vec![ea.id()]);
}

#[tokio::test]
async fn newer_connection_owns_the_slot() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);

    let (watcher, mut rw) = h.hub(&eb).await;
    watcher.subscribe(topic).await.unwrap();
    next(&mut rw).await; // snapshot

    let (old, mut ro) = h.hub(&ea).await;
    old.subscribe(topic).await.unwrap();
    next(&mut ro).await;
    assert_eq!(
        next(&mut rw).await,
        ServerFrame::Joined { topic, id: ea.id() }
    );

    // Same endpoint reconnects (e.g. after a network change) before the old
    // connection has timed out.
    let (new, mut rn) = h.hub(&ea).await;
    new.subscribe(topic).await.unwrap();
    next(&mut rn).await;
    assert_eq!(
        next(&mut rw).await,
        ServerFrame::Joined { topic, id: ea.id() }
    );

    // The stale connection going away must not evict the live one.
    old.close();
    assert_quiet(&mut rw).await;
    assert_eq!(
        sorted_ids(h.sfu.members(topic)),
        sorted_ids(vec![ea.id(), eb.id()])
    );

    new.announce(topic, Bytes::from_static(b"still-here"))
        .await
        .unwrap();
    assert_eq!(
        next(&mut rw).await,
        ServerFrame::Presence {
            topic,
            id: ea.id(),
            blob: Bytes::from_static(b"still-here")
        }
    );
}

fn sorted_ids(mut ids: Vec<iroh::EndpointId>) -> Vec<iroh::EndpointId> {
    ids.sort_by_key(|id| *id.as_bytes());
    ids
}

/// A publish reaches every other subscriber once and never echoes back;
/// publishing to a topic you are not subscribed to is refused.
#[tokio::test]
async fn publish_fans_out_to_the_room() {
    let h = Harness::start().await;
    let topic = random_topic();
    let other_topic = random_topic();
    let (ea, eb, ec, ed) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );
    let (a, mut ra) = h.hub(&ea).await;
    let (b, mut rb) = h.hub(&eb).await;
    let (c, mut rc) = h.hub(&ec).await;
    let (d, mut rd) = h.hub(&ed).await;
    for (client, rx) in [(&a, &mut ra), (&b, &mut rb), (&c, &mut rc)] {
        client.subscribe(topic).await.unwrap();
        next(rx).await; // snapshot
    }
    d.subscribe(other_topic).await.unwrap();
    next(&mut rd).await;
    // Drain the JOINED notifications.
    next(&mut ra).await;
    next(&mut ra).await;
    next(&mut rb).await;

    a.publish(topic, Bytes::from_static(b"sealed-envelope"))
        .await
        .unwrap();
    let delivered = ServerFrame::Deliver {
        topic,
        payload: Bytes::from_static(b"sealed-envelope"),
    };
    assert_eq!(next(&mut rb).await, delivered);
    assert_eq!(next(&mut rc).await, delivered);
    assert_quiet(&mut ra).await;
    assert_quiet(&mut rd).await;
    assert_eq!(
        h.sfu
            .stats()
            .delivered
            .load(std::sync::atomic::Ordering::Relaxed),
        2
    );

    d.publish(topic, Bytes::from_static(b"intruder"))
        .await
        .unwrap();
    assert!(matches!(next(&mut rd).await, ServerFrame::Error { .. }));
    assert_quiet(&mut rb).await;
}

/// Datagrams sent to the hub reach the topic's other subscribers.
#[tokio::test]
async fn datagrams_fan_out_to_the_room() {
    let h = Harness::start().await;
    let topic = random_topic();
    let (ea, eb, ec) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );
    let (a, mut ra) = h.hub(&ea).await;
    let (b, mut rb) = h.hub(&eb).await;
    let (c, mut rc) = h.hub(&ec).await;
    for (client, rx) in [(&a, &mut ra), (&b, &mut rb), (&c, &mut rc)] {
        client.subscribe(topic).await.unwrap();
        next(rx).await;
    }
    // Datagrams are best effort: keep sending until both peers saw one.
    let got = tokio::time::timeout(WAIT, async {
        let (mut b_got, mut c_got) = (false, false);
        while !(b_got && c_got) {
            a.send_datagram(&topic, b"voice-frame").unwrap();
            tokio::select! {
                Ok((t, payload)) = b.read_datagram() => {
                    assert_eq!((t, &payload[..]), (topic, &b"voice-frame"[..]));
                    b_got = true;
                }
                Ok((t, payload)) = c.read_datagram() => {
                    assert_eq!((t, &payload[..]), (topic, &b"voice-frame"[..]));
                    c_got = true;
                }
                _ = tokio::time::sleep(Duration::from_millis(50)) => {}
            }
        }
    })
    .await;
    assert!(got.is_ok(), "hub did not forward datagrams");
}

/// `GET /kt/hub` names the hub, the relay and the protocol.
#[tokio::test]
async fn info_endpoint_serves_hub_id() {
    let h = Harness::start().await;
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let body = info::hub_info_json(
        &h.sfu.hub_id().to_string(),
        h.sfu.relay_url().as_str(),
        Some(7842),
    );
    tokio::spawn(info::serve(listener, body));

    let get = |path: &'static str| async move {
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut out = String::new();
        stream.read_to_string(&mut out).await.unwrap();
        out
    };
    let ok = get("/kt/hub").await;
    assert!(ok.starts_with("HTTP/1.1 200"), "{ok}");
    assert!(
        ok.contains(&format!(r#""hub":"{}""#, h.sfu.hub_id())),
        "{ok}"
    );
    assert!(ok.contains(r#""alpn":"keeptalking/hub/1""#), "{ok}");
    assert!(ok.contains(r#""qad_port":7842"#), "{ok}");
    assert!(get("/other").await.starts_with("HTTP/1.1 404"));
}

/// Peers with no IP transports can only reach each other through the
/// embedded relay.
#[tokio::test]
async fn relay_carries_peer_traffic() {
    let h = Harness::start().await;
    let (ea, eb) = (h.endpoint(true).await, h.endpoint(true).await);
    let conn = dial(&h, &ea, &eb).await;
    echo_roundtrip(&conn).await;
    let selected = conn
        .paths()
        .iter()
        .find(|p| p.is_selected())
        .map(|p| p.is_relay());
    assert_eq!(
        selected,
        Some(true),
        "relay-only connection should ride the relay"
    );
}

/// Dialled with only the relay URL, peers on the same host punch through to a
/// direct path.
#[tokio::test]
async fn peers_upgrade_to_direct() {
    let h = Harness::start().await;
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);
    let conn = dial(&h, &ea, &eb).await;
    echo_roundtrip(&conn).await;
    let direct = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if conn.paths().iter().any(|p| p.is_selected() && p.is_ip()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await;
    assert!(direct.is_ok(), "no direct path selected within 20s");
    echo_roundtrip(&conn).await;
}

/// `from` dials `to` knowing only its id and the relay URL, the same
/// information a peer gets from a presence blob. `to` echoes every stream.
async fn dial(h: &Harness, from: &Endpoint, to: &Endpoint) -> Connection {
    let acceptor = to.clone();
    tokio::spawn(async move {
        let conn = acceptor.accept().await.unwrap().await.unwrap();
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4];
                while recv.read_exact(&mut buf).await.is_ok() {
                    if send.write_all(&buf).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let addr = EndpointAddr::new(to.id()).with_relay_url(h.sfu.relay_url().clone());
    tokio::time::timeout(WAIT, from.connect(addr, TEST_ALPN))
        .await
        .unwrap()
        .unwrap()
}

async fn echo_roundtrip(conn: &Connection) {
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    tokio::time::timeout(WAIT, recv.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&back, b"ping");
}
