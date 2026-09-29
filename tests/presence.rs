//! End-to-end tests against an in-process `Sfu` on localhost: presence
//! rooms, and peer connections carried by the embedded relay.

use std::{net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use iroh::{Endpoint, EndpointAddr, SecretKey, endpoint::Connection};
use keeptalking_sfu::{
    client::{ClientOptions, PresenceClient, bind_client},
    proto::{Member, ServerFrame},
    server::{Sfu, SfuConfig},
    tls::DevCert,
};
use tokio::sync::mpsc;
use uuid::Uuid;

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

    async fn presence(&self, endpoint: &Endpoint) -> (PresenceClient, mpsc::Receiver<ServerFrame>) {
        PresenceClient::connect(endpoint, self.sfu.hub_addr())
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

fn sorted(mut members: Vec<Member>) -> Vec<Member> {
    members.sort_by_key(|m| *m.id.as_bytes());
    members
}

#[tokio::test]
async fn room_lifecycle() {
    let h = Harness::start().await;
    let ctx = Uuid::new_v4();
    let (ea, eb, ec) = (
        h.endpoint(false).await,
        h.endpoint(false).await,
        h.endpoint(false).await,
    );

    let (a, mut ra) = h.presence(&ea).await;
    a.join(ctx).await.unwrap();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Snapshot {
            context: ctx,
            members: vec![]
        }
    );

    let (b, mut rb) = h.presence(&eb).await;
    b.join(ctx).await.unwrap();
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Snapshot {
            context: ctx,
            members: vec![Member {
                id: ea.id(),
                blob: Bytes::new()
            }]
        }
    );
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Joined {
            context: ctx,
            id: eb.id()
        }
    );

    a.publish(ctx, Bytes::from_static(b"sealed-a"))
        .await
        .unwrap();
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Presence {
            context: ctx,
            id: ea.id(),
            blob: Bytes::from_static(b"sealed-a")
        }
    );
    b.publish(ctx, Bytes::from_static(b"sealed-b"))
        .await
        .unwrap();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Presence {
            context: ctx,
            id: eb.id(),
            blob: Bytes::from_static(b"sealed-b")
        }
    );

    // A late joiner gets everyone's latest presence in its snapshot.
    let (c, mut rc) = h.presence(&ec).await;
    c.join(ctx).await.unwrap();
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
        ServerFrame::Joined {
            context: ctx,
            id: ec.id()
        }
    );
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Joined {
            context: ctx,
            id: ec.id()
        }
    );

    // Explicit leave.
    c.leave(ctx).await.unwrap();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Left {
            context: ctx,
            id: ec.id()
        }
    );
    assert_eq!(
        next(&mut rb).await,
        ServerFrame::Left {
            context: ctx,
            id: ec.id()
        }
    );

    // Publishing to a context you are not in is refused, not forwarded.
    c.publish(ctx, Bytes::from_static(b"nope")).await.unwrap();
    assert!(matches!(next(&mut rc).await, ServerFrame::Error { .. }));
    assert_quiet(&mut ra).await;

    // Dropping the connection leaves every joined room.
    b.close();
    assert_eq!(
        next(&mut ra).await,
        ServerFrame::Left {
            context: ctx,
            id: eb.id()
        }
    );
    assert_eq!(h.sfu.members(ctx), vec![ea.id()]);
}

#[tokio::test]
async fn newer_connection_owns_the_slot() {
    let h = Harness::start().await;
    let ctx = Uuid::new_v4();
    let (ea, eb) = (h.endpoint(false).await, h.endpoint(false).await);

    let (watcher, mut rw) = h.presence(&eb).await;
    watcher.join(ctx).await.unwrap();
    next(&mut rw).await; // snapshot

    let (old, mut ro) = h.presence(&ea).await;
    old.join(ctx).await.unwrap();
    next(&mut ro).await;
    assert_eq!(
        next(&mut rw).await,
        ServerFrame::Joined {
            context: ctx,
            id: ea.id()
        }
    );

    // Same endpoint reconnects (e.g. after a network change) before the old
    // connection has timed out.
    let (new, mut rn) = h.presence(&ea).await;
    new.join(ctx).await.unwrap();
    next(&mut rn).await;
    assert_eq!(
        next(&mut rw).await,
        ServerFrame::Joined {
            context: ctx,
            id: ea.id()
        }
    );

    // The stale connection going away must not evict the live one.
    old.close();
    assert_quiet(&mut rw).await;
    assert_eq!(
        sorted_ids(h.sfu.members(ctx)),
        sorted_ids(vec![ea.id(), eb.id()])
    );

    new.publish(ctx, Bytes::from_static(b"still-here"))
        .await
        .unwrap();
    assert_eq!(
        next(&mut rw).await,
        ServerFrame::Presence {
            context: ctx,
            id: ea.id(),
            blob: Bytes::from_static(b"still-here")
        }
    );
}

fn sorted_ids(mut ids: Vec<iroh::EndpointId>) -> Vec<iroh::EndpointId> {
    ids.sort_by_key(|id| *id.as_bytes());
    ids
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
