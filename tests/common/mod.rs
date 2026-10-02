//! Shared harness: an in-process `Sfu` on localhost plus clients for it.

#![allow(dead_code)]

use std::{net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, SecretKey,
    endpoint::{Connection, ConnectionError, RecvStream, SendStream},
};
use keeptalking_sfu::{
    client::{ClientOptions, SfuClient, bind_client},
    proto::{ClientFrame, Member, SFU_ALPN, ServerFrame, Topic, read_frame},
    server::{Limits, Sfu, SfuConfig},
    tls::DevCert,
};
use tokio::sync::mpsc;

pub const TEST_ALPN: &[u8] = b"keeptalking/test/1";
pub const WAIT: Duration = Duration::from_secs(10);

pub struct Harness {
    pub sfu: Sfu,
    pub dev: DevCert,
}

impl Harness {
    pub async fn start() -> Self {
        Self::with_limits(Limits::default()).await
    }

    pub async fn with_limits(limits: Limits) -> Self {
        let dev = DevCert::generate(&[]).unwrap();
        let local = |port| (Ipv4Addr::LOCALHOST, port).into();
        let sfu = Sfu::spawn(SfuConfig {
            relay_http_bind: local(0),
            relay_https_bind: local(0),
            relay_quic_bind: Some(local(0)),
            cert: dev.cert_config().unwrap(),
            public_relay_url: None,
            public_quic_port: None,
            sfu_bind: vec![local(0)],
            sfu_secret: SecretKey::generate(),
            sfu_ca: Some(dev.ca()),
            limits,
        })
        .await
        .unwrap();
        Self { sfu, dev }
    }

    pub async fn endpoint(&self, relay_only: bool) -> Endpoint {
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

    /// The SFU's address including its UDP sockets, so a connection is
    /// direct from the first packet instead of starting on the relay.
    pub fn direct_addr(&self) -> EndpointAddr {
        self.sfu
            .sfu_sockets()
            .into_iter()
            .fold(self.sfu.sfu_addr(), EndpointAddr::with_ip_addr)
    }

    /// A reference client dialled with only the relay URL (as apps do).
    pub async fn sfu_client(
        &self,
        endpoint: &Endpoint,
    ) -> (SfuClient, mpsc::Receiver<ServerFrame>) {
        SfuClient::connect(endpoint, self.sfu.sfu_addr())
            .await
            .unwrap()
    }

    /// A reference client on a direct path.
    pub async fn direct_client(
        &self,
        endpoint: &Endpoint,
    ) -> (SfuClient, mpsc::Receiver<ServerFrame>) {
        SfuClient::connect(endpoint, self.direct_addr())
            .await
            .unwrap()
    }

    /// A raw connection on a direct path, for frames the reference client
    /// would never send and for reading chunks as they arrive.
    pub async fn raw(&self, endpoint: &Endpoint) -> Raw {
        let conn = tokio::time::timeout(WAIT, endpoint.connect(self.direct_addr(), SFU_ALPN))
            .await
            .expect("connect timed out")
            .expect("connect");
        let (send, recv) = conn.open_bi().await.unwrap();
        Raw { conn, send, recv }
    }
}

pub struct Raw {
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
}

impl Raw {
    pub async fn send_bytes(&mut self, bytes: &[u8]) {
        self.send.write_all(bytes).await.unwrap();
    }

    pub async fn send(&mut self, frame: ClientFrame) {
        let bytes = frame.encode();
        self.send_bytes(&bytes).await;
    }

    /// The next frame, decoded, without merging snapshot chunks.
    pub async fn next(&mut self) -> ServerFrame {
        let (tag, body) = tokio::time::timeout(WAIT, read_frame(&mut self.recv))
            .await
            .expect("timed out waiting for frame")
            .expect("read")
            .expect("stream ended");
        ServerFrame::decode(tag, body).expect("decode")
    }

    /// Waits for the SFU to close the connection; returns the application
    /// close code and reason.
    pub async fn closed(&self) -> (u64, String) {
        let err = tokio::time::timeout(WAIT, self.conn.closed())
            .await
            .expect("connection was not closed");
        match err {
            ConnectionError::ApplicationClosed(close) => (
                close.error_code.into_inner(),
                String::from_utf8_lossy(&close.reason).into_owned(),
            ),
            other => panic!("closed without an application close: {other:?}"),
        }
    }
}

pub async fn next(rx: &mut mpsc::Receiver<ServerFrame>) -> ServerFrame {
    tokio::time::timeout(WAIT, rx.recv())
        .await
        .expect("timed out waiting for frame")
        .expect("closed")
}

pub async fn assert_quiet(rx: &mut mpsc::Receiver<ServerFrame>) {
    if let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(300), rx.recv()).await {
        panic!("unexpected frame {frame:?}");
    }
}

/// Polls `check` until it holds or `WAIT` passes.
pub async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let deadline = tokio::time::Instant::now() + WAIT;
    while !check() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

pub fn random_topic() -> Topic {
    Topic(SecretKey::generate().to_bytes())
}

pub fn sorted(mut members: Vec<Member>) -> Vec<Member> {
    members.sort_by_key(|m| *m.id.as_bytes());
    members
}

pub fn snapshot(topic: Topic, members: Vec<Member>) -> ServerFrame {
    ServerFrame::Snapshot {
        topic,
        more: false,
        members,
    }
}

pub fn error(topic: Topic, reason: &str) -> ServerFrame {
    ServerFrame::Error {
        topic: Some(topic),
        reason: reason.into(),
    }
}

pub fn bytes(len: usize) -> Bytes {
    Bytes::from(vec![0x5A; len])
}
