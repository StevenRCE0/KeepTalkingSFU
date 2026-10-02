//! Shared harness: an in-process `Sfu` on localhost plus clients for it.

#![allow(dead_code)]

use std::{net::Ipv4Addr, time::Duration};

use bytes::Bytes;
use iroh::{
    Endpoint, EndpointAddr, SecretKey,
    endpoint::{Connection, ConnectionError, QuicTransportConfig, RecvStream, SendStream},
};
use keeptalking_sfu::{
    client::{ClientOptions, Delivery, Inbox, SfuClient, bind_client},
    proto::{ClientFrame, Lane, Member, SFU_ALPN, ServerFrame, Topic, read_frame},
    server::{Limits, Rate, RelayRateLimit, Sfu, SfuConfig},
    tls::DevCert,
};

pub const TEST_ALPN: &[u8] = b"keeptalking/test/1";
pub const WAIT: Duration = Duration::from_secs(10);

/// A publish rate no test hits.
pub const GENEROUS: Rate = Rate {
    bytes_per_second: 1e12,
    burst_bytes: 1e12,
    frames_per_second: 1e9,
    burst_frames: 1e9,
};

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
            relay_rate_limit: Some(RelayRateLimit::default()),
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
        self.bind(relay_only, None).await
    }

    /// An endpoint with its own QUIC transport settings (e.g. small stream
    /// windows, to make a slow reader).
    pub async fn endpoint_with(&self, transport: QuicTransportConfig) -> Endpoint {
        self.bind(false, Some(transport)).await
    }

    async fn bind(&self, relay_only: bool, transport: Option<QuicTransportConfig>) -> Endpoint {
        bind_client(ClientOptions {
            relay_map: self.sfu.relay_map().clone(),
            ca: Some(self.dev.ca()),
            alpns: vec![TEST_ALPN.to_vec()],
            secret_key: None,
            relay_only,
            transport,
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
    pub async fn sfu_client(&self, endpoint: &Endpoint) -> (SfuClient, Inbox) {
        SfuClient::connect(endpoint, self.sfu.sfu_addr())
            .await
            .unwrap()
    }

    /// A reference client on a direct path.
    pub async fn direct_client(&self, endpoint: &Endpoint) -> (SfuClient, Inbox) {
        SfuClient::connect(endpoint, self.direct_addr())
            .await
            .unwrap()
    }

    /// A raw connection on a direct path, for frames the reference client
    /// would never send and for reading streams as they arrive.
    pub async fn raw(&self, endpoint: &Endpoint) -> Raw {
        let conn = tokio::time::timeout(WAIT, endpoint.connect(self.direct_addr(), SFU_ALPN))
            .await
            .expect("connect timed out")
            .expect("connect");
        let (send, recv) = conn.open_bi().await.unwrap();
        Raw { conn, send, recv }
    }
}

/// A raw connection: its session stream plus helpers for lane streams.
pub struct Raw {
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
}

impl Raw {
    pub async fn send_bytes(&mut self, bytes: &[u8]) {
        self.send.write_all(bytes).await.unwrap();
    }

    /// Sends a frame on the session stream.
    pub async fn send(&mut self, frame: ClientFrame) {
        let bytes = frame.encode();
        self.send_bytes(&bytes).await;
    }

    /// The next session frame, decoded, without merging snapshot chunks.
    pub async fn next(&mut self) -> ServerFrame {
        read_server_frame(&mut self.recv).await
    }

    /// Opens a lane stream whose first byte is `first` (a lane byte or not).
    pub async fn open_stream(&self, first: u8) -> SendStream {
        let mut send = self.conn.open_uni().await.unwrap();
        send.write_all(&[first]).await.unwrap();
        send
    }

    /// The next stream the SFU opens towards us, with its first byte.
    pub async fn accept_lane(&self) -> (Lane, RecvStream) {
        let mut recv = tokio::time::timeout(WAIT, self.conn.accept_uni())
            .await
            .expect("timed out waiting for a lane stream")
            .expect("accept lane stream");
        let mut byte = [0u8; 1];
        recv.read_exact(&mut byte).await.unwrap();
        (Lane::from_byte(byte[0]).expect("lane byte"), recv)
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

/// Writes `frames` to a client stream.
pub async fn write_frames(send: &mut SendStream, frames: &[ClientFrame]) {
    for frame in frames {
        send.write_all(&frame.encode()).await.unwrap();
    }
}

/// The next frame on a stream, decoded.
pub async fn read_server_frame(recv: &mut RecvStream) -> ServerFrame {
    let (tag, body) = tokio::time::timeout(WAIT, read_frame(recv))
        .await
        .expect("timed out waiting for frame")
        .expect("read")
        .expect("stream ended");
    ServerFrame::decode(tag, body).expect("decode")
}

/// Waits for the client to stop a stream we send on; returns the code.
pub async fn stopped(send: &SendStream) -> u64 {
    tokio::time::timeout(WAIT, send.stopped())
        .await
        .expect("stream was not stopped")
        .expect("stopped")
        .expect("stopped with a code, not acknowledged")
        .into_inner()
}

/// The next session frame of a reference client.
pub async fn next(inbox: &mut Inbox) -> ServerFrame {
    tokio::time::timeout(WAIT, inbox.frames.recv())
        .await
        .expect("timed out waiting for frame")
        .expect("closed")
}

/// The next DELIVER of a reference client, from any lane.
pub async fn delivery(inbox: &mut Inbox) -> Delivery {
    tokio::time::timeout(WAIT, inbox.deliveries.recv())
        .await
        .expect("timed out waiting for a delivery")
        .expect("closed")
}

/// Neither a session frame nor a delivery arrives for a while.
pub async fn assert_quiet(inbox: &mut Inbox) {
    // A closed channel disables its branch; only the timer ends the wait.
    tokio::select! {
        Some(frame) = inbox.frames.recv() => panic!("unexpected frame {frame:?}"),
        Some(delivery) = inbox.deliveries.recv() => panic!("unexpected delivery {delivery:?}"),
        _ = tokio::time::sleep(Duration::from_millis(300)) => {}
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

pub fn deliver(lane: Lane, topic: Topic, payload: impl Into<Bytes>) -> Delivery {
    Delivery {
        lane,
        topic,
        payload: payload.into(),
    }
}

pub fn bytes(len: usize) -> Bytes {
    Bytes::from(vec![0x5A; len])
}
