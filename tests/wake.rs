//! Push wakes end to end: a client mints handles and sends wakes over
//! `keeptalking/wake/1`, and the SFU posts them to a fake APNs over HTTP/2.

mod common;

use std::{
    collections::VecDeque,
    convert::Infallible,
    sync::{Arc, Mutex},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use common::*;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, body::Incoming, header::HeaderMap, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use keeptalking_sfu::{
    proto::read_frame_up_to,
    server::{Limits, Rate},
    wake::{
        HANDLE_ID_KEY, Kind, MAX_WAKE_FRAME_LEN, MintedHandle, WAKE_ALPN, WakeConfig, WakeRequest,
        WakeResponse,
        apns::ApnsConfig,
        handle::{Environment, Purpose},
        status,
    },
};
use ring::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair},
};
use serde_json::Value;
use tokio::net::TcpListener;

const TOKEN: [u8; 32] = [0xAB; 32];
const BUNDLE: &str = "dev.keeptalking.app";

struct Recorded {
    path: String,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Default)]
struct FakeApns {
    requests: Mutex<Vec<Recorded>>,
    replies: Mutex<VecDeque<(u16, &'static str)>>,
}

impl FakeApns {
    async fn start() -> (Arc<Self>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let apns = Arc::new(Self::default());
        let state = apns.clone();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let state = state.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: Request<Incoming>| {
                        let state = state.clone();
                        async move {
                            let (parts, body) = request.into_parts();
                            let body = body.collect().await.unwrap().to_bytes();
                            let (status, reason) =
                                state.replies.lock().unwrap().pop_front().unwrap_or((200, ""));
                            state.requests.lock().unwrap().push(Recorded {
                                path: parts.uri.path().to_owned(),
                                headers: parts.headers,
                                body,
                            });
                            let body = if status == 200 {
                                Bytes::new()
                            } else {
                                Bytes::from(format!(r#"{{"reason":"{reason}"}}"#))
                            };
                            Ok::<_, Infallible>(
                                Response::builder().status(status).body(Full::new(body)).unwrap(),
                            )
                        }
                    });
                    let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
        });
        (apns, url)
    }

    fn reply(&self, status: u16, reason: &'static str) {
        self.replies.lock().unwrap().push_back((status, reason));
    }

    fn take(&self) -> Vec<Recorded> {
        std::mem::take(&mut self.requests.lock().unwrap())
    }
}

fn wake_config(url: &str) -> WakeConfig {
    let rng = SystemRandom::new();
    let key = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    let mut apns = ApnsConfig::new("KEYID12345".into(), "TEAMID1234".into(), key.as_ref().to_vec());
    apns.production_url = url.parse().unwrap();
    apns.development_url = url.parse().unwrap();
    WakeConfig {
        handle_secret: vec![42; 32],
        apns,
    }
}

struct WakeClient {
    _endpoint: iroh::Endpoint,
    _conn: Connection,
    send: SendStream,
    recv: RecvStream,
}

impl WakeClient {
    async fn connect(h: &Harness) -> Self {
        let endpoint = h.endpoint(false).await;
        let conn = tokio::time::timeout(WAIT, endpoint.connect(h.direct_addr(), WAKE_ALPN))
            .await
            .expect("connect timed out")
            .expect("connect");
        let (send, recv) = conn.open_bi().await.unwrap();
        Self {
            _endpoint: endpoint,
            _conn: conn,
            send,
            recv,
        }
    }

    async fn ask(&mut self, request: WakeRequest) -> WakeResponse {
        self.send.write_all(&request.encode().unwrap()).await.unwrap();
        let (tag, body) = tokio::time::timeout(WAIT, read_frame_up_to(&mut self.recv, MAX_WAKE_FRAME_LEN))
            .await
            .expect("timed out waiting for a response")
            .expect("read")
            .expect("stream ended");
        WakeResponse::decode(tag, body).expect("decode")
    }

    async fn mint(&mut self, purposes: Vec<Purpose>) -> Vec<MintedHandle> {
        match self
            .ask(WakeRequest::Mint {
                environment: Environment::Development,
                apns_topic: BUNDLE.into(),
                token: TOKEN.to_vec(),
                purposes,
            })
            .await
        {
            WakeResponse::Minted(handles) => handles,
            other => panic!("expected MINTED, got {other:?}"),
        }
    }

    async fn send(&mut self, kind: Kind, handle: &MintedHandle, payload: &str) -> (u16, String) {
        match self
            .ask(WakeRequest::Send {
                kind,
                handle: handle.handle.clone(),
                payload: Bytes::copy_from_slice(payload.as_bytes()),
            })
            .await
        {
            WakeResponse::Result { status, reason } => (status, reason),
            other => panic!("expected RESULT, got {other:?}"),
        }
    }
}

fn header<'a>(recorded: &'a Recorded, name: &str) -> Option<&'a str> {
    recorded.headers.get(name).map(|value| value.to_str().unwrap())
}

/// A context wake reaches APNs as an alert addressed by the sealed token,
/// collapsing by handle, carrying the payload and the handle id, signed with
/// an ES256 token naming the key.
#[tokio::test]
async fn a_minted_handle_wakes_its_device() {
    let (apns, url) = FakeApns::start().await;
    let h = Harness::with_wake(Limits::default(), wake_config(&url)).await;
    let mut client = WakeClient::connect(&h).await;

    let handles = client
        .mint(vec![Purpose::ContextMessage, Purpose::ActionAuthorisation])
        .await;
    assert_eq!(handles.len(), 2);
    assert_ne!(handles[0].id, handles[1].id);

    assert_eq!(
        client.send(Kind::Context, &handles[0], r#"{"ciphertext":"sealed"}"#).await,
        (status::OK, String::new())
    );
    let sent = apns.take();
    assert_eq!(sent.len(), 1);
    let request = &sent[0];
    assert_eq!(request.path, format!("/3/device/{}", "ab".repeat(32)));
    assert_eq!(header(request, "apns-topic"), Some(BUNDLE));
    assert_eq!(header(request, "apns-push-type"), Some("alert"));
    assert_eq!(header(request, "apns-priority"), Some("10"));
    let id = handles[0].id.to_string();
    assert_eq!(header(request, "apns-collapse-id"), Some(id.as_str()));

    let token = header(request, "authorization").unwrap().strip_prefix("Bearer ").unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let jwt_header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    assert_eq!(jwt_header["alg"], "ES256");
    assert_eq!(jwt_header["kid"], "KEYID12345");
    let claims: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(claims["iss"], "TEAMID1234");

    let body: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(body["kt_context_wake"]["ciphertext"], "sealed");
    assert_eq!(body[HANDLE_ID_KEY], id.as_str());
    assert_eq!(body["aps"]["mutable-content"], 1);
}

/// A revocation goes out as a background push, which never collapses.
#[tokio::test]
async fn a_revocation_is_a_background_push() {
    let (apns, url) = FakeApns::start().await;
    let h = Harness::with_wake(Limits::default(), wake_config(&url)).await;
    let mut client = WakeClient::connect(&h).await;
    let handle = client.mint(vec![Purpose::ContextMessage]).await.remove(0);

    assert_eq!(client.send(Kind::Revocation, &handle, r#"{"ciphertext":"x"}"#).await.0, status::OK);
    let sent = apns.take();
    assert_eq!(header(&sent[0], "apns-push-type"), Some("background"));
    assert_eq!(header(&sent[0], "apns-priority"), Some("5"));
    assert_eq!(header(&sent[0], "apns-collapse-id"), None);
}

/// Nothing reaches Apple for a handle this service did not seal, the wrong
/// kind for a handle, a payload that is not a JSON object, or a body over
/// 4 KB.
#[tokio::test]
async fn bad_sends_never_reach_apns() {
    let (apns, url) = FakeApns::start().await;
    let h = Harness::with_wake(Limits::default(), wake_config(&url)).await;
    let mut client = WakeClient::connect(&h).await;
    let handles = client
        .mint(vec![Purpose::ContextMessage, Purpose::ActionAuthorisation])
        .await;

    let forged = MintedHandle {
        id: handles[0].id,
        handle: Bytes::from(vec![0u8; handles[0].handle.len()]),
    };
    assert_eq!(client.send(Kind::Context, &forged, "{}").await.0, status::BAD_REQUEST);
    assert_eq!(client.send(Kind::Action, &handles[0], "{}").await.0, status::BAD_REQUEST);
    assert_eq!(client.send(Kind::Context, &handles[1], "{}").await.0, status::BAD_REQUEST);
    assert_eq!(client.send(Kind::Context, &handles[0], "[]").await.0, status::BAD_REQUEST);
    let huge = format!(r#"{{"ciphertext":"{}"}}"#, "k".repeat(4096));
    assert_eq!(client.send(Kind::Context, &handles[0], &huge).await.0, status::TOO_LARGE);
    assert!(apns.take().is_empty());
}

/// Apple's refusal comes back as is (410: drop the handle), and an expired
/// provider token is renewed and the push retried once.
#[tokio::test]
async fn apple_refusals_are_relayed_and_expired_tokens_renewed() {
    let (apns, url) = FakeApns::start().await;
    let h = Harness::with_wake(Limits::default(), wake_config(&url)).await;
    let mut client = WakeClient::connect(&h).await;
    let handle = client.mint(vec![Purpose::ContextMessage]).await.remove(0);

    apns.reply(410, "Unregistered");
    assert_eq!(
        client.send(Kind::Context, &handle, "{}").await,
        (410, "Unregistered".to_owned())
    );

    apns.reply(403, "ExpiredProviderToken");
    assert_eq!(client.send(Kind::Context, &handle, "{}").await.0, status::OK);
    let sent = apns.take();
    assert_eq!(sent.len(), 3);
    assert_ne!(header(&sent[1], "authorization"), header(&sent[2], "authorization"));
}

#[tokio::test]
async fn wakes_are_rate_limited_per_connection() {
    let (apns, url) = FakeApns::start().await;
    let limits = Limits {
        wake_rate: Rate::frames(0.0, 2.0),
        ..Limits::default()
    };
    let h = Harness::with_wake(limits, wake_config(&url)).await;
    let mut client = WakeClient::connect(&h).await;
    let handle = client.mint(vec![Purpose::ContextMessage]).await.remove(0);

    assert_eq!(client.send(Kind::Context, &handle, "{}").await.0, status::OK);
    assert_eq!(client.send(Kind::Context, &handle, "{}").await.0, status::RATE_LIMITED);
    assert_eq!(apns.take().len(), 1);
}

/// Without an APNs key the SFU does not offer the wake ALPN at all.
#[tokio::test]
async fn wakes_are_not_offered_without_apns() {
    let h = Harness::start().await;
    let endpoint = h.endpoint(false).await;
    let connected = tokio::time::timeout(WAIT, endpoint.connect(h.direct_addr(), WAKE_ALPN))
        .await
        .expect("connect timed out");
    assert!(connected.is_err());
}
