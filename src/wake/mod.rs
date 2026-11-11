//! Push wakes over APNs (ALPN [`WAKE_ALPN`]).
//!
//! A device mints **handles** for its APNs address; a peer holding one asks
//! the service to wake that device. The handle is the whole capability: it
//! is sealed with a key only this service holds, and nothing else about the
//! wake is checked. Handles say nothing about contexts or rooms, so the
//! service never learns what a wake is for. Every push carries the handle's
//! `id` (as `kt_wake_handle`), which the device maps back to what it minted
//! the handle for.
//!
//! The client opens one bidirectional stream and sends request frames; the
//! service answers each, in order, with one response frame. Frames are the
//! SFU's `[u32 BE len][u8 tag][body]`, at most [`MAX_WAKE_FRAME_LEN`].
//!
//! | dir | tag  | frame  | body                                                                        |
//! |-----|------|--------|-----------------------------------------------------------------------------|
//! | C→S | 0x51 | MINT   | environment(u8) ‖ u8 len ‖ apns topic ‖ u8 len ‖ token ‖ u8 n ‖ n × purpose(u8) |
//! | C→S | 0x52 | SEND   | kind(u8) ‖ u16 len ‖ handle ‖ payload (a JSON object)                      |
//! | S→C | 0x61 | MINTED | u8 n ‖ n × (id(16) ‖ u16 len ‖ handle), one per requested purpose, in order |
//! | S→C | 0x62 | RESULT | u16 status ‖ UTF-8 reason                                                   |
//!
//! - **environment** 0 = development (sandbox), 1 = production. **purpose**
//!   1 = context message, 2 = action authorisation.
//! - **kind** 1 = context (alert, `kt_context_wake`), 2 = action (alert,
//!   `kt_action_wake`), 3 = revocation (background, `kt_context_revoke`).
//!   Context and revocation ride a context-message handle, action an
//!   action-authorisation one.
//! - The payload goes into the APNs body under the kind's key, unread.
//!   Alerts collapse by handle.
//! - A SEND is answered with RESULT 200 when Apple accepted the push,
//!   Apple's own status and reason when it refused it (410: the token is
//!   gone, drop the handle), or 400 (malformed, or a handle this service did
//!   not seal, or the wrong kind for it), 413 (over APNs' 4 KB),
//!   429 (rate limited) or 502 (Apple unreachable). A MINT is answered with
//!   MINTED, or RESULT 400 / 429.

pub mod apns;
pub mod handle;

use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde_json::{Map, Value, json};
use tracing::debug;
use uuid::Uuid;

use apns::{Apns, ApnsConfig, Delivery};
use handle::{Environment, Handle, HandleSealer, Purpose};

pub const WAKE_ALPN: &[u8] = b"keeptalking/wake/1";
pub const MAX_WAKE_FRAME_LEN: usize = 8 * 1024;
/// APNs refuses a larger body.
pub const MAX_APNS_BODY_LEN: usize = 4096;
pub const MAX_PURPOSES_PER_MINT: usize = 8;
/// The user-info key carrying the handle id.
pub const HANDLE_ID_KEY: &str = "kt_wake_handle";

pub mod tag {
    pub const MINT: u8 = 0x51;
    pub const SEND: u8 = 0x52;
    pub const MINTED: u8 = 0x61;
    pub const RESULT: u8 = 0x62;
}

pub mod status {
    pub const OK: u16 = 200;
    pub const BAD_REQUEST: u16 = 400;
    pub const TOO_LARGE: u16 = 413;
    pub const RATE_LIMITED: u16 = 429;
    pub const UNREACHABLE: u16 = 502;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Context = 1,
    Action = 2,
    Revocation = 3,
}

impl Kind {
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Context),
            2 => Some(Self::Action),
            3 => Some(Self::Revocation),
            _ => None,
        }
    }

    fn purpose(self) -> Purpose {
        match self {
            Self::Context | Self::Revocation => Purpose::ContextMessage,
            Self::Action => Purpose::ActionAuthorisation,
        }
    }

    fn user_info_key(self) -> &'static str {
        match self {
            Self::Context => "kt_context_wake",
            Self::Action => "kt_action_wake",
            Self::Revocation => "kt_context_revoke",
        }
    }

    /// Shown as-is only when the device's notification service extension
    /// can't resolve the real content.
    fn aps(self) -> Value {
        let alert = |title: &str, body: &str| {
            json!({
                "alert": { "title": title, "body": body },
                "sound": "default",
                "content-available": 1,
                "mutable-content": 1,
            })
        };
        match self {
            Self::Context => alert("New KeepTalking activity", "Open KeepTalking to catch up."),
            Self::Action => alert("Action approval requested", "Open KeepTalking to review it."),
            Self::Revocation => json!({ "content-available": 1 }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeRequest {
    Mint {
        environment: Environment,
        apns_topic: String,
        token: Vec<u8>,
        purposes: Vec<Purpose>,
    },
    Send {
        kind: Kind,
        handle: Bytes,
        payload: Bytes,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MintedHandle {
    pub id: Uuid,
    pub handle: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeResponse {
    Minted(Vec<MintedHandle>),
    Result { status: u16, reason: String },
}

impl WakeResponse {
    pub fn status(status: u16, reason: impl Into<String>) -> Self {
        Self::Result {
            status,
            reason: reason.into(),
        }
    }
}

fn frame(tag: u8, body: BytesMut) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + body.len());
    out.put_u32(1 + body.len() as u32);
    out.put_u8(tag);
    out.put_slice(&body);
    out.freeze()
}

fn take_short(body: &mut Bytes) -> Result<Bytes> {
    ensure!(body.remaining() >= 1, "truncated");
    let len = body.get_u8() as usize;
    ensure!(body.remaining() >= len, "truncated");
    Ok(body.split_to(len))
}

fn take_long(body: &mut Bytes) -> Result<Bytes> {
    ensure!(body.remaining() >= 2, "truncated");
    let len = body.get_u16() as usize;
    ensure!(body.remaining() >= len, "truncated");
    Ok(body.split_to(len))
}

impl WakeRequest {
    pub fn encode(&self) -> Result<Bytes> {
        let mut body = BytesMut::new();
        match self {
            Self::Mint {
                environment,
                apns_topic,
                token,
                purposes,
            } => {
                ensure!(apns_topic.len() <= u8::MAX as usize && token.len() <= u8::MAX as usize);
                ensure!(purposes.len() <= MAX_PURPOSES_PER_MINT);
                body.put_u8(*environment as u8);
                body.put_u8(apns_topic.len() as u8);
                body.put_slice(apns_topic.as_bytes());
                body.put_u8(token.len() as u8);
                body.put_slice(token);
                body.put_u8(purposes.len() as u8);
                body.extend(purposes.iter().map(|purpose| *purpose as u8));
                Ok(frame(tag::MINT, body))
            }
            Self::Send {
                kind,
                handle,
                payload,
            } => {
                ensure!(handle.len() <= u16::MAX as usize);
                body.put_u8(*kind as u8);
                body.put_u16(handle.len() as u16);
                body.put_slice(handle);
                body.put_slice(payload);
                Ok(frame(tag::SEND, body))
            }
        }
    }

    pub fn decode(tag: u8, mut body: Bytes) -> Result<Self> {
        match tag {
            tag::MINT => {
                ensure!(body.remaining() >= 1, "truncated");
                let environment =
                    Environment::from_byte(body.get_u8()).context("unknown environment")?;
                let apns_topic = String::from_utf8(take_short(&mut body)?.to_vec())?;
                let token = take_short(&mut body)?.to_vec();
                let purposes = take_short(&mut body)?
                    .iter()
                    .map(|byte| Purpose::from_byte(*byte).context("unknown purpose"))
                    .collect::<Result<Vec<_>>>()?;
                ensure!(body.is_empty(), "trailing bytes");
                ensure!(!apns_topic.is_empty() && !token.is_empty(), "empty topic or token");
                ensure!(
                    (1..=MAX_PURPOSES_PER_MINT).contains(&purposes.len()),
                    "1 to {MAX_PURPOSES_PER_MINT} purposes"
                );
                Ok(Self::Mint {
                    environment,
                    apns_topic,
                    token,
                    purposes,
                })
            }
            tag::SEND => {
                ensure!(body.remaining() >= 1, "truncated");
                let kind = Kind::from_byte(body.get_u8()).context("unknown kind")?;
                let handle = take_long(&mut body)?;
                Ok(Self::Send {
                    kind,
                    handle,
                    payload: body,
                })
            }
            other => bail!("unknown request {other:#04x}"),
        }
    }
}

impl WakeResponse {
    pub fn encode(&self) -> Bytes {
        let mut body = BytesMut::new();
        match self {
            Self::Minted(handles) => {
                body.put_u8(handles.len() as u8);
                for minted in handles {
                    body.put_slice(minted.id.as_bytes());
                    body.put_u16(minted.handle.len() as u16);
                    body.put_slice(&minted.handle);
                }
                frame(tag::MINTED, body)
            }
            Self::Result { status, reason } => {
                body.put_u16(*status);
                body.put_slice(reason.as_bytes());
                frame(tag::RESULT, body)
            }
        }
    }

    pub fn decode(tag: u8, mut body: Bytes) -> Result<Self> {
        match tag {
            tag::MINTED => {
                ensure!(body.remaining() >= 1, "truncated");
                let count = body.get_u8();
                let mut handles = Vec::with_capacity(count as usize);
                for _ in 0..count {
                    ensure!(body.remaining() >= 16, "truncated");
                    let id = Uuid::from_slice(&body.split_to(16))?;
                    handles.push(MintedHandle {
                        id,
                        handle: take_long(&mut body)?,
                    });
                }
                Ok(Self::Minted(handles))
            }
            tag::RESULT => {
                ensure!(body.remaining() >= 2, "truncated");
                let status = body.get_u16();
                Ok(Self::Result {
                    status,
                    reason: String::from_utf8(body.to_vec())?,
                })
            }
            other => bail!("unknown response {other:#04x}"),
        }
    }
}

pub struct WakeConfig {
    /// At least [`handle::MIN_SECRET_LEN`] bytes. Handles minted under one
    /// secret open under no other, so it must outlive restarts.
    pub handle_secret: Vec<u8>,
    pub apns: ApnsConfig,
}

pub struct Wake {
    sealer: HandleSealer,
    apns: Apns,
}

impl Wake {
    pub fn new(config: WakeConfig) -> Result<Self> {
        Ok(Self {
            sealer: HandleSealer::new(&config.handle_secret)?,
            apns: Apns::new(config.apns)?,
        })
    }

    pub async fn respond(&self, tag: u8, body: Bytes) -> WakeResponse {
        match WakeRequest::decode(tag, body) {
            Ok(request) => self.answer(request).await,
            Err(err) => WakeResponse::status(status::BAD_REQUEST, format!("{err:#}")),
        }
    }

    async fn answer(&self, request: WakeRequest) -> WakeResponse {
        match request {
            WakeRequest::Mint {
                environment,
                apns_topic,
                token,
                purposes,
            } => self.mint(environment, apns_topic, token, purposes),
            WakeRequest::Send {
                kind,
                handle,
                payload,
            } => self.send(kind, &handle, &payload).await,
        }
    }

    fn mint(
        &self,
        environment: Environment,
        apns_topic: String,
        token: Vec<u8>,
        purposes: Vec<Purpose>,
    ) -> WakeResponse {
        let minted = purposes
            .into_iter()
            .map(|purpose| {
                let id = Uuid::new_v4();
                let handle = self.sealer.seal(&Handle {
                    id: *id.as_bytes(),
                    purpose,
                    environment,
                    apns_topic: apns_topic.clone(),
                    token: token.clone(),
                })?;
                Ok(MintedHandle { id, handle })
            })
            .collect::<Result<Vec<_>>>();
        match minted {
            Ok(handles) => WakeResponse::Minted(handles),
            Err(err) => WakeResponse::status(status::BAD_REQUEST, format!("{err:#}")),
        }
    }

    async fn send(&self, kind: Kind, sealed: &[u8], payload: &[u8]) -> WakeResponse {
        let handle = match self.sealer.open(sealed) {
            Ok(handle) if handle.purpose == kind.purpose() => handle,
            Ok(_) => return WakeResponse::status(status::BAD_REQUEST, "wrong kind for this handle"),
            Err(err) => return WakeResponse::status(status::BAD_REQUEST, format!("{err:#}")),
        };
        let id = Uuid::from_bytes(handle.id).to_string();
        let body = match apns_body(kind, &id, payload) {
            Ok(body) => body,
            Err(err) => return WakeResponse::status(status::BAD_REQUEST, format!("{err:#}")),
        };
        if body.len() > MAX_APNS_BODY_LEN {
            return WakeResponse::status(status::TOO_LARGE, "over the APNs body limit");
        }
        let delivery = match kind {
            Kind::Context | Kind::Action => Delivery::Alert { collapse_id: id },
            Kind::Revocation => Delivery::Background,
        };
        match self.apns.send(&handle, &delivery, body).await {
            Ok(outcome) => {
                if outcome.status != status::OK {
                    debug!(status = outcome.status, reason = %outcome.reason, "APNs refused a wake");
                }
                WakeResponse::status(outcome.status, outcome.reason)
            }
            Err(err) => WakeResponse::status(status::UNREACHABLE, format!("{err:#}")),
        }
    }
}

/// `{"aps": …, <kind key>: payload, "kt_wake_handle": id}`.
pub fn apns_body(kind: Kind, handle_id: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let payload: Value = serde_json::from_slice(payload).context("payload is not JSON")?;
    ensure!(payload.is_object(), "payload is not a JSON object");
    let mut body = Map::new();
    body.insert("aps".into(), kind.aps());
    body.insert(kind.user_info_key().into(), payload);
    body.insert(HANDLE_ID_KEY.into(), Value::String(handle_id.into()));
    Ok(serde_json::to_vec(&Value::Object(body))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_and_responses_round_trip() {
        let requests = [
            WakeRequest::Mint {
                environment: Environment::Development,
                apns_topic: "dev.keeptalking.app".into(),
                token: vec![1; 32],
                purposes: vec![Purpose::ContextMessage, Purpose::ActionAuthorisation],
            },
            WakeRequest::Send {
                kind: Kind::Revocation,
                handle: Bytes::from_static(&[9; 80]),
                payload: Bytes::from_static(br#"{"ciphertext":"x"}"#),
            },
        ];
        for request in requests {
            let mut frame = request.encode().unwrap();
            frame.advance(4);
            let tag = frame.get_u8();
            assert_eq!(WakeRequest::decode(tag, frame).unwrap(), request);
        }
        let responses = [
            WakeResponse::Minted(vec![MintedHandle {
                id: Uuid::new_v4(),
                handle: Bytes::from_static(&[3; 70]),
            }]),
            WakeResponse::status(410, "Unregistered"),
        ];
        for response in responses {
            let mut frame = response.encode();
            frame.advance(4);
            let tag = frame.get_u8();
            assert_eq!(WakeResponse::decode(tag, frame).unwrap(), response);
        }
    }

    #[test]
    fn a_mint_needs_a_topic_a_token_and_some_purposes() {
        let encode = |purposes: Vec<Purpose>, token: Vec<u8>| {
            let mut frame = WakeRequest::Mint {
                environment: Environment::Production,
                apns_topic: "dev.keeptalking.app".into(),
                token,
                purposes,
            }
            .encode()
            .unwrap();
            frame.advance(5);
            WakeRequest::decode(tag::MINT, frame)
        };
        assert!(encode(vec![], vec![1]).is_err());
        assert!(encode(vec![Purpose::ContextMessage], vec![]).is_err());
        assert!(encode(vec![Purpose::ContextMessage], vec![1]).is_ok());
    }

    /// The SDK budgets 4096 − 256 bytes for the context wake it seals.
    #[test]
    fn the_sdk_budget_fits_every_alert() {
        let ciphertext = "k".repeat(4096 - 256 - r#"{"ciphertext":""}"#.len());
        let payload = format!(r#"{{"ciphertext":"{ciphertext}"}}"#);
        let id = Uuid::new_v4().to_string();
        for kind in [Kind::Context, Kind::Action] {
            let body = apns_body(kind, &id, payload.as_bytes()).unwrap();
            assert!(body.len() <= MAX_APNS_BODY_LEN, "{kind:?}: {}", body.len());
        }
    }

    #[test]
    fn a_payload_must_be_a_json_object() {
        assert!(apns_body(Kind::Context, "id", b"[1]").is_err());
        assert!(apns_body(Kind::Context, "id", b"nope").is_err());
        let body: Value =
            serde_json::from_slice(&apns_body(Kind::Revocation, "id", br#"{"a":1}"#).unwrap()).unwrap();
        assert_eq!(body["kt_context_revoke"]["a"], 1);
        assert_eq!(body[HANDLE_ID_KEY], "id");
        assert_eq!(body["aps"], json!({ "content-available": 1 }));
    }
}
