//! Push wakes (ALPN [`WAKE_ALPN`]).
//!
//! A device mints **handles** for its push address; a peer holding one asks
//! the service to wake that device. The handle is the whole capability: it
//! is sealed with a key only this service holds, and nothing else about the
//! wake is checked. Handles say nothing about contexts or rooms, so the
//! service never learns what a wake is for. Every push carries the handle's
//! `id` (as `kt_wake_handle`), which the device maps back to what it minted
//! the handle for.
//!
//! An address names its push provider; each provider is optional. The ALPN
//! is always offered: a provider that isn't configured, or none at all,
//! answers 501 with the provider's name as the reason (empty when a SEND's
//! handle can't say, because no provider ever was). Providers:
//!
//! | byte | provider | address                                                 |
//! |------|----------|---------------------------------------------------------|
//! | 0x01 | `apns`   | environment(u8) ‖ u8 len ‖ topic (bundle id) ‖ u8 len ‖ token |
//!
//! (APNs environment 0 = development/sandbox, 1 = production.)
//!
//! The client opens one bidirectional stream and sends request frames; the
//! service answers each, in order, with one response frame. Frames are the
//! SFU's `[u32 BE len][u8 tag][body]`, at most [`MAX_WAKE_FRAME_LEN`].
//!
//! | dir | tag  | frame  | body                                                                        |
//! |-----|------|--------|-----------------------------------------------------------------------------|
//! | C→S | 0x51 | MINT   | u8 n ‖ n × purpose(u8) ‖ provider(u8) ‖ address                             |
//! | C→S | 0x52 | SEND   | kind(u8) ‖ u16 len ‖ handle ‖ payload (a JSON object)                      |
//! | S→C | 0x61 | MINTED | u8 n ‖ n × (id(16) ‖ u16 len ‖ handle), one per requested purpose, in order |
//! | S→C | 0x62 | RESULT | u16 status ‖ UTF-8 reason                                                   |
//!
//! - **purpose** 1 = context message, 2 = action authorisation.
//! - **kind** 1 = context, 2 = action, 3 = revocation. Context and
//!   revocation ride a context-message handle, action an
//!   action-authorisation one. The payload reaches the device unread under
//!   `kt_context_wake`, `kt_action_wake` or `kt_context_revoke`; how a
//!   provider shows it (alert, background, collapsing) is its own.
//! - A SEND is answered with RESULT 200 when the provider accepted the push,
//!   the provider's own status and reason when it refused it (APNs 410: the
//!   token is gone, drop the handle), or 400 (malformed, a handle this
//!   service did not seal, or the wrong kind for it), 413 (over the
//!   provider's size limit), 429 (rate limited), 501 (provider not
//!   configured here, named in the reason) or 502 (provider unreachable). A MINT is answered with
//!   MINTED, or RESULT 400 / 429 / 501.

pub mod apns;
pub mod handle;

use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::debug;
use uuid::Uuid;

use apns::{Apns, ApnsConfig};
use handle::{Address, Handle, HandleSealer, Purpose};

pub const WAKE_ALPN: &[u8] = b"keeptalking/wake/1";
pub const MAX_WAKE_FRAME_LEN: usize = 8 * 1024;
pub const MAX_PURPOSES_PER_MINT: usize = 8;
/// The key carrying the handle id in every push.
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
    pub const UNSUPPORTED: u16 = 501;
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

    pub fn data_key(self) -> &'static str {
        match self {
            Self::Context => "kt_context_wake",
            Self::Action => "kt_action_wake",
            Self::Revocation => "kt_context_revoke",
        }
    }
}

/// How a push went.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: u16,
    pub reason: String,
}

impl Outcome {
    pub fn new(status: u16, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeRequest {
    Mint {
        purposes: Vec<Purpose>,
        address: Address,
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
    Result(Outcome),
}

impl WakeResponse {
    pub fn status(status: u16, reason: impl Into<String>) -> Self {
        Self::Result(Outcome::new(status, reason))
    }
}

fn frame(tag: u8, body: BytesMut) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + body.len());
    out.put_u32(1 + body.len() as u32);
    out.put_u8(tag);
    out.put_slice(&body);
    out.freeze()
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
            Self::Mint { purposes, address } => {
                ensure!(purposes.len() <= MAX_PURPOSES_PER_MINT, "too many purposes");
                ensure!(address.is_encodable(), "address too long");
                body.put_u8(purposes.len() as u8);
                body.extend(purposes.iter().map(|purpose| *purpose as u8));
                address.encode(&mut body);
                Ok(frame(tag::MINT, body))
            }
            Self::Send {
                kind,
                handle,
                payload,
            } => {
                ensure!(handle.len() <= u16::MAX as usize, "handle too long");
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
                let count = body.get_u8() as usize;
                ensure!(
                    (1..=MAX_PURPOSES_PER_MINT).contains(&count),
                    "1 to {MAX_PURPOSES_PER_MINT} purposes"
                );
                ensure!(body.remaining() >= count, "truncated");
                let purposes = body
                    .split_to(count)
                    .iter()
                    .map(|byte| Purpose::from_byte(*byte).context("unknown purpose"))
                    .collect::<Result<Vec<_>>>()?;
                let address = Address::decode(&mut body)?;
                Ok(Self::Mint { purposes, address })
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
            Self::Result(outcome) => {
                body.put_u16(outcome.status);
                body.put_slice(outcome.reason.as_bytes());
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
                Ok(Self::Result(Outcome::new(
                    status,
                    String::from_utf8(body.to_vec())?,
                )))
            }
            other => bail!("unknown response {other:#04x}"),
        }
    }
}

pub struct WakeConfig {
    /// At least [`handle::MIN_SECRET_LEN`] bytes. Handles minted under one
    /// secret open under no other, so it must outlive restarts.
    pub handle_secret: Vec<u8>,
    pub apns: Option<ApnsConfig>,
}

/// The wake service. It is always offered: without providers it answers
/// every request 501, so a client meets one error for "nothing configured"
/// and "not this provider".
pub struct Wake {
    sealer: Option<HandleSealer>,
    apns: Option<Apns>,
}

impl Wake {
    pub fn new(config: Option<WakeConfig>) -> Result<Self> {
        let Some(config) = config else {
            return Ok(Self {
                sealer: None,
                apns: None,
            });
        };
        Ok(Self {
            sealer: Some(HandleSealer::new(&config.handle_secret)?),
            apns: config.apns.map(Apns::new).transpose()?,
        })
    }

    pub async fn respond(&self, tag: u8, body: Bytes) -> WakeResponse {
        match WakeRequest::decode(tag, body) {
            Ok(WakeRequest::Mint { purposes, address }) => self.mint(purposes, address),
            Ok(WakeRequest::Send {
                kind,
                handle,
                payload,
            }) => WakeResponse::Result(self.send(kind, &handle, &payload).await),
            Err(err) => WakeResponse::status(status::BAD_REQUEST, format!("{err:#}")),
        }
    }

    fn offers(&self, address: &Address) -> bool {
        match address {
            Address::Apns(_) => self.apns.is_some(),
        }
    }

    fn mint(&self, purposes: Vec<Purpose>, address: Address) -> WakeResponse {
        let Some(sealer) = self.sealer.as_ref().filter(|_| self.offers(&address)) else {
            return WakeResponse::status(status::UNSUPPORTED, address.provider_name());
        };
        let minted = purposes
            .into_iter()
            .map(|purpose| {
                let id = Uuid::new_v4();
                let handle = sealer.seal(&Handle {
                    id: *id.as_bytes(),
                    purpose,
                    address: address.clone(),
                })?;
                Ok(MintedHandle { id, handle })
            })
            .collect::<Result<Vec<_>>>();
        match minted {
            Ok(handles) => WakeResponse::Minted(handles),
            Err(err) => WakeResponse::status(status::BAD_REQUEST, format!("{err:#}")),
        }
    }

    async fn send(&self, kind: Kind, sealed: &[u8], payload: &[u8]) -> Outcome {
        let Some(sealer) = &self.sealer else {
            return Outcome::new(status::UNSUPPORTED, "");
        };
        let handle = match sealer.open(sealed) {
            Ok(handle) if handle.purpose == kind.purpose() => handle,
            Ok(_) => return Outcome::new(status::BAD_REQUEST, "wrong kind for this handle"),
            Err(err) => return Outcome::new(status::BAD_REQUEST, format!("{err:#}")),
        };
        let id = Uuid::from_bytes(handle.id).to_string();
        let outcome = match (&handle.address, &self.apns) {
            (Address::Apns(address), Some(apns)) => apns.send(address, kind, &id, payload).await,
            (Address::Apns(_), None) => {
                Outcome::new(status::UNSUPPORTED, handle.address.provider_name())
            }
        };
        if outcome.status != status::OK {
            debug!(status = outcome.status, reason = %outcome.reason, "a wake was refused");
        }
        outcome
    }
}

#[cfg(test)]
mod tests {
    use super::{
        apns::{ApnsAddress, Environment},
        *,
    };

    fn apns_address(token: Vec<u8>) -> Address {
        Address::Apns(ApnsAddress {
            environment: Environment::Development,
            topic: "dev.keeptalking.app".into(),
            token,
        })
    }

    #[test]
    fn requests_and_responses_round_trip() {
        let requests = [
            WakeRequest::Mint {
                purposes: vec![Purpose::ContextMessage, Purpose::ActionAuthorisation],
                address: apns_address(vec![1; 32]),
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
    fn a_mint_needs_some_purposes_and_a_whole_address() {
        let decode = |purposes: Vec<Purpose>, token: Vec<u8>| {
            let mut frame = WakeRequest::Mint {
                purposes,
                address: apns_address(token),
            }
            .encode()
            .unwrap();
            frame.advance(5);
            WakeRequest::decode(tag::MINT, frame)
        };
        assert!(decode(vec![], vec![1]).is_err());
        assert!(decode(vec![Purpose::ContextMessage], vec![]).is_err());
        assert!(decode(vec![Purpose::ContextMessage], vec![1]).is_ok());
    }
}
