//! Wire format of the SFU protocol (ALPN [`SFU_ALPN`]).
//!
//! A client opens exactly one bidirectional QUIC stream on its connection to
//! the SFU and speaks first. Both directions carry length-prefixed,
//! type-tagged frames:
//!
//! ```text
//! [4-byte BE length = 1 + body] [1-byte type] [body]
//! ```
//!
//! Rooms are keyed by a 32-byte **topic**. Clients derive it from their
//! context secret, so the SFU never learns which context a room is; it only
//! groups subscribers. Identity is the QUIC connection's authenticated
//! remote `EndpointId`; there is no hello/challenge. The all-zero topic is
//! reserved (it marks an ERROR that is not about a topic) and cannot be
//! subscribed to.
//!
//! # Client → server
//!
//! | tag  | frame       | body                          |
//! |------|-------------|-------------------------------|
//! | 0x21 | SUBSCRIBE   | topic(32)                     |
//! | 0x22 | UNSUBSCRIBE | topic(32)                     |
//! | 0x23 | ANNOUNCE    | topic(32) ‖ blob (≤ 1 KiB)    |
//! | 0x24 | PUBLISH     | topic(32) ‖ payload (≤ 1 MiB) |
//!
//! # Server → client
//!
//! | tag  | frame    | body                                                            |
//! |------|----------|-----------------------------------------------------------------|
//! | 0x31 | SNAPSHOT | topic ‖ flags(u8) ‖ u16 n ‖ n × (id(32) ‖ u32 len ‖ blob[len])  |
//! | 0x32 | JOINED   | topic ‖ id(32)                                                  |
//! | 0x33 | LEFT     | topic ‖ id(32)                                                  |
//! | 0x34 | PRESENCE | topic ‖ id(32) ‖ blob                                           |
//! | 0x35 | DELIVER  | topic ‖ payload                                                 |
//! | 0x3F | ERROR    | topic ‖ UTF-8 reason (all-zero topic: not about a topic)        |
//!
//! ## Rooms
//!
//! - SUBSCRIBE joins the topic's room. The subscriber's first frame for that
//!   topic is its SNAPSHOT (the other members and their latest blobs); every
//!   later JOINED/LEFT/PRESENCE/DELIVER for the topic follows it. A SUBSCRIBE
//!   for a topic the connection already holds is a no-op: no second
//!   snapshot, no JOINED.
//! - SNAPSHOT is chunked. Flags bit 0 is **MORE**: more chunks of this
//!   topic's snapshot follow. The SFU cuts a chunk at
//!   [`SNAPSHOT_CHUNK_ENTRIES`] entries or [`SNAPSHOT_CHUNK_BYTES`] of body,
//!   whichever comes first, and sends a snapshot's chunks back to back. An
//!   empty room is one chunk with n = 0 and MORE clear. A client accumulates
//!   chunks until one without MORE and treats the union as the whole room.
//!   Other flag bits are reserved: senders set them to 0, receivers ignore
//!   them.
//! - A room holds at most [`MAX_MEMBERS_PER_TOPIC`] members. A SUBSCRIBE to a
//!   full room is answered with `ERROR(topic, "room full")` and does not
//!   subscribe. One connection holds at most [`MAX_TOPICS_PER_CONNECTION`]
//!   topics (`ERROR(topic, "too many topics")`).
//! - ANNOUNCE stores the sender's presence blob (its context-sealed endpoint
//!   id) and is relayed as PRESENCE; a late subscriber gets every latest blob
//!   in its SNAPSHOT. A zero-length blob means "not announced yet".
//! - PUBLISH is reliable fan-out: the SFU sends DELIVER with the same payload
//!   to every *other* subscriber, so a sender uploads once however large the
//!   room. DELIVER does not name the sender; the sealed payload does.
//! - Only subscribers may ANNOUNCE, PUBLISH or send datagrams to a topic.
//!
//! ## Errors
//!
//! ERROR names the topic it is about, or the all-zero topic. Refused frames
//! have no other effect. The reasons the SFU sends for refusals are fixed
//! strings (see [`reason`]); malformed frames get a free-form reason.
//!
//! ## Framing errors
//!
//! - A length prefix of 0 or above [`MAX_FRAME_LEN`] is fatal: the receiver
//!   closes the connection (the SFU with [`close::PROTOCOL`]).
//! - A frame with a valid length but an unknown tag or malformed body is
//!   skipped and the connection continues. The SFU counts it and answers
//!   `ERROR(0, …)`; clients must skip unknown server frames the same way.
//!
//! ## Server policy
//!
//! The SFU bounds each connection (defaults in `server::Limits`): a per
//! connection token bucket for PUBLISH+ANNOUNCE (bytes and frames; over the
//! limit → `ERROR(topic, "rate limited")`, frame dropped), one for room joins
//! (over the limit → `ERROR(topic, "rate limited")`, not subscribed) and one
//! for datagrams (over the limit → dropped silently). A connection whose
//! outbound queue exceeds its byte budget is closed with
//! [`close::SLOW_CONSUMER`]; one whose stream makes no write progress for the
//! stall timeout with [`close::STALLED`]; one that opens no stream in time
//! with [`close::NO_STREAM`].
//!
//! # Datagrams
//!
//! QUIC datagrams on the SFU connection are `topic(32) ‖ payload`. The SFU
//! forwards the identical bytes to every other subscriber, best effort (voice).

use std::fmt;

use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use iroh::EndpointId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// ALPN for the SFU protocol.
pub const SFU_ALPN: &[u8] = b"keeptalking/sfu/1";
/// Largest presence blob a client may announce. Real blobs are ~112 bytes.
pub const MAX_ANNOUNCE_LEN: usize = 1024;
/// Largest payload a client may publish (one sealed envelope).
pub const MAX_PUBLISH_LEN: usize = 1 << 20;
/// Largest frame on the wire: a full publish plus headroom.
pub const MAX_FRAME_LEN: usize = MAX_PUBLISH_LEN + 64 * 1024;
/// Members one room may hold.
pub const MAX_MEMBERS_PER_TOPIC: usize = 1024;
/// Topics one connection may subscribe to at once.
pub const MAX_TOPICS_PER_CONNECTION: usize = 512;
/// Most entries in one SNAPSHOT chunk.
pub const SNAPSHOT_CHUNK_ENTRIES: usize = 256;
/// Most body bytes in one SNAPSHOT chunk (unless a single entry is larger).
pub const SNAPSHOT_CHUNK_BYTES: usize = 256 * 1024;
/// SNAPSHOT flag: more chunks of this topic's snapshot follow.
pub const SNAPSHOT_MORE: u8 = 0x01;

/// Frame type tags.
pub mod tag {
    pub const SUBSCRIBE: u8 = 0x21;
    pub const UNSUBSCRIBE: u8 = 0x22;
    pub const ANNOUNCE: u8 = 0x23;
    pub const PUBLISH: u8 = 0x24;
    pub const SNAPSHOT: u8 = 0x31;
    pub const JOINED: u8 = 0x32;
    pub const LEFT: u8 = 0x33;
    pub const PRESENCE: u8 = 0x34;
    pub const DELIVER: u8 = 0x35;
    pub const ERROR: u8 = 0x3F;
}

/// Fixed ERROR reasons for refused frames.
pub mod reason {
    /// SUBSCRIBE to a room at [`super::MAX_MEMBERS_PER_TOPIC`].
    pub const ROOM_FULL: &str = "room full";
    /// SUBSCRIBE beyond [`super::MAX_TOPICS_PER_CONNECTION`].
    pub const TOO_MANY_TOPICS: &str = "too many topics";
    /// PUBLISH/ANNOUNCE or room join over the connection's rate limit.
    pub const RATE_LIMITED: &str = "rate limited";
    /// ANNOUNCE/PUBLISH to a topic the connection is not subscribed to.
    pub const NOT_SUBSCRIBED: &str = "not subscribed";
    /// ANNOUNCE blob above [`super::MAX_ANNOUNCE_LEN`].
    pub const ANNOUNCE_TOO_LARGE: &str = "announce too large";
    /// PUBLISH payload above [`super::MAX_PUBLISH_LEN`].
    pub const PUBLISH_TOO_LARGE: &str = "publish too large";
    /// SUBSCRIBE to the all-zero topic.
    pub const RESERVED_TOPIC: &str = "reserved topic";
}

/// Application close codes the SFU uses.
pub mod close {
    /// Normal shutdown.
    pub const NORMAL: u32 = 0;
    /// The connection's outbound queue went over its byte budget.
    pub const SLOW_CONSUMER: u32 = 1;
    /// Fatal framing error (length prefix 0 or above `MAX_FRAME_LEN`).
    pub const PROTOCOL: u32 = 2;
    /// The stream made no write progress for the stall timeout.
    pub const STALLED: u32 = 3;
    /// The client did not open its stream in time.
    pub const NO_STREAM: u32 = 4;
}

/// A room key: 32 opaque bytes the clients derive from their context secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic(pub [u8; 32]);

impl Topic {
    /// The reserved all-zero topic: "not about a topic" in ERROR.
    pub const ZERO: Topic = Topic([0; 32]);

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(&self) -> bool {
        self.0 == [0; 32]
    }

    /// First 10 hex digits, like `EndpointId::fmt_short`.
    pub fn fmt_short(&self) -> String {
        hex(&self.0[..5])
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        ensure!(s.len() == 64, "topic must be 64 hex digits");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).context("topic is not hex")?;
        }
        Ok(Self(out))
    }
}

impl fmt::Debug for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Topic({})", self.fmt_short())
    }
}

impl fmt::Display for Topic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex(&self.0))
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A frame sent by a client to the SFU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    Subscribe { topic: Topic },
    Unsubscribe { topic: Topic },
    Announce { topic: Topic, blob: Bytes },
    Publish { topic: Topic, payload: Bytes },
}

/// One entry of a [`ServerFrame::Snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: EndpointId,
    /// Latest announced presence, empty if the member has not announced.
    pub blob: Bytes,
}

/// A frame sent by the SFU to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFrame {
    /// One chunk of a room snapshot; `more` means further chunks follow.
    /// [`crate::client::SfuClient`] hands out assembled snapshots only
    /// (`more == false`, every member).
    Snapshot {
        topic: Topic,
        more: bool,
        members: Vec<Member>,
    },
    Joined {
        topic: Topic,
        id: EndpointId,
    },
    Left {
        topic: Topic,
        id: EndpointId,
    },
    Presence {
        topic: Topic,
        id: EndpointId,
        blob: Bytes,
    },
    Deliver {
        topic: Topic,
        payload: Bytes,
    },
    /// `topic` is `None` when the error is not about a topic (all-zero on
    /// the wire).
    Error {
        topic: Option<Topic>,
        reason: String,
    },
}

impl ClientFrame {
    pub fn encode(&self) -> Bytes {
        match self {
            ClientFrame::Subscribe { topic } => encode(tag::SUBSCRIBE, 32, |out| {
                out.put_slice(topic.as_bytes());
            }),
            ClientFrame::Unsubscribe { topic } => encode(tag::UNSUBSCRIBE, 32, |out| {
                out.put_slice(topic.as_bytes());
            }),
            ClientFrame::Announce { topic, blob } => {
                encode(tag::ANNOUNCE, 32 + blob.len(), |out| {
                    out.put_slice(topic.as_bytes());
                    out.put_slice(blob);
                })
            }
            ClientFrame::Publish { topic, payload } => {
                encode(tag::PUBLISH, 32 + payload.len(), |out| {
                    out.put_slice(topic.as_bytes());
                    out.put_slice(payload);
                })
            }
        }
    }

    pub fn decode(tag: u8, mut body: Bytes) -> Result<Self> {
        let frame = match tag {
            tag::SUBSCRIBE => ClientFrame::Subscribe {
                topic: take_topic(&mut body)?,
            },
            tag::UNSUBSCRIBE => ClientFrame::Unsubscribe {
                topic: take_topic(&mut body)?,
            },
            tag::ANNOUNCE => {
                let topic = take_topic(&mut body)?;
                return Ok(ClientFrame::Announce { topic, blob: body });
            }
            tag::PUBLISH => {
                let topic = take_topic(&mut body)?;
                return Ok(ClientFrame::Publish {
                    topic,
                    payload: body,
                });
            }
            other => bail!("unknown client frame 0x{other:02x}"),
        };
        ensure!(
            body.is_empty(),
            "trailing bytes in client frame 0x{tag:02x}"
        );
        Ok(frame)
    }
}

impl ServerFrame {
    pub fn encode(&self) -> Bytes {
        match self {
            ServerFrame::Snapshot {
                topic,
                more,
                members,
            } => {
                let members = &members[..members.len().min(usize::from(u16::MAX))];
                encode_snapshot_chunk(*topic, *more, members)
            }
            ServerFrame::Joined { topic, id } => encode(tag::JOINED, 64, |out| {
                out.put_slice(topic.as_bytes());
                out.put_slice(id.as_bytes());
            }),
            ServerFrame::Left { topic, id } => encode(tag::LEFT, 64, |out| {
                out.put_slice(topic.as_bytes());
                out.put_slice(id.as_bytes());
            }),
            ServerFrame::Presence { topic, id, blob } => {
                encode(tag::PRESENCE, 64 + blob.len(), |out| {
                    out.put_slice(topic.as_bytes());
                    out.put_slice(id.as_bytes());
                    out.put_slice(blob);
                })
            }
            ServerFrame::Deliver { topic, payload } => {
                encode(tag::DELIVER, 32 + payload.len(), |out| {
                    out.put_slice(topic.as_bytes());
                    out.put_slice(payload);
                })
            }
            ServerFrame::Error { topic, reason } => encode(tag::ERROR, 32 + reason.len(), |out| {
                out.put_slice(topic.unwrap_or(Topic::ZERO).as_bytes());
                out.put_slice(reason.as_bytes());
            }),
        }
    }

    pub fn decode(tag: u8, mut body: Bytes) -> Result<Self> {
        let frame = match tag {
            tag::SNAPSHOT => {
                let topic = take_topic(&mut body)?;
                ensure!(body.remaining() >= 3, "truncated snapshot header");
                let flags = body.get_u8();
                let count = body.get_u16();
                // Each entry takes at least 36 bytes, so a bogus count cannot
                // make us reserve much more than the body.
                let mut members = Vec::with_capacity(usize::from(count).min(body.remaining() / 36));
                for _ in 0..count {
                    let id = take_id(&mut body)?;
                    ensure!(body.remaining() >= 4, "truncated snapshot blob length");
                    let len = body.get_u32() as usize;
                    ensure!(body.remaining() >= len, "truncated snapshot blob");
                    members.push(Member {
                        id,
                        blob: body.split_to(len),
                    });
                }
                ServerFrame::Snapshot {
                    topic,
                    more: flags & SNAPSHOT_MORE != 0,
                    members,
                }
            }
            tag::JOINED => ServerFrame::Joined {
                topic: take_topic(&mut body)?,
                id: take_id(&mut body)?,
            },
            tag::LEFT => ServerFrame::Left {
                topic: take_topic(&mut body)?,
                id: take_id(&mut body)?,
            },
            tag::PRESENCE => {
                let topic = take_topic(&mut body)?;
                let id = take_id(&mut body)?;
                return Ok(ServerFrame::Presence {
                    topic,
                    id,
                    blob: body,
                });
            }
            tag::DELIVER => {
                let topic = take_topic(&mut body)?;
                return Ok(ServerFrame::Deliver {
                    topic,
                    payload: body,
                });
            }
            tag::ERROR => {
                let topic = take_topic(&mut body)?;
                let reason = String::from_utf8_lossy(&body).into_owned();
                return Ok(ServerFrame::Error {
                    topic: (!topic.is_zero()).then_some(topic),
                    reason,
                });
            }
            other => bail!("unknown server frame 0x{other:02x}"),
        };
        ensure!(
            body.is_empty(),
            "trailing bytes in server frame 0x{tag:02x}"
        );
        Ok(frame)
    }
}

/// Body bytes one member takes in a SNAPSHOT: `id(32) ‖ u32 len ‖ blob`.
pub fn snapshot_entry_len(member: &Member) -> usize {
    32 + 4 + member.blob.len()
}

/// SNAPSHOT body bytes before the entries: `topic ‖ flags ‖ u16 n`.
const SNAPSHOT_HEAD_LEN: usize = 32 + 1 + 2;

/// Splits `members` into SNAPSHOT chunks of at most `max_entries` entries
/// and `max_body` body bytes and encodes them, MORE set on all but the last.
/// An empty room is one empty chunk. An entry larger than `max_body` on its
/// own still goes out, alone in its chunk.
pub fn encode_snapshot(
    topic: Topic,
    members: &[Member],
    max_entries: usize,
    max_body: usize,
) -> Vec<Bytes> {
    let max_entries = max_entries.clamp(1, usize::from(u16::MAX));
    let mut chunks = Vec::with_capacity(members.len() / max_entries + 1);
    let mut start = 0;
    loop {
        let mut end = start;
        let mut body = SNAPSHOT_HEAD_LEN;
        while end < members.len() && end - start < max_entries {
            let entry = snapshot_entry_len(&members[end]);
            if end > start && body + entry > max_body {
                break;
            }
            body += entry;
            end += 1;
        }
        let more = end < members.len();
        chunks.push(encode_snapshot_chunk(topic, more, &members[start..end]));
        if !more {
            return chunks;
        }
        start = end;
    }
}

/// Wire size of [`encode_snapshot`]'s output to within a few chunk headers,
/// cheap enough to compute under a lock (for queue accounting).
pub fn snapshot_wire_len(members: &[Member], max_entries: usize) -> usize {
    let entries: usize = members.iter().map(snapshot_entry_len).sum();
    let chunks = (members.len() / max_entries.max(1)).max(entries / SNAPSHOT_CHUNK_BYTES) + 1;
    entries + chunks * (5 + SNAPSHOT_HEAD_LEN)
}

fn encode_snapshot_chunk(topic: Topic, more: bool, members: &[Member]) -> Bytes {
    let body: usize = SNAPSHOT_HEAD_LEN + members.iter().map(snapshot_entry_len).sum::<usize>();
    encode(tag::SNAPSHOT, body, |out| {
        out.put_slice(topic.as_bytes());
        out.put_u8(if more { SNAPSHOT_MORE } else { 0 });
        out.put_u16(members.len() as u16);
        for member in members {
            out.put_slice(member.id.as_bytes());
            out.put_u32(member.blob.len() as u32);
            out.put_slice(&member.blob);
        }
    })
}

/// Builds an SFU datagram: `topic ‖ payload`.
pub fn datagram(topic: &Topic, payload: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(32 + payload.len());
    out.put_slice(topic.as_bytes());
    out.put_slice(payload);
    out.freeze()
}

/// Splits an SFU datagram into its topic and payload.
pub fn split_datagram(mut datagram: Bytes) -> Option<(Topic, Bytes)> {
    let topic = take_topic(&mut datagram).ok()?;
    Some((topic, datagram))
}

/// The 5-byte frame header (`length ‖ tag`) for a body of `body_len` bytes,
/// for callers that send a body they already hold without copying it.
pub fn frame_header(tag: u8, body_len: usize) -> Bytes {
    let mut out = BytesMut::with_capacity(5);
    out.put_u32(1 + body_len as u32);
    out.put_u8(tag);
    out.freeze()
}

/// Encodes one frame into a single allocation.
fn encode(tag: u8, body_len: usize, body: impl FnOnce(&mut BytesMut)) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + body_len);
    out.put_u32(1 + body_len as u32);
    out.put_u8(tag);
    body(&mut out);
    debug_assert_eq!(out.len(), 5 + body_len);
    out.freeze()
}

fn take_topic(body: &mut Bytes) -> Result<Topic> {
    ensure!(body.remaining() >= 32, "truncated topic");
    Ok(Topic(body.split_to(32)[..].try_into().expect("32 bytes")))
}

fn take_id(body: &mut Bytes) -> Result<EndpointId> {
    ensure!(body.remaining() >= 32, "truncated endpoint id");
    let bytes: [u8; 32] = body.split_to(32)[..].try_into().expect("32 bytes");
    EndpointId::from_bytes(&bytes).context("invalid endpoint id")
}

/// A length prefix of 0 or above [`MAX_FRAME_LEN`]: the stream cannot be
/// resynchronised, so the connection must close.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLengthError(pub usize);

impl fmt::Display for FrameLengthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "frame length {} out of range", self.0)
    }
}

impl std::error::Error for FrameLengthError {}

/// Bytes read per step while filling a frame body, so a peer has to send
/// data before we allocate memory for it.
const READ_STEP: usize = 64 * 1024;

/// Reads one raw frame. Returns `Ok(None)` when the stream ends cleanly on a
/// frame boundary. Every error is fatal for the stream; a bad length prefix
/// is a [`FrameLengthError`]. The tag and body are not validated: decode
/// them with [`ClientFrame::decode`] / [`ServerFrame::decode`] and skip the
/// frame if that fails.
pub async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Option<(u8, Bytes)>> {
    let mut len = [0u8; 4];
    match recv.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    if !(1..=MAX_FRAME_LEN).contains(&len) {
        return Err(FrameLengthError(len).into());
    }
    // Grow the buffer as bytes arrive instead of trusting the declared
    // length up front.
    let mut buf = BytesMut::with_capacity(len.min(READ_STEP));
    while buf.len() < len {
        let step = (len - buf.len()).min(READ_STEP);
        buf.reserve(step);
        let read = (&mut *recv)
            .take(step as u64)
            .read_buf(&mut buf)
            .await
            .context("reading frame body")?;
        ensure!(read > 0, "truncated frame");
    }
    let mut buf = buf.freeze();
    let tag = buf.get_u8();
    Ok(Some((tag, buf)))
}

pub async fn write_frame<W: AsyncWrite + Unpin>(send: &mut W, frame: &Bytes) -> Result<()> {
    send.write_all(frame).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[seed; 32]).public()
    }

    async fn roundtrip_server(frame: ServerFrame) -> ServerFrame {
        let bytes = frame.encode();
        let (tag, body) = read_frame(&mut &bytes[..]).await.unwrap().unwrap();
        ServerFrame::decode(tag, body).unwrap()
    }

    async fn roundtrip_client(frame: ClientFrame) -> ClientFrame {
        let bytes = frame.encode();
        let (tag, body) = read_frame(&mut &bytes[..]).await.unwrap().unwrap();
        ClientFrame::decode(tag, body).unwrap()
    }

    #[tokio::test]
    async fn frames_roundtrip() {
        let topic = Topic([7; 32]);
        for frame in [
            ClientFrame::Subscribe { topic },
            ClientFrame::Unsubscribe { topic },
            ClientFrame::Announce {
                topic,
                blob: Bytes::from_static(b"sealed"),
            },
            ClientFrame::Announce {
                topic,
                blob: Bytes::new(),
            },
            ClientFrame::Publish {
                topic,
                payload: Bytes::from_static(b"payload"),
            },
        ] {
            assert_eq!(roundtrip_client(frame.clone()).await, frame);
        }
        for frame in [
            ServerFrame::Snapshot {
                topic,
                more: true,
                members: vec![
                    Member {
                        id: id(1),
                        blob: Bytes::from_static(b"a"),
                    },
                    Member {
                        id: id(2),
                        blob: Bytes::new(),
                    },
                ],
            },
            ServerFrame::Snapshot {
                topic,
                more: false,
                members: vec![],
            },
            ServerFrame::Joined { topic, id: id(3) },
            ServerFrame::Left { topic, id: id(3) },
            ServerFrame::Presence {
                topic,
                id: id(4),
                blob: Bytes::from_static(b"x"),
            },
            ServerFrame::Deliver {
                topic,
                payload: Bytes::from_static(b"y"),
            },
            ServerFrame::Error {
                topic: Some(topic),
                reason: "nope".into(),
            },
            ServerFrame::Error {
                topic: None,
                reason: "general".into(),
            },
        ] {
            assert_eq!(roundtrip_server(frame.clone()).await, frame);
        }
    }

    #[test]
    fn snapshot_and_error_layout() {
        let topic = Topic([0xAB; 32]);
        let empty = ServerFrame::Snapshot {
            topic,
            more: false,
            members: vec![],
        }
        .encode();
        assert_eq!(&empty[..5], &[0, 0, 0, 36, tag::SNAPSHOT]);
        assert_eq!(&empty[5..37], &[0xAB; 32]);
        assert_eq!(&empty[37..], &[0, 0, 0]);

        let error = ServerFrame::Error {
            topic: None,
            reason: "x".into(),
        }
        .encode();
        assert_eq!(&error[..5], &[0, 0, 0, 34, tag::ERROR]);
        assert_eq!(&error[5..37], &[0; 32]);
        assert_eq!(&error[37..], b"x");

        // Reserved flag bits are ignored.
        let mut body = BytesMut::from(&empty[5..]);
        body[32] = 0xFE;
        assert_eq!(
            ServerFrame::decode(tag::SNAPSHOT, body.freeze()).unwrap(),
            ServerFrame::Snapshot {
                topic,
                more: false,
                members: vec![]
            }
        );
    }

    fn members(count: usize, blob_len: usize) -> Vec<Member> {
        (0..count)
            .map(|i| Member {
                id: iroh::SecretKey::from_bytes(&[(i % 251) as u8 + 1; 32]).public(),
                blob: Bytes::from(vec![(i % 256) as u8; blob_len]),
            })
            .collect()
    }

    fn decode_chunks(chunks: &[Bytes]) -> Vec<(bool, Vec<Member>)> {
        chunks
            .iter()
            .map(|chunk| {
                assert!(chunk.len() - 4 <= MAX_FRAME_LEN);
                let mut chunk = chunk.clone();
                let len = chunk.get_u32() as usize;
                assert_eq!(len, chunk.len());
                let tag = chunk.get_u8();
                match ServerFrame::decode(tag, chunk).unwrap() {
                    ServerFrame::Snapshot { more, members, .. } => (more, members),
                    other => panic!("not a snapshot: {other:?}"),
                }
            })
            .collect()
    }

    fn assert_chunked(chunks: &[(bool, Vec<Member>)], expected: &[Member]) {
        for (i, (more, chunk)) in chunks.iter().enumerate() {
            assert_eq!(*more, i + 1 < chunks.len(), "MORE on chunk {i}");
            assert!(chunk.len() <= SNAPSHOT_CHUNK_ENTRIES);
            let body = SNAPSHOT_HEAD_LEN + chunk.iter().map(snapshot_entry_len).sum::<usize>();
            assert!(
                body <= SNAPSHOT_CHUNK_BYTES,
                "chunk {i} has {body} body bytes"
            );
        }
        let union: Vec<Member> = chunks.iter().flat_map(|(_, m)| m.clone()).collect();
        assert_eq!(union, expected);
    }

    #[test]
    fn snapshots_are_chunked_by_entries() {
        let topic = Topic([1; 32]);
        let all = members(600, 16);
        let chunks = encode_snapshot(topic, &all, SNAPSHOT_CHUNK_ENTRIES, SNAPSHOT_CHUNK_BYTES);
        let decoded = decode_chunks(&chunks);
        assert_eq!(
            decoded.iter().map(|(_, m)| m.len()).collect::<Vec<_>>(),
            [256, 256, 88]
        );
        assert_chunked(&decoded, &all);
        assert_estimate(&chunks, &all);
    }

    fn assert_estimate(chunks: &[Bytes], members: &[Member]) {
        let actual = chunks.iter().map(Bytes::len).sum::<usize>();
        let estimate = snapshot_wire_len(members, SNAPSHOT_CHUNK_ENTRIES);
        assert!(
            actual.abs_diff(estimate) <= 2 * (5 + SNAPSHOT_HEAD_LEN),
            "{actual} vs {estimate}"
        );
    }

    #[test]
    fn snapshots_are_chunked_by_bytes() {
        let topic = Topic([2; 32]);
        // 1024 members with maximal blobs: ~1 MiB, far above one chunk.
        let all = members(MAX_MEMBERS_PER_TOPIC, MAX_ANNOUNCE_LEN);
        let chunks = encode_snapshot(topic, &all, SNAPSHOT_CHUNK_ENTRIES, SNAPSHOT_CHUNK_BYTES);
        let decoded = decode_chunks(&chunks);
        assert!(decoded.len() >= 5, "{} chunks", decoded.len());
        assert!(
            decoded
                .iter()
                .all(|(_, m)| m.len() < SNAPSHOT_CHUNK_ENTRIES)
        );
        assert_chunked(&decoded, &all);
        assert_estimate(&chunks, &all);
    }

    #[test]
    fn empty_and_small_snapshots_are_one_chunk() {
        let topic = Topic([3; 32]);
        let decoded = decode_chunks(&encode_snapshot(topic, &[], 256, SNAPSHOT_CHUNK_BYTES));
        assert_eq!(decoded, vec![(false, vec![])]);
        let few = members(3, 112);
        let decoded = decode_chunks(&encode_snapshot(topic, &few, 256, SNAPSHOT_CHUNK_BYTES));
        assert_eq!(decoded, vec![(false, few)]);
        // An oversized entry still goes out, alone.
        let big = members(3, 2048);
        let decoded = decode_chunks(&encode_snapshot(topic, &big, 256, 1024));
        assert_eq!(decoded.len(), 3);
        assert_chunked_loosely(&decoded, &big);
    }

    fn assert_chunked_loosely(chunks: &[(bool, Vec<Member>)], expected: &[Member]) {
        let union: Vec<Member> = chunks.iter().flat_map(|(_, m)| m.clone()).collect();
        assert_eq!(union, expected);
        assert!(chunks[..chunks.len() - 1].iter().all(|(more, _)| *more));
        assert!(!chunks.last().unwrap().0);
    }

    #[tokio::test]
    async fn framing_errors() {
        assert!(read_frame(&mut &b""[..]).await.unwrap().is_none());
        let zero = read_frame(&mut &[0u8, 0, 0, 0][..]).await.unwrap_err();
        assert_eq!(zero.downcast_ref(), Some(&FrameLengthError(0)));
        let huge = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes();
        let huge = read_frame(&mut &huge[..]).await.unwrap_err();
        assert_eq!(
            huge.downcast_ref(),
            Some(&FrameLengthError(MAX_FRAME_LEN + 1))
        );
        // A declared length the peer never sends is a truncation, not an
        // allocation of MAX_FRAME_LEN.
        let mut short = (MAX_FRAME_LEN as u32).to_be_bytes().to_vec();
        short.extend_from_slice(&[tag::PUBLISH, 1, 2, 3]);
        let err = read_frame(&mut &short[..]).await.unwrap_err();
        assert!(err.downcast_ref::<FrameLengthError>().is_none());
        // A large frame arriving in pieces is reassembled.
        let payload = Bytes::from(vec![9u8; 300_000]);
        let frame = ClientFrame::Publish {
            topic: Topic([4; 32]),
            payload: payload.clone(),
        }
        .encode();
        let (tag, body) = read_frame(&mut &frame[..]).await.unwrap().unwrap();
        assert_eq!(
            ClientFrame::decode(tag, body).unwrap(),
            ClientFrame::Publish {
                topic: Topic([4; 32]),
                payload
            }
        );

        assert!(ClientFrame::decode(tag::SUBSCRIBE, Bytes::from_static(&[0; 31])).is_err());
        assert!(ClientFrame::decode(tag::SUBSCRIBE, Bytes::from_static(&[0; 33])).is_err());
        assert!(ServerFrame::decode(0x99, Bytes::new()).is_err());
        assert!(ServerFrame::decode(tag::ERROR, Bytes::from_static(b"short")).is_err());
    }

    #[test]
    fn subscribe_layout_and_datagrams() {
        let topic = Topic([0xAB; 32]);
        let encoded = ClientFrame::Subscribe { topic }.encode();
        assert_eq!(&encoded[..5], &[0, 0, 0, 33, 0x21]);
        assert_eq!(&encoded[5..], &[0xAB; 32]);
        assert_eq!(&frame_header(tag::DELIVER, 32)[..], &[0, 0, 0, 33, 0x35]);

        let dg = datagram(&topic, b"voice");
        let (back, payload) = split_datagram(dg).unwrap();
        assert_eq!(back, topic);
        assert_eq!(&payload[..], b"voice");
        assert!(split_datagram(Bytes::from_static(&[0; 31])).is_none());
        assert_eq!(Topic::from_hex(&topic.to_string()).unwrap(), topic);
        assert!(Topic::ZERO.is_zero() && !topic.is_zero());
    }
}
