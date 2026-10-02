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
//! remote `EndpointId`; there is no hello/challenge.
//!
//! # Client → server
//!
//! | tag  | frame       | body                         |
//! |------|-------------|------------------------------|
//! | 0x21 | SUBSCRIBE   | topic(32)                    |
//! | 0x22 | UNSUBSCRIBE | topic(32)                    |
//! | 0x23 | ANNOUNCE    | topic(32) ‖ blob (≤ 16 KiB)  |
//! | 0x24 | PUBLISH     | topic(32) ‖ payload (≤ 1 MiB)|
//!
//! # Server → client
//!
//! | tag  | frame    | body                                                   |
//! |------|----------|--------------------------------------------------------|
//! | 0x31 | SNAPSHOT | topic ‖ u16 n ‖ n × (id(32) ‖ u32 len ‖ blob[len])     |
//! | 0x32 | JOINED   | topic ‖ id(32)                                         |
//! | 0x33 | LEFT     | topic ‖ id(32)                                         |
//! | 0x34 | PRESENCE | topic ‖ id(32) ‖ blob                                  |
//! | 0x35 | DELIVER  | topic ‖ payload                                        |
//! | 0x3F | ERROR    | UTF-8 reason                                           |
//!
//! - ANNOUNCE stores the sender's presence blob (its context-sealed endpoint
//!   id) and is relayed as PRESENCE; a late subscriber gets every latest blob
//!   in its SNAPSHOT. A zero-length blob means "not announced yet".
//! - PUBLISH is reliable fan-out: the SFU sends DELIVER with the same payload
//!   to every *other* subscriber, so a sender uploads once however large the
//!   room. DELIVER does not name the sender; the sealed payload does.
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
/// Largest presence blob a client may announce.
pub const MAX_ANNOUNCE_LEN: usize = 16 * 1024;
/// Largest payload a client may publish (one sealed envelope).
pub const MAX_PUBLISH_LEN: usize = 1 << 20;
/// Largest frame on the wire: a full publish plus headroom.
pub const MAX_FRAME_LEN: usize = MAX_PUBLISH_LEN + 64 * 1024;

mod tag {
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

/// A room key: 32 opaque bytes the clients derive from their context secret.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Topic(pub [u8; 32]);

impl Topic {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
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
    Snapshot {
        topic: Topic,
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
    Error {
        reason: String,
    },
}

impl ClientFrame {
    pub fn encode(&self) -> Bytes {
        let mut body = BytesMut::new();
        let tag = match self {
            ClientFrame::Subscribe { topic } => {
                body.put_slice(topic.as_bytes());
                tag::SUBSCRIBE
            }
            ClientFrame::Unsubscribe { topic } => {
                body.put_slice(topic.as_bytes());
                tag::UNSUBSCRIBE
            }
            ClientFrame::Announce { topic, blob } => {
                body.put_slice(topic.as_bytes());
                body.put_slice(blob);
                tag::ANNOUNCE
            }
            ClientFrame::Publish { topic, payload } => {
                body.put_slice(topic.as_bytes());
                body.put_slice(payload);
                tag::PUBLISH
            }
        };
        frame(tag, &body)
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
        let mut body = BytesMut::new();
        let tag = match self {
            ServerFrame::Snapshot { topic, members } => {
                body.put_slice(topic.as_bytes());
                body.put_u16(u16::try_from(members.len()).unwrap_or(u16::MAX));
                for member in members.iter().take(usize::from(u16::MAX)) {
                    body.put_slice(member.id.as_bytes());
                    body.put_u32(member.blob.len() as u32);
                    body.put_slice(&member.blob);
                }
                tag::SNAPSHOT
            }
            ServerFrame::Joined { topic, id } => {
                body.put_slice(topic.as_bytes());
                body.put_slice(id.as_bytes());
                tag::JOINED
            }
            ServerFrame::Left { topic, id } => {
                body.put_slice(topic.as_bytes());
                body.put_slice(id.as_bytes());
                tag::LEFT
            }
            ServerFrame::Presence { topic, id, blob } => {
                body.put_slice(topic.as_bytes());
                body.put_slice(id.as_bytes());
                body.put_slice(blob);
                tag::PRESENCE
            }
            ServerFrame::Deliver { topic, payload } => {
                body.put_slice(topic.as_bytes());
                body.put_slice(payload);
                tag::DELIVER
            }
            ServerFrame::Error { reason } => {
                body.put_slice(reason.as_bytes());
                tag::ERROR
            }
        };
        frame(tag, &body)
    }

    pub fn decode(tag: u8, mut body: Bytes) -> Result<Self> {
        let frame = match tag {
            tag::SNAPSHOT => {
                let topic = take_topic(&mut body)?;
                ensure!(body.remaining() >= 2, "truncated snapshot count");
                let count = body.get_u16();
                let mut members = Vec::with_capacity(usize::from(count));
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
                ServerFrame::Snapshot { topic, members }
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
                let reason = String::from_utf8_lossy(&body).into_owned();
                return Ok(ServerFrame::Error { reason });
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

fn frame(tag: u8, body: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + body.len());
    out.put_u32(1 + body.len() as u32);
    out.put_u8(tag);
    out.put_slice(body);
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

/// Reads one raw frame. Returns `Ok(None)` when the stream ends cleanly on a
/// frame boundary.
pub async fn read_frame<R: AsyncRead + Unpin>(recv: &mut R) -> Result<Option<(u8, Bytes)>> {
    let mut len = [0u8; 4];
    match recv.read_exact(&mut len).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err.into()),
    }
    let len = u32::from_be_bytes(len) as usize;
    ensure!(
        (1..=MAX_FRAME_LEN).contains(&len),
        "frame length {len} out of range"
    );
    let mut buf = vec![0u8; len];
    recv.read_exact(&mut buf).await.context("truncated frame")?;
    let mut buf = Bytes::from(buf);
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
                reason: "nope".into(),
            },
        ] {
            assert_eq!(roundtrip_server(frame.clone()).await, frame);
        }
    }

    #[tokio::test]
    async fn clean_eof_is_none_and_garbage_is_rejected() {
        assert!(read_frame(&mut &b""[..]).await.unwrap().is_none());
        assert!(read_frame(&mut &[0u8, 0, 0, 0][..]).await.is_err());
        assert!(ClientFrame::decode(tag::SUBSCRIBE, Bytes::from_static(&[0; 31])).is_err());
        assert!(ClientFrame::decode(tag::SUBSCRIBE, Bytes::from_static(&[0; 33])).is_err());
        assert!(ServerFrame::decode(0x99, Bytes::new()).is_err());
    }

    #[test]
    fn subscribe_layout_and_datagrams() {
        let topic = Topic([0xAB; 32]);
        let encoded = ClientFrame::Subscribe { topic }.encode();
        assert_eq!(&encoded[..5], &[0, 0, 0, 33, 0x21]);
        assert_eq!(&encoded[5..], &[0xAB; 32]);

        let dg = datagram(&topic, b"voice");
        let (back, payload) = split_datagram(dg).unwrap();
        assert_eq!(back, topic);
        assert_eq!(&payload[..], b"voice");
        assert!(split_datagram(Bytes::from_static(&[0; 31])).is_none());
        assert_eq!(Topic::from_hex(&topic.to_string()).unwrap(), topic);
    }
}
