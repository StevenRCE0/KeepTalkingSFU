//! Wire format of the presence protocol (ALPN [`PRESENCE_ALPN`]).
//!
//! The client opens exactly one bidirectional QUIC stream on its connection
//! to the hub and speaks first. Both directions carry length-prefixed,
//! type-tagged frames, laid out like the Swift SFU's `SFUFrame`:
//!
//! ```text
//! [4-byte BE length = 1 + body] [1-byte type] [body]
//! ```
//!
//! Identity is the QUIC connection's authenticated remote `EndpointId`, so
//! there is no hello/challenge exchange. One connection may join many
//! contexts.
//!
//! # Client → server
//!
//! | tag  | frame   | body                  |
//! |------|---------|-----------------------|
//! | 0x11 | JOIN    | ctx(16)               |
//! | 0x12 | LEAVE   | ctx(16)               |
//! | 0x13 | PUBLISH | ctx(16) ‖ blob        |
//!
//! # Server → client
//!
//! | tag  | frame    | body                                                   |
//! |------|----------|--------------------------------------------------------|
//! | 0x14 | SNAPSHOT | ctx(16) ‖ u16 n ‖ n × (id(32) ‖ u32 len ‖ blob[len])   |
//! | 0x15 | JOINED   | ctx(16) ‖ id(32)                                       |
//! | 0x16 | LEFT     | ctx(16) ‖ id(32)                                       |
//! | 0x17 | PRESENCE | ctx(16) ‖ id(32) ‖ blob                                |
//! | 0x3F | ERROR    | UTF-8 reason                                           |
//!
//! `ctx` is the context UUID in RFC 4122 byte order, the same order as
//! Swift's `UUID.uuid` tuple. `id` is a 32-byte ed25519 `EndpointId`.
//! `blob` is opaque to the server: clients put their context-sealed presence
//! envelope there. A zero-length blob in SNAPSHOT means the member has not
//! published yet.

use anyhow::{Context, Result, bail, ensure};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use iroh::EndpointId;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

/// ALPN for the presence protocol spoken with the hub endpoint.
pub const PRESENCE_ALPN: &[u8] = b"keeptalking/presence/1";

/// Largest frame (type byte + body) either side accepts.
pub const MAX_FRAME_LEN: usize = 256 * 1024;
/// Largest presence blob a member may publish.
pub const MAX_PRESENCE_LEN: usize = 16 * 1024;

mod tag {
    pub const JOIN: u8 = 0x11;
    pub const LEAVE: u8 = 0x12;
    pub const PUBLISH: u8 = 0x13;
    pub const SNAPSHOT: u8 = 0x14;
    pub const JOINED: u8 = 0x15;
    pub const LEFT: u8 = 0x16;
    pub const PRESENCE: u8 = 0x17;
    pub const ERROR: u8 = 0x3F;
}

/// A frame sent by a client to the hub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientFrame {
    Join { context: Uuid },
    Leave { context: Uuid },
    Publish { context: Uuid, blob: Bytes },
}

/// One entry of a [`ServerFrame::Snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member {
    pub id: EndpointId,
    /// Latest published presence, empty if the member has not published.
    pub blob: Bytes,
}

/// A frame sent by the hub to a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerFrame {
    Snapshot {
        context: Uuid,
        members: Vec<Member>,
    },
    Joined {
        context: Uuid,
        id: EndpointId,
    },
    Left {
        context: Uuid,
        id: EndpointId,
    },
    Presence {
        context: Uuid,
        id: EndpointId,
        blob: Bytes,
    },
    Error {
        reason: String,
    },
}

impl ClientFrame {
    pub fn encode(&self) -> Bytes {
        let mut body = BytesMut::new();
        let tag = match self {
            ClientFrame::Join { context } => {
                body.put_slice(context.as_bytes());
                tag::JOIN
            }
            ClientFrame::Leave { context } => {
                body.put_slice(context.as_bytes());
                tag::LEAVE
            }
            ClientFrame::Publish { context, blob } => {
                body.put_slice(context.as_bytes());
                body.put_slice(blob);
                tag::PUBLISH
            }
        };
        frame(tag, &body)
    }

    pub fn decode(tag: u8, mut body: Bytes) -> Result<Self> {
        let frame = match tag {
            tag::JOIN => ClientFrame::Join {
                context: take_uuid(&mut body)?,
            },
            tag::LEAVE => ClientFrame::Leave {
                context: take_uuid(&mut body)?,
            },
            tag::PUBLISH => {
                let context = take_uuid(&mut body)?;
                return Ok(ClientFrame::Publish {
                    context,
                    blob: body,
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
            ServerFrame::Snapshot { context, members } => {
                body.put_slice(context.as_bytes());
                body.put_u16(u16::try_from(members.len()).unwrap_or(u16::MAX));
                for member in members.iter().take(usize::from(u16::MAX)) {
                    body.put_slice(member.id.as_bytes());
                    body.put_u32(member.blob.len() as u32);
                    body.put_slice(&member.blob);
                }
                tag::SNAPSHOT
            }
            ServerFrame::Joined { context, id } => {
                body.put_slice(context.as_bytes());
                body.put_slice(id.as_bytes());
                tag::JOINED
            }
            ServerFrame::Left { context, id } => {
                body.put_slice(context.as_bytes());
                body.put_slice(id.as_bytes());
                tag::LEFT
            }
            ServerFrame::Presence { context, id, blob } => {
                body.put_slice(context.as_bytes());
                body.put_slice(id.as_bytes());
                body.put_slice(blob);
                tag::PRESENCE
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
                let context = take_uuid(&mut body)?;
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
                ServerFrame::Snapshot { context, members }
            }
            tag::JOINED => ServerFrame::Joined {
                context: take_uuid(&mut body)?,
                id: take_id(&mut body)?,
            },
            tag::LEFT => ServerFrame::Left {
                context: take_uuid(&mut body)?,
                id: take_id(&mut body)?,
            },
            tag::PRESENCE => {
                let context = take_uuid(&mut body)?;
                let id = take_id(&mut body)?;
                return Ok(ServerFrame::Presence {
                    context,
                    id,
                    blob: body,
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

fn frame(tag: u8, body: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + body.len());
    out.put_u32(1 + body.len() as u32);
    out.put_u8(tag);
    out.put_slice(body);
    out.freeze()
}

fn take_uuid(body: &mut Bytes) -> Result<Uuid> {
    ensure!(body.remaining() >= 16, "truncated context id");
    Ok(Uuid::from_slice(&body.split_to(16)).expect("16 bytes"))
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
        let context = Uuid::new_v4();
        for frame in [
            ClientFrame::Join { context },
            ClientFrame::Leave { context },
            ClientFrame::Publish {
                context,
                blob: Bytes::from_static(b"sealed"),
            },
            ClientFrame::Publish {
                context,
                blob: Bytes::new(),
            },
        ] {
            assert_eq!(roundtrip_client(frame.clone()).await, frame);
        }
        for frame in [
            ServerFrame::Snapshot {
                context,
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
                context,
                members: vec![],
            },
            ServerFrame::Joined { context, id: id(3) },
            ServerFrame::Left { context, id: id(3) },
            ServerFrame::Presence {
                context,
                id: id(4),
                blob: Bytes::from_static(b"x"),
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
        assert!(ClientFrame::decode(tag::JOIN, Bytes::from_static(&[0; 15])).is_err());
        assert!(ClientFrame::decode(tag::JOIN, Bytes::from_static(&[0; 17])).is_err());
        assert!(ServerFrame::decode(0x99, Bytes::new()).is_err());
    }

    #[test]
    fn uuid_bytes_are_rfc_order() {
        let context = Uuid::parse_str("00112233-4455-6677-8899-aabbccddeeff").unwrap();
        let encoded = ClientFrame::Join { context }.encode();
        assert_eq!(
            &encoded[5..],
            &hex_bytes("00112233445566778899aabbccddeeff")[..]
        );
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
