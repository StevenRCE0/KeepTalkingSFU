//! KeepTalking SFU: a topic-room forwarding service plus an embedded iroh relay.
//!
//! - **Relay.** An embedded `iroh-relay` server coordinates hole punching
//!   and carries traffic between peers that cannot reach each other directly.
//!   It only ever sees QUIC ciphertext.
//! - **SFU.** An iroh endpoint (ALPN [`proto::SFU_ALPN`]) keeps one room per
//!   topic — 32 bytes the clients derive from their context secret, so the
//!   SFU never learns the context. It relays sealed presence blobs (peers
//!   learn each other's endpoint ids from them, so the server cannot swap in
//!   its own key) and fans published payloads and datagrams out to the room,
//!   so a sender in a large room uploads once.
//! - **Info.** `GET /kt/sfu` (behind the proxy) tells clients the SFU id.

pub mod client;
pub mod info;
pub mod proto;
pub mod server;
pub mod tls;
