//! KeepTalking SFU: a hub plus an embedded iroh relay.
//!
//! - **Relay.** An embedded `iroh-relay` server coordinates hole punching
//!   and carries traffic between peers that cannot reach each other directly.
//!   It only ever sees QUIC ciphertext.
//! - **Hub.** An iroh endpoint (ALPN [`proto::HUB_ALPN`]) keeps one room per
//!   topic — 32 bytes the clients derive from their context secret, so the
//!   hub never learns the context. It relays sealed presence blobs (peers
//!   learn each other's endpoint ids from them, so the server cannot swap in
//!   its own key) and fans published payloads and datagrams out to the room,
//!   so a sender in a large room uploads once.
//! - **Info.** `GET /kt/hub` (behind the proxy) tells clients the hub id.

pub mod client;
pub mod info;
pub mod proto;
pub mod server;
pub mod tls;
