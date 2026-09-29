//! KeepTalking SFU: presence rooms plus an embedded iroh relay.
//!
//! The service does two things and nothing else:
//!
//! - **Relay.** An embedded `iroh-relay` server coordinates hole punching
//!   and carries traffic between peers that cannot reach each other directly.
//!   It only ever sees QUIC ciphertext.
//! - **Presence.** A hub iroh endpoint (ALPN [`proto::PRESENCE_ALPN`]) keeps
//!   one room per context: who is in it, and each member's latest opaque
//!   presence blob. Peers learn each other's endpoint ids from those blobs,
//!   which are sealed with the context secret, so the server cannot swap in
//!   its own key.
//!
//! All message, blob and voice traffic goes peer to peer over iroh.

pub mod client;
pub mod proto;
pub mod server;
pub mod tls;
