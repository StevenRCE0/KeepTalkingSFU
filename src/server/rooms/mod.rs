//! Rooms and presence: one room per topic, joined and left over each
//! connection's session stream, which also carries the room's snapshots,
//! JOINED/LEFT events and relayed presence blobs.

pub(crate) mod registry;
pub(crate) mod session;
pub(crate) mod session_writer;
