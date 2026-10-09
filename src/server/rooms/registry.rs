//! Rooms: membership per topic, sharded, and the fan-out of session events,
//! DELIVERs and datagram targets to members.

use std::{
    collections::HashMap,
    sync::{Mutex, MutexGuard},
};

use bytes::Bytes;
use iroh::{EndpointId, endpoint::Connection};

use crate::proto::{Lane, Member, ServerFrame, Topic, snapshot_wire_len};
use crate::server::{
    Limits,
    data_channels::queues::{Deliver, MemberHandle, SessionItem},
};

/// Room shards; topics are uniformly random, so any byte picks a shard.
const SHARDS: usize = 64;

struct Slot {
    handle: MemberHandle,
    blob: Bytes,
}

type Room = HashMap<EndpointId, Slot>;

/// Why a publish was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    NotSubscribed,
    NoSuchRecipient,
}

/// Rooms keyed by topic, members keyed by endpoint id, sharded by topic.
/// Every membership change and the frames it causes are queued under the
/// room's shard lock, so each client sees a room's session events in a
/// consistent order (snapshot first). Frames are encoded before taking the
/// lock (a snapshot by the receiving writer) and nothing logs under it.
pub(crate) struct Rooms {
    shards: Box<[Mutex<HashMap<Topic, Room>>]>,
    max_members: usize,
    chunk_entries: usize,
}

impl Rooms {
    pub(crate) fn new(limits: &Limits) -> Self {
        Self {
            shards: (0..SHARDS).map(|_| Mutex::default()).collect(),
            max_members: limits.max_members_per_topic.max(1),
            chunk_entries: limits.snapshot_chunk_entries.max(1),
        }
    }

    fn shard(&self, topic: &Topic) -> MutexGuard<'_, HashMap<Topic, Room>> {
        let index = usize::from(u16::from_le_bytes([topic.0[0], topic.0[1]])) % SHARDS;
        self.shards[index].lock().expect("rooms lock")
    }

    /// Adds the connection to the room and queues its snapshot. Returns the
    /// new room size, or `None` (changing nothing) if the room is full.
    pub(crate) fn join(&self, topic: Topic, handle: &MemberHandle) -> Option<usize> {
        let joined = ServerFrame::Joined {
            topic,
            id: handle.peer,
        }
        .encode();
        let mut shard = self.shard(&topic);
        let room = shard.entry(topic).or_default();
        // A newer connection from the same endpoint takes its slot over;
        // that does not grow the room. (A new room is never full: the limit
        // is at least 1.)
        if !room.contains_key(&handle.peer) && room.len() >= self.max_members {
            return None;
        }
        room.insert(
            handle.peer,
            Slot {
                handle: handle.clone(),
                blob: Bytes::new(),
            },
        );
        let members: Vec<Member> = room
            .iter()
            .filter(|(id, _)| **id != handle.peer)
            .map(|(id, slot)| Member {
                id: *id,
                blob: slot.blob.clone(),
            })
            .collect();
        let size = snapshot_wire_len(&members, self.chunk_entries);
        handle.push_session(SessionItem::Snapshot { topic, members }, size);
        broadcast(room, handle.peer, &joined);
        Some(room.len())
    }

    /// Removes the connection's slot (if it still owns it) and tells the
    /// room. Returns the remaining size if it left.
    pub(crate) fn leave(&self, topic: Topic, handle: &MemberHandle) -> Option<usize> {
        let left = ServerFrame::Left {
            topic,
            id: handle.peer,
        }
        .encode();
        let mut shard = self.shard(&topic);
        let room = shard.get_mut(&topic)?;
        // Only the connection that owns the slot may vacate it.
        if !owns_slot(room, handle) {
            return None;
        }
        room.remove(&handle.peer);
        broadcast(room, handle.peer, &left);
        let size = room.len();
        if size == 0 {
            shard.remove(&topic);
        }
        Some(size)
    }

    /// Stores the blob and relays it as PRESENCE. False if the connection
    /// no longer owns its slot.
    pub(crate) fn announce(&self, topic: Topic, handle: &MemberHandle, blob: Bytes) -> bool {
        let presence = ServerFrame::Presence {
            topic,
            id: handle.peer,
            blob: blob.clone(),
        }
        .encode();
        let mut shard = self.shard(&topic);
        let Some(room) = shard.get_mut(&topic) else {
            return false;
        };
        match room.get_mut(&handle.peer) {
            Some(slot) if slot.handle.conn_id == handle.conn_id => slot.blob = blob,
            _ => return false,
        }
        broadcast(room, handle.peer, &presence);
        true
    }

    /// Whether the connection holds its slot in the topic's room.
    pub(crate) fn is_member(&self, topic: Topic, handle: &MemberHandle) -> bool {
        self.shard(&topic)
            .get(&topic)
            .is_some_and(|room| owns_slot(room, handle))
    }

    /// Queues the DELIVER on `lane` for every other member; returns how many
    /// members it reached.
    pub(crate) fn publish(
        &self,
        topic: Topic,
        handle: &MemberHandle,
        lane: Lane,
        frame: &Deliver,
    ) -> Result<usize, Refusal> {
        let shard = self.shard(&topic);
        let room = shard
            .get(&topic)
            .filter(|room| owns_slot(room, handle))
            .ok_or(Refusal::NotSubscribed)?;
        let mut sent = 0;
        for (id, slot) in room {
            if *id != handle.peer {
                slot.handle.deliver(lane, frame);
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// Queues the DELIVER on `lane` for `recipient` alone, if it is another
    /// member of the room.
    pub(crate) fn publish_to(
        &self,
        topic: Topic,
        handle: &MemberHandle,
        recipient: EndpointId,
        lane: Lane,
        frame: &Deliver,
    ) -> Result<usize, Refusal> {
        let shard = self.shard(&topic);
        let room = shard
            .get(&topic)
            .filter(|room| owns_slot(room, handle))
            .ok_or(Refusal::NotSubscribed)?;
        if recipient == handle.peer {
            return Err(Refusal::NoSuchRecipient);
        }
        let slot = room.get(&recipient).ok_or(Refusal::NoSuchRecipient)?;
        slot.handle.deliver(lane, frame);
        Ok(1)
    }

    /// Connections of the room's other members, if `handle` is subscribed.
    pub(crate) fn datagram_targets(
        &self,
        topic: Topic,
        handle: &MemberHandle,
    ) -> Option<Vec<Connection>> {
        let shard = self.shard(&topic);
        let room = shard.get(&topic)?;
        if !owns_slot(room, handle) {
            return None;
        }
        Some(
            room.iter()
                .filter(|(id, _)| **id != handle.peer)
                .map(|(_, slot)| slot.handle.conn.clone())
                .collect(),
        )
    }

    pub(crate) fn members(&self, topic: Topic) -> Vec<EndpointId> {
        self.shard(&topic)
            .get(&topic)
            .map(|room| room.keys().copied().collect())
            .unwrap_or_default()
    }

    pub(crate) fn occupancy(&self) -> (usize, usize) {
        self.shards.iter().fold((0, 0), |(rooms, members), shard| {
            let shard = shard.lock().expect("rooms lock");
            (
                rooms + shard.len(),
                members + shard.values().map(HashMap::len).sum::<usize>(),
            )
        })
    }
}

fn owns_slot(room: &Room, handle: &MemberHandle) -> bool {
    room.get(&handle.peer)
        .is_some_and(|slot| slot.handle.conn_id == handle.conn_id)
}

/// Queues `frame` on the session stream of everyone in `room` but `except`.
fn broadcast(room: &Room, except: EndpointId, frame: &Bytes) {
    for (id, slot) in room {
        if *id != except {
            slot.handle.push_frame(frame.clone());
        }
    }
}
