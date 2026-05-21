import Foundation

/// Wire encoding helpers for the SFU's presence frames (PEER_JOINED,
/// PEER_LEFT, PEERS_SNAPSHOT, LIST_PEERS). Kept separate from `SFUFrame`
/// so both sides of the connection share an authoritative codec —
/// hand-rolling these in two places is how PoCs break later.
public enum PresenceEncoding {
    /// Body shared by PEER_JOINED and PEER_LEFT:
    ///   [context UUID (16)] [pubkey (32)]
    public static func contextPeer(cid: UUID, pubkey: Data) -> Data {
        precondition(pubkey.count == 32, "pubkey must be 32 bytes")
        var out = Data(capacity: 16 + 32)
        out.append(contentsOf: uuidBytes(cid))
        out.append(pubkey)
        return out
    }

    public static func decodeContextPeer(_ body: Data) -> (cid: UUID, pubkey: Data)? {
        guard body.count == 48 else { return nil }
        let cid = uuidFrom(body.prefix(16))
        let pubkey = Data(body.suffix(32))
        return (cid, pubkey)
    }

    /// PEERS_SNAPSHOT body:
    ///   [context UUID (16)] [UInt16-BE count] [count * pubkey (32)]
    public static func snapshot(cid: UUID, peers: [Data]) -> Data {
        let count = UInt16(min(peers.count, Int(UInt16.max)))
        var out = Data(capacity: 16 + 2 + 32 * peers.count)
        out.append(contentsOf: uuidBytes(cid))
        out.append(UInt8((count >> 8) & 0xFF))
        out.append(UInt8(count & 0xFF))
        for p in peers.prefix(Int(count)) {
            precondition(p.count == 32, "snapshot pubkey must be 32 bytes")
            out.append(p)
        }
        return out
    }

    public static func decodeSnapshot(_ body: Data) -> (cid: UUID, peers: [Data])? {
        guard body.count >= 18 else { return nil }
        let cid = uuidFrom(body.prefix(16))
        let count = Int((UInt16(body[body.startIndex + 16]) << 8) | UInt16(body[body.startIndex + 17]))
        let expectedTotal = 18 + count * 32
        guard body.count >= expectedTotal else { return nil }
        var peers: [Data] = []
        peers.reserveCapacity(count)
        let base = body.startIndex + 18
        for i in 0..<count {
            let start = base + i * 32
            peers.append(Data(body[start..<(start + 32)]))
        }
        return (cid, peers)
    }

    // MARK: - UUID helpers

    public static func uuidBytes(_ uuid: UUID) -> [UInt8] {
        let t = uuid.uuid
        return [t.0, t.1, t.2, t.3, t.4, t.5, t.6, t.7,
                t.8, t.9, t.10, t.11, t.12, t.13, t.14, t.15]
    }

    static func uuidFrom<C: Collection>(_ collection: C) -> UUID where C.Element == UInt8 {
        var bytes = (UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
                     UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0))
        withUnsafeMutableBytes(of: &bytes) { buf in
            for (i, byte) in collection.enumerated() where i < 16 {
                buf[i] = byte
            }
        }
        return UUID(uuid: bytes)
    }
}
