import Foundation

/// Wire format spoken between SFU peers and the SFU itself. Length-prefixed,
/// type-tagged frames.
///
///   [4-byte BE total length]   total = 1 + body
///   [1-byte type]
///   [body]
///
/// # Type tags
///
///   0x01 CLIENT_HELLO   — peer announces "I exist". Empty body.
///                          Wire-compat marker: under HTTP/2 transport
///                          the server already gets the request HEADERS,
///                          so CLIENT_HELLO is now a no-op on the
///                          server. Kept so the same frame parser works
///                          across any future transport that needs an
///                          explicit "client speaks first" nudge.
///   0x10 HELLO          — peer announces itself: body = pubkey (32) || sig (64)
///                          over the server-supplied challenge nonce.
///   0x11 JOIN           — peer joins a context: body = context UUID (16).
///   0x12 LEAVE          — peer leaves a context: body = context UUID (16).
///   0x13 LIST_PEERS     — request peer list: body = context UUID (16).
///   0x14 PEERS_SNAPSHOT — server reply: body = context UUID (16) ||
///                          UInt16-BE count || N * pubkey (32 each).
///   0x15 PEER_JOINED    — server event: body = context UUID (16) || pubkey (32).
///   0x16 PEER_LEFT      — server event: body = context UUID (16) || pubkey (32).
///   0x20 ROUTE_TO       — unicast envelope. Wire-v2 layout:
///                          dest(32) || sender(32) || channel(1) || sig(64) || envelope...
///                          sig = Ed25519.sign(sender_priv,
///                                  sender || dest || channel || envelope).
///                          Server validates sender == registeredPeerID for the
///                          connection. Receiver verifies sig against sender.
///   0x21 BROADCAST      — context broadcast. Wire-v2 layout:
///                          ctx(16) || sender(32) || channel(1) || sig(64) || envelope...
///                          sig = Ed25519.sign(sender_priv,
///                                  sender || ctx || channel || envelope).
///   0x30 SERVER_HELO    — server's challenge: body = nonce (32).
///   0x31 READY          — server signals the peer is fully registered in
///                          the router and routing to/from it is now safe.
///                          Sent after `router.register` actually completes.
///                          Empty body.
///   0x22 RELAY_OPEN     — opens a virtual relay channel between two peers
///                          co-resident in a context. The SFU forwards
///                          opaque QUIC datagrams between the two endpoints
///                          on this relayID, replacing the external-TURN
///                          fallback for symmetric NAT cases.
///                          Client→Server body: relayID(16) || destPeer(32) || context(16)
///                          Server→Peer body:   relayID(16) || sourcePeer(32) || context(16)
///                          (SFU rewrites the 32-byte peer slot to identify
///                           the other endpoint when forwarding.)
///   0x23 RELAY_DATA     — opaque payload on an open relay.
///                          Body: relayID(16) || payload(...)
///                          The SFU validates relayID is open and that the
///                          sender is one of its endpoints, then forwards
///                          unmodified to the other endpoint.
///   0x24 RELAY_CLOSE    — either side closes a relay. The SFU forwards to
///                          the partner and drops the table entry.
///                          Body: relayID(16) || reason(1)
///   0x3F ERROR          — server-side rejection: body = UTF-8 reason.
///
/// Liveness is intentionally *not* a wire-level concern: it rides on the
/// transport (HTTP/2 PING frames + `IdleStateHandler`) so all carriers
/// inherit it uniformly without proliferating frame types.
///
/// # Channel byte (in ROUTE_TO / BROADCAST)
///
///   0x00 chat        — usually L2-broadcast (context secret AEAD)
///   0x01 blob        — broadcast or pairwise depending on envelope kind
///   0x02 actionCall  — usually L2-pairwise (per-relation key AEAD)
///   0x03 signaling   — trust handshakes / lures (pairwise)
///   0x04 p2pSignal   — SDP/ICE for libjuice direct P2P (pairwise)
///
/// The SFU treats channel as opaque routing-payload metadata — it never
/// dispatches differently by channel today. Receivers use it as a hint
/// to pick the right L2 decryption path.
///
/// The router never inspects bytes past the framing header — `envelope`
/// stays opaque from the SFU's perspective.
public enum SFUFrameType: UInt8, Sendable {
    case clientHello = 0x01
    case hello = 0x10
    case join = 0x11
    case leave = 0x12
    case listPeers = 0x13
    case peersSnapshot = 0x14
    case peerJoined = 0x15
    case peerLeft = 0x16
    case routeTo = 0x20
    case broadcast = 0x21
    case relayOpen = 0x22
    case relayData = 0x23
    case relayClose = 0x24
    case serverHello = 0x30
    case ready = 0x31
    case error = 0x3F
}

/// Channel tag carried in ROUTE_TO and BROADCAST bodies. The receiver uses
/// it to pick which L2 decryption path to attempt; the SFU treats it as
/// opaque. Numeric values are stable wire constants — never reorder.
public enum SFUChannel: UInt8, Sendable, CaseIterable {
    case chat = 0x00
    case blob = 0x01
    case actionCall = 0x02
    case signaling = 0x03
    case p2pSignal = 0x04
}

public enum SFUFrame {
    public static func encode(type: SFUFrameType, body: Data) -> Data {
        var out = Data(capacity: 5 + body.count)
        let total = UInt32(1 + body.count)
        out.append(UInt8((total >> 24) & 0xFF))
        out.append(UInt8((total >> 16) & 0xFF))
        out.append(UInt8((total >> 8) & 0xFF))
        out.append(UInt8(total & 0xFF))
        out.append(type.rawValue)
        out.append(body)
        return out
    }

    public struct Decoded: Sendable {
        public let type: SFUFrameType
        public let body: Data
    }

    public struct Parser: Sendable {
        private var buffer = Data()

        public init() {}

        public mutating func feed(_ chunk: Data) -> [Decoded] {
            buffer.append(chunk)
            var out: [Decoded] = []
            while let frame = takeFrame() { out.append(frame) }
            return out
        }

        private mutating func takeFrame() -> Decoded? {
            guard buffer.count >= 5 else { return nil }
            let len = buffer.withUnsafeBytes { buf -> UInt32 in
                let bytes = buf.bindMemory(to: UInt8.self)
                return (UInt32(bytes[0]) << 24)
                    | (UInt32(bytes[1]) << 16)
                    | (UInt32(bytes[2]) << 8)
                    | UInt32(bytes[3])
            }
            let total = 4 + Int(len)
            guard buffer.count >= total else { return nil }
            let raw = buffer[4]
            let body = buffer.subdata(in: 5..<total)
            buffer.removeSubrange(0..<total)
            guard let type = SFUFrameType(rawValue: raw) else {
                // Unknown frame: skip silently. A noisier policy would
                // close the connection — fine for phase 1.
                return nil
            }
            return Decoded(type: type, body: body)
        }
    }
}

// MARK: - Routed-frame layout (ROUTE_TO / BROADCAST)

/// The signed envelope payload shared by ROUTE_TO and BROADCAST. The
/// "address" varies — destination pubkey for ROUTE_TO, context UUID for
/// BROADCAST — but everything else is identical.
public struct SFURoutedBody: Sendable {
    /// 32-byte destination pubkey (ROUTE_TO) or 16-byte context UUID (BROADCAST).
    /// `address` and `kind` together pin which case this is.
    public enum Address: Sendable {
        case peer(Data)      // 32 bytes
        case context(UUID)   // 16 bytes
    }

    public let address: Address
    public let sender: Data        // 32 bytes
    public let channel: SFUChannel
    public let signature: Data     // 64 bytes
    public let envelope: Data      // opaque AEAD ciphertext

    public init(
        address: Address,
        sender: Data,
        channel: SFUChannel,
        signature: Data,
        envelope: Data
    ) {
        self.address = address
        self.sender = sender
        self.channel = channel
        self.signature = signature
        self.envelope = envelope
    }
}

public enum SFURoutedBodyCodec {
    /// Builds the byte tuple that gets Ed25519-signed.
    /// Always: sender || address-bytes || channel || envelope.
    public static func signingTuple(
        sender: Data,
        address: SFURoutedBody.Address,
        channel: SFUChannel,
        envelope: Data
    ) -> Data {
        var buf = Data(capacity: 32 + 32 + 1 + envelope.count)
        buf.append(sender)
        switch address {
        case .peer(let pubkey):
            buf.append(pubkey)
        case .context(let uuid):
            buf.append(contentsOf: PresenceEncoding.uuidBytes(uuid))
        }
        buf.append(channel.rawValue)
        buf.append(envelope)
        return buf
    }

    public static func encodeRouteTo(_ body: SFURoutedBody) -> Data {
        guard case .peer(let dest) = body.address else {
            preconditionFailure("encodeRouteTo requires peer address")
        }
        var out = Data(capacity: 32 + 32 + 1 + 64 + body.envelope.count)
        out.append(dest)
        out.append(body.sender)
        out.append(body.channel.rawValue)
        out.append(body.signature)
        out.append(body.envelope)
        return out
    }

    public static func encodeBroadcast(_ body: SFURoutedBody) -> Data {
        guard case .context(let cid) = body.address else {
            preconditionFailure("encodeBroadcast requires context address")
        }
        var out = Data(capacity: 16 + 32 + 1 + 64 + body.envelope.count)
        out.append(contentsOf: PresenceEncoding.uuidBytes(cid))
        out.append(body.sender)
        out.append(body.channel.rawValue)
        out.append(body.signature)
        out.append(body.envelope)
        return out
    }

    public static func decodeRouteTo(_ rawBody: Data) -> SFURoutedBody? {
        guard rawBody.count >= 32 + 32 + 1 + 64 else { return nil }
        let base = rawBody.startIndex
        let dest = rawBody.subdata(in: base..<(base + 32))
        let sender = rawBody.subdata(in: (base + 32)..<(base + 64))
        let chanByte = rawBody[base + 64]
        guard let channel = SFUChannel(rawValue: chanByte) else { return nil }
        let signature = rawBody.subdata(in: (base + 65)..<(base + 129))
        let envelope = rawBody.subdata(in: (base + 129)..<rawBody.endIndex)
        return SFURoutedBody(
            address: .peer(dest),
            sender: sender,
            channel: channel,
            signature: signature,
            envelope: envelope
        )
    }

    public static func decodeRelayOpen(_ rawBody: Data) -> SFURelayOpenBody? {
        guard rawBody.count == 16 + 32 + 16 else { return nil }
        let base = rawBody.startIndex
        let relayID = rawBody.subdata(in: base..<(base + 16))
        let peer = rawBody.subdata(in: (base + 16)..<(base + 48))
        let ctx = PresenceEncoding.uuidFrom(rawBody[(base + 48)..<(base + 64)])
        return SFURelayOpenBody(relayID: relayID, peer: peer, context: ctx)
    }

    public static func encodeRelayOpen(_ body: SFURelayOpenBody) -> Data {
        var out = Data(capacity: 64)
        out.append(body.relayID)
        out.append(body.peer)
        out.append(contentsOf: PresenceEncoding.uuidBytes(body.context))
        return out
    }

    public static func decodeRelayData(_ rawBody: Data) -> SFURelayDataBody? {
        guard rawBody.count >= 16 else { return nil }
        let base = rawBody.startIndex
        let relayID = rawBody.subdata(in: base..<(base + 16))
        let payload = rawBody.subdata(in: (base + 16)..<rawBody.endIndex)
        return SFURelayDataBody(relayID: relayID, payload: payload)
    }

    public static func encodeRelayData(_ body: SFURelayDataBody) -> Data {
        var out = Data(capacity: 16 + body.payload.count)
        out.append(body.relayID)
        out.append(body.payload)
        return out
    }

    public static func decodeRelayClose(_ rawBody: Data) -> SFURelayCloseBody? {
        guard rawBody.count == 17 else { return nil }
        let base = rawBody.startIndex
        let relayID = rawBody.subdata(in: base..<(base + 16))
        let reason = rawBody[base + 16]
        return SFURelayCloseBody(relayID: relayID, reason: reason)
    }

    public static func encodeRelayClose(_ body: SFURelayCloseBody) -> Data {
        var out = Data(capacity: 17)
        out.append(body.relayID)
        out.append(body.reason)
        return out
    }

    public static func decodeBroadcast(_ rawBody: Data) -> SFURoutedBody? {
        guard rawBody.count >= 16 + 32 + 1 + 64 else { return nil }
        let base = rawBody.startIndex
        let cid = PresenceEncoding.uuidFrom(rawBody[base..<(base + 16)])
        let sender = rawBody.subdata(in: (base + 16)..<(base + 48))
        let chanByte = rawBody[base + 48]
        guard let channel = SFUChannel(rawValue: chanByte) else { return nil }
        let signature = rawBody.subdata(in: (base + 49)..<(base + 113))
        let envelope = rawBody.subdata(in: (base + 113)..<rawBody.endIndex)
        return SFURoutedBody(
            address: .context(cid),
            sender: sender,
            channel: channel,
            signature: signature,
            envelope: envelope
        )
    }
}

// MARK: - Relay-frame layout (RELAY_OPEN / RELAY_DATA / RELAY_CLOSE)

public struct SFURelayOpenBody: Sendable {
    /// 16-byte client-generated relay identifier. Both endpoints address
    /// the relay by this ID for the lifetime of the session.
    public let relayID: Data
    /// Client→Server: 32-byte destination peer pubkey.
    /// Server→Peer: 32-byte source peer pubkey (rewritten by the SFU).
    public let peer: Data
    /// Context UUID both peers must be co-resident in.
    public let context: UUID

    public init(relayID: Data, peer: Data, context: UUID) {
        self.relayID = relayID
        self.peer = peer
        self.context = context
    }
}

public struct SFURelayDataBody: Sendable {
    public let relayID: Data
    public let payload: Data

    public init(relayID: Data, payload: Data) {
        self.relayID = relayID
        self.payload = payload
    }
}

public struct SFURelayCloseBody: Sendable {
    public let relayID: Data
    /// Reason byte. 0x00 = normal, 0x01 = peer-disconnected,
    /// 0x02 = unauthorized, 0x03 = unknown-relay. Values are advisory.
    public let reason: UInt8

    public init(relayID: Data, reason: UInt8) {
        self.relayID = relayID
        self.reason = reason
    }
}

public enum SFURelayCloseReason {
    public static let normal: UInt8 = 0x00
    public static let peerDisconnected: UInt8 = 0x01
    public static let unauthorized: UInt8 = 0x02
    public static let unknownRelay: UInt8 = 0x03
}

