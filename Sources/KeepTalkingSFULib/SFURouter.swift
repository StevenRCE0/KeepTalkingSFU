import Foundation
import KeepTalkingSFUProtocol
import Logging

/// In-memory SFU routing core. Decoupled from transport so the same logic
/// can be exercised in unit tests with stubbed peer handles.
///
/// Semantics: each peer connects with an opaque `peerID` (Ed25519 pubkey)
/// and joins zero or more `contextID`s. Each inbound frame carries the
/// destination peer ID; the router looks it up and forwards opaquely.
/// The router never decrypts; it just shuffles bytes by address.
///
/// Concurrency: the router is an `actor` so all mutations of the peer
/// table serialize. Peer handle work (sending bytes) happens off-actor
/// via the handle's own `send` closure.
public actor SFURouter {
    public typealias PeerID = Data
    public typealias ContextID = UUID

    /// Abstract handle to a peer connection. Concrete transports plug in
    /// their own `send` implementation; the router doesn't care whether
    /// the bytes go out over Network.framework QUIC, NIO, or a test stub.
    public struct PeerHandle: Sendable {
        public let id: PeerID
        public let sessionID: UUID
        public let sendFrame: @Sendable (Data) async -> Void
        public let closeReason: @Sendable (String) async -> Void

        public init(
            id: PeerID,
            sessionID: UUID = UUID(),
            sendFrame: @Sendable @escaping (Data) async -> Void,
            closeReason: @Sendable @escaping (String) async -> Void
        ) {
            self.id = id
            self.sessionID = sessionID
            self.sendFrame = sendFrame
            self.closeReason = closeReason
        }
    }

    public enum RouteError: Error, Sendable {
        case unknownDestination
    }

    /// Identifier for a relay session. Client-generated 16-byte token,
    /// scoped to the opener; the router uses (opener, relayID) as the
    /// table key to avoid collisions across opening peers.
    public struct RelayKey: Hashable, Sendable {
        public let opener: PeerID
        public let relayID: Data
        public init(opener: PeerID, relayID: Data) {
            self.opener = opener
            self.relayID = relayID
        }
    }

    public struct RelayEntry: Sendable {
        /// The peer that issued RELAY_OPEN.
        public let opener: PeerID
        /// The peer the opener requested to talk to.
        public let target: PeerID
        public let context: ContextID
    }

    public enum RelayOpenError: Error, Sendable {
        case targetNotInContext
        case openerNotInContext
        case unknownTarget
        case duplicateRelay
    }

    public enum RelayForwardError: Error, Sendable {
        case unknownRelay
        case unauthorized
    }

    private let log: Logger
    private var peers: [PeerID: PeerHandle] = [:]
    private var contextMembers: [ContextID: Set<PeerID>] = [:]
    /// Active relays keyed by (opener, relayID). Looked up from either
    /// endpoint's perspective via `findRelay`.
    private var relays: [RelayKey: RelayEntry] = [:]

    public init(log: Logger = Logger(label: "kt.sfu.router")) {
        self.log = log
    }

    // MARK: - Registration

    /// Registers a peer, **kicking any prior session with the same
    /// pubkey**. This is the "last-write-wins" semantics: a client that
    /// reconnects (e.g. after `Close → Start` in the lab, or after a
    /// network drop where the old QUIC connection hasn't fully torn
    /// down) immediately supersedes its previous session. The old
    /// session is asked to close via `closeReason`, then dropped from
    /// the router; context memberships transfer to the new session so
    /// presence stays continuous from the perspective of other peers.
    public func register(peer: PeerHandle) async {
        let prior = peers.updateValue(peer, forKey: peer.id)
        if let prior, prior.sessionID != peer.sessionID {
            log.info("kicking prior session for peer id=\(peer.id.shortHex)")
            // Install the replacement before closing the prior stream.
            // Its delayed channelInactive can then be identified as stale
            // and cannot unregister this new session.
            await prior.closeReason("superseded by new session")
        }
        log.info("peer registered id=\(peer.id.shortHex)")
    }

    /// Removes `peerID` only when the disconnect belongs to the currently
    /// registered transport session. Returns the contexts that lost the peer,
    /// or `nil` when a superseded stream reported a late disconnect.
    @discardableResult
    public func unregister(peerID: PeerID, sessionID: UUID) async -> [ContextID]? {
        guard peers[peerID]?.sessionID == sessionID else { return nil }
        peers.removeValue(forKey: peerID)
        let contexts = contexts(of: peerID)
        for cid in contexts {
            guard var members = contextMembers[cid] else { continue }
            members.remove(peerID)
            if members.isEmpty {
                contextMembers.removeValue(forKey: cid)
            } else {
                contextMembers[cid] = members
            }
        }
        await closeRelaysReferencing(
            peerID,
            reason: SFURelayCloseReason.peerDisconnected
        )
        log.info("peer unregistered id=\(peerID.shortHex)")
        return contexts
    }

    /// Administrative removal of whichever session is currently registered.
    public func unregister(peerID: PeerID) async {
        guard let sessionID = peers[peerID]?.sessionID else { return }
        await unregister(peerID: peerID, sessionID: sessionID)
    }

    // MARK: - Context membership

    public func join(peerID: PeerID, context: ContextID) {
        guard peers[peerID] != nil else { return }
        contextMembers[context, default: []].insert(peerID)
        log.info("peer=\(peerID.shortHex) joined context=\(context)")
    }

    public func leave(peerID: PeerID, context: ContextID) {
        guard var members = contextMembers[context] else { return }
        members.remove(peerID)
        if members.isEmpty {
            contextMembers.removeValue(forKey: context)
        } else {
            contextMembers[context] = members
        }
        log.info("peer=\(peerID.shortHex) left context=\(context)")
    }

    // MARK: - Routing

    /// Unicast: forward an opaque envelope to a specific destination peer.
    public func route(frame: Data, to destination: PeerID) async throws {
        guard let target = peers[destination] else {
            throw RouteError.unknownDestination
        }
        await target.sendFrame(frame)
    }

    /// Multicast: broadcast a frame to every member of a context except
    /// the sender. The router stays oblivious to the payload — it only
    /// knows membership.
    public func broadcast(frame: Data, context: ContextID, excluding sender: PeerID) async {
        guard let members = contextMembers[context] else { return }
        for memberID in members where memberID != sender {
            if let handle = peers[memberID] {
                await handle.sendFrame(frame)
            }
        }
    }

    // MARK: - Relay

    /// Opens a virtual relay between `opener` and `target` inside `context`.
    /// Both must be currently joined to the context. On success the SFU
    /// forwards a RELAY_OPEN frame to the target (with opener as the peer
    /// field) — the caller passes that frame in via `targetNotificationFrame`.
    public func openRelay(
        opener: PeerID,
        relayID: Data,
        target: PeerID,
        context: ContextID,
        targetNotificationFrame: Data
    ) async throws {
        guard let members = contextMembers[context] else {
            throw RelayOpenError.openerNotInContext
        }
        guard members.contains(opener) else {
            throw RelayOpenError.openerNotInContext
        }
        guard members.contains(target) else {
            throw RelayOpenError.targetNotInContext
        }
        guard let targetHandle = peers[target] else {
            throw RelayOpenError.unknownTarget
        }
        let key = RelayKey(opener: opener, relayID: relayID)
        guard relays[key] == nil else {
            throw RelayOpenError.duplicateRelay
        }
        relays[key] = RelayEntry(opener: opener, target: target, context: context)
        await targetHandle.sendFrame(targetNotificationFrame)
        log.info("relay opened opener=\(opener.shortHex) target=\(target.shortHex) ctx=\(context)")
    }

    /// Forwards a RELAY_DATA payload. The caller has already decoded the
    /// frame to extract relayID and payload; this method resolves the
    /// other endpoint and re-emits the frame. `sender` must be one of the
    /// relay's endpoints.
    public func forwardRelayData(
        relayID: Data,
        sender: PeerID,
        frameToForward: Data
    ) async throws {
        guard let (_, entry) = findRelay(relayID: relayID, participant: sender) else {
            throw RelayForwardError.unknownRelay
        }
        let other = (sender == entry.opener) ? entry.target : entry.opener
        guard let handle = peers[other] else {
            throw RelayForwardError.unknownRelay
        }
        await handle.sendFrame(frameToForward)
    }

    /// Closes a relay and forwards a RELAY_CLOSE frame to the partner.
    public func closeRelay(
        relayID: Data,
        sender: PeerID,
        frameToForward: Data
    ) async throws {
        guard let (key, entry) = findRelay(relayID: relayID, participant: sender) else {
            throw RelayForwardError.unknownRelay
        }
        let other = (sender == entry.opener) ? entry.target : entry.opener
        relays.removeValue(forKey: key)
        if let handle = peers[other] {
            await handle.sendFrame(frameToForward)
        }
        log.info("relay closed relayID=\(relayID.shortHex) by=\(sender.shortHex)")
    }

    private func findRelay(relayID: Data, participant: PeerID) -> (RelayKey, RelayEntry)? {
        for (key, entry) in relays {
            guard entry.opener == participant || entry.target == participant else { continue }
            // From the opener's side, key.relayID == relayID directly.
            // From the target's side, the target's view of the relayID
            // matches what the opener picked — we forwarded it unchanged.
            if key.relayID == relayID {
                return (key, entry)
            }
        }
        return nil
    }

    private func closeRelaysReferencing(_ peer: PeerID, reason: UInt8) async {
        let affected = relays.filter { $0.value.opener == peer || $0.value.target == peer }
        for (key, entry) in affected {
            relays.removeValue(forKey: key)
            let other = (peer == entry.opener) ? entry.target : entry.opener
            guard let handle = peers[other] else { continue }
            let frame = SFUFrame.encode(
                type: .relayClose,
                body: SFURoutedBodyCodec.encodeRelayClose(
                    SFURelayCloseBody(relayID: key.relayID, reason: reason)
                )
            )
            await handle.sendFrame(frame)
        }
    }

    // MARK: - Presence queries

    /// Snapshot of pubkeys currently joined to `context`. Sorted for
    /// deterministic test output.
    public func members(in context: ContextID) -> [PeerID] {
        guard let members = contextMembers[context] else { return [] }
        return members.sorted { $0.lexicographicallyPrecedes($1) }
    }

    /// Contexts the given peer is a member of. Used during disconnect to
    /// know whom to send PEER_LEFT events to.
    public func contexts(of peer: PeerID) -> [ContextID] {
        contextMembers.compactMap { (cid, members) -> ContextID? in
            members.contains(peer) ? cid : nil
        }
    }

    public func handle(for peer: PeerID) -> PeerHandle? {
        peers[peer]
    }

    // MARK: - Diagnostics

    public func stats() -> Stats {
        Stats(
            peerCount: peers.count,
            contextCount: contextMembers.count,
            membershipPairs: contextMembers.values.reduce(0) { $0 + $1.count }
        )
    }

    public struct Stats: Sendable, Equatable {
        public let peerCount: Int
        public let contextCount: Int
        public let membershipPairs: Int
    }
}

extension Data {
    /// Short hex prefix for log lines — never the full key.
    var shortHex: String {
        let prefix = prefix(4)
        return prefix.map { String(format: "%02x", $0) }.joined()
    }
}
