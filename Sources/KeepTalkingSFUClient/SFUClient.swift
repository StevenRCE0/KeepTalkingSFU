import Crypto
import Foundation
import KeepTalkingSFUProtocol
import Logging
import NIOCore
import NIOFoundationCompat
import NIOHPACK
import NIOHTTP2
import NIOPosix
@preconcurrency import NIOSSL

/// Client-side counterpart to `SFUHTTP2Server`. Opens a long-lived
/// bidirectional HTTP/2 stream (POST /sfu) to the SFU over TLS, performs
/// the Ed25519 challenge-response auth, then exposes unicast
/// (`route(to:)`) and broadcast (`broadcast(context:)`) sends.
///
/// The client never knows or cares what's inside an envelope — it just
/// hands opaque bytes to the SFU with a destination tag, and surfaces
/// inbound bytes via `onEnvelope`.
public final class SFUClient: @unchecked Sendable {
    public struct Configuration: Sendable {
        public var host: String
        public var port: Int
        public var alpn: String
        /// When `true`, the TLS verifier accepts any server certificate.
        /// Lab mode — relies on the SFU presenting the bundled lab cert.
        public var trustAnyServerCert: Bool

        public init(
            host: String,
            port: Int = 9701,
            alpn: String = "h2",
            trustAnyServerCert: Bool = true
        ) {
            self.host = host
            self.port = port
            self.alpn = alpn
            self.trustAnyServerCert = trustAnyServerCert
        }
    }

    public enum State: Sendable, Equatable {
        case idle
        case connecting
        case authenticating
        case ready
        case failed(String)
        case closed
    }

    /// Inbound envelope as carried by ROUTE_TO / BROADCAST.
    public struct InboundEnvelope: Sendable {
        public let bytes: Data
        public let context: UUID?
        public let sender: Data
        public let channel: SFUChannel
    }

    // MARK: - Public surface

    public var onState: (@Sendable (State) -> Void)?
    public var onEnvelope: (@Sendable (InboundEnvelope) -> Void)?
    public var onLog: (@Sendable (String) -> Void)?
    public var onPresence: (@Sendable (PresenceEvent) -> Void)?
    public var onRelayOpen:
        (@Sendable (_ relayID: Data, _ peer: Data, _ context: UUID) -> Void)?
    public var onRelayData:
        (@Sendable (_ relayID: Data, _ payload: Data) -> Void)?
    public var onRelayClose:
        (@Sendable (_ relayID: Data, _ reason: UInt8) -> Void)?

    public enum PresenceEvent: Sendable {
        case snapshot(context: UUID, peers: [Data])
        case joined(context: UUID, pubkey: Data)
        case left(context: UUID, pubkey: Data)
    }

    public var state: State {
        stateLock.lock()
        defer { stateLock.unlock() }
        return stateStorage
    }

    // MARK: - Storage

    private let configuration: Configuration
    public let signingKey: Curve25519.Signing.PrivateKey
    public let publicKey: Data
    private let log: Logger
    private let stateLock = NSLock()
    private var stateStorage: State = .idle
    private var connectionGeneration: UInt64 = 0

    /// NIO plumbing. `eventLoopGroup` is owned, shut down on `close()`.
    private var eventLoopGroup: MultiThreadedEventLoopGroup?
    /// Bootstrap attempt retained so shutdown can close it before its group.
    private var connectionAttempt: EventLoopFuture<Channel>?
    /// The parent (connection-level) channel.
    private var connectionChannel: Channel?
    /// The per-stream channel created via the HTTP/2 multiplexer.
    private var streamChannel: Channel?

    private var parser = SFUFrame.Parser()
    private var pendingFrames: [Data] = []
    private var pendingContextSubscriptions: [(context: UUID, isJoin: Bool)] =
        []
    private var didAuth = false

    /// Liveness knobs. The HTTP/2 layer drives this — `IdleStateHandler`
    /// declares the connection dead if no inbound bytes arrive for
    /// `livenessDeadline`, and a connection-level HTTP/2 PING goes out
    /// every `pingInterval` to keep the path warm.
    public var pingInterval: TimeAmount = .seconds(15)
    public var livenessDeadline: TimeAmount = .seconds(45)

    public init(
        configuration: Configuration,
        signingKey: Curve25519.Signing.PrivateKey = .init(),
        log: Logger = Logger(label: "kt.sfu.client")
    ) {
        self.configuration = configuration
        self.signingKey = signingKey
        self.publicKey = signingKey.publicKey.rawRepresentation
        self.log = log
    }

    public func connect() {
        stateLock.lock()
        let previousState = stateStorage
        guard previousState == .idle || previousState == .closed else {
            stateLock.unlock()
            log.warning("connect() called in state=\(previousState)")
            return
        }
        connectionGeneration &+= 1
        let generation = connectionGeneration
        stateStorage = .connecting
        stateLock.unlock()
        onState?(.connecting)

        let tlsConfig = makeClientTLSConfig()
        let sslContext: NIOSSLContext
        do {
            sslContext = try NIOSSLContext(configuration: tlsConfig)
        } catch {
            markFailed("tls config: \(error)", generation: generation)
            return
        }

        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let host = configuration.host
        let port = configuration.port
        let alpn = configuration.alpn
        let weakSelf = WeakBox(self)

        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            // OS-level keepalive so a silently-dead SFU connection
            // (Wi-Fi handoff, server crash without RST) eventually
            // surfaces as a closed channel instead of a hung stream.
            .channelOption(ChannelOptions.socketOption(.so_keepalive), value: 1)
            .channelInitializer { channel in
                // Connection-level death observer. Stream-level events
                // can miss abrupt drops; this catches everything.
                channel.closeFuture.whenComplete { _ in
                    weakSelf.value?.handleConnectionLost(
                        reason: "channel closed",
                        generation: generation
                    )
                }
                let sslHandler: NIOSSLClientHandler
                do {
                    sslHandler = try NIOSSLClientHandler(
                        context: sslContext,
                        serverHostname: Self.serverHostnameForTLS(host)
                    )
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
                do {
                    try channel.pipeline.syncOperations.addHandler(sslHandler)
                    // Application-level liveness — sees decrypted byte
                    // activity from SSL and emits HTTP/2 PINGs on idle.
                    // Sits before the HTTP/2 stack so it observes raw
                    // inbound bytes (including auto-ACKed PING replies)
                    // and stays transport-agnostic.
                    try channel.pipeline.syncOperations.addHandler(
                        HTTP2KeepAliveHandler(
                            pingInterval: weakSelf.value?.pingInterval ?? .seconds(15),
                            readDeadline: weakSelf.value?.livenessDeadline ?? .seconds(45)
                        )
                    )
                } catch {
                    return channel.eventLoop.makeFailedFuture(error)
                }
                return channel.configureHTTP2Pipeline(mode: .client) { _ in
                    // Server-initiated streams are unexpected from the
                    // SFU; drop them on the floor.
                    channel.eventLoop.makeSucceededVoidFuture()
                }.map { _ in () }
            }

        emit("connecting host=\(host):\(port) alpn=\(alpn)")
        stateLock.lock()
        guard connectionGeneration == generation else {
            stateLock.unlock()
            Self.shutdown(group)
            return
        }
        eventLoopGroup = group
        let attempt = bootstrap.connect(host: host, port: port)
        connectionAttempt = attempt
        stateLock.unlock()
        attempt.whenComplete { result in
            switch result {
            case .success(let channel):
                weakSelf.value?.handleConnectionReady(
                    channel: channel,
                    generation: generation
                )
            case .failure(let err):
                weakSelf.value?.markFailed(
                    "connect: \(err.localizedDescription)",
                    generation: generation
                )
            }
        }
    }

    public func close() {
        stateLock.lock()
        connectionGeneration &+= 1
        let stream = streamChannel
        let parent = connectionChannel
        let attempt = connectionAttempt
        let group = eventLoopGroup
        streamChannel = nil
        connectionChannel = nil
        connectionAttempt = nil
        eventLoopGroup = nil
        pendingFrames.removeAll()
        pendingContextSubscriptions.removeAll()
        didAuth = false
        stateStorage = .closed
        stateLock.unlock()

        guard let group else {
            onState?(.closed)
            emit("closed")
            return
        }
        stream?.close(promise: nil)
        if let parent {
            parent.close().whenComplete { _ in
                Self.shutdown(group)
            }
        } else if let attempt {
            attempt.whenComplete { result in
                switch result {
                case .success(let channel):
                    channel.close().whenComplete { _ in
                        Self.shutdown(group)
                    }
                case .failure:
                    Self.shutdown(group)
                }
            }
        } else {
            Self.shutdown(group)
        }
        onState?(.closed)
        emit("closed")
    }

    /// Joins a context (the SFU starts broadcasting context messages to us).
    public func join(context: UUID) {
        stateLock.lock()
        if didAuth, streamChannel != nil {
            stateLock.unlock()
            sendImmediate(
                SFUFrame.encode(type: .join, body: Self.uuidBytes(context))
            )
        } else {
            pendingContextSubscriptions.append((context, true))
            stateLock.unlock()
        }
    }

    public func leave(context: UUID) {
        stateLock.lock()
        if didAuth, streamChannel != nil {
            stateLock.unlock()
            sendImmediate(
                SFUFrame.encode(type: .leave, body: Self.uuidBytes(context))
            )
        } else {
            pendingContextSubscriptions.append((context, false))
            stateLock.unlock()
        }
    }

    public func route(
        envelope: Data,
        to destination: Data,
        channel: SFUChannel = .chat
    ) {
        precondition(
            destination.count == 32,
            "destination must be 32-byte ed25519 pubkey"
        )
        let routed = makeRoutedBody(
            address: .peer(destination),
            channel: channel,
            envelope: envelope
        )
        send(type: .routeTo, body: SFURoutedBodyCodec.encodeRouteTo(routed))
    }

    public func broadcast(
        envelope: Data,
        context: UUID,
        channel: SFUChannel = .chat
    ) {
        let routed = makeRoutedBody(
            address: .context(context),
            channel: channel,
            envelope: envelope
        )
        send(type: .broadcast, body: SFURoutedBodyCodec.encodeBroadcast(routed))
    }

    public func listPeers(context: UUID) {
        send(type: .listPeers, body: Data(PresenceEncoding.uuidBytes(context)))
    }

    // MARK: - Relay

    @discardableResult
    public func openRelay(to peer: Data, context: UUID) -> Data {
        precondition(peer.count == 32, "peer must be 32-byte ed25519 pubkey")
        let relayID = Self.makeRelayID()
        let body = SFURoutedBodyCodec.encodeRelayOpen(
            SFURelayOpenBody(relayID: relayID, peer: peer, context: context)
        )
        send(type: .relayOpen, body: body)
        return relayID
    }

    public func sendRelayData(_ payload: Data, on relayID: Data) {
        precondition(relayID.count == 16, "relayID must be 16 bytes")
        let body = SFURoutedBodyCodec.encodeRelayData(
            SFURelayDataBody(relayID: relayID, payload: payload)
        )
        send(type: .relayData, body: body)
    }

    public func closeRelay(
        _ relayID: Data,
        reason: UInt8 = SFURelayCloseReason.normal
    ) {
        precondition(relayID.count == 16, "relayID must be 16 bytes")
        let body = SFURoutedBodyCodec.encodeRelayClose(
            SFURelayCloseBody(relayID: relayID, reason: reason)
        )
        send(type: .relayClose, body: body)
    }

    // MARK: - Connection plumbing

    private func makeClientTLSConfig() -> TLSConfiguration {
        var config = TLSConfiguration.makeClientConfiguration()
        config.applicationProtocols = [configuration.alpn]
        config.minimumTLSVersion = .tlsv12
        if configuration.trustAnyServerCert {
            config.certificateVerification = .none
        }
        return config
    }

    /// NIOSSL's hostname matcher rejects bare IPs and complains on
    /// numeric hosts. For the lab profile (trustAny) we just pass any
    /// arbitrary hostname; SNI still gets set.
    private static func serverHostnameForTLS(_ host: String) -> String? {
        // If host parses as IPv4/IPv6 we pass nil — NIOSSL skips SNI then.
        if host.contains(":") { return nil }  // crude IPv6 sniff
        if host.allSatisfy({ "0123456789.".contains($0) }) { return nil }
        return host
    }

    private func handleConnectionReady(
        channel: Channel,
        generation: UInt64
    ) {
        stateLock.lock()
        guard connectionGeneration == generation else {
            stateLock.unlock()
            channel.close(promise: nil)
            return
        }
        connectionAttempt = nil
        connectionChannel = channel
        stateLock.unlock()
        let host = configuration.host
        let weakSelf = WeakBox(self)

        // Open one bidirectional HTTP/2 stream and wire SFUFrame plumbing.
        // We're inside whatever event loop the connect future completed
        // on — hop onto the channel's event loop before reaching for the
        // multiplexer.
        channel.eventLoop.execute {
            channel.pipeline.handler(type: HTTP2StreamMultiplexer.self)
                .whenComplete { result in
                    switch result {
                    case .failure(let err):
                        weakSelf.value?.markFailed(
                            "multiplexer lookup: \(err)",
                            generation: generation
                        )
                    case .success(let mux):
                        weakSelf.value?.openClientStream(
                            via: mux,
                            host: host,
                            generation: generation
                        )
                    }
                }
        }
    }

    private func openClientStream(
        via mux: HTTP2StreamMultiplexer,
        host: String,
        generation: UInt64
    ) {
        let weakSelf = WeakBox(self)
        mux.createStreamChannel { streamChannel in
            let handler = SFUClientStreamHandler(
                onFrame: { [weakSelf] frame in
                    weakSelf.value?.handle(
                        frame: frame,
                        generation: generation
                    )
                },
                onClose: { [weakSelf] reason in
                    weakSelf.value?.handleStreamClosed(
                        reason: reason,
                        generation: generation
                    )
                }
            )
            return streamChannel.pipeline.addHandler(handler).flatMap {
                guard weakSelf.value?.installStream(
                    streamChannel,
                    generation: generation
                ) == true else {
                    return streamChannel.close()
                }
                weakSelf.value?.kickoffStream(
                    streamChannel: streamChannel,
                    host: host,
                    generation: generation
                )
                return streamChannel.eventLoop.makeSucceededVoidFuture()
            }
        }.whenFailure { error in
            weakSelf.value?.markFailed(
                "stream open: \(error.localizedDescription)",
                generation: generation
            )
        }
    }

    private func installStream(
        _ streamChannel: Channel,
        generation: UInt64
    ) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard connectionGeneration == generation else { return false }
        self.streamChannel = streamChannel
        return true
    }

    private func kickoffStream(
        streamChannel: Channel,
        host: String,
        generation: UInt64
    ) {
        guard isCurrent(generation) else {
            streamChannel.close(promise: nil)
            return
        }
        // 1. Send request HEADERS (POST /sfu). After server's response
        // headers arrive, server will start sending SFUFrames via DATA.
        var headers = HPACKHeaders()
        headers.add(name: ":method", value: "POST")
        headers.add(name: ":scheme", value: "https")
        headers.add(name: ":path", value: "/sfu")
        headers.add(name: ":authority", value: host)
        headers.add(
            name: "content-type",
            value: "application/x-keep-talking-sfu"
        )
        let hdrFrame = HTTP2Frame.FramePayload.headers(
            .init(headers: headers, endStream: false)
        )
        streamChannel.writeAndFlush(hdrFrame, promise: nil)

        // 2. Wire-compat: emit CLIENT_HELLO as the first DATA frame so
        // backends that key off it (none today) still work. SERVER_HELO
        // arrives on response headers.
        writeImmediate(
            SFUFrame.encode(type: .clientHello, body: Data()),
            to: streamChannel
        )
        emit("opened http/2 stream to \(host)")
    }

    private func handleStreamClosed(reason: String, generation: UInt64) {
        guard isCurrent(generation) else { return }
        emit("stream closed: \(reason)")
        markFailed("stream closed: \(reason)", generation: generation)
    }

    /// Parent (TCP/TLS) channel went away — observed via `closeFuture`.
    /// Catches the cases the stream-level handler misses (abrupt drop,
    /// keepalive-detected silent death). Once this fires the SFU broadcast
    /// route is unavailable and `BroadcastChannel`'s state-machine
    /// triggers reconnect.
    private func handleConnectionLost(
        reason: String,
        generation: UInt64
    ) {
        guard isCurrent(generation) else { return }
        emit("connection lost: \(reason)")
        // Drop the stream-channel reference so subsequent sends fail
        // fast instead of queuing on a dead pipe.
        stateLock.lock()
        guard connectionGeneration == generation else {
            stateLock.unlock()
            return
        }
        streamChannel = nil
        didAuth = false
        stateLock.unlock()
        markFailed("connection lost: \(reason)", generation: generation)
    }

    private func markFailed(_ reason: String, generation: UInt64) {
        let next = State.failed(reason)
        stateLock.lock()
        guard connectionGeneration == generation else {
            stateLock.unlock()
            return
        }
        switch stateStorage {
        case .closed, .failed:
            stateLock.unlock()
            return
        default:
            stateStorage = next
            stateLock.unlock()
            onState?(next)
        }
    }

    // MARK: - Frame dispatch

    private func handle(frame: SFUFrame.Decoded, generation: UInt64) {
        guard isCurrent(generation) else { return }
        switch frame.type {
        case .serverHello:
            let nonce = frame.body
            do {
                let sig = try signingKey.signature(for: nonce)
                var body = Data()
                body.append(publicKey)
                body.append(sig)
                sendImmediate(SFUFrame.encode(type: .hello, body: body))
                transitionTo(.authenticating, generation: generation)
                emit("sent HELLO (nonce \(nonce.count)B); awaiting READY")
            } catch {
                markFailed("sign failed: \(error)", generation: generation)
            }

        case .ready:
            transitionTo(.ready, generation: generation)
            flushQueued(generation: generation)
            emit("received READY; registration confirmed")

        case .error:
            let msg = String(data: frame.body, encoding: .utf8) ?? "?"
            markFailed("server error: \(msg)", generation: generation)

        case .clientHello, .hello, .join, .leave, .listPeers:
            // Client-originated; ignore inbound.
            break

        case .peersSnapshot:
            if let decoded = PresenceEncoding.decodeSnapshot(frame.body) {
                onPresence?(
                    .snapshot(context: decoded.cid, peers: decoded.peers)
                )
            }
        case .peerJoined:
            if let decoded = PresenceEncoding.decodeContextPeer(frame.body) {
                onPresence?(
                    .joined(context: decoded.cid, pubkey: decoded.pubkey)
                )
            }
        case .peerLeft:
            if let decoded = PresenceEncoding.decodeContextPeer(frame.body) {
                onPresence?(.left(context: decoded.cid, pubkey: decoded.pubkey))
            }

        case .relayOpen:
            if let body = SFURoutedBodyCodec.decodeRelayOpen(frame.body) {
                onRelayOpen?(body.relayID, body.peer, body.context)
            }
        case .relayData:
            if let body = SFURoutedBodyCodec.decodeRelayData(frame.body) {
                onRelayData?(body.relayID, body.payload)
            }
        case .relayClose:
            if let body = SFURoutedBodyCodec.decodeRelayClose(frame.body) {
                onRelayClose?(body.relayID, body.reason)
            }

        case .routeTo, .broadcast:
            handleInbound(frame: frame)
        }
    }

    private func handleInbound(frame: SFUFrame.Decoded) {
        switch frame.type {
        case .routeTo:
            guard let body = SFURoutedBodyCodec.decodeRouteTo(frame.body) else {
                return
            }
            guard verifySignature(body) else { return }
            onEnvelope?(
                .init(
                    bytes: body.envelope,
                    context: nil,
                    sender: body.sender,
                    channel: body.channel
                )
            )
        case .broadcast:
            guard let body = SFURoutedBodyCodec.decodeBroadcast(frame.body)
            else { return }
            guard verifySignature(body) else { return }
            guard case .context(let cid) = body.address else { return }
            onEnvelope?(
                .init(
                    bytes: body.envelope,
                    context: cid,
                    sender: body.sender,
                    channel: body.channel
                )
            )
        default:
            break
        }
    }

    private func verifySignature(_ body: SFURoutedBody) -> Bool {
        do {
            let pubkey = try Curve25519.Signing.PublicKey(
                rawRepresentation: body.sender
            )
            let tuple = SFURoutedBodyCodec.signingTuple(
                sender: body.sender,
                address: body.address,
                channel: body.channel,
                envelope: body.envelope
            )
            if pubkey.isValidSignature(body.signature, for: tuple) {
                return true
            }
            emit("dropped: bad signature from sender=\(senderHex(body.sender))")
            return false
        } catch {
            emit(
                "dropped: malformed sender pubkey: \(error.localizedDescription)"
            )
            return false
        }
    }

    private func senderHex(_ data: Data) -> String {
        data.prefix(4).map { String(format: "%02x", $0) }.joined() + "…"
    }

    // MARK: - Send helpers

    private func makeRoutedBody(
        address: SFURoutedBody.Address,
        channel: SFUChannel,
        envelope: Data
    ) -> SFURoutedBody {
        let sender = publicKey
        let tuple = SFURoutedBodyCodec.signingTuple(
            sender: sender,
            address: address,
            channel: channel,
            envelope: envelope
        )
        let signature: Data
        do {
            signature = try signingKey.signature(for: tuple)
        } catch {
            emit("WARNING: ed25519 sign failed: \(error)")
            signature = Data(repeating: 0, count: 64)
        }
        return SFURoutedBody(
            address: address,
            sender: sender,
            channel: channel,
            signature: signature,
            envelope: envelope
        )
    }

    private func send(type: SFUFrameType, body: Data) {
        let frame = SFUFrame.encode(type: type, body: body)
        stateLock.lock()
        let ready = didAuth && streamChannel != nil
        if !ready {
            pendingFrames.append(frame)
            stateLock.unlock()
            return
        }
        stateLock.unlock()
        sendImmediate(frame)
    }

    private func sendImmediate(_ data: Data) {
        stateLock.lock()
        let stream = streamChannel
        stateLock.unlock()
        guard let stream else { return }
        writeImmediate(data, to: stream)
    }

    private func writeImmediate(_ data: Data, to stream: Channel) {
        var buffer = stream.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        let frame = HTTP2Frame.FramePayload.data(
            .init(data: .byteBuffer(buffer), endStream: false)
        )
        stream.eventLoop.execute {
            stream.writeAndFlush(frame, promise: nil)
        }
    }

    private func flushQueued(generation: UInt64) {
        stateLock.lock()
        guard connectionGeneration == generation else {
            stateLock.unlock()
            return
        }
        didAuth = true
        let subs = pendingContextSubscriptions
        let frames = pendingFrames
        pendingContextSubscriptions.removeAll()
        pendingFrames.removeAll()
        stateLock.unlock()

        for (cid, isJoin) in subs {
            let bytes = Self.uuidBytes(cid)
            sendImmediate(
                SFUFrame.encode(type: isJoin ? .join : .leave, body: bytes)
            )
        }
        for frame in frames {
            sendImmediate(frame)
        }
    }

    private func emit(_ message: String) {
        log.info("\(message)")
        onLog?(message)
    }

    private func isCurrent(_ generation: UInt64) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        return connectionGeneration == generation
    }

    private static func shutdown(_ group: MultiThreadedEventLoopGroup) {
        DispatchQueue.global().async {
            try? group.syncShutdownGracefully()
        }
    }

    private func transitionTo(_ next: State, generation: UInt64) {
        stateLock.lock()
        guard connectionGeneration == generation, stateStorage != .closed else {
            stateLock.unlock()
            return
        }
        stateStorage = next
        stateLock.unlock()
        onState?(next)
    }

    private static func uuidBytes(_ uuid: UUID) -> Data {
        withUnsafeBytes(of: uuid.uuid) { Data($0) }
    }

    private static func makeRelayID() -> Data {
        var bytes = Data(count: 16)
        bytes.withUnsafeMutableBytes { ptr in
            var rng = SystemRandomNumberGenerator()
            var written = 0
            while written < ptr.count {
                let chunk = rng.next()
                withUnsafeBytes(of: chunk) { chunkBytes in
                    let toCopy = Swift.min(
                        ptr.count - written,
                        chunkBytes.count
                    )
                    for i in 0..<toCopy {
                        ptr[written + i] = chunkBytes[i]
                    }
                    written += toCopy
                }
            }
        }
        return bytes
    }
}

// MARK: - Per-stream NIO handler

/// Reads inbound HTTP/2 frames on the client's single stream:
///   - HEADERS (response status 200) → ignored, signals stream open
///   - DATA   → SFUFrame.Parser feed
///   - RST/GOAWAY → close
final class SFUClientStreamHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload

    private var parser = SFUFrame.Parser()
    private var didNotifyClose = false
    private let onFrame: (SFUFrame.Decoded) -> Void
    private let onClose: (String) -> Void

    init(
        onFrame: @escaping (SFUFrame.Decoded) -> Void,
        onClose: @escaping (String) -> Void
    ) {
        self.onFrame = onFrame
        self.onClose = onClose
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let payload = unwrapInboundIn(data)
        switch payload {
        case .headers:
            // Response headers — ignore. The server starts sending DATA
            // (SERVER_HELO) right after.
            break
        case .data(let d):
            switch d.data {
            case .byteBuffer(var buf):
                let bytes = buf.readData(length: buf.readableBytes) ?? Data()
                for frame in parser.feed(bytes) {
                    onFrame(frame)
                }
            case .fileRegion:
                break
            }
            if d.endStream {
                context.close(promise: nil)
            }
        case .rstStream(let code):
            notifyClose("rst \(code)")
            context.close(promise: nil)
        case .goAway(let lastID, let code, _):
            notifyClose("goaway last=\(lastID) code=\(code)")
            context.close(promise: nil)
        default:
            break
        }
    }

    func channelInactive(context: ChannelHandlerContext) {
        notifyClose("inactive")
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        notifyClose("error: \(error)")
        context.close(promise: nil)
    }

    private func notifyClose(_ reason: String) {
        guard !didNotifyClose else { return }
        didNotifyClose = true
        onClose(reason)
    }
}

private final class WeakBox<T: AnyObject>: @unchecked Sendable {
    weak var value: T?
    init(_ value: T) { self.value = value }
}
