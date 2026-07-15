import Crypto
import Foundation
import KeepTalkingSFUClient
import KeepTalkingSFUProtocol
import Logging
import NIOCore
import NIOFoundationCompat
import NIOHPACK
import NIOHTTP2
import NIOPosix
@preconcurrency import NIOSSL

/// HTTP/2 server adapter for `SFURouter`. Each peer connects with a
/// single long-lived bidirectional HTTP/2 stream (one POST per peer)
/// over TLS; SFU frames ride inside the DATA-frame body in both
/// directions.
///
/// Auth flow on each new stream:
///   client → HEADERS (POST /sfu, h2 stream open)
///   client → DATA (CLIENT_HELLO frame, body)
///   server → HEADERS (200, response stream open)
///   server → DATA (SERVER_HELO with challenge nonce)
///   client → DATA (HELLO: pubkey || sig over nonce)
///   server verifies; on success registers the peer with the router
///   server → DATA (READY)
///
/// The framing protocol on top of the DATA stream is unchanged — exactly
/// the same length-prefixed `SFUFrame` shape the QUIC backend used.
public final class SFUHTTP2Server: @unchecked Sendable {
    public struct Configuration: Sendable {
        public var bindHost: String
        public var bindPort: Int
        public var alpn: String
        public var identity: ServerIdentity

        public init(
            bindHost: String = "0.0.0.0",
            bindPort: Int = 9701,
            alpn: String = "h2",
            identity: ServerIdentity
        ) {
            self.bindHost = bindHost
            self.bindPort = bindPort
            self.alpn = alpn
            self.identity = identity
        }
    }

    /// TLS identity that the HTTP/2 server presents to peers. Phase 1
    /// uses the same lab PKCS12 the QUIC backend did; when KT moves to
    /// production this becomes per-deploy material (PEM/PKCS12 from
    /// systemd/KMS/config).
    public struct ServerIdentity: Sendable {
        public let pkcs12Base64: String
        public let passphrase: String

        public init(pkcs12Base64: String, passphrase: String) {
            self.pkcs12Base64 = pkcs12Base64
            self.passphrase = passphrase
        }
    }

    public let router: SFURouter

    private let configuration: Configuration
    private let log: Logger
    private var eventLoopGroup: MultiThreadedEventLoopGroup?
    private var channel: Channel?

    public init(
        configuration: Configuration,
        log: Logger = Logger(label: "kt.sfu.server"),
        router: SFURouter = SFURouter()
    ) {
        self.configuration = configuration
        self.log = log
        self.router = router
    }

    public func start() throws {
        let group = MultiThreadedEventLoopGroup(
            numberOfThreads: System.coreCount
        )
        self.eventLoopGroup = group

        let tlsContext = try makeTLSContext()
        let router = self.router
        let log = self.log

        let bootstrap = ServerBootstrap(group: group)
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            .serverChannelOption(
                ChannelOptions.socketOption(.so_reuseaddr),
                value: 1
            )
            .childChannelOption(
                ChannelOptions.socketOption(.so_reuseaddr),
                value: 1
            )
            .childChannelInitializer { childChannel in
                // 1. TLS first.
                let sslHandler = NIOSSLServerHandler(context: tlsContext)
                do {
                    try childChannel.pipeline.syncOperations.addHandler(sslHandler)
                    // 2. Liveness: emits HTTP/2 PINGs on idle and closes
                    // the connection if no inbound bytes arrive within
                    // the read deadline. Mirrors the client.
                    try childChannel.pipeline.syncOperations.addHandler(
                        HTTP2KeepAliveHandler()
                    )
                } catch {
                    return childChannel.eventLoop.makeFailedFuture(error)
                }
                // 3. HTTP/2 multiplexer: one Peer Session per stream.
                return childChannel.configureHTTP2Pipeline(
                    mode: .server,
                    inboundStreamInitializer: { streamChannel in
                        streamChannel.pipeline.addHandler(
                            SFUPeerSessionHandler(router: router, log: log)
                        )
                    }
                ).map { _ in () }
            }

        let bound =
            try bootstrap
            .bind(host: configuration.bindHost, port: configuration.bindPort)
            .wait()
        self.channel = bound
        log.info(
            "KeepTalkingSFU (HTTP/2) listening on \(configuration.bindHost):\(configuration.bindPort)"
        )
    }

    public func stop() {
        try? channel?.close().wait()
        channel = nil
        try? eventLoopGroup?.syncShutdownGracefully()
        eventLoopGroup = nil
    }

    private func makeTLSContext() throws -> NIOSSLContext {
        guard
            let pkcs12Bytes = Data(
                base64Encoded: configuration.identity.pkcs12Base64
            )
        else {
            throw SFUHTTP2ServerError.invalidIdentity(
                "pkcs12 base64 decode failed"
            )
        }
        let bundle = try NIOSSLPKCS12Bundle(
            buffer: Array(pkcs12Bytes),
            passphrase: Array(configuration.identity.passphrase.utf8)
        )
        var tlsConfig = TLSConfiguration.makeServerConfiguration(
            certificateChain: bundle.certificateChain.map { .certificate($0) },
            privateKey: .privateKey(bundle.privateKey)
        )
        tlsConfig.minimumTLSVersion = .tlsv12
        tlsConfig.applicationProtocols = [configuration.alpn]
        return try NIOSSLContext(configuration: tlsConfig)
    }
}

public enum SFUHTTP2ServerError: Error, Sendable {
    case invalidIdentity(String)
}

// MARK: - Per-peer stream handler

/// One instance per accepted HTTP/2 stream. Mirrors the per-connection
/// PeerSession from the old QUIC backend: parses SFU frames out of
/// DATA-frame bodies, runs the Ed25519 auth dance, and dispatches into
/// the router.
final class SFUPeerSessionHandler: ChannelInboundHandler, @unchecked Sendable {
    typealias InboundIn = HTTP2Frame.FramePayload
    typealias OutboundOut = HTTP2Frame.FramePayload

    private let router: SFURouter
    private let log: Logger
    private let sessionID = UUID()
    private var parser = SFUFrame.Parser()
    private var registeredPeerID: Data?
    private var authNonce: Data = SFUPeerSessionHandler.makeNonce()
    private var sentResponseHeaders = false
    private var authenticationTimeout: Scheduled<Void>?
    private weak var context: ChannelHandlerContext?
    private var loopBoundContext: NIOLoopBound<ChannelHandlerContext>?

    init(router: SFURouter, log: Logger) {
        self.router = router
        self.log = log
    }

    func handlerAdded(context: ChannelHandlerContext) {
        self.context = context
        let loopBoundContext = context.loopBound
        self.loopBoundContext = loopBoundContext
        authenticationTimeout = context.eventLoop.scheduleTask(
            in: .seconds(30)
        ) { [weak self, loopBoundContext] in
            guard let self, self.registeredPeerID == nil else { return }
            self.log.warning("closing unauthenticated SFU stream after 30s")
            loopBoundContext.value.close(promise: nil)
        }
    }

    func handlerRemoved(context: ChannelHandlerContext) {
        authenticationTimeout?.cancel()
        authenticationTimeout = nil
        self.context = nil
        self.loopBoundContext = nil
    }

    func channelInactive(context: ChannelHandlerContext) {
        guard let id = registeredPeerID else { return }
        let router = self.router
        let log = self.log
        let sessionID = self.sessionID
        Task {
            guard
                let contexts = await router.unregister(
                    peerID: id,
                    sessionID: sessionID
                )
            else {
                log.debug(
                    "ignored stale disconnect peer=\(id.shortHex) session=\(sessionID.uuidString.lowercased())"
                )
                return
            }
            for cid in contexts {
                let leftFrame = SFUFrame.encode(
                    type: .peerLeft,
                    body: PresenceEncoding.contextPeer(cid: cid, pubkey: id)
                )
                for memberID in await router.members(in: cid)
                where memberID != id {
                    if let handle = await router.handle(for: memberID) {
                        await handle.sendFrame(leftFrame)
                    }
                }
            }
            log.debug(
                "presence: peer=\(id.shortHex) disconnected, notified \(contexts.count) contexts"
            )
        }
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        log.warning("stream error: \(error)")
        context.close(promise: nil)
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let payload = unwrapInboundIn(data)
        switch payload {
        case .headers(let h):
            // Client request headers — emit our response headers (200)
            // immediately so the response stream is open and we can start
            // streaming SERVER_HELO + everything else back.
            log.debug("inbound headers: \(h.headers)")
            sendResponseHeaders(context: context)
            sendFrame(
                SFUFrame.encode(type: .serverHello, body: authNonce),
                context: context
            )

        case .data(let data):
            switch data.data {
            case .byteBuffer(var buffer):
                let bytes =
                    buffer.readData(length: buffer.readableBytes) ?? Data()
                let frames = parser.feed(bytes)
                for frame in frames {
                    handle(frame: frame, context: context)
                }
            case .fileRegion:
                // We don't request file-region delivery; ignore.
                break
            }
            if data.endStream {
                context.close(promise: nil)
            }

        case .rstStream, .goAway:
            context.close(promise: nil)

        default:
            break
        }
    }

    // MARK: - Outbound helpers

    private func sendResponseHeaders(context: ChannelHandlerContext) {
        guard !sentResponseHeaders else { return }
        sentResponseHeaders = true
        var headers = HPACKHeaders()
        headers.add(name: ":status", value: "200")
        headers.add(
            name: "content-type",
            value: "application/x-keep-talking-sfu"
        )
        let frame = HTTP2Frame.FramePayload.headers(
            .init(headers: headers, endStream: false)
        )
        context.writeAndFlush(wrapOutboundOut(frame), promise: nil)
    }

    private func sendFrame(_ data: Data, context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: data.count)
        buffer.writeBytes(data)
        let frame = HTTP2Frame.FramePayload.data(
            .init(data: .byteBuffer(buffer), endStream: false)
        )
        context.writeAndFlush(wrapOutboundOut(frame), promise: nil)
    }

    /// Off-event-loop send used by `SFURouter.PeerHandle.sendFrame`. Hops
    /// onto the channel's event loop before writing.
    private func sendFromAnywhere(_ data: Data) {
        guard let loopBoundContext else { return }
        loopBoundContext.eventLoop.execute {
            let ctx = loopBoundContext.value
            var buffer = ctx.channel.allocator.buffer(capacity: data.count)
            buffer.writeBytes(data)
            let frame = HTTP2Frame.FramePayload.data(
                .init(data: .byteBuffer(buffer), endStream: false)
            )
            ctx.writeAndFlush(self.wrapOutboundOut(frame), promise: nil)
        }
    }

    private func closeFromAnywhere() {
        guard let loopBoundContext else { return }
        loopBoundContext.eventLoop.execute {
            loopBoundContext.value.close(promise: nil)
        }
    }

    // MARK: - Frame dispatch

    private func handle(frame: SFUFrame.Decoded, context: ChannelHandlerContext)
    {
        switch frame.type {
        case .clientHello:
            // No-op under HTTP/2 transport: the server's challenge already
            // went out on response-headers receipt. CLIENT_HELLO becomes
            // a no-op marker frame the client may still emit for
            // wire-compatibility with the legacy backend.
            break

        case .hello:
            guard registeredPeerID == nil else {
                log.warning("ignoring duplicate HELLO")
                return
            }
            guard let identity = verifyHello(body: frame.body) else {
                rejectAndClose(reason: "auth failed", context: context)
                return
            }
            registeredPeerID = identity
            authenticationTimeout?.cancel()
            authenticationTimeout = nil
            let registered = identity

            // Capture self weakly through a closure-captured send hook so
            // the router's PeerHandle doesn't retain us across the
            // event-loop boundary.
            let weakSelf = WeakBox(self)
            let send: @Sendable (Data) async -> Void = { payload in
                weakSelf.value?.sendFromAnywhere(payload)
            }
            let close: @Sendable (String) async -> Void = { _ in
                weakSelf.value?.closeFromAnywhere()
            }
            let handle = SFURouter.PeerHandle(
                id: registered,
                sessionID: sessionID,
                sendFrame: send,
                closeReason: close
            )
            let router = self.router
            let log = self.log
            let weakBox = weakSelf
            Task {
                await router.register(peer: handle)
                // READY ack rides back via the same sendFromAnywhere path.
                let ack = SFUFrame.encode(type: .ready, body: Data())
                weakBox.value?.sendFromAnywhere(ack)
                log.info("peer registered id=\(registered.shortHex)")
            }
            log.info("peer authed id=\(registered.shortHex)")

        case .join:
            guard frame.body.count == 16, let peer = registeredPeerID else {
                return
            }
            let cid = uuid(from: frame.body)
            let router = self.router
            let log = self.log
            Task {
                let existing = await router.members(in: cid)
                await router.join(peerID: peer, context: cid)
                let joinedFrame = SFUFrame.encode(
                    type: .peerJoined,
                    body: PresenceEncoding.contextPeer(cid: cid, pubkey: peer)
                )
                for memberID in existing where memberID != peer {
                    if let handle = await router.handle(for: memberID) {
                        await handle.sendFrame(joinedFrame)
                    }
                }
                let roster = await router.members(in: cid)
                let snapshot = SFUFrame.encode(
                    type: .peersSnapshot,
                    body: PresenceEncoding.snapshot(cid: cid, peers: roster)
                )
                if let joinerHandle = await router.handle(for: peer) {
                    await joinerHandle.sendFrame(snapshot)
                }
                log.debug(
                    "presence: peer=\(peer.shortHex) joined context=\(cid) roster=\(roster.count)"
                )
            }

        case .leave:
            guard frame.body.count == 16, let peer = registeredPeerID else {
                return
            }
            let cid = uuid(from: frame.body)
            let router = self.router
            let log = self.log
            Task {
                let leftFrame = SFUFrame.encode(
                    type: .peerLeft,
                    body: PresenceEncoding.contextPeer(cid: cid, pubkey: peer)
                )
                await router.leave(peerID: peer, context: cid)
                for memberID in await router.members(in: cid) {
                    if let handle = await router.handle(for: memberID) {
                        await handle.sendFrame(leftFrame)
                    }
                }
                log.debug("presence: peer=\(peer.shortHex) left context=\(cid)")
            }

        case .listPeers:
            guard frame.body.count == 16 else { return }
            let cid = uuid(from: frame.body)
            let weakBox = WeakBox(self)
            let router = self.router
            Task {
                let members = await router.members(in: cid)
                let snapshot = SFUFrame.encode(
                    type: .peersSnapshot,
                    body: PresenceEncoding.snapshot(cid: cid, peers: members)
                )
                weakBox.value?.sendFromAnywhere(snapshot)
            }

        case .routeTo:
            guard let registered = registeredPeerID else {
                log.warning("route dropped: peer not registered")
                return
            }
            guard let routed = SFURoutedBodyCodec.decodeRouteTo(frame.body)
            else {
                log.warning(
                    "route dropped: malformed v2 ROUTE_TO body=\(frame.body.count)B"
                )
                return
            }
            guard routed.sender == registered else {
                log.warning(
                    "route dropped: sender=\(routed.sender.shortHex) != registered=\(registered.shortHex)"
                )
                rejectAndClose(
                    reason: "sender pubkey mismatch",
                    context: context
                )
                return
            }
            let forwarded = SFUFrame.encode(type: .routeTo, body: frame.body)
            guard case .peer(let dest) = routed.address else { return }
            let router = self.router
            let log = self.log
            Task {
                do {
                    try await router.route(frame: forwarded, to: dest)
                } catch {
                    log.debug("route dropped at router: \(error)")
                }
            }

        case .broadcast:
            guard let registered = registeredPeerID else {
                log.warning("broadcast dropped: peer not registered")
                return
            }
            guard let routed = SFURoutedBodyCodec.decodeBroadcast(frame.body)
            else {
                log.warning(
                    "broadcast dropped: malformed v2 BROADCAST body=\(frame.body.count)B"
                )
                return
            }
            guard routed.sender == registered else {
                log.warning(
                    "broadcast dropped: sender=\(routed.sender.shortHex) != registered=\(registered.shortHex)"
                )
                rejectAndClose(
                    reason: "sender pubkey mismatch",
                    context: context
                )
                return
            }
            guard case .context(let cid) = routed.address else { return }
            let forwarded = SFUFrame.encode(type: .broadcast, body: frame.body)
            let payloadSize = routed.envelope.count
            let router = self.router
            let log = self.log
            Task {
                let members = await router.members(in: cid)
                log.info(
                    "broadcast from=\(registered.shortHex) ctx=\(cid) ch=\(routed.channel) payload=\(payloadSize)B members=\(members.count)"
                )
                await router.broadcast(
                    frame: forwarded,
                    context: cid,
                    excluding: registered
                )
            }

        case .relayOpen:
            guard let registered = registeredPeerID else { return }
            guard let body = SFURoutedBodyCodec.decodeRelayOpen(frame.body)
            else { return }
            let forwardBody = SFURoutedBodyCodec.encodeRelayOpen(
                SFURelayOpenBody(
                    relayID: body.relayID,
                    peer: registered,
                    context: body.context
                )
            )
            let forwardFrame = SFUFrame.encode(
                type: .relayOpen,
                body: forwardBody
            )
            let router = self.router
            let log = self.log
            Task {
                do {
                    try await router.openRelay(
                        opener: registered,
                        relayID: body.relayID,
                        target: body.peer,
                        context: body.context,
                        targetNotificationFrame: forwardFrame
                    )
                } catch {
                    log.warning("relayOpen rejected: \(error)")
                }
            }

        case .relayData:
            guard let registered = registeredPeerID else { return }
            guard let body = SFURoutedBodyCodec.decodeRelayData(frame.body)
            else { return }
            let forwardFrame = SFUFrame.encode(
                type: .relayData,
                body: frame.body
            )
            let router = self.router
            let log = self.log
            Task {
                do {
                    try await router.forwardRelayData(
                        relayID: body.relayID,
                        sender: registered,
                        frameToForward: forwardFrame
                    )
                } catch {
                    log.debug("relayData dropped: \(error)")
                }
            }

        case .relayClose:
            guard let registered = registeredPeerID else { return }
            guard let body = SFURoutedBodyCodec.decodeRelayClose(frame.body)
            else { return }
            let forwardFrame = SFUFrame.encode(
                type: .relayClose,
                body: frame.body
            )
            let router = self.router
            Task {
                try? await router.closeRelay(
                    relayID: body.relayID,
                    sender: registered,
                    frameToForward: forwardFrame
                )
            }

        case .serverHello, .ready, .error, .peersSnapshot, .peerJoined,
            .peerLeft:
            log.warning("unexpected client frame type=\(frame.type.rawValue)")
        }
    }

    private func verifyHello(body: Data) -> Data? {
        guard body.count == 32 + 64 else { return nil }
        let pubkey = body.prefix(32)
        let sig = body.suffix(64)
        do {
            let key = try Curve25519.Signing.PublicKey(
                rawRepresentation: pubkey
            )
            return key.isValidSignature(sig, for: authNonce)
                ? Data(pubkey) : nil
        } catch {
            return nil
        }
    }

    private func rejectAndClose(reason: String, context: ChannelHandlerContext)
    {
        log.warning("rejecting peer: \(reason)")
        let errFrame = SFUFrame.encode(type: .error, body: Data(reason.utf8))
        sendFrame(errFrame, context: context)
        context.close(promise: nil)
    }

    private func uuid(from data: Data) -> UUID {
        var bytes = (
            UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0)
        )
        withUnsafeMutableBytes(of: &bytes) { buf in
            let n = Swift.min(buf.count, data.count)
            for i in 0..<n {
                buf[i] = data[data.startIndex + i]
            }
        }
        return UUID(uuid: bytes)
    }

    private static func makeNonce() -> Data {
        var nonce = Data(count: 32)
        nonce.withUnsafeMutableBytes { ptr in
            _ = SystemRandomNumberGenerator.fill(ptr)
        }
        return nonce
    }
}

/// Tiny weak holder so handlers can hand the router a `@Sendable` send
/// closure without retaining themselves across the event-loop boundary.
private final class WeakBox<T: AnyObject>: @unchecked Sendable {
    weak var value: T?
    init(_ value: T) { self.value = value }
}

extension SystemRandomNumberGenerator {
    /// Fills `ptr` with cryptographic-quality random bytes by sampling a
    /// `SystemRandomNumberGenerator` 8 bytes at a time. Available
    /// everywhere swift-crypto is.
    static func fill(_ ptr: UnsafeMutableRawBufferPointer) -> Int {
        var rng = SystemRandomNumberGenerator()
        var written = 0
        while written < ptr.count {
            let chunk = rng.next()
            let bytes = withUnsafeBytes(of: chunk) { Data($0) }
            let remaining = ptr.count - written
            let toCopy = Swift.min(remaining, bytes.count)
            for i in 0..<toCopy {
                ptr[written + i] = bytes[i]
            }
            written += toCopy
        }
        return written
    }
}
