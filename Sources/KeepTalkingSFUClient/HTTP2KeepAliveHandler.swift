import Foundation
import NIOCore
import NIOHTTP2

/// Drives application-level liveness on an HTTP/2 connection.
///
/// Sits between `NIOSSLHandler` (head-side) and the HTTP/2 handler stack
/// (tail-side). Watches inbound bytes for liveness and emits HTTP/2 PING
/// frames on idle. The HTTP/2 spec mandates the peer ACK pings, and
/// swift-nio-http2's `NIOHTTP2Handler` does so automatically — the ACK
/// arrives as inbound bytes that reset our read deadline.
///
/// When the read deadline elapses without any inbound activity the
/// handler closes the channel. The carrier owning the channel observes
/// `closeFuture` and routes the failure through its state machine —
/// `BroadcastChannel.onTransportDegraded` for the SFU client, the
/// `DirectChannel` state machine for `BlobHTTP2Channel`.
///
/// Why bytes, not HTTP/2 frames? After `configureHTTP2Pipeline` the
/// multiplexer consumes connection-level frames internally; we'd never
/// see PING ACKs at a higher layer. Counting inbound bytes pre-HTTP/2
/// is transport-agnostic and catches the cases that matter (TLS close,
/// abrupt TCP RST, silent network death).
public final class HTTP2KeepAliveHandler: ChannelInboundHandler, @unchecked Sendable {
    public typealias InboundIn = ByteBuffer
    public typealias InboundOut = ByteBuffer

    /// How often to emit an HTTP/2 PING if the connection has been
    /// quiet (no inbound bytes within this interval).
    public let pingInterval: TimeAmount

    /// Inbound deadline. If no bytes have arrived within this window
    /// the channel is closed. Should be ≥ 2× `pingInterval` so a single
    /// dropped PING/ACK doesn't trip the alarm.
    public let readDeadline: TimeAmount

    private var lastReadAt: NIODeadline = .now()
    private var task: RepeatedTask?
    private var nextPingNonce: UInt64 = 1

    public init(
        pingInterval: TimeAmount = .seconds(2),
        readDeadline: TimeAmount = .seconds(5)
    ) {
        self.pingInterval = pingInterval
        self.readDeadline = readDeadline
    }

    public func handlerAdded(context: ChannelHandlerContext) {
        lastReadAt = .now()
        let loop = context.eventLoop
        let channel = context.channel
        let handlerSelf = self
        task = loop.scheduleRepeatedTask(initialDelay: pingInterval, delay: pingInterval) { _ in
            handlerSelf.tick(channel: channel, loop: loop)
        }
    }

    public func handlerRemoved(context: ChannelHandlerContext) {
        task?.cancel(promise: nil)
        task = nil
    }

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // Any inbound byte counts. We don't peek into HTTP/2 frames — even
        // PING ACKs surface here as bytes before NIOHTTP2Handler parses
        // them downstream.
        lastReadAt = .now()
        context.fireChannelRead(data)
    }

    public func channelInactive(context: ChannelHandlerContext) {
        task?.cancel(promise: nil)
        task = nil
        context.fireChannelInactive()
    }

    private func tick(channel: Channel, loop: EventLoop) {
        let now = NIODeadline.now()
        if now - lastReadAt > readDeadline {
            // Read timeout — close the channel. The owning carrier
            // observes `closeFuture` and routes the failure through its
            // state machine.
            channel.close(promise: nil)
            return
        }
        // Emit a PING. `NIOHTTP2Handler` downstream serializes it; the
        // peer auto-ACKs per spec. Even if both ends are otherwise idle,
        // this keeps bytes flowing on the path.
        let nonce = nextPingNonce
        nextPingNonce &+= 1
        let frame = HTTP2Frame(
            streamID: .rootStream,
            payload: .ping(HTTP2PingData(withInteger: nonce), ack: false)
        )
        channel.writeAndFlush(frame, promise: nil)
    }
}
