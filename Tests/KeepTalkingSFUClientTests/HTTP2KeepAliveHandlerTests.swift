import KeepTalkingSFUClient
import NIOCore
import NIOEmbedded
import Testing

@Suite("HTTP/2 keepalive")
struct HTTP2KeepAliveHandlerTests {
    @Test("production defaults tolerate slow public-network handshakes")
    func productionDefaults() {
        let handler = HTTP2KeepAliveHandler()

        #expect(handler.pingInterval == .seconds(15))
        #expect(handler.readDeadline == .seconds(45))
    }

    @Test("inbound progress renews the read deadline")
    func inboundProgressRenewsDeadline() throws {
        let loop = EmbeddedEventLoop()
        let channel = EmbeddedChannel(
            handler: HTTP2KeepAliveHandler(
                pingInterval: .seconds(1),
                readDeadline: .seconds(3)
            ),
            loop: loop
        )
        try channel.connect(
            to: SocketAddress(unixDomainSocketPath: "/keep-talking-sfu")
        ).wait()

        loop.advanceTime(by: .seconds(2))
        #expect(channel.isActive)

        var inbound = channel.allocator.buffer(capacity: 1)
        inbound.writeInteger(UInt8(0))
        _ = try channel.writeInbound(inbound)

        loop.advanceTime(by: .seconds(3))
        #expect(channel.isActive)

        loop.advanceTime(by: .seconds(1))
        #expect(!channel.isActive)
    }
}
