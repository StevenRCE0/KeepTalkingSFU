import Foundation
import Testing
@testable import KeepTalkingSFULib
import KeepTalkingSFUProtocol

@Suite("SFURouter")
struct SFURouterTests {
    @Test("unicast routes only to destination")
    func unicastRoutesOnly() async throws {
        let router = SFURouter()
        let bobInbox = Inbox()
        let aliceInbox = Inbox()

        await router.register(peer: makePeer(id: "alice", inbox: aliceInbox))
        await router.register(peer: makePeer(id: "bob", inbox: bobInbox))

        try await router.route(frame: Data("hi bob".utf8), to: Self.id("bob"))

        // Allow the dispatch hop to settle.
        try? await Task.sleep(nanoseconds: 100_000_000)
        #expect(await bobInbox.snapshot() == [Data("hi bob".utf8)])
        #expect(await aliceInbox.snapshot() == [])
    }

    @Test("broadcast hits context members except sender")
    func broadcastSkipsSender() async throws {
        let router = SFURouter()
        let aliceInbox = Inbox()
        let bobInbox = Inbox()
        let carolInbox = Inbox()
        await router.register(peer: makePeer(id: "alice", inbox: aliceInbox))
        await router.register(peer: makePeer(id: "bob", inbox: bobInbox))
        await router.register(peer: makePeer(id: "carol", inbox: carolInbox))

        let cid = UUID()
        await router.join(peerID: Self.id("alice"), context: cid)
        await router.join(peerID: Self.id("bob"), context: cid)
        await router.join(peerID: Self.id("carol"), context: cid)

        await router.broadcast(frame: Data("ping".utf8), context: cid, excluding: Self.id("alice"))

        try? await Task.sleep(nanoseconds: 100_000_000)
        #expect(await aliceInbox.snapshot() == [])
        #expect(await bobInbox.snapshot() == [Data("ping".utf8)])
        #expect(await carolInbox.snapshot() == [Data("ping".utf8)])
    }

    @Test("unknown destination throws")
    func unknownDestinationThrows() async throws {
        let router = SFURouter()
        await #expect(throws: SFURouter.RouteError.self) {
            try await router.route(frame: Data(), to: Self.id("ghost"))
        }
    }

    @Test("re-register with same peerID kicks the prior session")
    func reregisterKicksPrior() async throws {
        let router = SFURouter()
        let firstClose = Inbox()
        let firstFrames = Inbox()
        let secondFrames = Inbox()

        let firstHandle = SFURouter.PeerHandle(
            id: Self.id("alice"),
            sendFrame: { frame in await firstFrames.append(frame) },
            closeReason: { reason in await firstClose.append(Data(reason.utf8)) }
        )
        let secondHandle = SFURouter.PeerHandle(
            id: Self.id("alice"),
            sendFrame: { frame in await secondFrames.append(frame) },
            closeReason: { _ in }
        )

        await router.register(peer: firstHandle)
        await router.register(peer: secondHandle)
        try? await Task.sleep(nanoseconds: 100_000_000)

        // The prior session was asked to close.
        #expect(await firstClose.snapshot().count == 1)

        // Subsequent routes go to the new session only.
        let payload = Data("hello".utf8)
        try await router.route(frame: payload, to: Self.id("alice"))
        try? await Task.sleep(nanoseconds: 100_000_000)
        #expect(await firstFrames.snapshot() == [])
        #expect(await secondFrames.snapshot() == [payload])
    }

    @Test("unregistering peer removes from contexts")
    func unregisterCleansContexts() async throws {
        let router = SFURouter()
        await router.register(peer: makePeer(id: "alice", inbox: Inbox()))
        let cid = UUID()
        await router.join(peerID: Self.id("alice"), context: cid)
        await router.unregister(peerID: Self.id("alice"))
        let stats = await router.stats()
        #expect(stats.peerCount == 0)
        #expect(stats.contextCount == 0)
    }

    // MARK: - Helpers

    private func makePeer(id: String, inbox: Inbox) -> SFURouter.PeerHandle {
        let pid = Self.id(id)
        return SFURouter.PeerHandle(
            id: pid,
            sendFrame: { frame in await inbox.append(frame) },
            closeReason: { _ in }
        )
    }

    private static func id(_ name: String) -> Data {
        // Pad/truncate to 32 bytes so test "ids" look like ed25519 pubkeys.
        var bytes = [UInt8](repeating: 0, count: 32)
        let src = Array(name.utf8)
        for i in 0..<Swift.min(src.count, 32) { bytes[i] = src[i] }
        return Data(bytes)
    }
}

actor Inbox {
    private var items: [Data] = []
    func append(_ data: Data) { items.append(data) }
    func snapshot() -> [Data] { items }
}
