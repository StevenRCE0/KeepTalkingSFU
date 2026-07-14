import Crypto
import Foundation
import KeepTalkingSFUClient
import KeepTalkingSFULib
import KeepTalkingSFUProtocol
import Logging
import Testing

@Suite("SFU end-to-end")
struct SFUClientRoundtripTests {
    @Test(
        "client→server→client unicast over loopback",
        .enabled(
            if: ProcessInfo.processInfo.environment[
                SFUServerTLSIdentity.envPathKey
            ] != nil
        )
    )
    func unicastRoundtrip() async throws {
        let resolved = try SFUServerTLSIdentity.resolve()
        // 1. Stand up an SFU on a free local port.
        let port = try pickFreePort()
        let identity = SFUHTTP2Server.ServerIdentity(
            pkcs12Base64: resolved.pkcs12Base64,
            passphrase: resolved.passphrase
        )
        let server = SFUHTTP2Server(
            configuration: .init(bindPort: Int(port), identity: identity),
            log: Logger(label: "test.sfu.server")
        )
        try server.start()
        defer { server.stop() }

        // 2. Two clients with fresh Ed25519 identities.
        let alice = SFUClient(
            configuration: .init(host: "127.0.0.1", port: Int(port)),
            log: Logger(label: "test.alice")
        )
        let bob = SFUClient(
            configuration: .init(host: "127.0.0.1", port: Int(port)),
            log: Logger(label: "test.bob")
        )

        let aliceReady = AsyncFlag()
        let bobReady = AsyncFlag()
        let bobInbox = LockedBox<[Data]>(value: [])

        alice.onState = { s in if s == .ready { aliceReady.signal() } }
        bob.onState = { s in if s == .ready { bobReady.signal() } }
        bob.onEnvelope = { env in bobInbox.mutate { $0.append(env.bytes) } }

        alice.connect()
        bob.connect()

        await aliceReady.wait(timeoutSeconds: 10)
        await bobReady.wait(timeoutSeconds: 10)
        // `.ready` is now sent by the server only after `router.register`
        // commits, so no extra sleep needed — peers are guaranteed to
        // exist in the router by the time the client sees the state flip.

        // 3. Alice unicasts to Bob.
        let payload = Data("hello bob from alice".utf8)
        let bobPubkey = bob.publicKey
        alice.route(envelope: payload, to: bobPubkey)

        // 4. Wait for delivery.
        try? await Task.sleep(for: .milliseconds(500))
        let received = bobInbox.get()
        #expect(received == [payload])

        alice.close()
        bob.close()
    }

    @Test("closing a connecting client invalidates stale callbacks")
    func closeDuringConnect() async throws {
        let port = try pickFreePort()
        let client = SFUClient(
            configuration: .init(host: "127.0.0.1", port: Int(port)),
            log: Logger(label: "test.lifecycle")
        )
        let events = LockedBox<[String]>(value: [])
        client.onLog = { message in
            events.mutate { $0.append(message) }
        }

        client.connect()
        client.close()
        try? await Task.sleep(for: .milliseconds(500))

        let captured = events.get()
        let closedIndex = try #require(captured.firstIndex(of: "closed"))
        #expect(!captured[closedIndex...].contains { $0.hasPrefix("opened ") })
        #expect(client.state == .closed)
    }

    // MARK: - Helpers

    private func pickFreePort() throws -> UInt16 {
        // Grab an ephemeral UDP port. Network.framework's NWListener will
        // happily bind to a port we just released; this is racy but fine
        // for a single-process smoke test.
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        precondition(fd >= 0)
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bindRC = withUnsafePointer(to: &addr) { ptr in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        precondition(bindRC == 0)
        var out = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameRC = withUnsafeMutablePointer(to: &out) { ptr -> Int32 in
            ptr.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(fd, $0, &len)
            }
        }
        precondition(nameRC == 0)
        return UInt16(bigEndian: out.sin_port)
    }
}

final class LockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value
    init(value: Value) { self.value = value }
    func get() -> Value { lock.lock(); defer { lock.unlock() }; return value }
    func mutate(_ body: (inout Value) -> Void) {
        lock.lock(); defer { lock.unlock() }; body(&value)
    }
}

final class AsyncFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var signalled = false
    private var continuations: [CheckedContinuation<Void, Never>] = []

    func wait(timeoutSeconds: Double = 10) async {
        let timeout = Task {
            try? await Task.sleep(for: .seconds(timeoutSeconds))
            self.signal()
        }
        await withCheckedContinuation { cont in
            lock.lock()
            if signalled {
                lock.unlock()
                cont.resume()
                return
            }
            continuations.append(cont)
            lock.unlock()
        }
        timeout.cancel()
    }

    func signal() {
        lock.lock()
        signalled = true
        let pending = continuations
        continuations.removeAll()
        lock.unlock()
        for cont in pending { cont.resume() }
    }
}
