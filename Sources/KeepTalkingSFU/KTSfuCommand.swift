import ArgumentParser
import Foundation
import KeepTalkingSFULib
import KeepTalkingSFUProtocol
import Logging

/// KeepTalkingSFU — small Swift SFU for KeepTalking. Phase 1: accepts
/// QUIC peers, routes opaque encrypted envelopes by destination peer
/// pubkey, never looks inside.
@main
struct KTSfuCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "KeepTalkingSFU",
        abstract: "Trust-aware envelope router for KeepTalking peers (QUIC)."
    )

    @Option(name: .long, help: "Bind address.")
    var bind: String = "0.0.0.0"

    @Option(name: .long, help: "Listen port.")
    var port: Int = 9701

    @Option(name: .long, help: "ALPN string peers must match. Use \"h2\" for plain HTTP/2 over TLS.")
    var alpn: String = "h2"

    @Option(name: .long, help: "Log verbosity (trace|debug|info|warn|error).")
    var logLevel: String = "info"

    @Option(
        name: .long,
        help: "Path to a PKCS#12 bundle for the server TLS identity. Falls back to the \(SFUServerTLSIdentity.envPathKey) env var. No default — misconfiguration is fatal."
    )
    var pkcs12Path: String?

    @Option(
        name: .long,
        help: "Passphrase for the PKCS#12 bundle. Falls back to the \(SFUServerTLSIdentity.envPassphraseKey) env var. Empty if neither is set."
    )
    var pkcs12Passphrase: String?

    mutating func run() async throws {
        let level = Logger.Level(rawValue: logLevel) ?? .info
        LoggingSystem.bootstrap { label in
            var handler = StreamLogHandler.standardOutput(label: label)
            handler.logLevel = level
            return handler
        }
        let log = Logger(label: "kt.sfu.main")

        let resolved: SFUServerTLSIdentity.Resolved
        do {
            resolved = try SFUServerTLSIdentity.resolve(
                pkcs12Path: pkcs12Path,
                passphrase: pkcs12Passphrase
            )
        } catch {
            log.error("TLS identity: \(error)")
            throw ExitCode(1)
        }
        let identity = SFUHTTP2Server.ServerIdentity(
            pkcs12Base64: resolved.pkcs12Base64,
            passphrase: resolved.passphrase
        )
        let server = SFUHTTP2Server(
            configuration: .init(
                bindHost: bind,
                bindPort: port,
                alpn: alpn,
                identity: identity
            )
        )

        do {
            try server.start()
        } catch {
            log.error("failed to start listener: \(error)")
            throw ExitCode(1)
        }

        log.info("KeepTalkingSFU running. ctrl-c to quit.")
        // Park this task forever. `withUnsafeContinuation` is the
        // pattern: no timer math (which is what breaks
        // `Task.sleep(nanoseconds: UInt64.max)` on the 6.3 toolchain),
        // and unlike the checked variant it doesn't print a "leaked
        // continuation" warning when SIGINT terminates the process —
        // because that's exactly what's supposed to happen here.
        await withUnsafeContinuation { (_: UnsafeContinuation<Void, Never>) in }
    }
}

