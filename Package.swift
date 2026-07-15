// swift-tools-version: 6.0
import PackageDescription

// KeepTalkingSFU — a dumb, encrypted-envelope router for KT.
//
// Three targets:
//   * KeepTalkingSFUProtocol — wire format + lab credentials. Shared
//                              by both client and server. Pure Foundation.
//   * KeepTalkingSFULib      — server-only logic: SFURouter actor +
//                              SFUHTTP2Server (swift-nio-http2). Long-lived
//                              bidirectional HTTP/2 stream per peer.
//   * KeepTalkingSFUClient   — client-side library KT apps depend on:
//                              connector, Ed25519 auth, join/route API,
//                              also over swift-nio-http2.
//
// Design principle: the SFU never decrypts envelopes. It authenticates
// the peer on connect (Ed25519 challenge/response over a long-lived
// bidirectional HTTP/2 stream), then routes opaque frames keyed by
// destination peer ID.

let package = Package(
    name: "KeepTalkingSFU",
    platforms: [
        .macOS(.v13),
        .iOS(.v17),
        .visionOS(.v1),
    ],
    products: [
        .executable(name: "KeepTalkingSFU", targets: ["KeepTalkingSFU"]),
        .library(name: "KeepTalkingSFULib", targets: ["KeepTalkingSFULib"]),
        .library(
            name: "KeepTalkingSFUClient",
            targets: ["KeepTalkingSFUClient"]
        ),
        .library(
            name: "KeepTalkingSFUProtocol",
            targets: ["KeepTalkingSFUProtocol"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-argument-parser.git",
            from: "1.7.0"
        ),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
        .package(
            url: "https://github.com/apple/swift-crypto.git",
            from: "3.0.0"
        ),
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.65.0"),
        .package(
            url: "https://github.com/apple/swift-nio-http2.git",
            from: "1.30.0"
        ),
        .package(
            url: "https://github.com/apple/swift-nio-ssl.git",
            from: "2.27.0"
        ),
    ],
    targets: [
        .target(
            name: "KeepTalkingSFUProtocol"
        ),
        .executableTarget(
            name: "KeepTalkingSFU",
            dependencies: [
                "KeepTalkingSFULib",
                "KeepTalkingSFUProtocol",
                .product(
                    name: "ArgumentParser",
                    package: "swift-argument-parser"
                ),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .target(
            name: "KeepTalkingSFULib",
            dependencies: [
                "KeepTalkingSFUProtocol",
                // Pulled in for `HTTP2KeepAliveHandler` — the only piece
                // SFULib needs to install on accepted child channels so
                // server-side liveness mirrors the client.
                "KeepTalkingSFUClient",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ]
        ),
        .target(
            name: "KeepTalkingSFUClient",
            dependencies: [
                "KeepTalkingSFUProtocol",
                .product(name: "Logging", package: "swift-log"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOHTTP2", package: "swift-nio-http2"),
                .product(name: "NIOHPACK", package: "swift-nio-http2"),
                .product(name: "NIOSSL", package: "swift-nio-ssl"),
                .product(name: "NIOFoundationCompat", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "KeepTalkingSFULibTests",
            dependencies: [
                "KeepTalkingSFULib",
                "KeepTalkingSFUProtocol",
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "KeepTalkingSFUClientTests",
            dependencies: [
                "KeepTalkingSFUClient",
                "KeepTalkingSFULib",
                "KeepTalkingSFUProtocol",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
            ]
        ),
    ]
)
