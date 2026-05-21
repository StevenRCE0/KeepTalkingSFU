import Foundation

/// TLS identity loader for the KeepTalkingSFU server.
///
/// **No private-key material is embedded in source.** Operators provide
/// a PKCS#12 bundle out-of-band (filesystem path, with passphrase via
/// env var or CLI flag). If nothing is configured the loader throws —
/// there is no silent fallback to a baked-in "lab" key.
///
/// Configuration surface, in order of precedence:
///   1. Explicit arguments to ``resolve(pkcs12Path:passphrase:)``
///   2. Environment variables ``envPathKey`` / ``envPassphraseKey``
///
/// Production deployments should mount the PKCS#12 via secrets manager,
/// systemd credential, or k8s Secret and pass the path through env.
public enum SFUServerTLSIdentity {
    public static let envPathKey = "KT_SFU_TLS_PKCS12_PATH"
    public static let envPassphraseKey = "KT_SFU_TLS_PASSPHRASE"

    public struct Resolved: Sendable {
        public let pkcs12Base64: String
        public let passphrase: String

        public init(pkcs12Base64: String, passphrase: String) {
            self.pkcs12Base64 = pkcs12Base64
            self.passphrase = passphrase
        }
    }

    public enum IdentityError: Swift.Error, CustomStringConvertible {
        case notConfigured
        case loadFailed(path: String, underlying: Swift.Error)

        public var description: String {
            switch self {
                case .notConfigured:
                    return """
                        SFU TLS identity not configured. Provide a PKCS#12 bundle via \
                        --pkcs12-path (or the \(SFUServerTLSIdentity.envPathKey) env var) \
                        and optionally a passphrase via --pkcs12-passphrase (or the \
                        \(SFUServerTLSIdentity.envPassphraseKey) env var).
                        """
                case let .loadFailed(path, underlying):
                    return "SFU TLS identity load failed (\(path)): \(underlying)"
            }
        }
    }

    public static func resolve(
        pkcs12Path: String? = nil,
        passphrase: String? = nil
    ) throws -> Resolved {
        let env = ProcessInfo.processInfo.environment
        let path = (pkcs12Path?.isEmpty == false ? pkcs12Path : nil)
            ?? env[envPathKey]
        let pass = (passphrase?.isEmpty == false ? passphrase : nil)
            ?? env[envPassphraseKey]
            ?? ""

        guard let path, !path.isEmpty else {
            throw IdentityError.notConfigured
        }

        let url = URL(fileURLWithPath: path)
        let bytes: Data
        do {
            bytes = try Data(contentsOf: url)
        } catch {
            throw IdentityError.loadFailed(path: path, underlying: error)
        }
        return Resolved(
            pkcs12Base64: bytes.base64EncodedString(),
            passphrase: pass
        )
    }
}
