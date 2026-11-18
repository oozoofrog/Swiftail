import CryptoKit

/// A public key in Tailscale's text format, a prefix followed by 32 bytes in hexadecimal.
///
/// Each key purpose (machine, node, disco) has a distinct prefix and shares the same byte format. The type parameter lets the compiler
/// catch mistakes such as passing a machine key in place of a node key. `Kind` is a marker that is never used as a value.
///
/// JSON uses this text as a string. Go sends zero-filled keys for empty keys (`nodekey:0000…`),
/// so `zero` represents absence (`nil` is not used).
///
/// `docs/protocol-notes/control-transport.md` §5.1 (origin: tailscale.com `types/key`).
public struct PrefixedKey<Kind: KeyKind>: Hashable, Sendable {
    public static var byteCount: Int { 32 }

    /// The 32 key bytes.
    public let rawValue: [UInt8]

    /// Returns `nil` if the length differs from 32 bytes.
    public init?(rawValue: some Collection<UInt8>) {
        guard rawValue.count == Self.byteCount else { return nil }
        self.rawValue = Array(rawValue)
    }

    /// A key with all bytes set to 0. Represents "no key" on the wire.
    public static var zero: Self { Self(repeating: 0) }

    public var isZero: Bool { rawValue.allSatisfy { $0 == 0 } }

    private init(repeating byte: UInt8) {
        rawValue = [UInt8](repeating: byte, count: Self.byteCount)
    }

    /// Converts a CryptoKit public key to a prefixed key.
    public init(_ key: Curve25519.KeyAgreement.PublicKey) {
        // A Curve25519 public key's raw representation is always 32 bytes. Failure would violate CryptoKit's contract.
        guard let value = Self(rawValue: key.rawRepresentation) else {
            preconditionFailure("Curve25519 public keys are 32 bytes")
        }
        self = value
    }
}

extension PrefixedKey: LosslessStringConvertible {
    /// Accepts only the form `"nodekey:" + 64 hexadecimal digits`. Returns `nil` for a different prefix or length.
    public init?(_ description: String) {
        guard description.hasPrefix(Kind.prefix),
              let bytes = [UInt8](hex: String(description.dropFirst(Kind.prefix.count)))
        else { return nil }
        self.init(rawValue: bytes)
    }

    public var description: String { Kind.prefix + rawValue.hex }
}

extension PrefixedKey: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let text = try container.decode(String.self)
        guard let key = Self(text) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Expected a \(Kind.prefix) key")
        }
        self = key
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// A key's purpose. Determines the text prefix.
public protocol KeyKind: Sendable {
    static var prefix: String { get }
}

/// A key that identifies a device. Authenticates the Noise connection to the control server.
public enum MachineKeyKind: KeyKind { public static let prefix = "mkey:" }
/// A node's WireGuard key. Changes when it expires.
public enum NodeKeyKind: KeyKind { public static let prefix = "nodekey:" }
/// A key that encrypts path discovery (disco) messages. Created anew at every startup.
public enum DiscoKeyKind: KeyKind { public static let prefix = "discokey:" }
/// A one-time key the control server sends in the early payload.
public enum ChallengeKeyKind: KeyKind { public static let prefix = "chalpub:" }

public typealias MachinePublicKey = PrefixedKey<MachineKeyKind>
public typealias NodePublicKey = PrefixedKey<NodeKeyKind>
public typealias DiscoPublicKey = PrefixedKey<DiscoKeyKind>
public typealias ChallengePublicKey = PrefixedKey<ChallengeKeyKind>
