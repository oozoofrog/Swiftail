import SwiftailBase

/// Tailscale이 텍스트로 주고받는 공개 키: 접두사 + 32바이트의 16진수.
///
/// 키의 쓰임(machine, node, disco)마다 접두사가 다르고 바이트 형식은 같다. 쓰임을 타입 인자로 구분해
/// node 키 자리에 machine 키를 넣는 실수를 컴파일러가 잡게 한다. `Kind`는 값으로 쓰이지 않는 표지다.
///
/// JSON에서는 이 텍스트의 문자열이다. Go는 비어 있는 키도 생략하지 않고 0으로 채워 보내므로
/// (`nodekey:0000…`) "없음"은 `nil`이 아니라 `zero`로 나타낸다.
///
/// `docs/protocol-notes/control-transport.md` 5.1 (출처: tailscale.com `types/key`).
public struct PrefixedKey<Kind: KeyKind>: Hashable, Sendable {
    public static var byteCount: Int { 32 }

    /// 키 바이트 32개.
    public let rawValue: [UInt8]

    /// 32바이트가 아니면 `nil`.
    public init?(rawValue: some Collection<UInt8>) {
        guard rawValue.count == Self.byteCount else { return nil }
        self.rawValue = Array(rawValue)
    }

    /// 모든 바이트가 0인 키. 와이어에서 "키 없음"을 뜻한다.
    public static var zero: Self { Self(repeating: 0) }

    public var isZero: Bool { rawValue.allSatisfy { $0 == 0 } }

    private init(repeating byte: UInt8) {
        rawValue = [UInt8](repeating: byte, count: Self.byteCount)
    }
}

extension PrefixedKey: LosslessStringConvertible {
    /// `"nodekey:" + 64자리 16진수` 형태만 받는다. 접두사가 다르거나 길이가 다르면 `nil`.
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
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "\(Kind.prefix) 키가 아니다")
        }
        self = key
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// 키의 쓰임. 텍스트 접두사를 정한다.
public protocol KeyKind: Sendable {
    static var prefix: String { get }
}

/// 기기를 가리키는 키. 제어 서버와의 Noise 연결을 인증한다.
public enum MachineKeyKind: KeyKind { public static let prefix = "mkey:" }
/// 노드의 WireGuard 키. 만료되면 바뀐다.
public enum NodeKeyKind: KeyKind { public static let prefix = "nodekey:" }
/// 경로 탐색(disco) 메시지를 암호화하는 키. 시작할 때마다 새로 만든다.
public enum DiscoKeyKind: KeyKind { public static let prefix = "discokey:" }
/// 제어 서버가 early payload로 보내는 일회용 키.
public enum ChallengeKeyKind: KeyKind { public static let prefix = "chalpub:" }

public typealias MachinePublicKey = PrefixedKey<MachineKeyKind>
public typealias NodePublicKey = PrefixedKey<NodeKeyKind>
public typealias DiscoPublicKey = PrefixedKey<DiscoKeyKind>
public typealias ChallengePublicKey = PrefixedKey<ChallengeKeyKind>
