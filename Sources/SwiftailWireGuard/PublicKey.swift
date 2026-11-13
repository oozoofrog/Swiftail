import CryptoKit
import SwiftailBase

/// Curve25519 공개 키 32바이트. 피어를 가리키는 이름으로 쓴다.
///
/// 공개 키는 비밀이 아니므로 `==`과 해시는 보통 비교로 충분하다.
public struct PublicKey: Hashable, Sendable, CustomStringConvertible {
    /// 키 바이트 32개.
    public let rawValue: [UInt8]

    /// 32바이트가 아니면 `nil`.
    public init?(rawValue: some Collection<UInt8>) {
        let bytes = Array(rawValue)
        guard bytes.count == 32 else { return nil }
        self.rawValue = bytes
    }

    /// 로그용 짧은 표기. 앞 8자리 16진 + "…".
    public var description: String { String(rawValue.hex.prefix(8)) + "…" }

    /// CryptoKit 공개 키는 늘 32바이트이므로 길이 검사가 필요 없다.
    init(_ key: Curve25519.KeyAgreement.PublicKey) {
        rawValue = Array(key.rawRepresentation)
    }
}
