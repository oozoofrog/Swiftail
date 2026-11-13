/// SwiftailCrypto가 던지는 오류.
public enum CryptoError: Error, Sendable, Equatable {
    /// 키·nonce·암호문 길이가 규격과 다르다.
    case invalidLength
    /// 인증 태그가 일치하지 않는다.
    case authenticationFailed
    /// X25519 결과가 전부 0이다(저차 점).
    case invalidKey
}

/// 길이가 같으면 내용과 무관한 시간에 비교한다. 길이가 다르면 `false`.
public func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count {
        diff |= a[i] ^ b[i]
    }
    return diff == 0
}
