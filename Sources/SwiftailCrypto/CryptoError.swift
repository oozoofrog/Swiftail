/// An error thrown by SwiftailCrypto.
public enum CryptoError: Error, Sendable, Equatable {
    /// The key, nonce, or ciphertext length differs from the specification. Also used when an Argon2i cost parameter (parallelism, passes, memory, or output length) is out of range.
    case invalidLength
    /// The authentication tag does not match.
    case authenticationFailed
    /// The X25519 result is all zeros (a low-order point).
    case invalidKey
}

/// Compares equal-length inputs in time independent of their contents. Returns `false` for different lengths.
public func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
    guard a.count == b.count else { return false }
    var diff: UInt8 = 0
    for i in 0..<a.count {
        diff |= a[i] ^ b[i]
    }
    return diff == 0
}
