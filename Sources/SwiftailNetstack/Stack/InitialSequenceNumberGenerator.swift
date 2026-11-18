import CryptoKit
import SwiftailBase

/// A connection's ISN (RFC 6528 §3, RFC 9293 §3.4.1).
///
/// `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`. M is the clock component, increasing by 1 every
/// 4 microseconds from stack creation (MUST-8). F is the first 32 bits of
/// `HMAC-SHA256(secret, local address ‖ local port ‖ remote address ‖ remote port)` (contract behavior S7). F must be infeasible to compute without the secret (RFC 6528 §3, MUST-9). ISNs for the same 4-tuple increase over time, and ISNs for different 4-tuples cannot
/// be inferred from one another.
///
/// The secret is omitted from `description` and `dump` (contract behavior K1).
struct InitialSequenceNumberGenerator: Sendable, CustomStringConvertible, CustomReflectable {
    private let key: SymmetricKey
    private let origin: ContinuousClock.Instant

    init(secret: [UInt8], origin: ContinuousClock.Instant) {
        key = SymmetricKey(data: secret)
        self.origin = origin
    }

    /// Returns the ISN for a new connection between `local` and `remote`.
    func initialSequenceNumber(
        local: IPEndpoint, remote: IPEndpoint, at now: ContinuousClock.Instant
    ) -> SequenceNumber {
        var connectionID: [UInt8] = []
        connectionID.reserveCapacity(36)
        connectionID += local.address.bytes
        connectionID += [UInt8(truncatingIfNeeded: local.port >> 8), UInt8(truncatingIfNeeded: local.port)]
        connectionID += remote.address.bytes
        connectionID += [UInt8(truncatingIfNeeded: remote.port >> 8), UInt8(truncatingIfNeeded: remote.port)]
        let code = HMAC<SHA256>.authenticationCode(for: connectionID, using: key)
        let function = code.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
        return SequenceNumber(function).advanced(by: clockComponent(at: now))
    }

    /// M advances by 1 every 4 microseconds (4×10¹² attoseconds) from `origin` and wraps at 2³². Arithmetic does not
    /// overflow even if time goes backward.
    func clockComponent(at now: ContinuousClock.Instant) -> UInt32 {
        let (seconds, attoseconds) = (now - origin).components
        let ticks = UInt64(bitPattern: seconds) &* 250_000 &+ UInt64(bitPattern: attoseconds / 4_000_000_000_000)
        return UInt32(truncatingIfNeeded: ticks)
    }

    var description: String { "InitialSequenceNumberGenerator(secret redacted)" }

    var customMirror: Mirror { Mirror(self, children: [:]) }
}
