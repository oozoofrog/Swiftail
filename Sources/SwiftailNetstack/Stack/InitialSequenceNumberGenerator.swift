import CryptoKit
import SwiftailBase

/// 연결의 ISN(RFC 6528 3, RFC 9293 3.4.1).
///
/// `ISN = M + F(localip, localport, remoteip, remoteport, secretkey)`. M은 스택을 만든 시각부터 4마이크로초마다 1씩 느는
/// 시계 성분이고(MUST-8), F는 `HMAC-SHA256(비밀, 자기 주소 ‖ 자기 포트 ‖ 상대 주소 ‖ 상대 포트)`의 앞 32비트다(계약 동작 S7).
/// F는 비밀 없이 밖에서 계산할 수 없어야 한다(RFC 6528 3, MUST-9). 같은 4-튜플의 ISN은 시간에 따라 늘고, 다른 4-튜플의
/// ISN은 서로 짐작할 수 없다.
///
/// 비밀은 `description`·`dump`에 나오지 않는다(계약 동작 K1).
struct InitialSequenceNumberGenerator: Sendable, CustomStringConvertible, CustomReflectable {
    private let key: SymmetricKey
    private let origin: ContinuousClock.Instant

    init(secret: [UInt8], origin: ContinuousClock.Instant) {
        key = SymmetricKey(data: secret)
        self.origin = origin
    }

    /// `local`과 `remote` 사이의 새 연결에 쓸 ISN.
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

    /// M: `origin`부터 4마이크로초(4×10¹² 아토초)마다 1. 2³²에서 돈다. 시각이 거꾸로 가도 죽지 않는다(넘치지 않는 산술).
    func clockComponent(at now: ContinuousClock.Instant) -> UInt32 {
        let (seconds, attoseconds) = (now - origin).components
        let ticks = UInt64(bitPattern: seconds) &* 250_000 &+ UInt64(bitPattern: attoseconds / 4_000_000_000_000)
        return UInt32(truncatingIfNeeded: ticks)
    }

    var description: String { "InitialSequenceNumberGenerator(비밀 숨김)" }

    var customMirror: Mirror { Mirror(self, children: [:]) }
}
