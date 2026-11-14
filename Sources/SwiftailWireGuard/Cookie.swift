import SwiftailCrypto

/// 핸드셰이크 메시지의 mac1·mac2와 cookie.
///
/// mac1은 받는 쪽의 공개 키를 아는 사람만 만들 수 있으므로, 받는 쪽은 비싼 DH 전에 무작위 패킷을
/// 걸러 낸다. 부하 상태의 받는 쪽은 mac2도 요구한다. mac2의 키는 받는 쪽이 cookie reply로 준
/// cookie이며, 보낸 쪽이 그 출발 주소에서 실제로 응답을 받을 수 있음을 증명한다.
///
/// 보내는 쪽은 `CookieGenerator`, 받는 쪽은 `CookieChecker`다. 받는 쪽이 언제 mac2를 요구하는지(부하 판정)와
/// 출처별 속도 제한은 `HandshakeLoad`·`RateLimiter`가 맡는다.
///
/// 백서 §5.4.4·§5.4.7, `docs/protocol-notes/wireguard.md` "mac1·mac2와 cookie"
/// (출처: wireguard-go `device/cookie.go`).
enum MAC {
    static let size = 16

    /// MAC(key, data) = keyed BLAKE2s, 출력 16바이트. HMAC이 아니며 256비트 결과를 자른 것도 아니다.
    static func authenticate(_ data: [UInt8], key: [UInt8]) -> [UInt8] {
        BLAKE2s.hash(data, outputByteCount: size, key: key)
    }

    /// mac1 키 = HASH("mac1----" ‖ 받는 쪽 공개 키).
    static func mac1Key(for receiver: PublicKey) -> [UInt8] {
        BLAKE2s.hash(Array("mac1----".utf8) + receiver.rawValue)
    }

    /// cookie 암호 키 = HASH("cookie--" ‖ 받는 쪽 공개 키).
    static func cookieKey(for receiver: PublicKey) -> [UInt8] {
        BLAKE2s.hash(Array("cookie--".utf8) + receiver.rawValue)
    }

    /// 받은 핸드셰이크 메시지의 mac1이 맞는지 상수 시간으로 확인한다.
    static func isValidMAC1(_ macs: MessageMACs, over bytesBeforeMACs: [UInt8], key mac1Key: [UInt8]) -> Bool {
        constantTimeEqual(macs.mac1, authenticate(bytesBeforeMACs, key: mac1Key))
    }
}

/// 한 피어에게 보내는 핸드셰이크 메시지에 MAC을 붙이고, 그 피어가 보낸 cookie를 보관한다
/// (wireguard-go의 `CookieGenerator`).
struct CookieGenerator {
    private struct Cookie {
        let value: [UInt8]
        let received: ContinuousClock.Instant
    }

    private let mac1Key: [UInt8]
    private let cookieKey: [UInt8]
    /// 마지막으로 보낸 mac1. cookie reply는 이것을 AAD로 암호화되어 온다.
    private var lastMAC1: [UInt8]?
    private var cookie: Cookie?

    init(peer: PublicKey) {
        mac1Key = MAC.mac1Key(for: peer)
        cookieKey = MAC.cookieKey(for: peer)
    }

    /// 메시지 본문에 붙일 mac1 ‖ mac2를 만든다.
    /// mac2는 받은 지 `cookieRefreshTime`이 지나지 않은 cookie가 있을 때만 계산하고, 아니면 0이다.
    mutating func macs(for bytesBeforeMACs: [UInt8], at now: ContinuousClock.Instant) -> MessageMACs {
        let mac1 = MAC.authenticate(bytesBeforeMACs, key: mac1Key)
        lastMAC1 = mac1
        guard let cookie, now - cookie.received <= Constants.cookieRefreshTime else {
            return MessageMACs(mac1: mac1, mac2: [UInt8](repeating: 0, count: MAC.size))
        }
        return MessageMACs(mac1: mac1, mac2: MAC.authenticate(bytesBeforeMACs + mac1, key: cookie.value))
    }

    /// cookie reply를 열어 cookie를 보관한다. 보낸 mac1이 없거나 열리지 않으면 `false`이고 상태는 그대로다.
    ///
    /// 보관한 cookie는 다음에 만드는 핸드셰이크 메시지부터 쓴다. 거절된 메시지를 곧바로 다시 보내지는 않는다.
    mutating func consume(_ reply: CookieReply, at now: ContinuousClock.Instant) -> Bool {
        guard let lastMAC1,
              let value = try? XChaCha20Poly1305.open(reply.encryptedCookie, key: cookieKey, nonce: reply.nonce, authenticating: lastMAC1)
        else { return false }
        cookie = Cookie(value: value, received: now)
        return true
    }
}

/// 부하 상태의 받는 쪽: mac2를 검사하고, 맞지 않으면 보낸 쪽에 cookie reply를 만든다
/// (wireguard-go의 `CookieChecker`의 mac2 부분).
///
/// cookie = MAC(비밀, 출처)다. 비밀은 받는 쪽만 알고 `cookieRefreshTime`(120초)마다 바뀌므로, cookie는 그 출처에서
/// 실제로 답장을 받을 수 있는 쪽만 얻고 오래 쓰지 못한다. 비밀과 cookie는 `dump`·디버거에 나오지 않는다.
struct CookieChecker {
    private struct Secret {
        let value: [UInt8]
        let created: ContinuousClock.Instant
    }

    /// cookie를 봉하는 키 = HASH("cookie--" ‖ 자기 공개 키).
    private let cookieKey: [UInt8]
    /// 아직 reply를 만든 적이 없으면 nil이다. 그동안 mac2는 늘 틀리다(Go의 0 시각 `secretSet`과 같다).
    private var secret: Secret?

    init(publicKey: PublicKey) {
        cookieKey = MAC.cookieKey(for: publicKey)
    }

    /// 받은 메시지의 mac2가 이 출처에 준 cookie로 만든 것인지 상수 시간으로 확인한다.
    /// 비밀이 없거나 120초를 넘었으면 거짓이다(그 비밀로 준 cookie는 보낸 쪽도 이미 쓰지 않는다).
    func isValidMAC2(
        _ macs: MessageMACs,
        over bytesBeforeMACs: [UInt8],
        from source: WireGuardDevice.Source,
        at now: ContinuousClock.Instant
    ) -> Bool {
        guard let secret, now - secret.created <= Constants.cookieRefreshTime else { return false }
        let cookie = MAC.authenticate(source.address, key: secret.value)
        return constantTimeEqual(macs.mac2, MAC.authenticate(bytesBeforeMACs + macs.mac1, key: cookie))
    }

    /// 거절한 핸드셰이크 메시지(보낸 쪽 index `sender`, mac1 `mac1`)에 답할 cookie reply를 만든다.
    ///
    /// 비밀이 없거나 120초를 넘었으면 먼저 `generator`로 새로 뽑는다. cookie는 거절한 메시지의 mac1을 AAD로 봉한다.
    /// 그 mac1을 보낸 쪽만 열 수 있으므로 reply를 엿보거나 꾸며도 다른 메시지에 쓸 수 없다.
    /// 봉하기는 키·nonce 길이가 고정이라 실패하지 않지만, 실패하면 nil이다.
    mutating func makeReply(
        to sender: UInt32,
        mac1: [UInt8],
        from source: WireGuardDevice.Source,
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> CookieReply? {
        let secret: Secret
        if let current = self.secret, now - current.created <= Constants.cookieRefreshTime {
            secret = current
        } else {
            secret = Secret(value: Self.randomBytes(32, using: &generator), created: now)
            self.secret = secret
        }
        let cookie = MAC.authenticate(source.address, key: secret.value)
        let nonce = Self.randomBytes(XChaCha20Poly1305.nonceByteCount, using: &generator)
        guard let sealed = try? XChaCha20Poly1305.seal(cookie, key: cookieKey, nonce: nonce, authenticating: mac1) else { return nil }
        return CookieReply(receiver: sender, nonce: nonce, encryptedCookie: sealed)
    }

    private static func randomBytes(_ count: Int, using generator: inout some RandomNumberGenerator) -> [UInt8] {
        (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }
}

extension CookieChecker: CustomReflectable {
    /// 비밀이 `print`·`dump`에 펼쳐지지 않게 아무것도 보이지 않는다.
    var customMirror: Mirror {
        Mirror(self, children: [:], displayStyle: .struct)
    }
}
