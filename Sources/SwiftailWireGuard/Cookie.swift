import SwiftailCrypto

/// 핸드셰이크 메시지의 mac1·mac2와 cookie.
///
/// mac1은 받는 쪽의 공개 키를 아는 사람만 만들 수 있으므로, 받는 쪽은 비싼 DH 전에 무작위 패킷을
/// 걸러 낸다. 부하 상태의 받는 쪽은 mac2도 요구한다. mac2의 키는 받는 쪽이 cookie reply로 준
/// cookie이며, 보낸 쪽이 그 출발 주소에서 실제로 응답을 받을 수 있음을 증명한다.
///
/// 이 모듈은 cookie를 **받아서 쓰는** 쪽만 구현한다.
/// shortcut: cookie reply를 보내는 쪽(부하 판정, mac2 검사, rate limiter)은 없다. 신뢰할 수 없는 네트워크에 UDP 포트를 여는 M4에서 올린다.
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
