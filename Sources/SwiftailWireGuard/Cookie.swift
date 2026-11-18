import SwiftailCrypto

/// The mac1, mac2, and cookie for handshake messages.
///
/// Only someone who knows the receiver's public key can create mac1, so the receiver can filter out random packets
/// before the expensive DH. A receiver under load also requires mac2. The mac2 key is the cookie the receiver sent in a cookie reply,
/// which proves that the sender can actually receive a response at that source address.
///
/// The sender uses `CookieGenerator` and the receiver uses `CookieChecker`. `HandshakeLoad` and `RateLimiter` handle when
/// the receiver requires mac2 (load detection) and per-source rate limiting.
///
/// Whitepaper §5.4.4 and §5.4.7, `docs/protocol-notes/wireguard.md` "mac1, mac2, and cookies"
/// (origin: wireguard-go `device/cookie.go`).
enum MAC {
    static let size = 16

    /// MAC(key, data) = keyed BLAKE2s with 16 bytes of output. It is neither HMAC nor a truncated 256-bit result.
    static func authenticate(_ data: [UInt8], key: [UInt8]) -> [UInt8] {
        BLAKE2s.hash(data, outputByteCount: size, key: key)
    }

    /// mac1 key = HASH("mac1----" ‖ the receiver's public key).
    static func mac1Key(for receiver: PublicKey) -> [UInt8] {
        BLAKE2s.hash(Array("mac1----".utf8) + receiver.rawValue)
    }

    /// Cookie encryption key = HASH("cookie--" ‖ the receiver's public key).
    static func cookieKey(for receiver: PublicKey) -> [UInt8] {
        BLAKE2s.hash(Array("cookie--".utf8) + receiver.rawValue)
    }

    /// Checks mac1 on a received handshake message in constant time.
    static func isValidMAC1(_ macs: MessageMACs, over bytesBeforeMACs: [UInt8], key mac1Key: [UInt8]) -> Bool {
        constantTimeEqual(macs.mac1, authenticate(bytesBeforeMACs, key: mac1Key))
    }
}

/// Attaches MACs to handshake messages sent to a peer and stores the cookie it sends back
/// (wireguard-go's `CookieGenerator`).
struct CookieGenerator {
    private struct Cookie {
        let value: [UInt8]
        let received: ContinuousClock.Instant
    }

    private let mac1Key: [UInt8]
    private let cookieKey: [UInt8]
    /// The last mac1 sent. The cookie reply is encrypted with it as AAD.
    private var lastMAC1: [UInt8]?
    private var cookie: Cookie?

    init(peer: PublicKey) {
        mac1Key = MAC.mac1Key(for: peer)
        cookieKey = MAC.cookieKey(for: peer)
    }

    /// Creates mac1 ‖ mac2 to append to the message body.
    /// Computes mac2 only if there is a received cookie no older than `cookieRefreshTime`. Otherwise mac2 is 0.
    mutating func macs(for bytesBeforeMACs: [UInt8], at now: ContinuousClock.Instant) -> MessageMACs {
        let mac1 = MAC.authenticate(bytesBeforeMACs, key: mac1Key)
        lastMAC1 = mac1
        guard let cookie, now - cookie.received <= Constants.cookieRefreshTime else {
            return MessageMACs(mac1: mac1, mac2: [UInt8](repeating: 0, count: MAC.size))
        }
        return MessageMACs(mac1: mac1, mac2: MAC.authenticate(bytesBeforeMACs + mac1, key: cookie.value))
    }

    /// Opens a cookie reply and stores the cookie. If no mac1 has been sent or opening fails, returns `false` and leaves state unchanged.
    ///
    /// Uses the stored cookie starting with the next handshake message it creates. It does not immediately resend the rejected message.
    mutating func consume(_ reply: CookieReply, at now: ContinuousClock.Instant) -> Bool {
        guard let lastMAC1,
              let value = try? XChaCha20Poly1305.open(reply.encryptedCookie, key: cookieKey, nonce: reply.nonce, authenticating: lastMAC1)
        else { return false }
        cookie = Cookie(value: value, received: now)
        return true
    }
}

/// Checks mac2 on the receiving side under load and creates a cookie reply for the sender if mac2 is invalid
/// (the mac2 portion of wireguard-go's `CookieChecker`).
///
/// Cookie = MAC(secret, source). Only the receiver knows the secret, which rotates every `cookieRefreshTime` (120 seconds). Only a sender that can
/// actually receive replies at that source can obtain the cookie, and it can use it only briefly. The secret and cookie are hidden from `dump` and the debugger.
struct CookieChecker {
    private struct Secret {
        let value: [UInt8]
        let created: ContinuousClock.Instant
    }

    /// Cookie sealing key = HASH("cookie--" ‖ the device's own public key).
    private let cookieKey: [UInt8]
    /// Nil until a reply has been created. Until then mac2 is always invalid (like time 0 for `secretSet` in Go).
    private var secret: Secret?

    init(publicKey: PublicKey) {
        cookieKey = MAC.cookieKey(for: publicKey)
    }

    /// Checks in constant time whether the received message's mac2 was made with the cookie issued to this source.
    /// Returns false if there is no secret or more than 120 seconds have elapsed (the sender has also stopped using any cookie issued with that secret).
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

    /// Creates a cookie reply for a rejected handshake message (sender index `sender`, mac1 `mac1`).
    ///
    /// If there is no secret or it is older than 120 seconds, draws a new one using `generator` first. Seals the cookie with the rejected message's mac1 as AAD.
    /// Only the sender of that mac1 can open it, so observing or forging the reply cannot make it usable with another message.
    /// Sealing cannot fail because the key and nonce lengths are fixed. If it fails, returns nil.
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
    /// Exposes nothing, so `print` and `dump` cannot expand the secret.
    var customMirror: Mirror {
        Mirror(self, children: [:], displayStyle: .struct)
    }
}
