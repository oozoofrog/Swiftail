import SwiftailBase
import SwiftailCrypto

/// The disco message envelope, including detection, sender key extraction, sealing, and opening.
///
/// The envelope is `magic(6) ‖ sender disco public key(32) ‖ nonce(24) ‖ secretbox(plaintext)` (notes 3.1). The magic and sender key are
/// not cryptographically bound. The sender key only selects the shared key to open with and becomes trusted after successful opening.
/// Takes randomness (the nonce) as an argument. Only the outer layer draws system randomness.
///
/// `docs/protocol-notes/disco-magicsock.md` §§3.1 and 3.2, 4.1 3
/// (origin: tailscale.com `disco/disco.go` and `types/key/disco.go`, BSD-3-Clause).
enum DiscoPacket {
    /// `"TS💬"`.
    static let magic: [UInt8] = [0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC]
    /// The minimum length for recognizing disco covers the magic and sender key (notes 4.1 3). Go's `LooksLikeDiscoWrapper` uses 62 bytes instead.
    static let classificationLength = 38

    private static let senderKeyRange = 6..<38
    private static let nonceRange = 38..<62
    private static let sealedStart = 62
    /// The minimum length for opening a packet covers the 62-byte header and 16-byte tag.
    private static let minimumOpenableLength = sealedStart + NaClSecretBox.overhead

    /// Whether the length is ≥ 38 and starts with magic. Does not try to open it.
    static func isDisco(_ bytes: [UInt8]) -> Bool {
        bytes.count >= classificationLength && bytes.starts(with: magic)
    }

    /// The sender's disco public key (offset 6..<38). Present only if `isDisco` is true.
    static func senderKey(of bytes: [UInt8]) -> DiscoPublicKey? {
        guard isDisco(bytes) else { return nil }
        return DiscoPublicKey(rawValue: bytes[senderKeyRange])
    }

    /// Creates `magic ‖ sender ‖ nonce ‖ secretbox(plaintext)`. The nonce must be 24 bytes (otherwise it traps as a programming error).
    static func seal(_ message: DiscoMessage, sender: DiscoPublicKey, sharedKey: DiscoSharedKey, nonce: [UInt8]) -> [UInt8] {
        magic + sender.rawValue + nonce + sharedKey.seal(message.plaintext, nonce: nonce)
    }

    /// Opens the envelope and parses the message. Parses only plaintext that was successfully opened.
    ///
    /// - Throws: `malformed` if it is not recognizable as disco (under 38 bytes or magic mismatch), is too short for the nonce and tag (under 78 bytes),
    ///   or the opened plaintext has the wrong format. `authenticationFailed` if opening fails. `unknownType` for an unsupported type.
    static func open(_ bytes: [UInt8], sharedKey: DiscoSharedKey) throws(DiscoError) -> DiscoMessage {
        guard isDisco(bytes), bytes.count >= minimumOpenableLength else { throw .malformed }
        let plaintext = try sharedKey.open(bytes[sealedStart...], nonce: Array(bytes[nonceRange]))
        return try DiscoMessage(parsing: plaintext)
    }
}
