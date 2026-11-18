/// A reason a disco message could not be opened or parsed.
///
/// In every case the receiver discards the packet without a response (`docs/protocol-notes/disco-magicsock.md` 3.2 6).
/// `Magicsock` reports `unknownType` as unsupported (`Drop.unsupportedDisco`) and the rest as messages that could not be opened
/// or parsed (`Drop.malformedDisco`) (contract behavior C1).
enum DiscoError: Error, Sendable, Equatable {
    /// The length or format differs from the tables in notes 3.1, 3.3, and 3.4. Includes a sealed packet too short to contain a nonce and tag.
    case malformed
    /// The type is outside `0x01`–`0x03`. Includes peer relay types (`0x04`–`0x09`), which M4 does not handle.
    case unknownType(UInt8)
    /// The secretbox cannot be opened because the key differs or the nonce, tag, or ciphertext changed.
    case authenticationFailed
    /// The peer's low-order public key yields an all-zero X25519 shared secret.
    case invalidKey
}
