/// A reason why `WireGuardDevice` rejected a datagram or IP packet.
///
/// wireguard-go silently discards these inputs. Here, the reason is returned so the caller can record metrics or logs.
/// None of these cases sends anything to the peer (a cookie reply under load is an output, rather than an error).
///
/// `send` or `receive` throws the error, or it is carried in `WireGuardDevice.Output.rejectedIPPacket`
/// when discarding an IP packet inside authenticated transport.
public enum WireGuardError: Error, Sendable, Equatable {
    /// The length, type, or reserved bytes differ from the specification. Includes an invalid header in the decrypted IP packet.
    case malformed
    /// An unregistered peer or an unknown receiver index.
    case unknownPeer
    /// An invalid mac1 or AEAD tag.
    case authenticationFailed
    /// A handshake timestamp or flood check, an already consumed response, or reuse of a transport counter.
    case replayed
    /// No usable keypair (including expiration).
    case noSession
    /// The decrypted IP packet's source address is outside the peer's AllowedIPs. Appears only as `rejectedIPPacket`.
    case disallowedSource
    /// The outgoing IP packet is larger than one transport message can hold.
    case packetTooLarge
    /// mac2 was valid under load, but the source host exceeded its processing allowance (20 per second, burst of 5).
    case rateLimited
}
