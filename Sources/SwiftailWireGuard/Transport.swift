/// Encryption, decryption, and padding for transport messages.
///
/// Pad each IP packet with 0 to a multiple of 16 bytes to obscure its length, then encrypt it with the keypair's send key and counter.
/// A transport message with empty plaintext is a keepalive.
///
/// Whitepaper §5.4.6 and `docs/protocol-notes/wireguard.md`, “Sending transport data” and “Receiving transport data”
/// (origin: wireguard-go `device/send.go`, `device/receive.go`).
extension Keypair {
    /// Encrypts the packet with the next counter. The caller checks `canSend(at:)` first.
    ///
    /// - Returns: The complete outgoing datagram (16-byte header + ciphertext + tag). One array is allocated once and filled.
    ///   If no padding is needed (a multiple of 16), encrypts the packet directly without copying it.
    // shortcut: Copies once from the `SealedBox` returned by CryptoKit into the datagram. There is no API to encrypt directly into the caller's buffer. Upgrade if measurements on a real device identify this as a bottleneck.
    mutating func seal(_ packet: [UInt8]) -> [UInt8] {
        let counter = sendNonce
        sendNonce += 1
        let padding = Self.paddingSize(for: packet.count, mtu: Constants.defaultMTU)
        let plaintext = padding == 0 ? packet : packet + [UInt8](repeating: 0, count: padding)
        var datagram = TransportData.header(
            receiver: remoteIndex,
            counter: counter,
            capacity: TransportData.headerSize + plaintext.count + AEAD.tagSize
        )
        AEAD.seal(plaintext, key: sendKey, counter: counter, appendingTo: &datagram)
        return datagram
    }

    /// Decrypts the message. After authentication, `replayFilter` checks for replays separately.
    func open(_ message: TransportData) -> [UInt8]? {
        AEAD.open(message.encryptedPacket, key: receiveKey, counter: message.counter)
    }

    /// Implements wireguard-go's `calculatePaddingSize`. For packets larger than the MTU, calculate padding from the remainder modulo the MTU.
    /// Cap the padded size of that final portion at the MTU. A keepalive (0 bytes) needs no padding.
    static func paddingSize(for packetSize: Int, mtu: Int) -> Int {
        let multiple = Constants.paddingMultiple
        let lastUnit = packetSize > mtu ? packetSize % mtu : packetSize
        let padded = min((lastUnit + multiple - 1) / multiple * multiple, mtu)
        return padded - lastUnit
    }
}
