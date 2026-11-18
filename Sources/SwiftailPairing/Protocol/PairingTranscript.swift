import CryptoKit
import Foundation
import SwiftailBase

/// The endpoints of one pairing connection. Both sides see the same four values because addresses do not change inside the tailnet.
struct PairingEndpoints: Sendable, Equatable {
    /// The joiner's (J) address and port.
    var joiner: IPEndpoint
    /// The host's (H) address and port.
    var host: IPEndpoint

    /// Checks whether an OS socket connection can be treated as having traversed the tunnel (contract behavior J2). The local endpoint must be this device's
    /// tailnet address, `localAddress`, and the remote endpoint must be in the same tailnet ranges used by the engine.
    ///
    /// The OS socket joiner relies on the OS for name resolution and routing. A range check alone would allow connections leaving through a local
    /// network that uses the same range (carrier NAT or router) while the tunnel is off. WireGuard did not authenticate that connection, so withhold
    /// hello. Compare the local endpoint with the app-supplied value to determine whether it is the tunnel address.
    func isOnTailnet(localAddress: IPAddress) -> Bool {
        isLocal(localAddress) && Self.isTailnetAddress(host.address)
    }

    /// Checks whether the local endpoint is `address`. Treats IPv4 and its IPv4-mapped IPv6 form as the same address.
    func isLocal(_ address: IPAddress) -> Bool {
        joiner.address.mapped == address.mapped
    }

    static func isTailnetAddress(_ address: IPAddress) -> Bool {
        address.unmappedIPv4.isTailscaleAddress
    }
}

extension IPAddress {
    fileprivate static let mappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]

    /// Converts IPv4-mapped IPv6 to IPv4 so the same range rules apply.
    var unmappedIPv4: IPAddress {
        guard bytes.starts(with: Self.mappedPrefix) else { return self }
        return IPAddress(bytes: bytes.suffix(4)) ?? self
    }

    /// The 16-byte representation. IPv4 uses IPv4-mapped IPv6 (`::ffff:a.b.c.d`). T uses this representation.
    fileprivate var mapped: [UInt8] {
        isIPv4 ? Self.mappedPrefix + bytes : bytes
    }
}

/// Transcript P, to which `proof` is applied. It includes everything established before the host nonce is revealed (contract §5).
///
/// ```
/// P = commitJ ‖ commitH ‖ nonceJ ‖ SHA256(offer host) ‖ offer port(2) ‖ SHA256(device name) ‖ J address(16)
///     ‖ J port(2) ‖ H address(16) ‖ H port(2)                                             198 bytes
/// ```
///
/// Binds the endpoints as seen by both sides. A node relaying bytes in the middle makes the two sides see different endpoints and thus different P
/// values, so one side's `proof` fails on the other. nonceH is absent because the joiner sends proof without it.
struct PairingProofTranscript: Sendable, Equatable {
    /// The length of P.
    static let length = 198

    let bytes: [UInt8]
    /// The commitH from `challenge`, as received by the joiner or sent by the host.
    private let hostCommitment: [UInt8]

    /// - Parameters:
    ///   - joinerNonce: The revealed nonceJ. The host first checks that the value matches the `hello` commitment.
    ///   - hostCommitment: commitH, the commitment to the host nonce.
    init(
        joinerNonce: [UInt8], hostCommitment: [UInt8], offerHost: String, offerPort: UInt16, deviceName: [UInt8],
        endpoints: PairingEndpoints
    ) {
        self.hostCommitment = hostCommitment
        bytes = PairingTranscript.commitment(toJoinerNonce: joinerNonce) + hostCommitment + joinerNonce
            + SHA256.hash(data: Data(offerHost.utf8)) + offerPort.bigEndianBytes
            + SHA256.hash(data: Data(deviceName))
            + endpoints.joiner.address.mapped + endpoints.joiner.port.bigEndianBytes
            + endpoints.host.address.mapped + endpoints.host.port.bigEndianBytes
    }

    /// The HMAC for J→H `proof`, showing that the joiner knows the secret.
    func proof(secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-3 joiner", bytes, secret: secret)
    }

    /// Transcript T after revealing the host nonce. Returns nil if `hostNonce` fails to match commitH, so a nonce selected after sending
    /// challenge cannot produce T.
    func opened(with hostNonce: [UInt8]) -> PairingTranscript? {
        // The commitment and nonce are on the wire, so comparison need not be constant-time.
        guard PairingTranscript.commitment(toHostNonce: hostNonce) == hostCommitment else { return nil }
        return PairingTranscript(bytes: bytes + hostNonce)
    }
}

/// Transcript T after both nonces are revealed, and the three values computed over T with the offer secret (contract §5).
///
/// ```
/// T = P ‖ nonceH                                                                            230 bytes
/// ```
///
/// The SAS is about 20 bits. A side that could choose its own nonce after seeing the peer's nonce could try values until it obtains the desired
/// number. Commitments therefore fix both nonces first. The joiner includes commitJ in `hello` and reveals nonceJ in `proof`. The
/// host includes commitH in `challenge` and reveals nonceH in `accepted` only after a valid `proof` uses the offer. Even someone who knows the secret
/// must use the offer to see the SAS, so they cannot repeatedly redial to get a number they like.
///
/// Each value has a distinct tag (`swiftail-pairing-3 …`) to prevent substitution. The commitments also use distinct tags so one side cannot reflect the peer's
/// commitment back as its own.
struct PairingTranscript: Sendable, Equatable {
    /// The length of T.
    static let length = PairingProofTranscript.length + PairingMessage.nonceLength

    let bytes: [UInt8]

    /// The joiner nonce commitment, commitJ = SHA256("swiftail-pairing-3 commit joiner" ‖ nonceJ).
    static func commitment(toJoinerNonce nonce: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(Array("swiftail-pairing-3 commit joiner".utf8) + nonce)))
    }

    /// The host nonce commitment, commitH = SHA256("swiftail-pairing-3 commit host" ‖ nonceH).
    static func commitment(toHostNonce nonce: [UInt8]) -> [UInt8] {
        Array(SHA256.hash(data: Data(Array("swiftail-pairing-3 commit host".utf8) + nonce)))
    }

    /// Created only by `PairingProofTranscript.opened(with:)`. T exists only when nonceH matches its commitment.
    fileprivate init(bytes: [UInt8]) {
        self.bytes = bytes
    }

    /// The HMAC for H→J `accepted`, showing that the host knows the secret.
    func accepted(secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-3 host", bytes, secret: secret)
    }

    /// The HMAC appended to `decision`'s `body`. It shows that the sender of the decision knows the secret.
    func decisionCode(for body: [UInt8], secret: [UInt8]) -> [UInt8] {
        authenticate("swiftail-pairing-3 decision", bytes + body, secret: secret)
    }

    /// The 6-digit SAS displayed on both screens. The user approves when the numbers on both screens match (contract behavior P5).
    func confirmationCode(secret: [UInt8]) -> String {
        let code = authenticate("swiftail-pairing-3 sas", bytes, secret: secret)
        let number = code.prefix(4).reduce(UInt32(0)) { $0 << 8 | UInt32($1) } % 1_000_000
        let digits = String(number)
        return String(repeating: "0", count: 6 - digits.count) + digits
    }
}

/// HMAC-SHA256(secret, tag ‖ message).
private func authenticate(_ label: String, _ message: [UInt8], secret: [UInt8]) -> [UInt8] {
    Array(HMAC<SHA256>.authenticationCode(for: Array(label.utf8) + message, using: SymmetricKey(data: secret)))
}

extension UInt16 {
    /// Two bytes in big-endian order.
    var bigEndianBytes: [UInt8] { [UInt8(self >> 8), UInt8(truncatingIfNeeded: self)] }
}
