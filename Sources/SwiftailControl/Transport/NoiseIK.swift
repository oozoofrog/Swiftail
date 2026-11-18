import CryptoKit
import SwiftailBase

/// The two initiator steps of the control Noise handshake (Noise_IK_25519_ChaChaPoly_BLAKE2s).
///
/// The client already knows the server's static public key from `/key` (IK). One initiation and one response
/// authenticate both parties and yield a transport key for each direction. The pattern is `<- s ... -> e, es, s, ss <- e, ee, se`.
/// Each step is a pure function that takes keys and a message and returns a result. The ephemeral key is also an argument.
///
/// The protocol version appears in plaintext in the initiation header and is authenticated by mixing the prologue
/// `"Tailscale Control Protocol v<decimal>"` into the transcript. The message type and length header itself is excluded from the transcript.
///
/// `docs/protocol-notes/control-transport.md` §4.5 steps 1~16
/// (origin: `ClientDeferred` and `continueClientHandshake` in tailscale.com `control/controlbase/handshake.go`).
enum NoiseIK {
    static let protocolName = "Noise_IK_25519_ChaChaPoly_BLAKE2s"

    static func prologue(protocolVersion: UInt16) -> [UInt8] {
        Array("Tailscale Control Protocol v\(protocolVersion)".utf8)
    }

    /// Steps 1~8 construct initiation.
    ///
    /// - Parameter ephemeral: A fresh ephemeral key used only for this connection.
    /// - Returns: `nil` if DH (es, ss) with the server's static key is 0.
    static func makeInitiation(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        protocolVersion: UInt16,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) -> (HandshakeInitiation, PendingHandshake)? {
        var state = SymmetricState(protocolName: protocolName)
        state.mixHash(prologue(protocolVersion: protocolVersion))
        state.mixHash(serverKey.rawValue)

        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        state.mixHash(ephemeralPublic)
        guard let esKey = state.mixDH(ephemeral, serverKey.rawValue) else { return nil }
        let encryptedMachineKey = state.encryptAndHash(Array(machineKey.publicKey.rawRepresentation), key: esKey)

        guard let ssKey = state.mixDH(machineKey, serverKey.rawValue) else { return nil }
        let tag = state.encryptAndHash([], key: ssKey)

        let initiation = HandshakeInitiation(
            protocolVersion: protocolVersion,
            ephemeralPublicKey: ephemeralPublic,
            encryptedMachineKey: encryptedMachineKey,
            tag: tag
        )
        return (initiation, PendingHandshake(state: state, machineKey: machineKey, ephemeral: ephemeral))
    }

    /// Steps 11~15 open response, authenticate the server, and derive transport keys.
    ///
    /// - Returns: `nil` if DH (ee, se) is 0 or the tag does not match.
    static func consumeResponse(_ response: HandshakeResponse, pending: PendingHandshake) -> TransportKeys? {
        var state = pending.state
        state.mixHash(response.ephemeralPublicKey)
        // For ee, discard the key and update only ck.
        guard state.mixDH(pending.ephemeral, response.ephemeralPublicKey) != nil,
              let seKey = state.mixDH(pending.machineKey, response.ephemeralPublicKey),
              state.decryptAndHash(response.tag, key: seKey) != nil
        else { return nil }
        let (send, receive) = state.split()
        return TransportKeys(send: send, receive: receive)
    }
}

/// The state while waiting for response after sending initiation.
struct PendingHandshake: Sendable {
    let state: SymmetricState
    let machineKey: Curve25519.KeyAgreement.PrivateKey
    let ephemeral: Curve25519.KeyAgreement.PrivateKey
}

/// The transport keys produced by the handshake, one per direction.
struct TransportKeys: Sendable {
    let send: SymmetricKey
    let receive: SymmetricKey
}
