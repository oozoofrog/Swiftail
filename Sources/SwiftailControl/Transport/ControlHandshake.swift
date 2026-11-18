import CryptoKit
import SwiftailBase

/// The initiator of the control Noise handshake (Noise_IK_25519_ChaChaPoly_BLAKE2s).
///
/// Calculates initiation at initialization (to place in the upgrade request header), then reads response from bytes
/// sent by the server after the 101 response. On opening response, returns the transport-phase `ControlSession` and any bytes
/// that followed it in the same read (usually early payload or records containing HTTP/2).
///
/// Holds no socket or clock. A connection that ends before response arrives (EOF after 101) fails the handshake. The server
/// sometimes closes the connection without an error message on handshake failure.
///
/// `docs/protocol-notes/control-transport.md` §4.4 step 2, §4.5 steps 9~16
/// (origin: tailscale.com `control/controlbase/handshake.go`).
public struct ControlHandshake: Sendable {
    /// The 101 initiation bytes to send to the server.
    public let initiation: [UInt8]

    private var state: State
    private var received: [UInt8] = []

    private enum State: Sendable {
        case awaitingResponse(PendingHandshake)
        case done
    }

    /// Generates an ephemeral key using system randomness and computes initiation.
    ///
    /// - Parameters:
    ///   - machineKey: This device's machine private key.
    ///   - serverKey: The server's Noise public key (`publicKey`) received from `/key`.
    ///   - protocolVersion: The capability version. Included in the prologue and initiation header.
    /// - Throws: `handshakeFailed` if the server key is a low-order point and the shared secret is 0. No initiation is available to send.
    public init(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        protocolVersion: UInt16 = 148
    ) throws(ControlTransportError) {
        try self.init(machineKey: machineKey, serverKey: serverKey, protocolVersion: protocolVersion, ephemeral: Curve25519.KeyAgreement.PrivateKey())
    }

    /// Accepts an ephemeral key as an argument. Used for fixed-vector tests.
    init(
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        protocolVersion: UInt16,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) throws(ControlTransportError) {
        guard let (message, pending) = NoiseIK.makeInitiation(
            machineKey: machineKey,
            serverKey: serverKey,
            protocolVersion: protocolVersion,
            ephemeral: ephemeral
        ) else { throw .handshakeFailed }
        initiation = message.bytes
        state = .awaitingResponse(pending)
    }

    /// Accepts bytes from the server. Returns nil until response arrives in full.
    /// When complete, returns the transport-phase session and bytes already received after response.
    ///
    /// - Throws: `handshakeFailed` if response cannot be opened or the server sent an error message, `malformed` for an invalid type
    ///   or length, or `closed` after returning a session or failing.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> (session: ControlSession, remainder: [UInt8])? {
        guard case .awaitingResponse(let pending) = state else { throw .closed }

        received += bytes
        do throws(ControlTransportError) {
            guard let response = try HandshakeResponse(parsingPrefixOf: received) else { return nil }
            guard let keys = NoiseIK.consumeResponse(response, pending: pending) else { throw .handshakeFailed }
            let remainder = Array(received[HandshakeResponse.size...])
            state = .done
            received = []
            return (ControlSession(keys: keys), remainder)
        } catch {
            state = .done
            received = []
            throw error
        }
    }
}

extension ControlHandshake: CustomReflectable {
    /// Exposes nothing to `dump` or `print` because it holds long-term keys, ephemeral keys, and the chaining key.
    public var customMirror: Mirror { Mirror(self, children: [:]) }
}
