import CryptoKit
import SwiftailCrypto

/// The four stages of a Noise IKpsk2 handshake, creating and opening the initiation and creating and opening the response.
///
/// Initiator I knows responder R's static public key in advance (IK). They authenticate each other and obtain two transport keys
/// in one round trip. Each stage is a pure function that takes inputs and returns the message and next state. Device-level decisions such as index assignment, peer lookup,
/// and replay checks belong to `WireGuardDevice`.
///
/// The transcript hash binds the peer across stages. Discard a message if any AEAD operation fails to open it.
///
/// Whitepaper §5.4.2–§5.4.5 and `docs/protocol-notes/wireguard.md`, from “Initiator creates an initiation”
/// through “Transport key derivation (`BeginSymmetricSession`)” (origin: wireguard-go `device/noise-protocol.go`).
enum Handshake {
    // shortcut: The PSK is fixed at 32 bytes of 0. Tailscale does not configure a PSK. Add it to peer configuration if a use case needs it.
    private static let presharedKey = [UInt8](repeating: 0, count: 32)

    /// Creates an initiation on the initiator side. `CookieGenerator` attaches the MACs separately.
    ///
    /// - Parameters:
    ///   - staticStaticSecret: Precomputed DH(S_i, S_r).
    ///   - ephemeral: A fresh ephemeral key for this attempt only. Generate one for each retry.
    /// - Returns: `nil` if DH with the peer's static key fails.
    static func makeInitiation(
        localStatic: Curve25519.KeyAgreement.PrivateKey,
        remoteStatic: PublicKey,
        staticStaticSecret: [UInt8],
        timestamp: TAI64N,
        localIndex: UInt32,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) -> (Initiation, PendingHandshake)? {
        var state = SymmetricState.initial
        state.mixHash(remoteStatic.rawValue)

        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        state.mixKey(ephemeralPublic)
        state.mixHash(ephemeralPublic)

        guard let es = sharedSecret(ephemeral, remoteStatic.rawValue) else { return nil }
        let staticKey = state.mixKeyAndDeriveKey(es)
        let encryptedStatic = state.encryptAndHash(Array(localStatic.publicKey.rawRepresentation), key: staticKey)

        let timestampKey = state.mixKeyAndDeriveKey(staticStaticSecret)
        let encryptedTimestamp = state.encryptAndHash(timestamp.bytes, key: timestampKey)

        let message = Initiation(
            sender: localIndex,
            ephemeral: ephemeralPublic,
            encryptedStatic: encryptedStatic,
            encryptedTimestamp: encryptedTimestamp
        )
        return (message, PendingHandshake(localIndex: localIndex, state: state, ephemeral: ephemeral))
    }

    /// Extracts the initiator's static public key from the initiation in responder stage 1.
    ///
    /// This stage by itself authenticates nothing. It identifies the claimed sender for peer lookup.
    static func openInitiation(_ message: Initiation, localStatic: Curve25519.KeyAgreement.PrivateKey) -> OpenedInitiation? {
        var state = SymmetricState.initial
        state.mixHash(Array(localStatic.publicKey.rawRepresentation))
        state.mixHash(message.ephemeral)
        state.mixKey(message.ephemeral)

        guard let es = sharedSecret(localStatic, message.ephemeral) else { return nil }
        let staticKey = state.mixKeyAndDeriveKey(es)
        guard let staticBytes = state.decryptAndHash(message.encryptedStatic, key: staticKey),
              let initiator = PublicKey(rawValue: staticBytes)
        else { return nil }
        return OpenedInitiation(initiator: initiator, message: message, state: state)
    }

    /// Opens the timestamp with static-static DH in responder stage 2. Success means the initiator holds that static private key.
    ///
    /// The caller performs timestamp replay and flood checks because they require peer state.
    static func authenticate(_ opened: OpenedInitiation, staticStaticSecret: [UInt8]) -> AuthenticatedInitiation? {
        var state = opened.state
        let timestampKey = state.mixKeyAndDeriveKey(staticStaticSecret)
        guard let timestampBytes = state.decryptAndHash(opened.message.encryptedTimestamp, key: timestampKey),
              let timestamp = TAI64N(bytes: timestampBytes)
        else { return nil }
        return AuthenticatedInitiation(
            initiator: opened.initiator,
            sender: opened.message.sender,
            ephemeral: opened.message.ephemeral,
            timestamp: timestamp,
            state: state
        )
    }

    /// Creates the response and immediately derives transport keys in responder stage 3.
    /// - Returns: `nil` if DH with the peer's ephemeral or static key fails.
    static func makeResponse(
        to initiation: AuthenticatedInitiation,
        localIndex: UInt32,
        ephemeral: Curve25519.KeyAgreement.PrivateKey
    ) -> (Response, SessionKeys)? {
        var state = initiation.state
        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        state.mixHash(ephemeralPublic)
        state.mixKey(ephemeralPublic)

        guard let ee = sharedSecret(ephemeral, initiation.ephemeral),
              let se = sharedSecret(ephemeral, initiation.initiator.rawValue)
        else { return nil }
        state.mixKey(ee)
        state.mixKey(se)

        let key = state.mixPresharedKey(presharedKey)
        let encryptedNothing = state.encryptAndHash([], key: key)

        let message = Response(
            sender: localIndex,
            receiver: initiation.sender,
            ephemeral: ephemeralPublic,
            encryptedNothing: encryptedNothing
        )
        let (receive, send) = state.split()
        return (message, SessionKeys(send: send, receive: receive))
    }

    /// Opens the response on the initiator side to authenticate the responder and derive transport keys. Returns `nil` on failure.
    static func consumeResponse(
        _ message: Response,
        pending: PendingHandshake,
        localStatic: Curve25519.KeyAgreement.PrivateKey
    ) -> SessionKeys? {
        var state = pending.state
        state.mixHash(message.ephemeral)
        state.mixKey(message.ephemeral)

        guard let ee = sharedSecret(pending.ephemeral, message.ephemeral),
              let se = sharedSecret(localStatic, message.ephemeral)
        else { return nil }
        state.mixKey(ee)
        state.mixKey(se)

        let key = state.mixPresharedKey(presharedKey)
        guard state.decryptAndHash(message.encryptedNothing, key: key) != nil else { return nil }
        let (send, receive) = state.split()
        return SessionKeys(send: send, receive: receive)
    }
}

/// The state the initiator holds while waiting for the response. It is discarded when a response arrives, a new initiation
/// replaces it, or key material is erased.
struct PendingHandshake {
    /// The initiation's sender field, returned as the response's receiver field.
    let localIndex: UInt32
    let state: SymmetricState
    let ephemeral: Curve25519.KeyAgreement.PrivateKey
}

/// An unauthenticated initiation with only its static key extracted.
struct OpenedInitiation {
    let initiator: PublicKey
    let message: Initiation
    let state: SymmetricState
}

/// An initiation whose timestamp was opened, authenticating the initiator.
struct AuthenticatedInitiation {
    let initiator: PublicKey
    let sender: UInt32
    let ephemeral: [UInt8]
    let timestamp: TAI64N
    let state: SymmetricState
}

/// The pair of transport keys derived from the handshake.
struct SessionKeys {
    let send: SymmetricKey
    let receive: SymmetricKey
}
