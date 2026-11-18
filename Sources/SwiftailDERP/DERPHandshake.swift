import CryptoKit
import Foundation
import SwiftailCrypto

/// The pure DERP handshake steps: request an upgrade, verify ServerKey, seal ClientInfo, and open ServerInfo.
///
/// Uses no socket, clock, or randomness. The nonce is an argument, and system randomness is drawn only at the edge (`DERPClient`).
///
/// `docs/protocol-notes/derp-stun.md` §3.3~§3.5, §3.7, §4.3
/// (origin: tailscale.com `derp/derp_client.go` and `types/key/node.go`, BSD-3-Clause).
enum DERPHandshake {
    /// The first 8 bytes of the ServerKey body are `"DERP🔑"`.
    static let serverKeyMagic: [UInt8] = [0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91]
    /// The ServerKey body limit, matching the Go client. Bytes after the first 40 are for future extensions and are discarded.
    static let maximumServerKeyBody = 1024
    static let nonceSize = 24
    /// The client advertises protocol version 2 and the ability to answer Ping.
    private static let clientInfoJSON = Array(#"{"version":2,"CanAckPings":true}"#.utf8)

    /// A `GET /derp` upgrade request. Sends no `User-Agent`, `Ideal-Node`, or fast-start.
    ///
    /// `host` must be a single header value. Rejects whitespace and control characters (including CR and LF) because they would corrupt the request head.
    static func upgradeRequest(host: String) throws(DERPError) -> [UInt8] {
        let bytes = Array(host.utf8)
        guard !bytes.isEmpty, !bytes.contains(where: { $0 <= 0x20 || $0 == 0x7F }) else { throw .malformed }
        return Array("GET /derp HTTP/1.1\r\nHost: \(host)\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n".utf8)
    }

    /// Extracts the server's public key from the ServerKey frame. Requires the expected type, length (at least 40), and magic.
    static func serverPublicKey(from frame: DERPFrame) throws(DERPError) -> [UInt8] {
        guard frame.kind == .serverKey, frame.body.count >= 40, frame.body.starts(with: serverKeyMagic) else {
            throw .handshakeFailed
        }
        return Array(frame.body[8..<40])
    }

    /// The ClientInfo frame body and the shared key for opening the subsequent ServerInfo.
    ///
    /// The body consists of `client public key(32) ‖ nonce(24) ‖ tag(16) ‖ ciphertext`. `box.Seal` has two steps.
    /// Derive a shared key with X25519 and HSalsa20 (`NaClBox.sharedKey`), then use it to seal with XSalsa20-Poly1305
    /// (`NaClSecretBox.seal`).
    static func clientInfo(
        privateKey: Curve25519.KeyAgreement.PrivateKey, serverKey: [UInt8], nonce: [UInt8]
    ) throws(DERPError) -> (body: [UInt8], sharedKey: [UInt8]) {
        do {
            let sharedKey = try NaClBox.sharedKey(privateKey: Array(privateKey.rawRepresentation), peerPublicKey: serverKey)
            let sealed = try NaClSecretBox.seal(clientInfoJSON, nonce: nonce, key: sharedKey)
            return (Array(privateKey.publicKey.rawRepresentation) + nonce + sealed, sharedKey)
        } catch {
            throw .handshakeFailed
        }
    }

    /// Opens the ServerInfo body (`nonce(24) ‖ box`) and validates its JSON.
    ///
    /// Throws `handshakeFailed` if it cannot open the body or `malformed` if the opened body is not a JSON object.
    /// shortcut: does not read rate limits (`TokenBucketBytesPerSecond` and `TokenBucketBytesBurst`). This version of the server
    /// sends only `{"version":2}`.
    static func openServerInfo(_ body: [UInt8], sharedKey: [UInt8]) throws(DERPError) {
        guard body.count >= nonceSize else { throw .handshakeFailed }
        let plaintext: [UInt8]
        do {
            plaintext = try NaClSecretBox.open(body[nonceSize...], nonce: Array(body[..<nonceSize]), key: sharedKey)
        } catch {
            throw .handshakeFailed
        }
        struct ServerInfo: Decodable { var version: Int? }
        guard (try? JSONDecoder().decode(ServerInfo.self, from: Data(plaintext))) != nil else { throw .malformed }
    }
}
