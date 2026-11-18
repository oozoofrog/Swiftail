import Foundation
import SwiftailBase

/// Separates the server's optional early payload from the start of the Noise plaintext stream.
///
/// The first 9 plaintext bytes from the server are either an HTTP/2 SETTINGS frame header or an early payload header with magic
/// `ff ff ff 54 53` and a JSON length (uint32 BE). When the magic matches, reads that many bytes of `tailcfg.EarlyNoise` JSON.
/// Otherwise, passes all bytes, including the first 9, unchanged to HTTP/2. Leaving the magic in the stream would break HTTP/2 parsing, so
/// this step runs even when the server sends no early payload.
///
/// JSON parsing follows Go's `json.Unmarshal` into a pointer. Treats `null` as no payload and ignores unknown fields.
/// An invalid `nodeKeyChallenge` prefix, length, or hexadecimal value fails, as does empty JSON (length 0).
///
/// `docs/protocol-notes/control-transport.md` §3.7, §4.7 step 8
/// (origin: `readHeader` in tailscale.com `control/ts2021/conn.go` and `EarlyNoise` in `tailcfg/tailcfg.go`).
public struct EarlyPayloadParser: Sendable {
    /// The optional early information the server can send on each connection.
    public struct EarlyPayload: Sendable, Equatable {
        /// A one-time public key used by the client to prove possession of the node private key.
        /// A missing field, `null`, or an all-zero key yields `nil`.
        public var nodeKeyChallenge: ChallengePublicKey?
    }

    static let magic: [UInt8] = [0xFF, 0xFF, 0xFF, 0x54, 0x53]
    /// The same size as an HTTP/2 frame header.
    static let headerSize = 9
    static let maximumPayloadSize = 10 << 20

    private var buffer: [UInt8] = []
    private var isDone = false

    public init() {}

    /// Returns nil until there are enough bytes to decide. Once determined, returns the early message (if present) and bytes following it (for HTTP/2).
    ///
    /// - Throws: `messageTooLarge` for a JSON length over 10MiB, `malformed` for invalid JSON,
    ///   or `closed` after returning the result or failing.
    public mutating func receive(_ plaintext: [UInt8]) throws(ControlTransportError) -> (payload: EarlyPayload?, remainder: [UInt8])? {
        guard !isDone else { throw .closed }
        buffer += plaintext
        guard buffer.count >= Self.headerSize else { return nil }

        guard buffer.starts(with: Self.magic) else {
            return finish(payload: nil, consumed: 0)
        }
        let length = Int(UInt32(bigEndianBytes: buffer[Self.magic.count..<Self.headerSize]))
        guard length <= Self.maximumPayloadSize else { throw fail(.messageTooLarge) }
        let end = Self.headerSize + length
        guard buffer.count >= end else { return nil }

        // Using `try?` would collapse JSON `null` and a parsing failure to the same nil.
        let decoded: EarlyNoise?
        do {
            decoded = try JSONDecoder().decode(EarlyNoise?.self, from: Data(buffer[Self.headerSize..<end]))
        } catch {
            throw fail(.malformed)
        }
        let payload = decoded.map { EarlyPayload(nodeKeyChallenge: $0.nodeKeyChallenge.flatMap { $0.isZero ? nil : $0 }) }
        return finish(payload: payload, consumed: end)
    }

    private mutating func finish(payload: EarlyPayload?, consumed: Int) -> (payload: EarlyPayload?, remainder: [UInt8]) {
        isDone = true
        let remainder = Array(buffer[consumed...])
        buffer = []
        return (payload, remainder)
    }

    private mutating func fail(_ error: ControlTransportError) -> ControlTransportError {
        isDone = true
        buffer = []
        return error
    }
}

/// The JSON shape of `tailcfg.EarlyNoise`, used only for wire decoding.
private struct EarlyNoise: Decodable {
    var nodeKeyChallenge: ChallengePublicKey?
}
