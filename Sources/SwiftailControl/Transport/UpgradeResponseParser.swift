import SwiftailIO

/// Reads and validates the server's upgrade response head.
///
/// Success yields `101 Switching Protocols` and `Upgrade: tailscale-control-protocol`. The Noise response follows immediately,
/// and one TCP read can contain both the HTTP head and Noise bytes.
/// `HTTPResponseHead` reads the head (assembling chunks, enforcing the 16KiB limit and line format). This parser returns bytes
/// already received after the head so they can be passed to `ControlHandshake`.
///
/// The client checks only the status and `Upgrade` value, skipping `Connection` validation. The `Upgrade` value must match
/// exactly.
///
/// `docs/protocol-notes/control-transport.md` §3.6, §4.4 step 2, items 3~4
/// (origin: tailscale.com `control/controlhttp/client.go`).
public struct UpgradeResponseParser: Sendable {
    /// The `Upgrade` header value.
    static let protocolName = "tailscale-control-protocol"

    /// The state for reading the head. Clears received bytes on completion or failure.
    private(set) var head = HTTPResponseHead.Parser()

    public init() {}

    /// Returns nil until the full head arrives, then returns the remaining bytes (for the Noise layer).
    ///
    /// - Throws: `upgradeRejected` for a status other than 101, `malformed` for an invalid format or different `Upgrade` value,
    ///   `messageTooLarge` for a head over 16KiB, or `closed` after returning the head or failing.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8]? {
        let response: HTTPResponseHead?
        do {
            response = try head.receive(bytes)
        } catch {
            switch error {
            case .malformedStatusLine:
                throw .malformed
            case .malformedHeader(let status):
                // Check status first. Anything other than 101 is a rejection regardless of the remaining format.
                throw status == 101 ? .malformed : .upgradeRejected(status: status)
            case .tooLarge:
                throw .messageTooLarge
            case .closed:
                throw .closed
            }
        }
        guard let response else { return nil }
        guard response.status == 101 else { throw .upgradeRejected(status: response.status) }
        guard let upgrade = response.firstValue(ofHeader: "upgrade"), upgrade.elementsEqual(Self.protocolName.utf8) else {
            throw .malformed
        }
        return response.remainder
    }
}
