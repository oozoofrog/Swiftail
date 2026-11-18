import SwiftailBase

/// The body of `POST /machine/set-dns`. Go `tailcfg.SetDNSRequest`.
///
/// Asks the control server to publish a TXT record for an ACME DNS-01 challenge. There is no delete operation, including in the Go struct.
/// `Version` is CapabilityVersion when sent over Noise. Go `LocalBackend.SetDNS` sets 1 but overwrites it with
/// `CurrentCapabilityVersion` just before sending over Noise (`setDNSNoise` in `control/controlclient/direct.go`), so set 148 from the start.
///
/// `docs/protocol-notes/whois-certs-state.md` §3.2 (origin: `SetDNSRequest` in tailscale.com `tailcfg/tailcfg.go`).
struct SetDNSRequest: Encodable, Sendable {
    /// The client's capability version.
    var version = 148
    /// The current node public key.
    var nodeKey: NodePublicKey
    /// The record name (`_acme-challenge.<cert domain>`).
    var name: String
    /// The record type. Always `TXT` for DNS-01.
    var type = "TXT"
    /// The record value (the TXT value without quotation marks).
    var value: String

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case name = "Name"
        case type = "Type"
        case value = "Value"
    }
}

/// The 200 response to `POST /machine/set-dns`. Go `tailcfg.SetDNSResponse` (a struct with no fields).
///
/// Checks only that the body is a JSON object and reads no fields. Go decodes one JSON value into an empty struct and also accepts `null`.
/// Swiftail accepts only objects (Swiftail's choice in contract `docs/contracts/SwiftailHost.md`, behavior D3).
struct SetDNSResponse: Decodable {
    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    /// Throws if the body is not a JSON object (for example, `null`, an array, a string, or a number). The synthesized `init(from:)` would accept anything without opening a container,
    /// so open the container explicitly.
    init(from decoder: any Decoder) throws {
        _ = try decoder.container(keyedBy: AnyKey.self)
    }
}
