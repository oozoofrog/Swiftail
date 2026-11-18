import SwiftailBase

/// A ping from the control server that requests a client reply. Go `tailcfg.PingRequest`.
///
/// Arrives as `PingRequest` in map responses, including KeepAlive. It is an event for this response only and carries no state.
/// If `types` is empty, sends a HEAD request to `url` to indicate the connection is alive. Replies once per ping URL.
/// Handling belongs outside this layer, in `ControlClient`.
/// `docs/protocol-notes/control-map.md` §4.5 (origin: `PingRequest` in tailscale.com `tailcfg/tailcfg.go`).
public struct PingRequest: Decodable, Sendable, Equatable {
    /// The URL to send the reply to.
    public internal(set) var url: String
    /// Calls `url` over the control Noise connection in place of ordinary HTTP.
    public internal(set) var urlIsNoise: Bool
    /// Requests logging of successes as well.
    public internal(set) var log: Bool
    /// Comma-separated ping types (such as `"disco"`, `"TSMP"`, or `"c2n"`). An empty string means a HEAD request.
    public internal(set) var types: String
    /// The target IP to ping. Used when `types` is present.
    public internal(set) var ip: IPAddress?
    /// The HTTP request bytes for a c2n ping.
    public internal(set) var payload: [UInt8]

    private enum CodingKeys: String, CodingKey {
        case url = "URL"
        case urlIsNoise = "URLIsNoise"
        case log = "Log"
        case types = "Types"
        case ip = "IP"
        case payload = "Payload"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        url = try container.decodeIfPresent(String.self, forKey: .url) ?? ""
        urlIsNoise = try container.decodeIfPresent(Bool.self, forKey: .urlIsNoise) ?? false
        log = try container.decodeIfPresent(Bool.self, forKey: .log) ?? false
        types = try container.decodeIfPresent(String.self, forKey: .types) ?? ""
        ip = try container.decodeIfPresent(IPAddress.self, forKey: .ip)
        payload = try container.decodeBytesIfPresent(forKey: .payload) ?? []
    }
}
