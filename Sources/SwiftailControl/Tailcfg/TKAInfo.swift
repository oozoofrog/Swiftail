/// Server-side tailnet lock (TKA) state. Go `tailcfg.TKAInfo`. Arrives as `TKAInfo` in a map response.
///
/// If initially absent, the server is treated as reporting lock disabled. Later, `nil` keeps the previous server-reported value.
/// Contract `docs/contracts/SwiftailTailnetLock.md` behaviors N and O cover interpretation of this value (`ServerLockState`) and the resulting procedure.
/// `docs/protocol-notes/control-map.md` §4.6 (origin: `TKAInfo` in tailscale.com `tailcfg/tka.go`).
public struct TKAInfo: Decodable, Sendable, Equatable {
    /// The newest AUM hash known to the server (base32 text).
    public internal(set) var head: String
    /// The server directs the client to disable the lock. This alone is insufficient to delete local lock state.
    public internal(set) var disabled: Bool

    private enum CodingKeys: String, CodingKey {
        case head = "Head"
        case disabled = "Disabled"
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        head = try container.decodeIfPresent(String.self, forKey: .head) ?? ""
        disabled = try container.decodeIfPresent(Bool.self, forKey: .disabled) ?? false
    }
}
