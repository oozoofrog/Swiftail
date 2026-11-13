/// tailnet lock(TKA)의 서버 쪽 상태. Go `tailcfg.TKAInfo`. 맵 응답의 `TKAInfo`로 온다.
///
/// 처음에 오지 않으면 lock이 꺼진 tailnet이다. 그 뒤로 `nil`이면 이전 것을 그대로 둔다.
/// Swiftail은 tailnet lock을 구현하지 않고 켜져 있는지만 본다(`Netmap.tailnetLockEnabled`).
/// `docs/protocol-notes/control-map.md` 4.6 (출처: tailscale.com `tailcfg/tka.go` `TKAInfo`).
public struct TKAInfo: Decodable, Sendable, Equatable {
    /// 서버가 아는 최신 AUM 해시(base32 텍스트).
    public internal(set) var head: String
    /// 서버가 lock을 끄라고 알린다. 이것만 믿고 로컬 lock 상태를 지우면 안 된다.
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
