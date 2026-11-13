import SwiftailBase

/// 제어 서버가 클라이언트에게 답을 요구하는 핑. Go `tailcfg.PingRequest`.
///
/// 맵 응답(KeepAlive 포함)의 `PingRequest`로 온다. 상태가 아니라 그 응답 한 번의 사건이다.
/// `types`가 비어 있으면 `url`에 HEAD 요청을 보내 연결이 살아 있음을 알린다. 같은 URL의 핑은 한 번만
/// 답한다. 처리는 이 계층 밖(`ControlClient`)이 맡는다.
/// `docs/protocol-notes/control-map.md` 4.5 (출처: tailscale.com `tailcfg/tailcfg.go` `PingRequest`).
public struct PingRequest: Decodable, Sendable, Equatable {
    /// 답을 보낼 URL.
    public internal(set) var url: String
    /// `url`을 일반 HTTP가 아니라 제어 Noise 연결로 부른다.
    public internal(set) var urlIsNoise: Bool
    /// 성공도 로그로 남겨 달라는 요청.
    public internal(set) var log: Bool
    /// 쉼표로 구분한 핑 종류(`"disco"`, `"TSMP"`, `"c2n"` 등). 비면 HEAD 요청이다.
    public internal(set) var types: String
    /// 핑할 대상 IP. `types`가 있을 때 쓴다.
    public internal(set) var ip: IPAddress?
    /// c2n 핑의 HTTP 요청 바이트.
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
