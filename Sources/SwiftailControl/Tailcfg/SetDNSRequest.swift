import SwiftailBase

/// `POST /machine/set-dns`의 본문. Go `tailcfg.SetDNSRequest`.
///
/// ACME DNS-01 challenge의 TXT 레코드를 제어 서버에 올려 달라고 한다. 삭제 동작은 없다(Go 구조체에도 없다).
/// `Version`은 Noise로 보낼 때의 CapabilityVersion이다. Go `LocalBackend.SetDNS`는 1을 넣지만 Noise로 보내기 직전에
/// `CurrentCapabilityVersion`으로 덮어쓰므로(`control/controlclient/direct.go` `setDNSNoise`) 처음부터 148을 넣는다.
///
/// `docs/protocol-notes/whois-certs-state.md` 3.2 (출처: tailscale.com `tailcfg/tailcfg.go` `SetDNSRequest`).
struct SetDNSRequest: Encodable, Sendable {
    /// 클라이언트의 capability version.
    var version = 148
    /// 지금의 node 공개 키.
    var nodeKey: NodePublicKey
    /// 레코드 이름(`_acme-challenge.<cert 도메인>`).
    var name: String
    /// 레코드 종류. DNS-01에서는 늘 `TXT`다.
    var type = "TXT"
    /// 레코드 값(따옴표 없는 TXT 값).
    var value: String

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case name = "Name"
        case type = "Type"
        case value = "Value"
    }
}

/// `POST /machine/set-dns`의 200 응답. Go `tailcfg.SetDNSResponse`(필드 없는 구조체).
///
/// 필드는 읽지 않고 본문이 JSON 객체인지만 본다. Go는 JSON 값 하나를 받아들이므로 `null`도 통과하지만,
/// Swiftail은 객체만 받는다(계약 `docs/contracts/SwiftailHost.md` 동작 D3의 Swiftail의 선택).
struct SetDNSResponse: Decodable {
    private struct AnyKey: CodingKey {
        var stringValue: String
        var intValue: Int? { nil }
        init(stringValue: String) { self.stringValue = stringValue }
        init?(intValue: Int) { nil }
    }

    /// 객체가 아니면(`null`, 배열, 문자열, 숫자) 던진다. 합성된 `init(from:)`는 컨테이너를 열지 않아 무엇이든 받으므로
    /// 직접 연다.
    init(from decoder: any Decoder) throws {
        _ = try decoder.container(keyedBy: AnyKey.self)
    }
}
