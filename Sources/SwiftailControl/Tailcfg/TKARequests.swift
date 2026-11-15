import Foundation
import SwiftailBase

// tailnet lock(TKA) RPC 셋의 본문. Go `tailcfg`의 `TKABootstrap*`·`TKASyncOffer*`·`TKASyncSend*`.
//
// 셋 다 Noise 채널 위의 `GET`이고 본문에 JSON을 싣는다. Go 구조체에 JSON 태그가 없어 필드 이름이 그대로 키다.
// AUM 해시는 base32 텍스트, AUM과 끄기 비밀은 base64(`[]byte`)다. 받은 값은 여기서 문자열과 바이트까지만 읽고,
// 해시와 AUM으로의 해석은 쓰는 쪽(`ControlClient`의 절차)이 한다.
//
// `docs/protocol-notes/tailnet-lock.md` 3.10, 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 Y7
// (출처: tailscale.com `tailcfg/tka.go`, BSD-3-Clause).

/// `GET /machine/tka/bootstrap`의 본문. lock을 켜거나 끄는 데 필요한 값을 달라고 한다.
struct TKABootstrapRequest: Encodable, Sendable {
    /// 클라이언트의 capability version.
    var version = 148
    var nodeKey: NodePublicKey
    /// 로컬 머리의 base32. lock 상태가 없으면 빈 문자열이고, 그때도 필드는 늘 있다.
    var head: String

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case head = "Head"
    }
}

/// 부트스트랩 RPC의 응답. 둘 다 없으면 빈 값이다.
struct TKABootstrapResponse: Decodable, Sendable {
    /// 서명 권한 상태를 시작할 체크포인트 AUM(CBOR).
    var genesisAUM: [UInt8]
    /// lock을 끄는 비밀. 검증에 쓰고 버린다. 저장하지도 로그에 남기지도 않는다.
    var disablementSecret: [UInt8]

    private enum CodingKeys: String, CodingKey {
        case genesisAUM = "GenesisAUM"
        case disablementSecret = "DisablementSecret"
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        genesisAUM = try container.decodeBytesIfPresent(forKey: .genesisAUM) ?? []
        disablementSecret = try container.decodeBytesIfPresent(forKey: .disablementSecret) ?? []
    }
}

/// `GET /machine/tka/sync/offer`의 본문. 로컬 머리와 교차점을 찾을 조상들을 알린다.
struct TKASyncOfferRequest: Encodable, Sendable {
    var version = 148
    var nodeKey: NodePublicKey
    var head: String
    var ancestors: [String]

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case head = "Head"
        case ancestors = "Ancestors"
    }
}

/// sync/offer의 응답: 서버의 머리와 조상들, 그리고 서버가 보기에 이 노드에 없는 AUM들.
struct TKASyncOfferResponse: Decodable, Sendable {
    var head: String
    var ancestors: [String]
    /// AUM의 CBOR 바이트들. 받은 순서 그대로다.
    var missingAUMs: [[UInt8]]

    private enum CodingKeys: String, CodingKey {
        case head = "Head"
        case ancestors = "Ancestors"
        case missingAUMs = "MissingAUMs"
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        head = try container.decodeIfPresent(String.self, forKey: .head) ?? ""
        ancestors = try container.decodeIfPresent([String].self, forKey: .ancestors) ?? []
        missingAUMs = try (container.decodeIfPresent([String].self, forKey: .missingAUMs) ?? []).map { text in
            guard let data = Data(base64Encoded: text) else {
                throw DecodingError.dataCorruptedError(forKey: .missingAUMs, in: container, debugDescription: "base64가 아니다")
            }
            return [UInt8](data)
        }
    }
}

/// `GET /machine/tka/sync/send`의 본문. 서버가 모르는 로컬 AUM과, 동기화 뒤의 로컬 머리를 알린다.
struct TKASyncSendRequest: Encodable, Sendable {
    var version = 148
    var nodeKey: NodePublicKey
    var head: String
    /// AUM의 CBOR 바이트들. 보낼 것이 없어도 `[]`로 나간다(null이 아니다).
    var missingAUMs: [[UInt8]]
    /// 관리자의 대화형 조작이 아니라 자동 동기화다. 보통 노드는 늘 false다.
    var interactive = false

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case head = "Head"
        case missingAUMs = "MissingAUMs"
        case interactive = "Interactive"
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(nodeKey, forKey: .nodeKey)
        try container.encode(head, forKey: .head)
        try container.encode(missingAUMs.map { Data($0).base64EncodedString() }, forKey: .missingAUMs)
        try container.encode(interactive, forKey: .interactive)
    }
}

/// sync/send의 응답: AUM을 받아들인 뒤의 서버 머리.
struct TKASyncSendResponse: Decodable, Sendable {
    var head: String

    private enum CodingKeys: String, CodingKey {
        case head = "Head"
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        head = try container.decodeIfPresent(String.self, forKey: .head) ?? ""
    }
}
