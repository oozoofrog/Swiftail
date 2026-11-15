import Foundation
import SwiftailBase

/// `POST /machine/register`의 본문. Go `tailcfg.RegisterRequest`.
///
/// 노드 키를 제어 서버에 등록하거나(처음, 키 교체) 로그인 완료를 기다리거나(`followup`)
/// 로그아웃한다(`expiry`를 과거로). 등록 절차의 흐름은 노트 4.1이 다룬다.
///
/// `omitempty`가 없는 필드는 비어 있어도 보낸다: 0 키는 `nodekey:000…`, 시각이 없으면
/// `0001-01-01T00:00:00Z`, Hostinfo·서명이 없으면 `null`. 기기 인증서 서명(`SignatureType` 등)은 쓰지 않는다.
/// `docs/protocol-notes/control-map.md` 3.1, 3.2 (출처: tailscale.com `tailcfg/tailcfg.go` `RegisterRequest`).
public struct RegisterRequest: Encodable, Sendable {
    /// 클라이언트가 이해하는 프로토콜 의미의 수준(capability version).
    public var version: Int
    /// 등록할 노드 키.
    public var nodeKey: NodePublicKey
    /// 키 교체일 때 이전 노드 키. 처음 등록이면 0 키.
    public var oldNodeKey: NodePublicKey
    /// 이 노드의 NL 공개 키(tailnet lock). `ControlClient`는 늘 0이 아닌 키를 싣는다. 생략하면 0 키.
    public var nlKey: NLPublicKey
    /// 인증 키 로그인일 때의 인증 수단. 없으면 JSON에서 빠진다.
    public var auth: RegisterResponseAuth?
    /// 요청하는 키 만료 시각. `nil`은 서버 정책에 맡김. 과거 시각은 로그아웃이다.
    public var expiry: Date?
    /// 이전 응답의 `AuthURL`. 비어 있지 않으면 사용자가 로그인을 마칠 때까지 응답을 기다린다.
    public var followup: String
    /// 노드 정보. testcontrol은 `Hostname`을 읽으므로 채워 보낸다.
    public var hostinfo: Hostinfo?
    /// 오래 비활성이면 서버가 지우는 노드를 요청한다.
    public var ephemeral: Bool
    /// 새 노드 키에 대한 tailnet lock 서명(NKS의 정준 CBOR). 비어 있으면 `null`.
    public var nodeKeySignature: [UInt8]

    public init(
        version: Int = 148,
        nodeKey: NodePublicKey,
        oldNodeKey: NodePublicKey = .zero,
        nlKey: NLPublicKey = .zero,
        auth: RegisterResponseAuth? = nil,
        expiry: Date? = nil,
        followup: String = "",
        hostinfo: Hostinfo?,
        ephemeral: Bool = false,
        nodeKeySignature: [UInt8] = []
    ) {
        self.version = version
        self.nodeKey = nodeKey
        self.oldNodeKey = oldNodeKey
        self.nlKey = nlKey
        self.auth = auth
        self.expiry = expiry
        self.followup = followup
        self.hostinfo = hostinfo
        self.ephemeral = ephemeral
        self.nodeKeySignature = nodeKeySignature
    }

    private enum CodingKeys: String, CodingKey {
        case version = "Version"
        case nodeKey = "NodeKey"
        case oldNodeKey = "OldNodeKey"
        case nlKey = "NLKey"
        case auth = "Auth"
        case expiry = "Expiry"
        case followup = "Followup"
        case hostinfo = "Hostinfo"
        case ephemeral = "Ephemeral"
        case nodeKeySignature = "NodeKeySignature"
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(version, forKey: .version)
        try container.encode(nodeKey, forKey: .nodeKey)
        try container.encode(oldNodeKey, forKey: .oldNodeKey)
        try container.encode(nlKey, forKey: .nlKey)
        try container.encodeIfPresent(auth, forKey: .auth)
        try container.encodeTime(expiry, forKey: .expiry)
        try container.encode(followup, forKey: .followup)
        try container.encode(hostinfo, forKey: .hostinfo)
        try container.encodeUnlessEmpty(ephemeral, forKey: .ephemeral)
        try container.encodeBytesOrNull(nodeKeySignature, forKey: .nodeKeySignature)
    }
}

/// 등록 요청의 인증 수단. Go `tailcfg.RegisterResponseAuth`.
///
/// 인증 키 로그인에서만 쓴다. 인증 키에 tailnet lock 재료(`--TL` 뒤)가 붙어 있으면 그 앞부분만 넣어야 한다
/// (노트 4.1의 2). 구 Android 전용 `Oauth2Token`은 두지 않는다.
public struct RegisterResponseAuth: Encodable, Sendable {
    /// 인증 키(`tskey-auth-…`). 비밀이므로 로그에 남기지 않는다.
    public var authKey: String

    public init(authKey: String) {
        self.authKey = authKey
    }

    private enum CodingKeys: String, CodingKey {
        case authKey = "AuthKey"
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeUnlessEmpty(authKey, forKey: .authKey)
    }
}

extension RegisterResponseAuth: CustomStringConvertible, CustomReflectable {
    /// 인증 키를 가린다. 요청 값을 그대로 로그에 찍어도 비밀이 새지 않게 하기 위해서다.
    public var description: String { "RegisterResponseAuth(authKey: <\(authKey.count)자>)" }

    /// `dump`와 `Mirror`에도 인증 키 대신 길이만 보인다. `description`만으로는 `dump`가 저장 속성을 그대로 내보낸다.
    /// 이 값을 품은 `RegisterRequest`를 `dump`해도 이 거울을 거친다.
    public var customMirror: Mirror {
        Mirror(self, children: ["authKey": "<\(authKey.count)자>"])
    }
}
