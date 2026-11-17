import Foundation

/// 여는 쪽이 낸 제안 하나. `PairingHost.openOffer(lifetime:authKey:)`가 만들고, 들어오는 쪽은 받은 링크나 QR의 문자열로
/// 만든다(`init(link:)`).
///
/// 비밀과 인증 키를 담으므로 `description`과 `dump`에서 가린다. 값을 그대로 로그에 찍어도 새지 않지만, `url(base:)`와
/// `qrCode(base:)`가 내는 것은 비밀 그 자체다. 로그·분석·대화 기록에 넣지 않는다. 비밀을 견줄 수 있게 되는 `Equatable`은
/// 일부러 따르지 않는다. 계약 `docs/contracts/SwiftailPairing.md` 3절.
public struct PairingOffer: Sendable {
    /// 여는 노드의 MagicDNS FQDN. 소문자이고 끝 점이 없다(`rd-mac-1a2b3c4d.tail0001.ts.net`).
    public let host: String
    /// 여는 쪽이 짝 맺기 연결을 받는 tailnet 포트.
    public let port: UInt16
    /// 제안이 끝나는 때(초 단위). 들어오는 쪽은 안내에만 쓴다. 시계가 다를 수 있어 거절은 여는 쪽이 한다(동작 O4).
    public let expires: Date
    /// 1회용 tailnet 인증 키. 들어오는 쪽이 아직 tailnet에 없으면 노드 설정(`NodeConfiguration.authKey`)에 한 번 넣는다.
    /// 저장하지 않는다.
    public let authKey: String?
    /// 제안의 비밀 32바이트. 짝 맺기 절차의 HMAC 키다. 앱에는 내보내지 않는다.
    package let secret: [UInt8]

    /// 비밀의 길이.
    static let secretLength = 32

    init(host: String, port: UInt16, expires: Date, authKey: String?, secret: [UInt8]) {
        self.host = host
        self.port = port
        self.expires = expires
        self.authKey = authKey
        self.secret = secret
    }
}

extension PairingOffer: CustomStringConvertible, CustomReflectable {
    /// 비밀과 인증 키를 가린다.
    public var description: String {
        "PairingOffer(host: \(host), port: \(port), expires: \(expires), authKey: \(redactedAuthKey), secret: <가림>)"
    }

    /// `dump`는 `description`을 거치지 않으므로 여기서도 가린다.
    public var customMirror: Mirror {
        Mirror(self, children: [
            "host": host,
            "port": port,
            "expires": expires,
            "authKey": redactedAuthKey,
            "secret": "<가림>",
        ])
    }

    private var redactedAuthKey: String { authKey == nil ? "없음" : "<가림>" }
}
