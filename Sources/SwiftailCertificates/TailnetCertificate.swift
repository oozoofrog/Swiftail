import CryptoKit
import Foundation

/// 노드의 ts.net 이름에 발급된 인증서와 그 개인 키.
///
/// 개인 키를 담으므로 `description`과 `dump`에는 이름과 유효 기간만 드러낸다.
public struct TailnetCertificate: Sendable {
    /// 인증서의 이름(`rd-mac-1a2b3c4d.tail0001.ts.net`).
    public let domain: String
    /// DER 인증서. leaf가 먼저이고 중간 인증서가 뒤따른다. ACME 서버가 루트를 함께 보낼 수도 있으므로(RFC 8555 9.1),
    /// 사슬을 검증한 뒤 leaf가 아닌 자기 서명 인증서를 떼어 낸 것이다(동작 S6). TLS 신원에 그대로 싣는다.
    public let chain: [[UInt8]]
    /// leaf의 개인 키. `x963Representation`을 `SecKeyCreateWithData`에 넘겨 `SecKey`를 만들 수 있다.
    public let privateKey: P256.Signing.PrivateKey
    /// leaf의 유효 기간이 시작하는 시각.
    public let notBefore: Date
    /// leaf의 유효 기간이 끝나는 시각. 이 시각 전(수명의 2/3 지점)에 관리자가 갱신한다.
    public let notAfter: Date

    /// 검증을 통과한 사슬에서만 만든다(동작 C8·S3).
    init(_ certificate: VerifiedCertificate) {
        domain = certificate.lifetime.domain.name
        chain = certificate.chain
        privateKey = certificate.privateKey
        notBefore = certificate.lifetime.notBefore
        notAfter = certificate.lifetime.notAfter
    }
}

extension TailnetCertificate: CustomStringConvertible, CustomReflectable {
    public var description: String {
        "TailnetCertificate(domain: \(domain), notBefore: \(notBefore), notAfter: \(notAfter))"
    }

    public var customMirror: Mirror {
        Mirror(self, children: ["domain": domain, "notBefore": notBefore, "notAfter": notAfter], displayStyle: .struct)
    }
}
