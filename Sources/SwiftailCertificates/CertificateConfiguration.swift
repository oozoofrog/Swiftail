import Foundation

/// `CertificateManager`의 설정.
public struct CertificateConfiguration: Sendable {
    /// Let's Encrypt 운영 서버의 디렉터리.
    public static let letsEncryptDirectoryURL: URL = {
        // Go `tempfork/acme/acme.go:47`의 `LetsEncryptURL`(노트 5장).
        guard let url = URL(string: "https://acme-v02.api.letsencrypt.org/directory") else {
            preconditionFailure("고정된 Let's Encrypt 디렉터리 URL은 올바른 URL이다")
        }
        return url
    }()

    /// ACME 디렉터리의 URL. `https`여야 한다. 시험과 스테이징에서 바꾼다.
    public var directoryURL: URL

    /// 받은 사슬과 저장된 사슬을 검증할 때 믿을 루트 인증서(DER). nil이면 시스템 신뢰 저장소다.
    ///
    /// 운영에서는 nil로 둔다. 시스템이 믿지 않는 인증 기관의 디렉터리(Let's Encrypt 스테이징, 시험 서버)를 쓸 때 그
    /// 기관의 루트를 준다. 주면 **그 루트만** 믿고 시스템 루트는 쓰지 않는다. 그렇게 받은 인증서는 브라우저와 다른
    /// 기기가 믿지 않는다. 빈 목록은 받지 않는다(아무것도 믿지 않는 설정이다).
    public var trustAnchors: [[UInt8]]?

    /// - Parameters:
    ///   - directoryURL: ACME 디렉터리의 URL. 기본은 Let's Encrypt 운영 서버다.
    ///   - trustAnchors: 믿을 루트 인증서(DER). 기본은 nil(시스템 신뢰 저장소).
    public init(directoryURL: URL = CertificateConfiguration.letsEncryptDirectoryURL, trustAnchors: [[UInt8]]? = nil) {
        self.directoryURL = directoryURL
        self.trustAnchors = trustAnchors
    }
}
