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

    /// - Parameter directoryURL: ACME 디렉터리의 URL. 기본은 Let's Encrypt 운영 서버다.
    public init(directoryURL: URL = CertificateConfiguration.letsEncryptDirectoryURL) {
        self.directoryURL = directoryURL
    }
}
