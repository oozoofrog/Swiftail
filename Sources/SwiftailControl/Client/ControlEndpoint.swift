import Foundation

/// 설정의 서버 URL을 연결에 쓸 값으로 한 번 검증해 둔 것.
///
/// - `http://`이면 그 포트(없으면 80)로 평문 TCP, `https://`이면 그 포트(없으면 443)로 TLS를 연다.
/// - 업그레이드 요청의 `Host`는 URL의 호스트와 (적혀 있으면) 포트다.
/// - Noise 위 HTTP/2의 `:authority`는 포트 없는 호스트다(Go는 `"https://" + 호스트 + 경로`로 요청한다).
///
/// `shortcut:` Go는 `http://` URL이면 80과 443을 경쟁시키고(443은 500ms 늦게), ControlDialPlan과 HTTP 프록시도
/// 따른다. Swiftail은 URL이 가리키는 하나만 시도한다. 필요해지는 시점: 443이나 80이 막힌 망이 보고될 때.
///
/// `docs/protocol-notes/control-transport.md` 3.6, 4.2, 4.4, 4.7의 3.
struct ControlEndpoint: Sendable, Equatable {
    var serverURL: URL
    var host: String
    var port: UInt16
    var usesTLS: Bool
    /// 업그레이드 요청의 `Host` 값.
    var hostHeader: String
    /// HTTP/2 요청의 `:authority` 값.
    var authority: String

    init(serverURL: URL) throws(ControlError) {
        guard let scheme = serverURL.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            throw .invalidConfiguration("서버 URL은 http:// 또는 https://여야 한다")
        }
        guard let host = serverURL.host(percentEncoded: false), !host.isEmpty,
              host.utf8.allSatisfy({ $0 > 0x20 && $0 != 0x7F && $0 != UInt8(ascii: "/") && $0 != UInt8(ascii: "@") })
        else { throw .invalidConfiguration("서버 URL에 올바른 호스트가 없다") }
        guard serverURL.user == nil, serverURL.password == nil else {
            throw .invalidConfiguration("서버 URL에 사용자 정보를 넣을 수 없다")
        }
        let explicitPort = serverURL.port
        if let explicitPort, !(1...65_535).contains(explicitPort) {
            throw .invalidConfiguration("서버 URL의 포트가 범위 밖이다")
        }
        // IPv6 리터럴은 Host·authority에서 대괄호로 감싼다.
        let bracketed = host.contains(":") ? "[\(host)]" : host

        self.serverURL = serverURL
        self.host = host
        usesTLS = scheme == "https"
        port = UInt16(explicitPort ?? (usesTLS ? 443 : 80))
        hostHeader = explicitPort.map { "\(bracketed):\($0)" } ?? bracketed
        authority = bracketed
    }

    /// 서버 URL에 경로(와 질의)를 붙인 URL. Go처럼 문자열로 잇는다.
    func url(path: String) -> URL? {
        var base = serverURL.absoluteString
        while base.hasSuffix("/") { base.removeLast() }
        return URL(string: base + path)
    }
}
