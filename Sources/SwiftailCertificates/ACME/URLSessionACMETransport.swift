import Foundation
import Security

/// `URLSession`으로 ACME 서버와 HTTPS 왕복을 한다. 이 타깃에서 `URLSession`을 쓰는 유일한 곳이다(계약 H8).
///
/// - ephemeral 설정: 쿠키·캐시·자격 증명 저장이 없다. 연결을 기다리지 않는다.
/// - 리다이렉트를 따르지 않는다. 3xx 응답을 그대로 돌려준다(계약 동작 X1).
/// - 요청 하나의 기한은 30초다(계약 동작 C10). 넘으면 `timedOut`.
/// - 응답 본문은 256KiB(인증서 사슬의 한도)까지만 받는다. 넘으면 `responseTooLarge`(계약 동작 X2).
/// - `User-Agent`는 `Swiftail/<버전>`이다(RFC 8555 6.1, 계약 H13).
/// - 서버 인증서는 운영에서는 시스템 루트로만 검증한다. 시험과 스테이징은 신뢰 앵커를 주며, 주면 그 앵커만 쓴다
///   (계약 동작 C8·S3 ⑤, H10. Go의 내장 루트 fallback은 옮기지 않는다).
final class URLSessionACMETransport: ACMETransport {
    /// `User-Agent` 머리 값. 저장소에 라이브러리 버전 문자열이 없어 여기에 둔다.
    static let userAgent = "Swiftail/0.1.0"
    /// 요청 하나의 기한.
    static let requestTimeout: TimeInterval = 30

    private let session: URLSession
    private let allowsLoopbackHTTP: Bool
    private let maximumBodyByteCount: Int

    /// 운영용: 시스템 루트로 검증하는 HTTPS만.
    convenience init() {
        self.init(trustAnchors: nil)
    }

    /// 시험·스테이징용 길(계약 H10).
    ///
    /// - Parameters:
    ///   - trustAnchors: 서버 인증서 사슬을 검증할 루트들의 DER. 주면 시스템 루트 대신 이것만 쓴다.
    ///   - allowsLoopbackHTTP: 참이면 루프백 호스트(`127.0.0.1`, `::1`, `localhost`)의 평문 `http`도 보낸다. 전송을
    ///     시험하는 루프백 서버만을 위한 길이다. 주문 절차는 이 값과 무관하게 `https` URL만 받는다(계약 동작 X1).
    ///   - requestTimeout: 요청 하나의 기한.
    ///   - maximumBodyByteCount: 응답 본문의 한도.
    init(
        trustAnchors: [[UInt8]]?,
        allowsLoopbackHTTP: Bool = false,
        requestTimeout: TimeInterval = URLSessionACMETransport.requestTimeout,
        maximumBodyByteCount: Int = ACMEInputRules.maximumCertificateChainByteCount
    ) {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.waitsForConnectivity = false
        configuration.timeoutIntervalForRequest = requestTimeout
        configuration.timeoutIntervalForResource = requestTimeout
        session = URLSession(configuration: configuration, delegate: SessionDelegate(trustAnchors: trustAnchors), delegateQueue: nil)
        self.allowsLoopbackHTTP = allowsLoopbackHTTP
        self.maximumBodyByteCount = maximumBodyByteCount
    }

    deinit {
        // 세션은 delegate를 강하게 쥐므로 무효화해야 둘 다 풀린다. 진행 중인 요청은 끝까지 간다.
        session.finishTasksAndInvalidate()
    }

    func send(_ request: ACMEHTTPRequest) async throws(ACMETransportError) -> ACMEHTTPResponse {
        guard let url = URL(string: request.url), isAllowed(url) else { throw .invalidURL }
        var urlRequest = URLRequest(url: url)
        urlRequest.httpMethod = switch request.method {
        case .get: "GET"
        case .head: "HEAD"
        case .post: "POST"
        }
        urlRequest.setValue(Self.userAgent, forHTTPHeaderField: "User-Agent")
        if request.method == .post {
            urlRequest.setValue("application/jose+json", forHTTPHeaderField: "Content-Type")
            urlRequest.httpBody = Data(request.body)
        }
        if let accept = request.accept {
            urlRequest.setValue(accept, forHTTPHeaderField: "Accept")
        }

        do {
            let (bytes, response) = try await session.bytes(for: urlRequest)
            guard let http = response as? HTTPURLResponse else { throw ACMETransportError.network }
            var body: [UInt8] = []
            for try await byte in bytes {
                guard body.count < maximumBodyByteCount else {
                    bytes.task.cancel()
                    throw ACMETransportError.responseTooLarge
                }
                body.append(byte)
            }
            return ACMEHTTPResponse(status: http.statusCode, headers: Self.headers(of: http), body: body)
        } catch let error as ACMETransportError {
            throw error
        } catch let error as URLError where error.code == .timedOut {
            throw .timedOut
        } catch {
            throw .network
        }
    }

    /// `https`는 늘, 평문 `http`는 시험용 길에서 루프백 호스트일 때만.
    private func isAllowed(_ url: URL) -> Bool {
        switch url.scheme?.lowercased() {
        case "https": url.host?.isEmpty == false
        case "http": allowsLoopbackHTTP && ["127.0.0.1", "::1", "localhost"].contains(url.host?.lowercased() ?? "")
        default: false
        }
    }

    /// 응답 머리.
    ///
    /// shortcut: `HTTPURLResponse`는 머리를 사전으로만 주므로 받은 순서와 같은 이름의 여러 줄을 되살릴 수 없다(같은 이름은
    /// 쉼표로 이어진 한 값이 된다). 이름 순으로 낸다. 이 절차가 읽는 머리(`Replay-Nonce`·`Location`·`Retry-After`)는
    /// 한 줄씩이다. `Link`(대체 사슬, 약관)를 읽게 되면 다시 본다.
    private static func headers(of response: HTTPURLResponse) -> [ACMEHTTPResponse.Header] {
        response.allHeaderFields
            .compactMap { name, value -> ACMEHTTPResponse.Header? in
                guard let name = name as? String, let value = value as? String else { return nil }
                return ACMEHTTPResponse.Header(name: name, value: value)
            }
            .sorted { $0.name.lowercased() < $1.name.lowercased() }
    }
}

/// 리다이렉트를 막고, 신뢰 앵커가 주어졌으면 서버 인증서를 그 앵커로만 검증한다.
private final class SessionDelegate: NSObject, URLSessionTaskDelegate, Sendable {
    private let trustAnchors: [[UInt8]]?

    init(trustAnchors: [[UInt8]]?) {
        self.trustAnchors = trustAnchors
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            // 클라이언트 인증서·암호 같은 다른 요구에는 응하지 않는다.
            return (.cancelAuthenticationChallenge, nil)
        }
        guard let trustAnchors else {
            // 운영: 시스템 루트와 기본 검사(이름·기간·사슬)를 그대로 쓴다.
            return (.performDefaultHandling, nil)
        }
        let anchors = trustAnchors.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        guard anchors.count == trustAnchors.count,
              SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil)
        else { return (.cancelAuthenticationChallenge, nil) }
        return (.useCredential, URLCredential(trust: trust))
    }
}
