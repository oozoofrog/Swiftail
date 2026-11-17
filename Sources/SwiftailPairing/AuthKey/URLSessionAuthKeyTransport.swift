import Foundation

/// `URLSession`으로 관리 API와 HTTPS 왕복을 한다. 이 타깃에서 `URLSession`을 쓰는 유일한 곳이다.
///
/// 계약 `docs/contracts/SwiftailPairing.md` 4절 K5:
/// - ephemeral 설정에 쿠키·캐시·자격 증명 저장을 모두 끈다. 연결을 기다리지 않는다.
/// - 요청 하나의 기한은 15초다. 넘으면 `.network`.
/// - 리다이렉트를 따르지 않는다. 3xx 응답을 그대로 돌려준다. 자격을 실은 요청이 다른 곳으로 옮겨 가지 않게 한다.
/// - 응답 본문은 64KiB까지만 받는다. 넘으면 `.invalidResponse`.
/// - 서버 인증서는 시스템 루트로 검증한다(기본 처리).
final class URLSessionAuthKeyTransport: AuthKeyTransport {
    /// 요청 하나의 기한.
    static let requestTimeout: TimeInterval = 15
    /// 응답 본문의 한도.
    static let maximumBodyByteCount = 64 * 1024

    private let session: URLSession

    init() {
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.httpShouldSetCookies = false
        configuration.httpCookieAcceptPolicy = .never
        configuration.urlCache = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalAndRemoteCacheData
        configuration.waitsForConnectivity = false
        configuration.timeoutIntervalForRequest = Self.requestTimeout
        configuration.timeoutIntervalForResource = Self.requestTimeout
        session = URLSession(configuration: configuration, delegate: RedirectBlocker(), delegateQueue: nil)
    }

    deinit {
        // 세션은 delegate를 강하게 쥐므로 무효화해야 둘 다 풀린다. 진행 중인 요청은 끝까지 간다.
        session.finishTasksAndInvalidate()
    }

    func send(_ request: AuthKeyHTTPRequest) async throws(AuthKeyIssueError) -> AuthKeyHTTPResponse {
        guard !Task.isCancelled else { throw .cancelled }
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = "POST"
        if let authorization = request.authorization {
            urlRequest.setValue(authorization, forHTTPHeaderField: "Authorization")
        }
        urlRequest.setValue(request.contentType, forHTTPHeaderField: "Content-Type")
        urlRequest.httpBody = Data(request.body)

        do {
            let (bytes, response) = try await session.bytes(for: urlRequest)
            guard let http = response as? HTTPURLResponse else { throw AuthKeyIssueError.network }
            var body: [UInt8] = []
            for try await byte in bytes {
                guard body.count < Self.maximumBodyByteCount else {
                    bytes.task.cancel()
                    throw AuthKeyIssueError.invalidResponse
                }
                body.append(byte)
            }
            return AuthKeyHTTPResponse(status: http.statusCode, body: body)
        } catch let error as AuthKeyIssueError {
            throw error
        } catch {
            // URLSession은 Task 취소를 `URLError.cancelled`나 `CancellationError`로 알린다.
            throw Task.isCancelled ? .cancelled : .network
        }
    }
}

/// 리다이렉트를 막는다.
private final class RedirectBlocker: NSObject, URLSessionTaskDelegate, Sendable {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest
    ) async -> URLRequest? {
        nil
    }
}
