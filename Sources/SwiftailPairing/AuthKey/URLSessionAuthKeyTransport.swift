import Foundation

/// Performs HTTPS round trips with the admin API using `URLSession`. This is the only use of `URLSession` in this target.
///
/// See contract `docs/contracts/SwiftailPairing.md` §4 K5.
/// - Uses an ephemeral configuration with cookie, cache, and credential storage disabled. Does not wait for connectivity.
/// - Limits each request to 15 seconds. Exceeding the deadline produces `.network`.
/// - Returns 3xx responses unchanged without following redirects. This keeps credential-bearing requests from going elsewhere.
/// - Accepts response bodies up to 64KiB. Exceeding the limit produces `.invalidResponse`.
/// - Verifies server certificates using system roots (default handling).
final class URLSessionAuthKeyTransport: AuthKeyTransport {
    /// The per-request deadline.
    static let requestTimeout: TimeInterval = 15
    /// The response body limit.
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
        // The session retains its delegate strongly. Invalidate the session to release both. In-flight requests run to completion.
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
            // URLSession reports Task cancellation as `URLError.cancelled` or `CancellationError`.
            throw Task.isCancelled ? .cancelled : .network
        }
    }
}

/// Blocks redirects.
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
