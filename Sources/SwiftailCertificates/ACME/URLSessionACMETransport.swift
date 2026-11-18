import Foundation
import Security

/// Performs HTTPS round trips to the ACME server with `URLSession`. This is the only use of `URLSession` in this target (contract H8).
///
/// - Uses an ephemeral configuration with no cookie, cache, or credential storage. It does not wait for connectivity.
/// - Returns 3xx responses unchanged without following redirects (contract behavior X1).
/// - Limits each request to 30 seconds (contract behavior C10). Exceeding the deadline produces `timedOut`.
/// - Accepts up to 256KiB of response body (the certificate chain limit). Exceeding it produces `responseTooLarge` (contract behavior X2).
/// - Uses `Swiftail/<version>` as `User-Agent` (RFC 8555 6.1, contract H13).
/// - Verifies server certificates using only system roots in production. Tests and staging supply trust anchors and use only those anchors
///   (contract behaviors C8 and S3 ⑤, H10. Go's embedded root fallback is omitted).
final class URLSessionACMETransport: ACMETransport {
    /// The `User-Agent` header value. It lives here because the repository has no library version string.
    static let userAgent = "Swiftail/0.1.2"
    /// The per-request deadline.
    static let requestTimeout: TimeInterval = 30

    private let session: URLSession
    private let allowsLoopbackHTTP: Bool
    private let maximumBodyByteCount: Int

    /// The production configuration. Allows only HTTPS verified with system roots.
    convenience init() {
        self.init(trustAnchors: nil)
    }

    /// The initialization path for tests and staging (contract H10).
    ///
    /// - Parameters:
    ///   - trustAnchors: DER for the roots used to verify the server certificate chain. When supplied, only these roots are used in place of system roots.
    ///   - allowsLoopbackHTTP: If true, also sends plaintext `http` to loopback hosts (`127.0.0.1`, `::1`, `localhost`). This is only for loopback
    ///     servers that test the transport. The order flow accepts only `https` URLs regardless of this value (contract behavior X1).
    ///   - requestTimeout: The per-request deadline.
    ///   - maximumBodyByteCount: The response body limit.
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
        // The session retains its delegate strongly. Invalidate the session to release both. In-flight requests run to completion.
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

    /// Allows `https` in all configurations and plaintext `http` only for loopback hosts in the test configuration.
    private func isAllowed(_ url: URL) -> Bool {
        switch url.scheme?.lowercased() {
        case "https": url.host?.isEmpty == false
        case "http": allowsLoopbackHTTP && ["127.0.0.1", "::1", "localhost"].contains(url.host?.lowercased() ?? "")
        default: false
        }
    }

    /// The response headers.
    ///
    /// shortcut: `HTTPURLResponse` supplies headers only as a dictionary, so wire order and repeated lines with the same name cannot be recovered
    /// (they become one comma-separated value). Return them in name order. This flow reads `Replay-Nonce`, `Location`, and `Retry-After`, each on a
    /// single line. Revisit if it starts reading `Link` (alternate chains, terms).
    private static func headers(of response: HTTPURLResponse) -> [ACMEHTTPResponse.Header] {
        response.allHeaderFields
            .compactMap { name, value -> ACMEHTTPResponse.Header? in
                guard let name = name as? String, let value = value as? String else { return nil }
                return ACMEHTTPResponse.Header(name: name, value: value)
            }
            .sorted { $0.name.lowercased() < $1.name.lowercased() }
    }
}

/// Blocks redirects and verifies server certificates using only the supplied trust anchors when present.
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

    /// The task from `session.bytes(for:)` asks for server trust only at the task level (the session-level handler is not called).
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        await urlSession(session, didReceive: challenge)
    }

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge
    ) async -> (URLSession.AuthChallengeDisposition, URLCredential?) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let trust = challenge.protectionSpace.serverTrust
        else {
            // Decline other challenges such as client certificates or passwords.
            return (.cancelAuthenticationChallenge, nil)
        }
        guard let trustAnchors else {
            // Production uses system roots and the default name, validity period, and chain checks.
            return (.performDefaultHandling, nil)
        }
        let anchors = trustAnchors.compactMap { SecCertificateCreateWithData(nil, Data($0) as CFData) }
        guard anchors.count == trustAnchors.count,
              SecTrustSetAnchorCertificates(trust, anchors as CFArray) == errSecSuccess,
              SecTrustSetAnchorCertificatesOnly(trust, true) == errSecSuccess,
              SecTrustSetNetworkFetchAllowed(trust, false) == errSecSuccess,
              SecTrustEvaluateWithError(trust, nil)
        else { return (.cancelAuthenticationChallenge, nil) }
        return (.useCredential, URLCredential(trust: trust))
    }
}
