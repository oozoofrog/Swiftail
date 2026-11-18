/// An HTTP round trip to the ACME server. The edge (`URLSession`) and tests (fake servers) implement it.
///
/// The order flow (`ACMEOrderFlow`) is unaware of this protocol. The driver (`issueCertificate`) sends requests emitted by
/// the flow through this protocol and passes responses back to the flow. It returns 3xx responses unchanged without following redirects (contract behavior X1).
protocol ACMETransport: Sendable {
    func send(_ request: ACMEHTTPRequest) async throws(ACMETransportError) -> ACMEHTTPResponse
}

/// An HTTP request to the ACME server.
struct ACMEHTTPRequest: Sendable, Equatable {
    enum Method: Sendable, Equatable { case get, head, post }
    var method: Method
    /// The URL string exactly as supplied by the server (RFC 8555 6.4). For POST, it matches the JWS `url` header.
    var url: String
    /// The body for POST requests only. Content-Type is `application/jose+json` (RFC 8555 6.2). GET and HEAD use an empty array.
    var body: [UInt8]
    /// The `Accept` header, omitted if nil. Only certificate downloads carry `application/pem-certificate-chain`
    /// (RFC 8555 7.4.2, contract behavior C7).
    var accept: String? = nil
}

/// An HTTP response from the ACME server.
struct ACMEHTTPResponse: Sendable, Equatable {
    struct Header: Sendable, Equatable {
        var name: String
        var value: String
    }

    var status: Int
    /// Headers in received order. Name comparisons are case-insensitive. A name can appear more than once (Link).
    var headers: [Header]
    /// The response body up to the size limit. The transport throws an error if the body exceeds it.
    var body: [UInt8]

    /// The first header value for the given name. The name is case-insensitive (RFC 7230 3.2).
    func firstHeader(named name: String) -> String? {
        headers.first { $0.name.lowercased() == name.lowercased() }?.value
    }
}

/// The reason the transport received no response. There are no associated values, keeping URLs and bodies out of errors (contract behaviors K2 and K3).
enum ACMETransportError: Error, Sendable, Equatable {
    /// The connection could not be established or dropped mid-request. This includes TLS server verification failures.
    case network
    /// The per-request deadline (30 seconds, contract behavior C10) elapsed.
    case timedOut
    /// The response body exceeded the transport limit.
    case responseTooLarge
    /// The URL could not be parsed or used a scheme the transport does not allow.
    case invalidURL
}
