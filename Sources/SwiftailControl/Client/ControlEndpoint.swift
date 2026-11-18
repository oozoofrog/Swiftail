import Foundation

/// The configured server URL, validated once into values used to connect.
///
/// - For `http://`, opens plaintext TCP on the given port (default 80). For `https://`, opens TLS on the given port (default 443).
/// The upgrade request's `Host` is the URL's host, with the port appended if specified.
/// - The HTTP/2 `:authority` over Noise is the host without the port (Go requests `"https://" + host + path`).
///
/// `shortcut:` for an `http://` URL, Go races 80 and 443 (443 starts 500ms later) and also follows ControlDialPlan and HTTP proxies.
/// Swiftail attempts only the endpoint named by the URL. Add support if a network is reported to block 443 or 80.
///
/// `docs/protocol-notes/control-transport.md` §3.6, §4.2, §4.4, §4.7 item 3.
struct ControlEndpoint: Sendable, Equatable {
    var serverURL: URL
    var host: String
    var port: UInt16
    var usesTLS: Bool
    /// The `Host` value for the upgrade request.
    var hostHeader: String
    /// The `:authority` value for HTTP/2 requests.
    var authority: String

    init(serverURL: URL) throws(ControlError) {
        guard let scheme = serverURL.scheme?.lowercased(), scheme == "http" || scheme == "https" else {
            throw .invalidConfiguration("Server URL must use http:// or https://")
        }
        guard let host = serverURL.host(percentEncoded: false), !host.isEmpty,
              host.utf8.allSatisfy({ $0 > 0x20 && $0 != 0x7F && $0 != UInt8(ascii: "/") && $0 != UInt8(ascii: "@") })
        else { throw .invalidConfiguration("Server URL lacks a valid host") }
        guard serverURL.user == nil, serverURL.password == nil else {
            throw .invalidConfiguration("Server URL cannot contain user information")
        }
        let explicitPort = serverURL.port
        if let explicitPort, !(1...65_535).contains(explicitPort) {
            throw .invalidConfiguration("Server URL port is out of range")
        }
        // Enclose IPv6 literals in square brackets in Host and authority.
        let bracketed = host.contains(":") ? "[\(host)]" : host

        self.serverURL = serverURL
        self.host = host
        usesTLS = scheme == "https"
        port = UInt16(explicitPort ?? (usesTLS ? 443 : 80))
        hostHeader = explicitPort.map { "\(bracketed):\($0)" } ?? bracketed
        authority = bracketed
    }

    /// The server URL with a path (and query) appended. Concatenates strings as Go does.
    func url(path: String) -> URL? {
        var base = serverURL.absoluteString
        while base.hasSuffix("/") { base.removeLast() }
        return URL(string: base + path)
    }
}
