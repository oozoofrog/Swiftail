import Foundation

/// A `POST /ts2021` HTTP/1.1 upgrade request.
///
/// The control connection starts as an ordinary HTTP request and switches to Noise on the same socket after `101 Switching Protocols`.
/// To save a round trip, sends Noise initiation as standard base64 in the `X-Tailscale-Handshake` request header.
/// There is no body. Without `Host`, the Go server returns 400 before the request reaches the handler.
///
/// `docs/protocol-notes/control-transport.md` §3.6, §4.4 step 2
/// (origin: tailscale.com `control/controlhttp/client.go`).
public enum UpgradeRequest {
    /// The complete request head bytes, including the blank line.
    ///
    /// - Parameters:
    ///   - host: The upgrade URL's host and port (for example, `127.0.0.1:9911`). Comes from configuration.
    ///     Whitespace or control characters are a programmer error.
    ///   - initiation: `ControlHandshake.initiation`.
    public static func bytes(host: String, initiation: [UInt8]) -> [UInt8] {
        precondition(
            !host.isEmpty && host.utf8.allSatisfy { $0 > 0x20 && $0 != 0x7F },
            "Spaces or control characters in the Host value corrupt the request head"
        )
        let lines = [
            "POST /ts2021 HTTP/1.1",
            "Host: \(host)",
            "Upgrade: \(UpgradeResponseParser.protocolName)",
            "Connection: upgrade",
            "X-Tailscale-Handshake: \(Data(initiation).base64EncodedString())",
            // Go also sends 0 for a POST without a body.
            "Content-Length: 0",
        ]
        return Array((lines.joined(separator: "\r\n") + "\r\n\r\n").utf8)
    }
}
