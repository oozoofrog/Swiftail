import Foundation
import SwiftailBase

/// Fetches the control server's Noise public key with `GET <serverURL>/key?v=148`.
///
/// Uses ordinary HTTP(S) outside Noise. For `https://`, uses URLSession's default certificate validation.
/// The response is `{"legacyPublicKey":"mkey:…","publicKey":"mkey:…"}`. Uses only `publicKey`. A zero key indicates a
/// legacy server without Noise and causes failure. Reads up to 64KiB of the body. testcontrol creates its Noise key pair in this request,
/// so call it before `/ts2021`.
///
/// `shortcut:` leaves this request unbound to `NWInterface`. URLSession has no way to bind a request to an interface. In the packet tunnel
/// extension, the control server address falls outside the tunnel routes (only the local tailnet addresses and the service IP), so the request is assumed to follow the system default route over the physical
/// interface. The server key is fetched again only after a connection failure, so requests are infrequent. If a real device shows the request entering
/// the tunnel, switch to HTTP/1.1 over `NetworkSocket` (including `Transfer-Encoding: chunked` decoding).
///
/// `docs/protocol-notes/control-transport.md` 3.8, 4.1.
enum ServerKey {
    static let maximumBodySize = 64 << 10

    static func fetch(for endpoint: ControlEndpoint) async throws(ControlError) -> MachinePublicKey {
        guard let url = endpoint.url(path: "/key?v=148") else {
            throw .invalidConfiguration("Could not construct the /key address from the server URL")
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.httpMethod = "GET"
        var body: [UInt8] = []
        let response: URLResponse
        do {
            let (bytes, received) = try await URLSession.shared.bytes(for: request)
            response = received
            for try await byte in bytes {
                guard body.count < maximumBodySize else { throw ControlError.connection("/key response exceeds 64KiB") }
                body.append(byte)
            }
        } catch let error as ControlError {
            throw error
        } catch {
            throw .connection("/key request failed (code \((error as NSError).code))")
        }
        guard let status = (response as? HTTPURLResponse)?.statusCode else {
            throw .connection("/key response is not HTTP")
        }
        guard status == 200 else { throw .http(status: status) }
        return try parse(body)
    }

    /// Extracts the Noise key from the `/key` response body.
    static func parse(_ body: [UInt8]) throws(ControlError) -> MachinePublicKey {
        guard let response = try? JSONDecoder().decode(Response.self, from: Data(body)) else {
            throw .connection("Could not parse the /key response")
        }
        guard !response.publicKey.isZero else { throw .connection("Control server is too old (missing Noise key)") }
        return response.publicKey
    }

    private struct Response: Decodable {
        var publicKey: MachinePublicKey
    }
}
