// The request format follows the same flow as Go.
// Origin: golang.org/x/oauth2 v0.37.0 `internal/token.go` (`newTokenRequest`, `RetrieveToken`, `doTokenRoundTrip`),
//       Go 1.27 `net/url` (`QueryEscape`, `Values.Encode`),
//       tailscale.com v1.104.7 `client/tailscale/keys.go` (`CreateKeyWithExpiry`, `KeyCapabilities`),
//       tailscale.com v1.104.7 `cmd/get-authkey/main.go`.
// Copyright 2014 The Go Authors; Copyright (c) Tailscale Inc & contributors. SPDX-License-Identifier: BSD-3-Clause.

import Foundation

/// Builds requests and reads responses for the auth key issuance round trip (contract `docs/contracts/SwiftailPairing.md` §4 K1).
///
/// Performs no I/O. `AuthKeyTransport` sends requests, and `AuthKeyIssuer` decides the order (token → alternative token request if needed → key).
/// This lets tests inspect the request bytes and response classifications directly.
enum AuthKeyExchange {
    // MARK: 1. OAuth Token

    /// How the token request carries client credentials (`AuthStyle` in `x/oauth2`).
    enum CredentialStyle: Sendable, CaseIterable {
        /// `Authorization: Basic` (RFC 6749 2.3.1). This is tried first.
        case header
        /// `client_id` and `client_secret` in the form body. Used once if the header method fails.
        case parameters
    }

    /// `POST <base>/api/v2/oauth/token` with the client credentials grant.
    ///
    /// The header method escapes the ID and secret separately with `url.QueryEscape`, joins them with `:`, and encodes them as base64. The body method
    /// puts both in form values and omits `Authorization`. The form is encoded in key order like Go's `url.Values.Encode`.
    static func tokenRequest(baseURL: URL, client: TailscaleOAuthClient, style: CredentialStyle) -> AuthKeyHTTPRequest {
        let url = endpoint(baseURL, "/api/v2/oauth/token")
        switch style {
        case .header:
            let credentials = queryEscape(client.id) + ":" + queryEscape(client.secret)
            return AuthKeyHTTPRequest(
                url: url,
                authorization: "Basic " + Data(credentials.utf8).base64EncodedString(),
                contentType: "application/x-www-form-urlencoded",
                body: Array("grant_type=client_credentials".utf8)
            )
        case .parameters:
            let form = "client_id=\(queryEscape(client.id))&client_secret=\(queryEscape(client.secret))&grant_type=client_credentials"
            return AuthKeyHTTPRequest(
                url: url, authorization: nil, contentType: "application/x-www-form-urlencoded", body: Array(form.utf8)
            )
        }
    }

    /// Extracts `access_token` from the token response (`doTokenRoundTrip` in `x/oauth2`).
    ///
    /// Success is 2xx with no `error` and a nonempty `access_token`. A 400 or 401, or a 2xx with an error or an empty access_token,
    /// means the client was rejected. Does not filter `token_type` (same as Go). Because the token goes in a Bearer header,
    /// characters that could split the header make the response unreadable.
    static func accessToken(from response: AuthKeyHTTPResponse) throws(AuthKeyIssueError) -> String {
        switch response.status {
        case 200..<300: break
        case 400, 401: throw .clientRejected
        default: throw .http(status: response.status)
        }
        struct Token: Decodable {
            var accessToken: String?
            var error: String?

            enum CodingKeys: String, CodingKey {
                case accessToken = "access_token"
                case error
            }
        }
        let token = try decode(Token.self, from: response.body)
        guard (token.error ?? "").isEmpty, let accessToken = token.accessToken, !accessToken.isEmpty else {
            throw .clientRejected
        }
        guard isHeaderSafe(accessToken) else { throw .invalidResponse }
        return accessToken
    }

    // MARK: 2. Auth Key

    /// Truncates `lifetime` to whole seconds (Go `int64(expiry.Seconds())`). Values shorter than 1 second are rejected (K3). The server sets
    /// the upper limit.
    static func expirySeconds(for lifetime: Duration) throws(AuthKeyIssueError) -> Int64 {
        let seconds = lifetime.components.seconds
        guard seconds >= 1 else { throw .invalidLifetime }
        return seconds
    }

    /// `POST <base>/api/v2/tailnet/-/keys`. The `-` denotes the token's tailnet.
    ///
    /// The body matches the JSON sent by Go's `CreateKeyWithExpiry`. The values are fixed (K3): single-use (`reusable`
    /// false), the joining node persists (`ephemeral` false, because an ephemeral node loses its StableID and breaks the pairing), and it joins without approval
    /// (`preauthorized` true, because waiting for approval stalls pairing). Go omits `Content-Type`, but this implementation explicitly sends it.
    static func keyRequest(baseURL: URL, token: String, tags: [String], expirySeconds: Int64) -> AuthKeyHTTPRequest {
        let body = KeyRequestBody(
            capabilities: .init(devices: .init(create: .init(reusable: false, ephemeral: false, preauthorized: true, tags: tags))),
            expirySeconds: expirySeconds
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        // Encoding does not fail because the struct contains only strings, booleans, and integers. If it does, send an empty body and let the server reject it.
        let bytes = (try? encoder.encode(body)).map(Array.init) ?? []
        return AuthKeyHTTPRequest(
            url: endpoint(baseURL, "/api/v2/tailnet/-/keys"),
            authorization: "Bearer " + token,
            contentType: "application/json",
            body: bytes
        )
    }

    /// Extracts `key` and `expires` from the key response. Only 200 is success (same as Go's `CreateKeyWithExpiry`).
    static func issuedKey(from response: AuthKeyHTTPResponse) throws(AuthKeyIssueError) -> IssuedAuthKey {
        switch response.status {
        case 200: break
        case 401: throw .unauthorized
        case 403: throw .forbidden
        default: throw .http(status: response.status)
        }
        struct Key: Decodable {
            var key: String
            var expires: String
        }
        let key = try decode(Key.self, from: response.body)
        guard key.key.hasPrefix("tskey-auth-"), isHeaderSafe(key.key), let expires = parseRFC3339(key.expires) else {
            throw .invalidResponse
        }
        return IssuedAuthKey(key: key.key, expires: expires)
    }

    // MARK: Helpers

    private struct KeyRequestBody: Encodable {
        struct Capabilities: Encodable { var devices: Devices }
        struct Devices: Encodable { var create: Create }
        struct Create: Encodable {
            var reusable: Bool
            var ephemeral: Bool
            var preauthorized: Bool
            var tags: [String]
        }

        var capabilities: Capabilities
        var expirySeconds: Int64
    }

    /// Appends the path to the base string like Go's `client/tailscale`. Removes one trailing `/` from the base.
    private static func endpoint(_ baseURL: URL, _ path: String) -> URL {
        var base = baseURL.absoluteString
        if base.hasSuffix("/") { base.removeLast() }
        // `AuthKeyIssuer.init` validated the base URL, and path is a fixed ASCII path, so parsing again succeeds.
        return URL(string: base + path) ?? baseURL
    }

    private static func decode<Value: Decodable>(_ type: Value.Type, from body: [UInt8]) throws(AuthKeyIssueError) -> Value {
        do {
            return try JSONDecoder().decode(type, from: Data(body))
        } catch {
            throw .invalidResponse
        }
    }

    /// A value safe to put in a header: nonempty printable ASCII without spaces. Prevents a server-supplied value from splitting the header.
    private static func isHeaderSafe(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { (0x21...0x7E).contains($0) }
    }

    /// An RFC 3339 time. Accepts optional fractional seconds, like Go's `time.Time` JSON.
    private static func parseRFC3339(_ value: String) -> Date? {
        (try? Date(value, strategy: .iso8601)) ?? (try? Date(value, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true)))
    }

    /// The bytes Go's `url.QueryEscape` leaves unchanged: English letters, digits, and `-` `_` `.` `~`.
    static func isUnreserved(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: "."), UInt8(ascii: "~"):
            true
        default:
            false
        }
    }

    /// Go's `url.QueryEscape` replaces spaces with `+` and other bytes outside the unchanged set with `%XX` (uppercase hexadecimal).
    ///
    /// Validated IDs and secrets use only unchanged bytes, so the values stay the same. The implementation still encodes them as Go does.
    static func queryEscape(_ value: String) -> String {
        let hex = Array("0123456789ABCDEF".utf8)
        var escaped: [UInt8] = []
        for byte in value.utf8 {
            if isUnreserved(byte) {
                escaped.append(byte)
            } else if byte == UInt8(ascii: " ") {
                escaped.append(UInt8(ascii: "+"))
            } else {
                escaped += [UInt8(ascii: "%"), hex[Int(byte >> 4)], hex[Int(byte & 0x0F)]]
            }
        }
        return String(decoding: escaped, as: UTF8.self)
    }
}
