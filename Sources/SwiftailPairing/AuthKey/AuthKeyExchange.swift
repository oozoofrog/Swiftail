// 요청의 모양은 Go의 같은 흐름을 따른다.
// 출처: golang.org/x/oauth2 v0.37.0 `internal/token.go` (`newTokenRequest`, `RetrieveToken`, `doTokenRoundTrip`),
//       Go 1.27 `net/url` (`QueryEscape`, `Values.Encode`),
//       tailscale.com v1.104.7 `client/tailscale/keys.go` (`CreateKeyWithExpiry`, `KeyCapabilities`),
//       tailscale.com v1.104.7 `cmd/get-authkey/main.go`.
// Copyright 2014 The Go Authors; Copyright (c) Tailscale Inc & contributors. SPDX-License-Identifier: BSD-3-Clause.

import Foundation

/// 인증 키 발급의 왕복(계약 `docs/contracts/SwiftailPairing.md` 4절 K1): 요청을 만들고 응답을 읽는다.
///
/// 입출력이 없다. 보내는 일은 `AuthKeyTransport`가, 순서(토큰 → 필요하면 다른 방식의 토큰 → 키)는 `AuthKeyIssuer`가
/// 정한다. 그래서 시험은 요청의 바이트와 응답의 분류를 직접 본다.
enum AuthKeyExchange {
    // MARK: 1. OAuth 토큰

    /// 토큰 요청에 클라이언트 자격을 싣는 방식(`x/oauth2`의 `AuthStyle`).
    enum CredentialStyle: Sendable, CaseIterable {
        /// `Authorization: Basic`(RFC 6749 2.3.1). 먼저 쓰는 방식이다.
        case header
        /// 폼 본문의 `client_id`·`client_secret`. 머리 방식이 실패했을 때 한 번 쓴다.
        case parameters
    }

    /// `POST <base>/api/v2/oauth/token`, client credentials 승인.
    ///
    /// 머리 방식은 ID와 비밀을 각각 `url.QueryEscape`로 이스케이프한 뒤 `:`로 잇고 base64로 쓴다. 본문 방식은 그 둘을
    /// 폼 값으로 넣고 `Authorization`을 싣지 않는다. 폼은 Go `url.Values.Encode`처럼 키 순으로 쓴다.
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

    /// 토큰 응답에서 `access_token`을 꺼낸다(`x/oauth2` `doTokenRoundTrip`).
    ///
    /// 성공은 2xx이고 `error`가 없으며 `access_token`이 비지 않은 것이다. 400·401과, 2xx인데 `error`가 있거나
    /// `access_token`이 빈 것은 클라이언트가 거절된 것이다. `token_type`은 거르지 않는다(Go와 같다). 토큰은 Bearer
    /// 머리에 실리므로 머리를 쪼갤 수 있는 글자가 있으면 읽지 못한 응답으로 본다.
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

    // MARK: 2. 인증 키

    /// `lifetime`을 초 단위로 버린다(Go `int64(expiry.Seconds())`). 1초보다 짧으면 받지 않는다(K3). 위쪽 한도는
    /// 서버가 정한다.
    static func expirySeconds(for lifetime: Duration) throws(AuthKeyIssueError) -> Int64 {
        let seconds = lifetime.components.seconds
        guard seconds >= 1 else { throw .invalidLifetime }
        return seconds
    }

    /// `POST <base>/api/v2/tailnet/-/keys`. `-`는 토큰의 tailnet이다.
    ///
    /// 본문은 Go `CreateKeyWithExpiry`가 보내는 것과 같은 JSON이다. 값은 고정이다(K3): 한 번만 쓰고(`reusable`
    /// 거짓), 들어온 노드가 남고(`ephemeral` 거짓. 임시 노드는 StableID가 사라져 짝이 깨진다), 승인 없이 들어온다
    /// (`preauthorized` 참. 승인 대기는 짝 맺기를 멈춘다). Go는 `Content-Type`을 싣지 않지만 여기서는 밝힌다.
    static func keyRequest(baseURL: URL, token: String, tags: [String], expirySeconds: Int64) -> AuthKeyHTTPRequest {
        let body = KeyRequestBody(
            capabilities: .init(devices: .init(create: .init(reusable: false, ephemeral: false, preauthorized: true, tags: tags))),
            expirySeconds: expirySeconds
        )
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        // 문자열·불·정수만 든 구조체라 부호화는 실패하지 않는다. 실패하면 빈 본문을 보내고 서버가 거절한다.
        let bytes = (try? encoder.encode(body)).map(Array.init) ?? []
        return AuthKeyHTTPRequest(
            url: endpoint(baseURL, "/api/v2/tailnet/-/keys"),
            authorization: "Bearer " + token,
            contentType: "application/json",
            body: bytes
        )
    }

    /// 키 응답에서 `key`·`expires`를 꺼낸다. 성공은 200만이다(Go `CreateKeyWithExpiry`와 같다).
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

    // MARK: 도움

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

    /// Go `client/tailscale`처럼 base 문자열 뒤에 경로를 잇는다. base 끝의 `/` 하나는 뺀다.
    private static func endpoint(_ baseURL: URL, _ path: String) -> URL {
        var base = baseURL.absoluteString
        if base.hasSuffix("/") { base.removeLast() }
        // base는 `AuthKeyIssuer.init`에서 검사한 URL이고 path는 고정된 ASCII 경로라 다시 해석해도 실패하지 않는다.
        return URL(string: base + path) ?? baseURL
    }

    private static func decode<Value: Decodable>(_ type: Value.Type, from body: [UInt8]) throws(AuthKeyIssueError) -> Value {
        do {
            return try JSONDecoder().decode(type, from: Data(body))
        } catch {
            throw .invalidResponse
        }
    }

    /// 머리 값에 실어도 되는 값: 비지 않은 인쇄 가능 ASCII(공백 제외). 서버가 준 값으로 머리를 쪼개지 못하게 한다.
    private static func isHeaderSafe(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.allSatisfy { (0x21...0x7E).contains($0) }
    }

    /// RFC 3339 시각. Go `time.Time`의 JSON처럼 소수 초가 있어도 없어도 받는다.
    private static func parseRFC3339(_ value: String) -> Date? {
        (try? Date(value, strategy: .iso8601)) ?? (try? Date(value, strategy: Date.ISO8601FormatStyle(includingFractionalSeconds: true)))
    }

    /// Go `url.QueryEscape`가 그대로 두는 바이트: 영문·숫자와 `-` `_` `.` `~`.
    static func isUnreserved(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "0")...UInt8(ascii: "9"),
             UInt8(ascii: "-"), UInt8(ascii: "_"), UInt8(ascii: "."), UInt8(ascii: "~"):
            true
        default:
            false
        }
    }

    /// Go `url.QueryEscape`: 그대로 두는 바이트 밖에서 공백은 `+`, 나머지는 `%XX`(대문자 16진).
    ///
    /// 검사를 지난 ID·비밀은 그대로 두는 바이트만 쓰므로 값이 바뀌지 않는다. 그래도 Go와 같은 식으로 만든다.
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
