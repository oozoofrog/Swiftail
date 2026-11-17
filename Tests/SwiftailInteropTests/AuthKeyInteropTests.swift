// 관문 (가) 7(계약 `docs/contracts/SwiftailPairing.md` 7절): Go의 같은 흐름(`x/oauth2/clientcredentials` +
// `client/tailscale`의 `CreateKeyWithExpiry`, `cmd/get-authkey`와 같다)과 Swift `AuthKeyIssuer`가 같은 기록 서버
// (`Tools/interop/cmd/authkeyrecorder`)에 보낸 요청을 견준다. 실제 관리 API에는 나가지 않는다.

import Foundation
import SwiftailPairing
import Testing

let authKeyRecorderBinary = ProcessInfo.processInfo.environment["SWIFTAIL_AUTHKEYRECORDER"].flatMap { $0.isEmpty ? nil : $0 }

@Suite("인증 키 발급: Go와 같은 요청", .enabled(if: authKeyRecorderBinary != nil,
    "SWIFTAIL_AUTHKEYRECORDER가 없어 건너뜁니다"), .timeLimit(.minutes(1)))
struct AuthKeyInteropTests {
    /// 기록 서버가 적은 요청 하나(README "authkeyrecorder").
    struct Recorded: Decodable, Equatable {
        let method: String
        let path: String
        let authorization: String
        let contentType: String
        let body: String
        let json: String
        let form: String
    }

    // 받는 글자(`A-Za-z0-9-_.~`)를 두루 쓴 가짜 값.
    static let clientID = "kEXAMPLE-client_1.~"
    static let secret = "tskey-client-EXAMPLE"
    static let tags = ["tag:example", "tag:example-2"]

    /// `rejectBasic`이면 기록 서버가 Basic 머리의 토큰 요청을 거절해 두 구현 모두 본문 방식으로 다시 묻는다.
    @Test("메서드·경로·인증 머리·본문이 같다", arguments: [false, true])
    func sameRequests(rejectBasic: Bool) async throws {
        let binary = try #require(authKeyRecorderBinary)
        let server = Process()
        let input = Pipe()
        let output = Pipe()
        server.executableURL = URL(fileURLWithPath: binary)
        server.arguments = rejectBasic ? ["serve", "-reject-basic"] : ["serve"]
        server.standardInput = input
        server.standardOutput = output
        server.standardError = FileHandle.nullDevice
        try server.run()
        defer {
            try? input.fileHandleForWriting.close()
            if server.isRunning { server.terminate() }
            server.waitUntilExit()
        }
        var firstLine: String?
        for try await line in output.fileHandleForReading.bytes.lines {
            firstLine = line
            break
        }
        let baseURL = try #require(firstLine.flatMap { URL(string: $0) }, "authkeyrecorder가 주소를 출력하지 않았다")

        // Go
        let goKey = try runGoIssue(binary: binary, baseURL: baseURL)
        #expect(goKey == "tskey-auth-EXAMPLE")
        let goRequests = try await recorded(baseURL)

        // Swift
        let issuer = try AuthKeyIssuer(
            client: TailscaleOAuthClient(id: Self.clientID, secret: Self.secret, tags: Self.tags), baseURL: baseURL
        )
        let issued = try await issuer.issue(lifetime: .seconds(600))
        #expect(issued.key == "tskey-auth-EXAMPLE")
        let swiftRequests = try await recorded(baseURL)

        let count = rejectBasic ? 3 : 2
        try #require(goRequests.count == count, "Go 요청: \(goRequests.map(\.path))")
        try #require(swiftRequests.count == count, "Swift 요청: \(swiftRequests.map(\.path))")
        for (go, swift) in zip(goRequests, swiftRequests) {
            #expect(go.method == "POST" && swift.method == "POST")
            #expect(go.path == swift.path)
            #expect(go.authorization == swift.authorization, "\(go.path)의 Authorization")
            #expect(go.json == swift.json, "\(go.path)의 JSON 본문")
            #expect(go.form == swift.form, "\(go.path)의 폼 본문")
            // Go `client/tailscale`은 키 요청에 Content-Type을 싣지 않는다(keys.go `CreateKeyWithExpiry`,
            // tailscale.go `Do`). Swift만 application/json을 싣는다(계약 4절 K1). 그 머리만 견주지 않는다.
            if go.path == "/api/v2/tailnet/-/keys" {
                #expect(go.contentType == "")
                #expect(swift.contentType == "application/json")
            } else {
                #expect(go.contentType == swift.contentType)
            }
        }

        let basic = "Basic " + Data("kEXAMPLE-client_1.~:tskey-client-EXAMPLE".utf8).base64EncodedString()
        #expect(goRequests[0].path == "/api/v2/oauth/token")
        #expect(goRequests[0].authorization == basic)
        #expect(goRequests[0].contentType == "application/x-www-form-urlencoded")
        #expect(goRequests[0].form == "grant_type=client_credentials")
        if rejectBasic {
            #expect(goRequests[1].path == "/api/v2/oauth/token")
            #expect(goRequests[1].authorization == "")
            #expect(goRequests[1].form == "client_id=kEXAMPLE-client_1.~&client_secret=tskey-client-EXAMPLE&grant_type=client_credentials")
        }
        let goKeyRequest = goRequests[count - 1]
        #expect(goKeyRequest.path == "/api/v2/tailnet/-/keys")
        #expect(goKeyRequest.authorization == "Bearer tskey-api-EXAMPLE-token")
        #expect(goKeyRequest.json == #"{"capabilities":{"devices":{"create":{"ephemeral":false,"preauthorized":true,"reusable":false,"tags":["tag:example","tag:example-2"]}}},"expirySeconds":600}"#)
    }

    /// `authkeyrecorder issue`를 돌려 Go가 만든 키를 받는다.
    private func runGoIssue(binary: String, baseURL: URL) throws -> String {
        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: binary)
        process.arguments = [
            "issue", "-base", baseURL.absoluteString, "-tags", Self.tags.joined(separator: ","), "-expiry", "600",
        ]
        process.environment = ["TS_API_CLIENT_ID": Self.clientID, "TS_API_CLIENT_SECRET": Self.secret]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        try #require(process.terminationStatus == 0, "authkeyrecorder issue가 실패했다")
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// 서버가 적은 요청을 받고 비운다.
    private func recorded(_ baseURL: URL) async throws -> [Recorded] {
        let (data, _) = try await URLSession.shared.data(from: baseURL.appending(path: "recorded"))
        return try JSONDecoder().decode([Recorded].self, from: data)
    }
}
