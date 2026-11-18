// Gate (a) 7 (`docs/contracts/SwiftailPairing.md` contract §7) compares requests from the equivalent Go flow (`x/oauth2/clientcredentials` +
// `CreateKeyWithExpiry` in `client/tailscale`, as in `cmd/get-authkey`) and Swift's `AuthKeyIssuer` to the same recording server
// (`Tools/interop/cmd/authkeyrecorder`). Neither calls the real management API.

import Foundation
import SwiftailPairing
import Testing

let authKeyRecorderBinary = ProcessInfo.processInfo.environment["SWIFTAIL_AUTHKEYRECORDER"].flatMap { $0.isEmpty ? nil : $0 }

@Suite("Auth key issuance with the same requests as Go", .enabled(if: authKeyRecorderBinary != nil,
    "Skipping because SWIFTAIL_AUTHKEYRECORDER is missing"), .timeLimit(.minutes(1)))
struct AuthKeyInteropTests {
    /// One request recorded by the server (README "authkeyrecorder").
    struct Recorded: Decodable, Equatable {
        let method: String
        let path: String
        let authorization: String
        let contentType: String
        let body: String
        let json: String
        let form: String
    }

    // Fake values that use a variety of accepted characters (`A-Za-z0-9-_.~`).
    static let clientID = "kEXAMPLE-client_1.~"
    static let secret = "tskey-client-EXAMPLE"
    static let tags = ["tag:example", "tag:example-2"]

    /// If `rejectBasic` is true, the recording server rejects the token request with a Basic header, so both implementations retry with credentials in the body.
    @Test("Methods, paths, authentication headers, and bodies match", arguments: [false, true])
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
        let baseURL = try #require(firstLine.flatMap { URL(string: $0) }, "authkeyrecorder did not print an address")

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
        try #require(goRequests.count == count, "Go requests: \(goRequests.map(\.path))")
        try #require(swiftRequests.count == count, "Swift requests: \(swiftRequests.map(\.path))")
        for (go, swift) in zip(goRequests, swiftRequests) {
            #expect(go.method == "POST" && swift.method == "POST")
            #expect(go.path == swift.path)
            #expect(go.authorization == swift.authorization, "Authorization for \(go.path)")
            #expect(go.json == swift.json, "JSON body for \(go.path)")
            #expect(go.form == swift.form, "Form body for \(go.path)")
            // Go `client/tailscale` omits Content-Type on key requests (keys.go `CreateKeyWithExpiry`,
            // tailscale.go `Do`). Only Swift sends application/json (contract §4 K1). That header alone is excluded from comparison.
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

    /// Runs `authkeyrecorder issue` and returns the key generated by Go.
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
        try #require(process.terminationStatus == 0, "authkeyrecorder issue failed")
        return String(decoding: data, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// Retrieves and clears the requests recorded by the server.
    private func recorded(_ baseURL: URL) async throws -> [Recorded] {
        let (data, _) = try await URLSession.shared.data(from: baseURL.appending(path: "recorded"))
        return try JSONDecoder().decode([Recorded].self, from: data)
    }
}
