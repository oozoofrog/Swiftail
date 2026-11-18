import Foundation
import SwiftailBase
import Testing

@testable import SwiftailControl

@Suite("Values sent during registration")
struct RegistrationValuesTests {
    @Test("Sends only the part of the auth key before --TL", arguments: [
        ("tskey-auth-fake", "tskey-auth-fake"),
        ("tskey-auth-fake--TLc2ln-cHJpdg", "tskey-auth-fake"),
        ("tskey-auth-fake--TL", "tskey-auth-fake"),
        ("--TLonly", ""),
        ("tskey-auth-fake-TL", "tskey-auth-fake-TL"),
        ("", ""),
    ])
    func authKey(input: String, expected: String) {
        #expect(AuthKey.controlValue(of: input) == expected)
    }

    @Test("Hostinfo: Minimum fields and the Swiftail identifier")
    func hostinfo() throws {
        let machineKey = try #require(MachinePublicKey("mkey:" + String(repeating: "ab", count: 32)))
        let hostinfo = Hostinfo.swiftail(hostname: "rd-mac-1a2b3c4d", machineKey: machineKey, netInfo: nil)
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(hostinfo)) as? [String: Any])

        #expect(object["Hostname"] as? String == "rd-mac-1a2b3c4d")
        #expect(object["IPNVersion"] as? String == "0.0.0-swiftail")
        #expect(object["App"] as? String == "swiftail")
        #expect(object["OS"] as? String == "macOS")
        #expect((object["OSVersion"] as? String)?.isEmpty == false)
        #expect(object["Userspace"] as? Bool == true)
        #expect(object["NetInfo"] == nil)
        // A fixed, nonsecret value. The same machine key yields the same value without revealing the key itself.
        let logID = try #require(object["BackendLogID"] as? String)
        #expect(logID.count == 64)
        #expect(!logID.contains("abababab"))
        #expect(Hostinfo.swiftail(hostname: "x", machineKey: machineKey, netInfo: nil).backendLogID == logID)
        #expect(Hostinfo.swiftail(hostname: "x", machineKey: .zero, netInfo: nil).backendLogID != logID)
    }

    @Test("Includes NetInfo in Hostinfo")
    func hostinfoNetInfo() throws {
        var netInfo = NetInfo()
        netInfo.preferredDERP = 1
        let hostinfo = Hostinfo.swiftail(hostname: "rd-mac-1a2b3c4d", machineKey: .zero, netInfo: netInfo)
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(hostinfo)) as? [String: Any])
        let encoded = try #require(object["NetInfo"] as? [String: Any])
        #expect(encoded["PreferredDERP"] as? Int == 1)
    }

    @Test("The configured auth key is absent from description")
    func configurationHidesAuthKey() throws {
        let configuration = ControlClient.Configuration(
            serverURL: try #require(URL(string: "http://127.0.0.1:9911")),
            hostname: "rd-mac-1a2b3c4d",
            authKey: "tskey-auth-secretvalue"
        )
        #expect(!String(describing: configuration).contains("secretvalue"))
    }

    @Test("Redacts the auth key (the original and the part before --TL) in rejection messages", arguments: [
        ("invalid authkey: tskey-auth-fake--TLc2ln-cHJpdg", "invalid authkey: <가림>"),
        ("invalid authkey: tskey-auth-fake", "invalid authkey: <가림>"),
        ("tskey-auth-fake and tskey-auth-fake", "<가림> and <가림>"),
        ("invalid authkey", "invalid authkey"),
    ])
    func rejectionHidesAuthKey(message: String, expected: String) {
        #expect(ControlClient.rejectionMessage(message, authKey: "tskey-auth-fake--TLc2ln-cHJpdg") == expected)
    }

    @Test("Leaves the message unchanged if the auth key is missing or empty and truncates long messages")
    func rejectionLength() {
        #expect(ControlClient.rejectionMessage("invalid authkey", authKey: nil) == "invalid authkey")
        #expect(ControlClient.rejectionMessage("invalid authkey", authKey: "") == "invalid authkey")
        #expect(ControlClient.rejectionMessage("--TL", authKey: "--TL") == "<가림>")
        let long = String(repeating: "가", count: 10_000)
        let shortened = ControlClient.rejectionMessage(long, authKey: nil)
        #expect(shortened.count == ControlClient.maximumRejectionLength + 1)
        #expect(shortened.hasSuffix("…"))
    }

    @Test("Extracts the Noise key from the /key response")
    func serverKey() throws {
        let key = "mkey:" + String(repeating: "cd", count: 32)
        let body = #"{"legacyPublicKey":"mkey:\#(String(repeating: "0", count: 64))","publicKey":"\#(key)"}"#
        #expect(try ServerKey.parse(Array(body.utf8)) == MachinePublicKey(key))
        for bad in ["", "null", "{}", #"{"publicKey":"mkey:\#(String(repeating: "0", count: 64))"}"#, #"{"publicKey":"nodekey:\#(String(repeating: "cd", count: 32))"}"#] {
            #expect(throws: ControlError.self) { try ServerKey.parse(Array(bad.utf8)) }
        }
    }

    @Test("Derives connection values from the server URL", arguments: [
        ("http://127.0.0.1:9911", "127.0.0.1", 9911, false, "127.0.0.1:9911", "127.0.0.1"),
        ("https://controlplane.example", "controlplane.example", 443, true, "controlplane.example", "controlplane.example"),
        ("http://controlplane.example/", "controlplane.example", 80, false, "controlplane.example", "controlplane.example"),
        ("http://[::1]:8080", "::1", 8080, false, "[::1]:8080", "[::1]"),
    ] as [(String, String, UInt16, Bool, String, String)])
    func endpoint(url: String, host: String, port: UInt16, tls: Bool, hostHeader: String, authority: String) throws {
        let endpoint = try ControlEndpoint(serverURL: try #require(URL(string: url)))
        #expect(endpoint.host == host)
        #expect(endpoint.port == port)
        #expect(endpoint.usesTLS == tls)
        #expect(endpoint.hostHeader == hostHeader)
        #expect(endpoint.authority == authority)
        #expect(endpoint.url(path: "/key?v=148")?.absoluteString.hasSuffix("/key?v=148") == true)
        #expect(endpoint.url(path: "/key?v=148")?.absoluteString.contains("//key") == false)
    }

    @Test("Rejects an invalid server URL", arguments: ["ftp://controlplane.example", "file:///x", "http://user:pass@controlplane.example", "http:///nohost"])
    func badEndpoint(url: String) throws {
        let parsed = try #require(URL(string: url))
        #expect(throws: ControlError.self) { try ControlEndpoint(serverURL: parsed) }
    }
}
