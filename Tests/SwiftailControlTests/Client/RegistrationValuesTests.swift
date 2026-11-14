import Foundation
import SwiftailBase
import Testing

@testable import SwiftailControl

@Suite("등록에 보내는 값")
struct RegistrationValuesTests {
    @Test("인증 키는 --TL 앞부분만 보낸다", arguments: [
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

    @Test("Hostinfo: 최소 필드와 Swiftail 표시")
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
        // 비밀이 아닌 고정값: 같은 machine 키면 같고, 키 자체를 드러내지 않는다.
        let logID = try #require(object["BackendLogID"] as? String)
        #expect(logID.count == 64)
        #expect(!logID.contains("abababab"))
        #expect(Hostinfo.swiftail(hostname: "x", machineKey: machineKey, netInfo: nil).backendLogID == logID)
        #expect(Hostinfo.swiftail(hostname: "x", machineKey: .zero, netInfo: nil).backendLogID != logID)
    }

    @Test("Hostinfo에 NetInfo를 싣는다")
    func hostinfoNetInfo() throws {
        var netInfo = NetInfo()
        netInfo.preferredDERP = 1
        let hostinfo = Hostinfo.swiftail(hostname: "rd-mac-1a2b3c4d", machineKey: .zero, netInfo: netInfo)
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(hostinfo)) as? [String: Any])
        let encoded = try #require(object["NetInfo"] as? [String: Any])
        #expect(encoded["PreferredDERP"] as? Int == 1)
    }

    @Test("설정의 인증 키는 description에 나오지 않는다")
    func configurationHidesAuthKey() throws {
        let configuration = ControlClient.Configuration(
            serverURL: try #require(URL(string: "http://127.0.0.1:9911")),
            hostname: "rd-mac-1a2b3c4d",
            authKey: "tskey-auth-secretvalue"
        )
        #expect(!String(describing: configuration).contains("secretvalue"))
    }

    @Test("거절 메시지에서 인증 키(원문과 --TL 앞부분)를 가린다", arguments: [
        ("invalid authkey: tskey-auth-fake--TLc2ln-cHJpdg", "invalid authkey: <가림>"),
        ("invalid authkey: tskey-auth-fake", "invalid authkey: <가림>"),
        ("tskey-auth-fake and tskey-auth-fake", "<가림> and <가림>"),
        ("invalid authkey", "invalid authkey"),
    ])
    func rejectionHidesAuthKey(message: String, expected: String) {
        #expect(ControlClient.rejectionMessage(message, authKey: "tskey-auth-fake--TLc2ln-cHJpdg") == expected)
    }

    @Test("인증 키가 없거나 비었으면 메시지를 그대로 두고, 긴 메시지는 자른다")
    func rejectionLength() {
        #expect(ControlClient.rejectionMessage("invalid authkey", authKey: nil) == "invalid authkey")
        #expect(ControlClient.rejectionMessage("invalid authkey", authKey: "") == "invalid authkey")
        #expect(ControlClient.rejectionMessage("--TL", authKey: "--TL") == "<가림>")
        let long = String(repeating: "가", count: 10_000)
        let shortened = ControlClient.rejectionMessage(long, authKey: nil)
        #expect(shortened.count == ControlClient.maximumRejectionLength + 1)
        #expect(shortened.hasSuffix("…"))
    }

    @Test("/key 응답에서 Noise 키를 꺼낸다")
    func serverKey() throws {
        let key = "mkey:" + String(repeating: "cd", count: 32)
        let body = #"{"legacyPublicKey":"mkey:\#(String(repeating: "0", count: 64))","publicKey":"\#(key)"}"#
        #expect(try ServerKey.parse(Array(body.utf8)) == MachinePublicKey(key))
        for bad in ["", "null", "{}", #"{"publicKey":"mkey:\#(String(repeating: "0", count: 64))"}"#, #"{"publicKey":"nodekey:\#(String(repeating: "cd", count: 32))"}"#] {
            #expect(throws: ControlError.self) { try ServerKey.parse(Array(bad.utf8)) }
        }
    }

    @Test("서버 URL에서 연결 값을 정한다", arguments: [
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

    @Test("잘못된 서버 URL은 거절한다", arguments: ["ftp://controlplane.example", "file:///x", "http://user:pass@controlplane.example", "http:///nohost"])
    func badEndpoint(url: String) throws {
        let parsed = try #require(URL(string: url))
        #expect(throws: ControlError.self) { try ControlEndpoint(serverURL: parsed) }
    }
}
