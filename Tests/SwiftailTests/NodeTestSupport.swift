// 노드 시험 공용 도우미: netmap JSON, 설정, 임시 상태 디렉터리, IPv4 UDP 패킷.
// tailcfg 값의 필드는 바깥에서 쓸 수 없으므로 제어 서버가 보내는 것과 같은 JSON을 해독해 만든다.

import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

enum NodeTestSupport {
    static let selfName = "rd-mac-1a2b3c4d.tail0001.ts.net."

    static func nodeKey(_ byte: UInt8) -> String {
        "nodekey:" + [UInt8](repeating: byte, count: 32).hex
    }

    /// 자기 노드(ID 1)의 netmap. `addresses`가 비면 주소 없는 자기 노드다. `regions`는 DERPMap의 `Regions` 안쪽 JSON,
    /// `dnsConfig`는 `DNSConfig` JSON이다.
    static func netmap(
        addresses: [String] = ["100.64.0.1/32"],
        machineAuthorized: Bool = true,
        regions: String? = nil,
        dnsConfig: String = #"{"Proxied":true}"#,
        peerAddress: String? = nil
    ) throws -> Netmap {
        let addressList = addresses.map { "\"\($0)\"" }.joined(separator: ",")
        let selfNode = #"{"ID":1,"StableID":"nStable1","Name":"\#(selfName)","User":101,"Key":"\#(nodeKey(0x11))","#
            + #""Addresses":[\#(addressList)],"MachineAuthorized":\#(machineAuthorized)}"#
        let peers = peerAddress.map { address in
            #"[{"ID":2,"Name":"rd-phone-1a2b3c4d.tail0001.ts.net.","User":101,"Key":"\#(nodeKey(0x22))","#
                + #""Addresses":["\#(address)"],"AllowedIPs":["\#(address)"],"HomeDERP":1}]"#
        } ?? "[]"
        let derpMap = regions.map { #","DERPMap":{"Regions":{\#($0)}}"# } ?? ""
        let json = #"{"Node":\#(selfNode),"Peers":\#(peers),"Domain":"tail0001.ts.net","DNSConfig":\#(dnsConfig)\#(derpMap)}"#
        let response = try JSONDecoder().decode(MapResponse.self, from: Data(json.utf8))
        var session = MapSession()
        return try #require(try session.apply(response, receivedAt: Date()).netmap)
    }

    /// 제어 서버가 없는 루프백 포트(9, discard)로 가는 설정. 연결은 실패하고 노드는 물러났다가 다시 시도한다.
    static func configuration(stateDirectory: URL) throws -> NodeConfiguration {
        NodeConfiguration(
            stateDirectory: stateDirectory,
            hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9"))
        )
    }

    /// 파일을 만들 수 없는 상태 디렉터리. `run()`을 부르지 않는 시험에 쓴다.
    static func unusedConfiguration() throws -> NodeConfiguration {
        try configuration(stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")))
    }

    /// 빈 임시 디렉터리를 만들어 `body`에 넘기고 끝나면 지운다.
    static func withTemporaryDirectory<T>(_ body: (URL) async throws -> T) async throws -> T {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-node-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        return try await body(directory)
    }

    /// IPv4 UDP 패킷. 체크섬은 0이다(엔진은 보지 않는다).
    static func udp(from source: [UInt8], _ sourcePort: UInt16, to destination: [UInt8], _ destinationPort: UInt16, payload: [UInt8]) -> [UInt8] {
        let udpLength = 8 + payload.count
        let total = 20 + udpLength
        let ip: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0, 0, 64, 17, 0, 0] + source + destination
        let udp: [UInt8] = [UInt8(sourcePort >> 8), UInt8(sourcePort & 0xFF), UInt8(destinationPort >> 8), UInt8(destinationPort & 0xFF),
                            UInt8(udpLength >> 8), UInt8(udpLength & 0xFF), 0, 0]
        return ip + udp + payload
    }

    /// DNS 질의(RD=1, 질문 하나, class IN).
    static func dnsQuery(_ name: String, type: UInt16, id: UInt16) -> [UInt8] {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes += Array(label.utf8)
        }
        bytes += [0, UInt8(type >> 8), UInt8(type & 0xFF), 0, 1]
        return bytes
    }

    /// 흐름이 끝날 때까지 읽는다.
    static func drain<Element>(_ stream: AsyncStream<Element>) async -> [Element] {
        var elements: [Element] = []
        for await element in stream { elements.append(element) }
        return elements
    }
}
