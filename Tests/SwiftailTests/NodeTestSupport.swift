// Shared node test helpers: netmap JSON, configuration, a temporary state directory, and IPv4 UDP packets.
// The fields of tailcfg values are inaccessible externally, so create the values by decoding the same JSON the control server sends.

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

    /// A netmap for the local node (ID 1). An empty `addresses` gives a local node with no addresses. `regions` is the JSON inside the DERPMap's `Regions`,
    /// and `dnsConfig` is `DNSConfig` JSON.
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

    /// Configuration using a loopback port with no control server (9, discard). The connection fails and the node backs off and retries.
    static func configuration(stateDirectory: URL) throws -> NodeConfiguration {
        NodeConfiguration(
            stateDirectory: stateDirectory,
            hostname: "rd-mac-1a2b3c4d",
            controlURL: try #require(URL(string: "http://127.0.0.1:9"))
        )
    }

    /// A state directory in which files cannot be created. Use in tests that do not call `run()`.
    static func unusedConfiguration() throws -> NodeConfiguration {
        try configuration(stateDirectory: try #require(URL(string: "file:///var/empty/swiftail-test/")))
    }

    /// Creates an empty temporary directory, passes it to `body`, and deletes it afterward.
    static func withTemporaryDirectory<T>(_ body: (URL) async throws -> T) async throws -> T {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-node-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        return try await body(directory)
    }

    /// An IPv4 UDP packet. The checksum is 0 (the engine does not check it).
    static func udp(from source: [UInt8], _ sourcePort: UInt16, to destination: [UInt8], _ destinationPort: UInt16, payload: [UInt8]) -> [UInt8] {
        let udpLength = 8 + payload.count
        let total = 20 + udpLength
        let ip: [UInt8] = [0x45, 0, UInt8(total >> 8), UInt8(total & 0xFF), 0, 0, 0, 0, 64, 17, 0, 0] + source + destination
        let udp: [UInt8] = [UInt8(sourcePort >> 8), UInt8(sourcePort & 0xFF), UInt8(destinationPort >> 8), UInt8(destinationPort & 0xFF),
                            UInt8(udpLength >> 8), UInt8(udpLength & 0xFF), 0, 0]
        return ip + udp + payload
    }

    /// A DNS query (RD=1, one question, class IN).
    static func dnsQuery(_ name: String, type: UInt16, id: UInt16) -> [UInt8] {
        var bytes: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            bytes.append(UInt8(label.utf8.count))
            bytes += Array(label.utf8)
        }
        bytes += [0, UInt8(type >> 8), UInt8(type & 0xFF), 0, 1]
        return bytes
    }

    /// Reads until the stream ends.
    static func drain<Element>(_ stream: AsyncStream<Element>) async -> [Element] {
        var elements: [Element] = []
        for await element in stream { elements.append(element) }
        return elements
    }
}
