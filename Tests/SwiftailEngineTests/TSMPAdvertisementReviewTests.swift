// Independent review tests for TSMP disco key advertisements on the engine side. Compare receiver boundary cases and advertisement bytes after netmap changes with Go.
// Reference sources in tailscale.com v1.104.7 are `net/packet/packet.go` (`decode4` and `decode6`) and `net/packet/tsmp.go`
// (`AsTSMPDiscoAdvertisement`), `net/tstun/wrap.go`(`filterPacketInboundFromWireGuard`),
// `wgengine/magicsock/magicsock.go`(`PriorityMessageForPeer`, `selfIPMatchingFamily`). BSD-3-Clause.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine
@testable import SwiftailWireGuard

private let reviewDisco = DiscoPublicKey(rawValue: [UInt8](repeating: 0xB7, count: 32))!

/// Sets up two engines (a receives, b sends) and establishes a session. Adds `bobExtraAllowedIPs` to b's AllowedIPs.
private struct ReviewPair {
    var a: TailnetEngine
    var b: TailnetEngine
    let aKey = Curve25519.KeyAgreement.PrivateKey()
    let bKey = Curve25519.KeyAgreement.PrivateKey()
    static let aSource = TailnetEngine.Source(address: [192, 0, 2, 1, 0x29, 0xA2], host: [192, 0, 2, 1])
    static let bSource = TailnetEngine.Source(address: [192, 0, 2, 2, 0x29, 0xA2], host: [192, 0, 2, 2])

    init(bobExtraAllowedIPs: [String] = []) throws {
        a = TailnetEngine(nodeKey: aKey, discoKey: .zero, now: clockStart, wallClock: wallClockStart)
        b = TailnetEngine(nodeKey: bKey, discoKey: .zero, now: clockStart, wallClock: wallClockStart)
        let aNode = Self.node(1, aKey, "100.64.0.1", "fd7a:115c:a1e0::1", extraAllowed: [])
        let bNode = Self.node(2, bKey, "100.64.0.2", "fd7a:115c:a1e0::2", extraAllowed: bobExtraAllowedIPs)
        _ = a.apply(try makeNetmap(selfNode: aNode, peers: [bNode], packetFilter: #"[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]"#),
                    at: clockStart, wallClock: wallClockStart)
        _ = b.apply(try makeNetmap(selfNode: bNode, peers: [aNode]), at: clockStart, wallClock: wallClockStart)
        // b sends first to establish the session.
        _ = deliverFromB(b.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), at: clockStart))
    }

    static func node(_ id: Int64, _ key: Curve25519.KeyAgreement.PrivateKey, _ v4: String, _ v6: String, extraAllowed: [String]) -> String {
        let allowed = (["\(v4)/32", "\(v6)/128"] + extraAllowed).map { "\"\($0)\"" }.joined(separator: ",")
        return makeNodeJSON(id: id, key: NodePublicKey(key.publicKey), addresses: ["\(v4)/32", "\(v6)/128"],
                            extra: #","AllowedIPs":[\#(allowed)],"DiscoKey":"\#(discoKeyText)","HomeDERP":1"#)
    }

    /// Passes b's output to a and a's replies to b until neither sends anything. Returns what a emits to the layer above.
    mutating func deliverFromB(_ outputs: [TailnetEngine.Output]) -> [TailnetEngine.Output] {
        var aOutputs: [TailnetEngine.Output] = []
        var queue = outputs.map { (fromB: true, output: $0) }
        while !queue.isEmpty {
            let (fromB, output) = queue.removeFirst()
            guard case let .datagram(bytes, _) = output else {
                if !fromB { aOutputs.append(output) }
                continue
            }
            if fromB {
                queue += a.receive(bytes, from: Self.bSource, at: clockStart).map { (fromB: false, output: $0) }
            } else {
                queue += b.receive(bytes, from: Self.aSource, at: clockStart).map { (fromB: true, output: $0) }
            }
        }
        return aOutputs
    }

    /// Sends an arbitrary IP packet from b over the session (a malicious peer can send TSMP at any time).
    mutating func bSendsRaw(_ packet: [UInt8]) throws -> [TailnetEngine.Output] {
        let datagrams = try b.device.send(packet, to: PublicKey(NodePublicKey(aKey.publicKey)), at: clockStart)
        return deliverFromB(b.route(datagrams))
    }
}

private func advertisementBytes(from source: String, to destination: String) -> [UInt8] {
    TSMPDiscoKeyAdvertisement(
        selfAddresses: [IPPrefix(address: IPAddress(source)!, length: source.contains(":") ? 128 : 32)!],
        destination: IPAddress(destination)!, key: reviewDisco
    )!.bytes
}

@Suite("Review of TSMP advertisement receiver boundaries")
struct TSMPAdvertisementBoundaryReviewTests {
    @Test("Accept advertisements even if the destination is not the local address (Go also ignores the destination). The source must be an address of that peer")
    func destinationIsNotChecked() throws {
        var pair = try ReviewPair()
        let outputs = try pair.bSendsRaw(advertisementBytes(from: "100.64.0.2", to: "100.64.0.77"))
        #expect(outputs == [.discoKeyAdvertised(reviewDisco, from: NodePublicKey(pair.bKey.publicKey))])
    }

    @Test("Accept IPv6 advertisements too")
    func ipv6Advertisement() throws {
        var pair = try ReviewPair()
        let outputs = try pair.bSendsRaw(advertisementBytes(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1"))
        #expect(outputs == [.discoKeyAdvertised(reviewDisco, from: NodePublicKey(pair.bKey.publicKey))])
    }

    @Test("Reject advertisements sourced from a subnet route because the engine excludes subnets from AllowedIPs (stricter than Go)")
    func subnetSourceIsRejected() throws {
        var pair = try ReviewPair(bobExtraAllowedIPs: ["10.9.0.0/24"])
        let outputs = try pair.bSendsRaw(advertisementBytes(from: "10.9.0.5", to: "100.64.0.1"))
        #expect(outputs == [.dropped(.wireGuard(.disallowedSource))])
    }

    @Test("Ignore advertisements in IPv4 fragments (MF or offset). Go `decode4` also drops fragmented TSMP", arguments: [UInt16(0x2000), 0x0001])
    func ipv4FragmentIsRejected(flagsAndOffset: UInt16) throws {
        var pair = try ReviewPair()
        let payload = [TSMPDiscoKeyAdvertisement.type] + reviewDisco.rawValue
        let packet = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 99, transport: payload, flagsAndOffset: flagsAndOffset)
        let outputs = try pair.bSendsRaw(packet)
        #expect(!outputs.contains(.discoKeyAdvertised(reviewDisco, from: NodePublicKey(pair.bKey.publicKey))))
    }

    @Test("Swiftail drops the first IPv6 fragment (TSMP after the fragment header), while Go accepts it. The difference is harmless because Go peers send the 73-byte advertisement unfragmented")
    func ipv6FirstFragmentDiffers() throws {
        let payload = [TSMPDiscoKeyAdvertisement.type] + reviewDisco.rawValue
        // Fragment header fields are next header 99, offset 0, and MF 1.
        let fragmentHeader: [UInt8] = [99, 0, 0x00, 0x01, 0, 0, 0, 1]
        let packet = TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: 44, transport: fragmentHeader + payload)
        #expect(throws: IPPacket.ParseError.fragment) { try IPPacket(parsing: packet) }
    }

    @Test("Ignore bytes beyond the total length in the header. A declared body shorter than 33 bytes is not an advertisement")
    func trailingBytesBeyondTotalLength() throws {
        var bytes = advertisementBytes(from: "100.64.0.2", to: "100.64.0.1")
        bytes[3] -= 1 // Total length 52 (body 32)
        let packet = try IPPacket(parsing: bytes)
        #expect(TSMPDiscoKeyAdvertisement(parsing: packet) == nil)
    }
}

@Suite("Review of advertisement bytes after netmap changes")
struct TSMPAdvertisementNetmapReviewTests {
    let selfKey = Curve25519.KeyAgreement.PrivateKey()
    let peerKey = Curve25519.KeyAgreement.PrivateKey()

    private func message(selfAddresses: [String], peerAddresses: [String], engine: inout TailnetEngine) throws -> [UInt8]? {
        let selfNode = makeNodeJSON(id: 1, key: NodePublicKey(selfKey.publicKey), addresses: selfAddresses,
                                    extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#)
        let peerNode = makeNodeJSON(id: 2, key: NodePublicKey(peerKey.publicKey), addresses: peerAddresses,
                                    extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#)
        _ = engine.apply(try makeNetmap(selfNode: selfNode, peers: [peerNode]), at: clockStart, wallClock: wallClockStart)
        return engine.device.peers[PublicKey(NodePublicKey(peerKey.publicKey))]?.priorityMessage
    }

    @Test("Advertisement source and destination follow local and peer address changes, and the advertisement is cleared when there is no matching family")
    func followsNetmap() throws {
        var engine = TailnetEngine(nodeKey: selfKey, discoKey: reviewDisco, now: clockStart, wallClock: wallClockStart)
        let first = try message(selfAddresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], peerAddresses: ["100.64.0.2/32"], engine: &engine)
        #expect(first == advertisementBytes(from: "100.64.0.1", to: "100.64.0.2"))

        let moved = try message(selfAddresses: ["100.64.0.11/32", "fd7a:115c:a1e0::1/128"], peerAddresses: ["100.64.0.12/32"], engine: &engine)
        #expect(moved == advertisementBytes(from: "100.64.0.11", to: "100.64.0.12"))

        // When the peer's first address changes to IPv6, send from the local IPv6 address.
        let v6 = try message(selfAddresses: ["100.64.0.11/32", "fd7a:115c:a1e0::1/128"], peerAddresses: ["fd7a:115c:a1e0::2/128", "100.64.0.12/32"], engine: &engine)
        #expect(v6 == advertisementBytes(from: "fd7a:115c:a1e0::1", to: "fd7a:115c:a1e0::2"))

        // When only a local IPv4 address remains, send nothing to the IPv6 peer (Go `selfIPMatchingFamily` is invalid → nil).
        let none = try message(selfAddresses: ["100.64.0.11/32"], peerAddresses: ["fd7a:115c:a1e0::2/128"], engine: &engine)
        #expect(none == nil)
    }
}
