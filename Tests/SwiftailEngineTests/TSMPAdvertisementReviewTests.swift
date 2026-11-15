// TSMP disco 키 광고의 독립 검토 시험(엔진 쪽). 받는 쪽의 경계와 netmap이 바뀔 때의 광고 바이트를 Go와 견준다.
// 기준: tailscale.com v1.104.7 `net/packet/packet.go`(`decode4`·`decode6`), `net/packet/tsmp.go`
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

/// 두 엔진(a: 받는 쪽, b: 보내는 쪽)을 세션까지 세운다. b의 AllowedIPs에 `bobExtraAllowedIPs`를 더한다.
private struct ReviewPair {
    var a: TailnetEngine
    var b: TailnetEngine
    let aKey = Curve25519.KeyAgreement.PrivateKey()
    let bKey = Curve25519.KeyAgreement.PrivateKey()
    static let aSource = TailnetEngine.Source(address: [192, 0, 2, 1, 0x29, 0xA2], host: [192, 0, 2, 1])
    static let bSource = TailnetEngine.Source(address: [192, 0, 2, 2, 0x29, 0xA2], host: [192, 0, 2, 2])

    init(bobExtraAllowedIPs: [String] = []) throws {
        a = TailnetEngine(nodeKey: aKey, now: clockStart, wallClock: wallClockStart)
        b = TailnetEngine(nodeKey: bKey, now: clockStart, wallClock: wallClockStart)
        let aNode = Self.node(1, aKey, "100.64.0.1", "fd7a:115c:a1e0::1", extraAllowed: [])
        let bNode = Self.node(2, bKey, "100.64.0.2", "fd7a:115c:a1e0::2", extraAllowed: bobExtraAllowedIPs)
        _ = a.apply(try makeNetmap(selfNode: aNode, peers: [bNode], packetFilter: #"[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":0,"Last":65535}}]}]"#),
                    at: clockStart, wallClock: wallClockStart)
        _ = b.apply(try makeNetmap(selfNode: bNode, peers: [aNode]), at: clockStart, wallClock: wallClockStart)
        // b가 먼저 보내 세션을 세운다.
        _ = deliverFromB(b.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), at: clockStart))
    }

    static func node(_ id: Int64, _ key: Curve25519.KeyAgreement.PrivateKey, _ v4: String, _ v6: String, extraAllowed: [String]) -> String {
        let allowed = (["\(v4)/32", "\(v6)/128"] + extraAllowed).map { "\"\($0)\"" }.joined(separator: ",")
        return makeNodeJSON(id: id, key: NodePublicKey(key.publicKey), addresses: ["\(v4)/32", "\(v6)/128"],
                            extra: #","AllowedIPs":[\#(allowed)],"DiscoKey":"\#(discoKeyText)","HomeDERP":1"#)
    }

    /// b의 출력을 a에게, a의 답을 b에게 조용해질 때까지 넘긴다. a가 위로 낸 것을 돌려준다.
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

    /// b가 세션으로 임의 IP 패킷을 보낸다(악의적인 피어는 TSMP를 아무 때나 보낼 수 있다).
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

@Suite("검토: TSMP 광고 받는 쪽 경계")
struct TSMPAdvertisementBoundaryReviewTests {
    @Test("목적지가 자기 주소가 아니어도 받는다(Go도 목적지를 보지 않는다). 출발지는 그 피어의 주소여야 한다")
    func destinationIsNotChecked() throws {
        var pair = try ReviewPair()
        let outputs = try pair.bSendsRaw(advertisementBytes(from: "100.64.0.2", to: "100.64.0.77"))
        #expect(outputs == [.discoKeyAdvertised(reviewDisco, from: NodePublicKey(pair.bKey.publicKey))])
    }

    @Test("IPv6 광고도 받는다")
    func ipv6Advertisement() throws {
        var pair = try ReviewPair()
        let outputs = try pair.bSendsRaw(advertisementBytes(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1"))
        #expect(outputs == [.discoKeyAdvertised(reviewDisco, from: NodePublicKey(pair.bKey.publicKey))])
    }

    @Test("서브넷 경로의 주소를 출발지로 쓴 광고는 엔진이 AllowedIPs에서 서브넷을 빼므로 받지 않는다(Go보다 엄격)")
    func subnetSourceIsRejected() throws {
        var pair = try ReviewPair(bobExtraAllowedIPs: ["10.9.0.0/24"])
        let outputs = try pair.bSendsRaw(advertisementBytes(from: "10.9.0.5", to: "100.64.0.1"))
        #expect(outputs == [.dropped(.wireGuard(.disallowedSource))])
    }

    @Test("IPv4 조각(MF 또는 offset)인 광고는 쓰지 않는다(Go `decode4`도 조각난 TSMP를 버린다)", arguments: [UInt16(0x2000), 0x0001])
    func ipv4FragmentIsRejected(flagsAndOffset: UInt16) throws {
        var pair = try ReviewPair()
        let payload = [TSMPDiscoKeyAdvertisement.type] + reviewDisco.rawValue
        let packet = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 99, transport: payload, flagsAndOffset: flagsAndOffset)
        let outputs = try pair.bSendsRaw(packet)
        #expect(!outputs.contains(.discoKeyAdvertised(reviewDisco, from: NodePublicKey(pair.bKey.publicKey))))
    }

    @Test("IPv6 첫 조각(조각 머리 뒤 TSMP)은 Swiftail은 버리고 Go는 받는다. Go 피어가 73바이트를 조각내지 않으므로 무해한 차이")
    func ipv6FirstFragmentDiffers() throws {
        let payload = [TSMPDiscoKeyAdvertisement.type] + reviewDisco.rawValue
        // 조각 머리: next header 99, offset 0, MF 1.
        let fragmentHeader: [UInt8] = [99, 0, 0x00, 0x01, 0, 0, 0, 1]
        let packet = TestPacket.ipv6(from: "fd7a:115c:a1e0::2", to: "fd7a:115c:a1e0::1", nextHeader: 44, transport: fragmentHeader + payload)
        #expect(throws: IPPacket.ParseError.fragment) { try IPPacket(parsing: packet) }
    }

    @Test("머리의 전체 길이 뒤에 붙은 바이트는 보지 않는다: 본문이 33바이트보다 짧게 선언되면 광고가 아니다")
    func trailingBytesBeyondTotalLength() throws {
        var bytes = advertisementBytes(from: "100.64.0.2", to: "100.64.0.1")
        bytes[3] -= 1 // 전체 길이 52(본문 32)
        let packet = try IPPacket(parsing: bytes)
        #expect(TSMPDiscoKeyAdvertisement(parsing: packet) == nil)
    }
}

@Suite("검토: netmap이 바뀔 때 광고 바이트")
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

    @Test("자기 주소·피어 주소가 바뀌면 광고의 출발지·목적지가 따라 바뀌고, 맞는 계열이 없어지면 지운다")
    func followsNetmap() throws {
        var engine = TailnetEngine(nodeKey: selfKey, discoKey: reviewDisco, now: clockStart, wallClock: wallClockStart)
        let first = try message(selfAddresses: ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"], peerAddresses: ["100.64.0.2/32"], engine: &engine)
        #expect(first == advertisementBytes(from: "100.64.0.1", to: "100.64.0.2"))

        let moved = try message(selfAddresses: ["100.64.0.11/32", "fd7a:115c:a1e0::1/128"], peerAddresses: ["100.64.0.12/32"], engine: &engine)
        #expect(moved == advertisementBytes(from: "100.64.0.11", to: "100.64.0.12"))

        // 피어의 첫 주소가 IPv6가 되면 자기 IPv6 주소에서 보낸다.
        let v6 = try message(selfAddresses: ["100.64.0.11/32", "fd7a:115c:a1e0::1/128"], peerAddresses: ["fd7a:115c:a1e0::2/128", "100.64.0.12/32"], engine: &engine)
        #expect(v6 == advertisementBytes(from: "fd7a:115c:a1e0::1", to: "fd7a:115c:a1e0::2"))

        // 자기에게 IPv4 주소만 남으면 IPv6 피어에게는 보내지 않는다(Go `selfIPMatchingFamily`가 무효 → nil).
        let none = try message(selfAddresses: ["100.64.0.11/32"], peerAddresses: ["fd7a:115c:a1e0::2/128"], engine: &engine)
        #expect(none == nil)
    }
}
