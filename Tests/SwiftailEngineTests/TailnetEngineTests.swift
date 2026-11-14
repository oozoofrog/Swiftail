// 계약 동작 3~5·7과 M-E1·M-E2: 엔진 둘을 메모리에서 맞물려(한쪽의 `.datagram`을 다른 쪽 `receive`에) 시험한다.
// 엔진은 경로를 모르므로 망은 데이터그램을 받는 쪽 엔진에 그대로 넘긴다(노드에서는 `Magicsock`이 그 자리에 있다).
// alice는 100.64.0.1·fd7a:115c:a1e0::1, bob은 100.64.0.2·fd7a:115c:a1e0::2이고 둘 다 홈 DERP 지역 1에 있다.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine
@testable import SwiftailWireGuard

/// 메모리에서 이어진 엔진 둘.
private struct EnginePair {
    enum Side {
        case alice, bob

        var other: Side { self == .alice ? .bob : .alice }
        var address4: String { self == .alice ? "100.64.0.1" : "100.64.0.2" }
        var address6: String { self == .alice ? "fd7a:115c:a1e0::1" : "fd7a:115c:a1e0::2" }
        var id: Int64 { self == .alice ? 1 : 2 }
        /// 이 쪽이 보낸 데이터그램이 상대에게 도착할 때의 출처(UDP `192.0.2.x:41641`).
        var source: TailnetEngine.Source {
            let host: [UInt8] = [192, 0, 2, self == .alice ? 1 : 2]
            return TailnetEngine.Source(address: host + [0x29, 0xA2], host: host)
        }
    }

    /// 한 번 오간 결과: 각 쪽이 위로 올린 패킷과 버린 것.
    struct Delivery {
        var packets: [Side: [[UInt8]]] = [:]
        var drops: [Side: [TailnetEngine.Drop]] = [:]
    }

    static let homeDERP: Int64 = 1
    /// alice가 받는 규칙: 어디서든 UDP 7과 TCP 22.
    static let aliceRules = #"[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":7,"Last":7}}],"IPProto":[17]},{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":22,"Last":22}}],"IPProto":[6]}]"#

    var alice: TailnetEngine
    var bob: TailnetEngine
    var aliceKey = Curve25519.KeyAgreement.PrivateKey()
    var bobKey = Curve25519.KeyAgreement.PrivateKey()

    /// alice는 `aliceRules`, bob은 규칙 없음(먼저 보낸 UDP의 응답만 받는다).
    init() throws {
        alice = TailnetEngine(nodeKey: aliceKey, now: clockStart, wallClock: wallClockStart)
        bob = TailnetEngine(nodeKey: bobKey, now: clockStart, wallClock: wallClockStart)
        _ = alice.apply(try netmap(for: .alice), at: clockStart, wallClock: wallClockStart)
        _ = bob.apply(try netmap(for: .bob), at: clockStart, wallClock: wallClockStart)
    }

    subscript(side: Side) -> TailnetEngine {
        get { side == .alice ? alice : bob }
        set {
            if side == .alice { alice = newValue } else { bob = newValue }
        }
    }

    func publicKey(_ side: Side) -> NodePublicKey {
        NodePublicKey((side == .alice ? aliceKey : bobKey).publicKey)
    }

    /// side의 자기 노드 JSON.
    func nodeJSON(_ side: Side, extra: String = "") -> String {
        makeNodeJSON(
            id: side.id, key: publicKey(side), addresses: ["\(side.address4)/32", "\(side.address6)/128"],
            extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":\#(Self.homeDERP)"# + extra
        )
    }

    /// side가 받는 netmap. 상대 피어 하나가 있다.
    func netmap(for side: Side, peerExtra: String = "", peers: [String]? = nil) throws -> Netmap {
        try makeNetmap(
            selfNode: nodeJSON(side),
            peers: peers ?? [nodeJSON(side.other, extra: peerExtra)],
            packetFilter: side == .alice ? Self.aliceRules : "[]"
        )
    }

    /// side의 출력을 상대에게 넘기고, 그 응답을 다시 넘기기를 조용해질 때까지 반복한다.
    mutating func deliver(_ outputs: [TailnetEngine.Output], from side: Side, at now: ContinuousClock.Instant = clockStart) -> Delivery {
        var delivery = Delivery()
        var queue = outputs.map { (from: side, output: $0) }
        while !queue.isEmpty {
            let (sender, output) = queue.removeFirst()
            switch output {
            case let .datagram(bytes, to: destination):
                #expect(destination == publicKey(sender.other))
                let replies = self[sender.other].receive(bytes, from: sender.source, at: now)
                queue += replies.map { (from: sender.other, output: $0) }
            case let .cookieReply(bytes):
                // 받은 데이터그램의 출처, 곧 방금 보낸 상대에게 되돌아간다.
                let replies = self[sender.other].receive(bytes, from: sender.source, at: now)
                queue += replies.map { (from: sender.other, output: $0) }
            case let .ipPacket(bytes):
                delivery.packets[sender, default: []].append(bytes)
            case let .dropped(drop):
                delivery.drops[sender, default: []].append(drop)
            }
        }
        return delivery
    }

    /// side가 IP 패킷 하나를 보내고 끝까지 주고받는다.
    mutating func send(_ packet: [UInt8], from side: Side, at now: ContinuousClock.Instant = clockStart) -> Delivery {
        deliver(self[side].send(packet, at: now), from: side, at: now)
    }
}

@Suite("TailnetEngine")
struct TailnetEngineTests {
    @Test("UDP 패킷이 왕복한다. bob은 규칙이 없어도 먼저 보낸 것의 응답을 받는다", arguments: [false, true])
    func udpRoundTrip(ipv6: Bool) throws {
        var pair = try EnginePair()
        let (bob, alice) = ipv6 ? (EnginePair.Side.bob.address6, EnginePair.Side.alice.address6) : (EnginePair.Side.bob.address4, EnginePair.Side.alice.address4)

        let request = TestPacket.udp(from: bob, 40000, to: alice, 7, payload: Array("ping".utf8))
        let first = pair.send(request, from: .bob)
        #expect(first.packets[.alice] == [request])
        #expect(first.drops.isEmpty)

        let reply = TestPacket.udp(from: alice, 7, to: bob, 40000, payload: Array("pong".utf8))
        let second = pair.send(reply, from: .alice, at: clockStart + .milliseconds(1))
        #expect(second.packets[.bob] == [reply])
        #expect(second.drops.isEmpty)

        // 응답이 아닌 UDP는 bob의 필터가 막는다.
        let unsolicited = TestPacket.udp(from: alice, 7, to: bob, 40001)
        let third = pair.send(unsolicited, from: .alice, at: clockStart + .milliseconds(2))
        #expect(third.packets[.bob] == nil)
        #expect(third.drops[.bob] == [.inbound(.noRuleMatched)])
    }

    @Test("필터가 막은 포트와 연 포트, TCP SYN")
    func inboundFilter() throws {
        var pair = try EnginePair()
        let open = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        #expect(open.packets[.alice]?.count == 1)
        let closed = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 8), from: .bob)
        #expect(closed.drops[.alice] == [.inbound(.noRuleMatched)])
        let syn22 = pair.send(TestPacket.tcp(from: "100.64.0.2", 50000, to: "100.64.0.1", 22, flags: 0x02), from: .bob)
        #expect(syn22.packets[.alice]?.count == 1)
        let syn23 = pair.send(TestPacket.tcp(from: "100.64.0.2", 50000, to: "100.64.0.1", 23, flags: 0x02), from: .bob)
        #expect(syn23.drops[.alice] == [.inbound(.noRuleMatched)])
    }

    @Test("목적지를 가진 피어가 없거나 패킷이 잘못되면 보내지 않는다")
    func sendDrops() throws {
        var pair = try EnginePair()
        #expect(pair.alice.send(TestPacket.udp(from: "100.64.0.1", 1, to: "100.64.0.3", 7), at: clockStart) == [.dropped(.noPeerForDestination)])
        #expect(pair.alice.send([0x45, 0, 0], at: clockStart) == [.dropped(.malformedPacket)])
        let fragment = TestPacket.ipv4(from: "100.64.0.1", to: "100.64.0.2", protocolNumber: 17, transport: [0, 1, 0, 2, 0, 8, 0, 0], flagsAndOffset: 0x2000)
        #expect(pair.alice.send(fragment, at: clockStart) == [.dropped(.unsupportedPacket)])
        let extensionHeader = TestPacket.ipv6(from: "fd7a:115c:a1e0::1", to: "fd7a:115c:a1e0::2", nextHeader: 0, transport: [17, 0, 0, 0, 0, 0, 0, 0])
        #expect(pair.alice.send(extensionHeader, at: clockStart) == [.dropped(.unsupportedPacket)])
    }

    @Test("netmap 갱신: 피어를 더하고 지운다")
    func addAndRemovePeer() throws {
        var pair = try EnginePair()
        // bob에게는 규칙이 없다. 아래에서 bob이 먼저 보낸 UDP(1 → 7)의 응답이 되는 패킷이다.
        let packet = TestPacket.udp(from: "100.64.0.1", 7, to: "100.64.0.2", 1)

        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: []), at: clockStart, wallClock: wallClockStart)
        #expect(pair.alice.send(packet, at: clockStart) == [.dropped(.noPeerForDestination)])
        // alice에서 지워진 bob이 보낸 initiation은 모르는 피어다.
        let rejected = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        #expect(rejected.drops[.alice] == [.wireGuard(.unknownPeer)])

        _ = pair.alice.apply(try pair.netmap(for: .alice), at: clockStart, wallClock: wallClockStart)
        let delivered = pair.send(packet, from: .alice, at: clockStart + .seconds(6))
        #expect(delivered.packets[.bob] == [packet])
    }

    @Test("세션이 선 뒤 피어를 지우면 그 세션의 데이터도 받지 않는다")
    func removePeerDropsSession() throws {
        var pair = try EnginePair()
        let toAlice = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(toAlice, from: .bob).packets[.alice] == [toAlice])

        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: []), at: clockStart + .seconds(1), wallClock: wallClockStart + 1)
        let after = pair.send(toAlice, from: .bob, at: clockStart + .seconds(1))
        #expect(after.packets[.alice] == nil)
        #expect(after.drops[.alice] == [.wireGuard(.unknownPeer)])
    }

    @Test("AllowedIPs만 바뀌면 세션을 잇는다")
    func allowedIPsChangeKeepsSession() throws {
        var pair = try EnginePair()
        let toAlice = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(toAlice, from: .bob).packets[.alice] == [toAlice])

        // IPv6 주소를 AllowedIPs에서 뺀다. 같은 키이므로 핸드셰이크 없이 transport 하나로 닿는다.
        _ = pair.alice.apply(try pair.netmap(for: .alice, peerExtra: #","AllowedIPs":["100.64.0.2/32"]"#), at: clockStart, wallClock: wallClockStart)
        let outputs = pair.bob.send(toAlice, at: clockStart + .milliseconds(1))
        #expect(outputs.count == 1)
        #expect(pair.deliver(outputs, from: .bob, at: clockStart + .milliseconds(1)).packets[.alice] == [toAlice])

        let fromV6 = TestPacket.udp(from: "fd7a:115c:a1e0::2", 1, to: "fd7a:115c:a1e0::1", 7)
        #expect(pair.send(fromV6, from: .bob, at: clockStart + .milliseconds(2)).drops[.alice] == [.wireGuard(.disallowedSource)])
    }

    @Test("netmap 갱신: 피어의 키가 바뀌면 옛 키를 내리고 새 키로 잇는다")
    func keyRotation() throws {
        var pair = try EnginePair()
        let toAlice = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(toAlice, from: .bob).packets[.alice] == [toAlice])
        let oldBob = pair.bob

        // bob이 새 node 키로 다시 시작한다.
        pair.bobKey = Curve25519.KeyAgreement.PrivateKey()
        pair.bob = TailnetEngine(nodeKey: pair.bobKey, now: clockStart, wallClock: wallClockStart)
        _ = pair.bob.apply(try pair.netmap(for: .bob), at: clockStart, wallClock: wallClockStart)
        _ = pair.alice.apply(try pair.netmap(for: .alice), at: clockStart, wallClock: wallClockStart)

        let rotated = pair.send(toAlice, from: .bob, at: clockStart + .seconds(1))
        #expect(rotated.packets[.alice] == [toAlice])

        // 옛 키의 세션으로 온 데이터는 모르는 피어다.
        var old = oldBob
        let stale = old.send(toAlice, at: clockStart + .seconds(1))
        let datagram = try #require(stale.compactMap { if case let .datagram(bytes, _) = $0 { bytes } else { nil } }.first)
        #expect(pair.alice.receive(datagram, from: EnginePair.Side.bob.source, at: clockStart + .seconds(1)) == [.dropped(.wireGuard(.unknownPeer))])
    }

    @Test("AllowedIPs 밖의 출발지는 필터보다 먼저 WireGuard가 버린다")
    func spoofedSource() throws {
        var pair = try EnginePair()
        // bob의 엔진은 목적지로 피어를 고를 뿐 출발지를 보지 않는다.
        let spoofed = TestPacket.udp(from: "100.64.0.99", 1, to: "100.64.0.1", 7)
        let delivery = pair.send(spoofed, from: .bob)
        #expect(delivery.packets[.alice] == nil)
        #expect(delivery.drops[.alice] == [.wireGuard(.disallowedSource)])
    }

    @Test("TSMP는 엔진이 소비하고 위로 올리지 않는다: 장치에서 온 것은 보내는 쪽이, 피어가 보낸 것은 받는 쪽이")
    func tsmpIsConsumed() throws {
        var pair = try EnginePair()
        let tsmp = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 99, transport: Array("p12345678".utf8))
        // 장치에서 읽은 TSMP는 WireGuard로 가지 않는다(계약 동작 L4).
        #expect(pair.bob.send(tsmp, at: clockStart) == [.dropped(.consumedControlPacket)])

        // 다른 구현의 피어가 보낸 TSMP는 장치를 거쳐 직접 만든다. 세션을 세운 뒤 transport로 보낸다.
        _ = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        let datagrams = pair.bob.route(try pair.bob.device.send(tsmp, to: PublicKey(pair.publicKey(.alice)), at: clockStart))
        #expect(!datagrams.isEmpty)
        let delivery = pair.deliver(datagrams, from: .bob)
        #expect(delivery.packets[.alice] == nil)
        #expect(delivery.drops[.alice] == [.consumedControlPacket])
    }

    @Test("홈 DERP가 우리와 다르거나 없는 피어에게도 데이터그램을 낸다. 경로는 Magicsock이 고른다(M-E1)")
    func peersOutsideHomeRegion() throws {
        var pair = try EnginePair()
        let packet = TestPacket.udp(from: "100.64.0.1", 5000, to: "100.64.0.2", 7)
        let otherRegion = makeNodeJSON(id: 2, key: pair.publicKey(.bob), addresses: ["100.64.0.2/32"], extra: #","HomeDERP":2"#)
        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: [otherRegion]), at: clockStart, wallClock: wallClockStart)
        let toRegion2 = pair.alice.send(packet, at: clockStart)
        #expect(toRegion2.count == 1)
        #expect(toRegion2.allSatisfy { if case .datagram(_, to: pair.publicKey(.bob)) = $0 { true } else { false } })

        // 홈 DERP가 0이어도 disco 키가 있으면 올린다(M-E3). 직접 경로로 닿을 수 있다.
        let noHome = makeNodeJSON(id: 2, key: pair.publicKey(.bob), addresses: ["100.64.0.2/32"], extra: #","DiscoKey":"\#(discoKeyText)""#)
        var fresh = TailnetEngine(nodeKey: pair.aliceKey, now: clockStart, wallClock: wallClockStart)
        _ = fresh.apply(try pair.netmap(for: .alice, peers: [noHome]), at: clockStart, wallClock: wallClockStart)
        #expect(fresh.send(packet, at: clockStart).allSatisfy { if case .datagram = $0 { true } else { false } })
    }

    @Test("netmap의 disco 키와 엔드포인트를 EnginePeer에 그대로 옮긴다(M-E3)")
    func peerCarriesDiscoAndEndpoints() throws {
        let pair = try EnginePair()
        let bob = makeNodeJSON(
            id: 2, key: pair.publicKey(.bob), addresses: ["100.64.0.2/32"],
            extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":1,"Endpoints":["127.0.0.1:41641","[2001:db8::1]:41641"]"#
        )
        let peer = try #require(EnginePeer.peers(in: try pair.netmap(for: .alice, peers: [bob]), at: wallClockStart).first)
        #expect(peer.discoKey.description == discoKeyText)
        #expect(peer.endpoints == [try #require(IPEndpoint("127.0.0.1:41641")), try #require(IPEndpoint("[2001:db8::1]:41641"))])
    }

    @Test("키 만료 시각에 피어가 내려간다")
    func peerKeyExpiry() throws {
        var pair = try EnginePair()
        // bob의 키는 wallClockStart + 60초에 만료된다.
        let netmap = try pair.netmap(for: .alice, peerExtra: #","KeyExpiry":"2027-01-15T08:01:00Z""#)
        _ = pair.alice.apply(netmap, at: clockStart, wallClock: wallClockStart)
        #expect(pair.alice.nextDeadline == clockStart + .seconds(60))

        let toAlice = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(toAlice, from: .bob, at: clockStart + .seconds(59)).packets[.alice] == [toAlice])

        _ = pair.alice.advance(to: clockStart + .seconds(60))
        let packet = TestPacket.udp(from: "100.64.0.1", 7, to: "100.64.0.2", 1)
        #expect(pair.alice.send(packet, at: clockStart + .seconds(60)) == [.dropped(.noPeerForDestination)])
        let after = pair.send(toAlice, from: .bob, at: clockStart + .seconds(60))
        #expect(after.drops[.alice] == [.wireGuard(.unknownPeer)])
    }

    @Test("아주 먼 키 만료는 하루마다 다시 보고, 그 시각이 오면 피어를 내린다")
    func distantPeerKeyExpiry() throws {
        var pair = try EnginePair()
        let day = Duration.seconds(24 * 60 * 60)
        // 9999년의 만료: 단조 시각으로 바꿀 때 넘치지 않게 하루 뒤에 다시 본다.
        let distant = try pair.netmap(for: .alice, peerExtra: #","KeyExpiry":"9999-12-31T00:00:00Z""#)
        _ = pair.alice.apply(distant, at: clockStart, wallClock: wallClockStart)
        #expect(pair.alice.nextDeadline == clockStart + day)
        _ = pair.alice.advance(to: clockStart + day)
        #expect(pair.alice.nextDeadline == clockStart + day + day)

        // 하루하고 1초 뒤의 만료(wallClockStart는 2027-01-15T08:00:00Z): 하루 뒤에 한 번 보고, 1초 뒤에 내린다.
        let soon = try pair.netmap(for: .alice, peerExtra: #","KeyExpiry":"2027-01-16T08:00:01Z""#)
        _ = pair.alice.apply(soon, at: clockStart, wallClock: wallClockStart)
        #expect(pair.alice.nextDeadline == clockStart + day)
        _ = pair.alice.advance(to: clockStart + day)
        #expect(pair.alice.nextDeadline == clockStart + day + .seconds(1))
        _ = pair.alice.advance(to: clockStart + day + .seconds(1))
        let packet = TestPacket.udp(from: "100.64.0.1", 7, to: "100.64.0.2", 1)
        #expect(pair.alice.send(packet, at: clockStart + day + .seconds(1)) == [.dropped(.noPeerForDestination)])
    }

    @Test("WireGuard 타이머를 advance로 처리하고 nextDeadline에 반영한다")
    func wireGuardTimers() throws {
        var pair = try EnginePair()
        #expect(pair.alice.nextDeadline == nil)
        // 응답 없는 initiation은 재시도 타이머를 건다.
        let outputs = pair.alice.send(TestPacket.udp(from: "100.64.0.1", 1, to: "100.64.0.2", 7), at: clockStart)
        #expect(outputs.count == 1)
        let deadline = try #require(pair.alice.nextDeadline)
        #expect(deadline > clockStart)
        let retry = pair.alice.advance(to: deadline)
        #expect(retry.allSatisfy { if case .datagram(_, to: pair.publicKey(.bob)) = $0 { true } else { false } })
        #expect(!retry.isEmpty)
    }

    @Test("부하 상태의 WireGuard가 낸 cookie reply를 출처로 되돌릴 것으로 내고, 같은 출처에서 mac2를 붙인 재시도로 세션이 선다")
    func cookieReplyUnderLoad() throws {
        var pair = try EnginePair()
        pair.bob.device.handshakeLoad.underLoadUntil = clockStart + .seconds(60)
        let request = TestPacket.udp(from: "100.64.0.1", 40000, to: "100.64.0.2", 7)
        let initiation = pair.alice.send(request, at: clockStart)
        guard case let .datagram(bytes, _)? = initiation.first else {
            Issue.record("initiation이 없다: \(initiation)")
            return
        }
        let answered = pair.bob.receive(bytes, from: EnginePair.Side.alice.source, at: clockStart)
        guard case let .cookieReply(reply)? = answered.first, answered.count == 1 else {
            Issue.record("cookie reply가 아니다: \(answered)")
            return
        }
        #expect(reply.count == 64 && reply[0] == 3)
        #expect(pair.alice.receive(reply, from: EnginePair.Side.bob.source, at: clockStart).isEmpty)

        // 재시도 initiation은 mac2를 붙인다. 다른 출처에서 오면 cookie가 맞지 않아 다시 cookie reply다.
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        guard case let .datagram(retried, _)? = retry.first else {
            Issue.record("재시도가 없다: \(retry)")
            return
        }
        let elsewhere = TailnetEngine.Source(address: [198, 51, 100, 9, 0x29, 0xA2], host: [198, 51, 100, 9])
        guard case .cookieReply? = pair.bob.receive(retried, from: elsewhere, at: retryAt).first else {
            Issue.record("다른 출처의 mac2를 받아들였다")
            return
        }
        let delivery = pair.deliver(pair.bob.receive(retried, from: EnginePair.Side.alice.source, at: retryAt), from: .bob, at: retryAt)
        #expect(delivery.drops[.alice] == nil)
        // 세션이 섰다. 대기열의 요청이 bob에 닿는다(bob은 규칙이 없어 필터가 버린다).
        #expect(delivery.drops[.bob] == [.inbound(.noRuleMatched)])
    }

    @Test("dump에 node 개인 키가 나오지 않는다")
    func dumpHidesSecrets() throws {
        var pair = try EnginePair()
        _ = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        var text = ""
        dump(pair.alice, to: &text)
        #expect(Mirror(reflecting: pair.alice).children.map(\.label) == ["publicKey", "peerCount"])
        #expect(text.contains(pair.publicKey(.alice).description))
        #expect(!text.contains(Array(pair.aliceKey.rawRepresentation).hex))
        #expect(!text.contains("device") && !text.contains("staticKey"))
    }

    @Test("임의 바이트열을 send·receive에 넣어도 죽지 않고 던지지 않는다")
    func fuzz() throws {
        var pair = try EnginePair()
        _ = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        var random = FuzzRandom(seed: 0xE61E)
        for step in 0..<5_000 {
            let bytes = random.bytes(Int.random(in: 0...200, using: &random))
            let now = clockStart + .milliseconds(step)
            _ = pair.alice.receive(bytes, from: EnginePair.Side.bob.source, at: now)
            _ = pair.alice.send(bytes, at: now)
        }
    }
}
