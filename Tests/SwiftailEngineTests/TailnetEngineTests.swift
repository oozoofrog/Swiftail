// Test contract behaviors 3–5 and 7 and M-E1 and M-E2 with two engines connected in memory (one side's `.datagram` goes to the other's `receive`).
// The engine is unaware of routes, so the network passes datagrams directly to the receiving engine (`Magicsock` fills that role in a node).
// alice uses 100.64.0.1 and fd7a:115c:a1e0::1, bob uses 100.64.0.2 and fd7a:115c:a1e0::2, and both are in home DERP region 1.

import CryptoKit
import Foundation
import Testing

import SwiftailBase
import SwiftailControl
@testable import SwiftailEngine
@testable import SwiftailWireGuard

/// Two engines connected in memory.
private struct EnginePair {
    enum Side {
        case alice, bob

        var other: Side { self == .alice ? .bob : .alice }
        var address4: String { self == .alice ? "100.64.0.1" : "100.64.0.2" }
        var address6: String { self == .alice ? "fd7a:115c:a1e0::1" : "fd7a:115c:a1e0::2" }
        var id: Int64 { self == .alice ? 1 : 2 }
        /// The source seen by the peer when a datagram from this side arrives (UDP `192.0.2.x:41641`).
        var source: TailnetEngine.Source {
            let host: [UInt8] = [192, 0, 2, self == .alice ? 1 : 2]
            return TailnetEngine.Source(address: host + [0x29, 0xA2], host: host)
        }
    }

    /// The results of one exchange, including packets each side passes up, drops, and TSMP disco key advertisements in receipt order.
    struct Delivery {
        var packets: [Side: [[UInt8]]] = [:]
        var drops: [Side: [TailnetEngine.Drop]] = [:]
        var advertisements: [Side: [DiscoPublicKey]] = [:]
        /// The order in which each receiving side passes results up. Advertisements are `"advert"` and packets are `"packet"`.
        var arrivals: [Side: [String]] = [:]
    }

    static let homeDERP: Int64 = 1
    /// alice's inbound rules allow UDP 7 and TCP 22 from anywhere.
    static let aliceRules = #"[{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":7,"Last":7}}],"IPProto":[17]},{"SrcIPs":["*"],"DstPorts":[{"IP":"*","Ports":{"First":22,"Last":22}}],"IPProto":[6]}]"#

    var alice: TailnetEngine
    var bob: TailnetEngine
    var aliceKey = Curve25519.KeyAgreement.PrivateKey()
    var bobKey = Curve25519.KeyAgreement.PrivateKey()

    /// alice uses `aliceRules` and bob has no rules (bob only accepts replies to outbound UDP). If a side has a nonzero disco key,
    /// it sends a TSMP disco key advertisement each time a session is established.
    init(aliceDisco: DiscoPublicKey = .zero, bobDisco: DiscoPublicKey = .zero) throws {
        alice = TailnetEngine(nodeKey: aliceKey, discoKey: aliceDisco, now: clockStart, wallClock: wallClockStart)
        bob = TailnetEngine(nodeKey: bobKey, discoKey: bobDisco, now: clockStart, wallClock: wallClockStart)
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

    /// The local node's JSON for side.
    func nodeJSON(_ side: Side, extra: String = "") -> String {
        makeNodeJSON(
            id: side.id, key: publicKey(side), addresses: ["\(side.address4)/32", "\(side.address6)/128"],
            extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":\#(Self.homeDERP)"# + extra
        )
    }

    /// The netmap received by side. It contains one peer, the other side.
    func netmap(for side: Side, peerExtra: String = "", peers: [String]? = nil) throws -> Netmap {
        try makeNetmap(
            selfNode: nodeJSON(side),
            peers: peers ?? [nodeJSON(side.other, extra: peerExtra)],
            packetFilter: side == .alice ? Self.aliceRules : "[]"
        )
    }

    /// Passes output from side to the peer and passes replies back and forth until neither sends anything.
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
                // Return to the received datagram's source, the peer that just sent it.
                let replies = self[sender.other].receive(bytes, from: sender.source, at: now)
                queue += replies.map { (from: sender.other, output: $0) }
            case let .ipPacket(bytes):
                delivery.packets[sender, default: []].append(bytes)
                delivery.arrivals[sender, default: []].append("packet")
            case let .discoKeyAdvertised(key, from: peer):
                #expect(peer == publicKey(sender.other))
                delivery.advertisements[sender, default: []].append(key)
                delivery.arrivals[sender, default: []].append("advert")
            case let .dropped(drop):
                delivery.drops[sender, default: []].append(drop)
            }
        }
        return delivery
    }

    /// Sends one IP packet from side and runs the exchange to completion.
    mutating func send(_ packet: [UInt8], from side: Side, at now: ContinuousClock.Instant = clockStart) -> Delivery {
        deliver(self[side].send(packet, at: now), from: side, at: now)
    }
}

@Suite("TailnetEngine")
struct TailnetEngineTests {
    @Test("UDP packets make a round trip. bob accepts replies to outbound packets even without rules", arguments: [false, true])
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

        // bob's filter blocks UDP packets other than replies.
        let unsolicited = TestPacket.udp(from: alice, 7, to: bob, 40001)
        let third = pair.send(unsolicited, from: .alice, at: clockStart + .milliseconds(2))
        #expect(third.packets[.bob] == nil)
        #expect(third.drops[.bob] == [.inbound(.noRuleMatched)])
    }

    @Test("Ports blocked and allowed by the filter, and TCP SYN")
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

    @Test("Skip sending if no peer owns the destination or the packet is invalid")
    func sendDrops() throws {
        var pair = try EnginePair()
        #expect(pair.alice.send(TestPacket.udp(from: "100.64.0.1", 1, to: "100.64.0.3", 7), at: clockStart) == [.dropped(.noPeerForDestination)])
        #expect(pair.alice.send([0x45, 0, 0], at: clockStart) == [.dropped(.malformedPacket)])
        let fragment = TestPacket.ipv4(from: "100.64.0.1", to: "100.64.0.2", protocolNumber: 17, transport: [0, 1, 0, 2, 0, 8, 0, 0], flagsAndOffset: 0x2000)
        #expect(pair.alice.send(fragment, at: clockStart) == [.dropped(.unsupportedPacket)])
        let extensionHeader = TestPacket.ipv6(from: "fd7a:115c:a1e0::1", to: "fd7a:115c:a1e0::2", nextHeader: 0, transport: [17, 0, 0, 0, 0, 0, 0, 0])
        #expect(pair.alice.send(extensionHeader, at: clockStart) == [.dropped(.unsupportedPacket)])
    }

    @Test("A netmap update adds and removes peers")
    func addAndRemovePeer() throws {
        var pair = try EnginePair()
        // bob has no rules. This packet will be a reply to the UDP packet (1 → 7) that bob sends first below.
        let packet = TestPacket.udp(from: "100.64.0.1", 7, to: "100.64.0.2", 1)

        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: []), at: clockStart, wallClock: wallClockStart)
        #expect(pair.alice.send(packet, at: clockStart) == [.dropped(.noPeerForDestination)])
        // To alice, an initiation from the removed bob comes from an unknown peer.
        let rejected = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        #expect(rejected.drops[.alice] == [.wireGuard(.unknownPeer)])

        _ = pair.alice.apply(try pair.netmap(for: .alice), at: clockStart, wallClock: wallClockStart)
        let delivered = pair.send(packet, from: .alice, at: clockStart + .seconds(6))
        #expect(delivered.packets[.bob] == [packet])
    }

    @Test("Removing a peer after establishing a session also blocks data from that session")
    func removePeerDropsSession() throws {
        var pair = try EnginePair()
        let toAlice = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(toAlice, from: .bob).packets[.alice] == [toAlice])

        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: []), at: clockStart + .seconds(1), wallClock: wallClockStart + 1)
        let after = pair.send(toAlice, from: .bob, at: clockStart + .seconds(1))
        #expect(after.packets[.alice] == nil)
        #expect(after.drops[.alice] == [.wireGuard(.unknownPeer)])
    }

    @Test("Preserve the session when only AllowedIPs changes")
    func allowedIPsChangeKeepsSession() throws {
        var pair = try EnginePair()
        let toAlice = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(toAlice, from: .bob).packets[.alice] == [toAlice])

        // Remove the IPv6 address from AllowedIPs. The key is unchanged, so one transport message is enough and no handshake is needed.
        _ = pair.alice.apply(try pair.netmap(for: .alice, peerExtra: #","AllowedIPs":["100.64.0.2/32"]"#), at: clockStart, wallClock: wallClockStart)
        let outputs = pair.bob.send(toAlice, at: clockStart + .milliseconds(1))
        #expect(outputs.count == 1)
        #expect(pair.deliver(outputs, from: .bob, at: clockStart + .milliseconds(1)).packets[.alice] == [toAlice])

        let fromV6 = TestPacket.udp(from: "fd7a:115c:a1e0::2", 1, to: "fd7a:115c:a1e0::1", 7)
        #expect(pair.send(fromV6, from: .bob, at: clockStart + .milliseconds(2)).drops[.alice] == [.wireGuard(.disallowedSource)])
    }

    @Test("A peer key change in the netmap removes the old key and connects with the new one")
    func keyRotation() throws {
        var pair = try EnginePair()
        let toAlice = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(toAlice, from: .bob).packets[.alice] == [toAlice])
        let oldBob = pair.bob

        // bob starts again with a new node key.
        pair.bobKey = Curve25519.KeyAgreement.PrivateKey()
        pair.bob = TailnetEngine(nodeKey: pair.bobKey, discoKey: .zero, now: clockStart, wallClock: wallClockStart)
        _ = pair.bob.apply(try pair.netmap(for: .bob), at: clockStart, wallClock: wallClockStart)
        _ = pair.alice.apply(try pair.netmap(for: .alice), at: clockStart, wallClock: wallClockStart)

        let rotated = pair.send(toAlice, from: .bob, at: clockStart + .seconds(1))
        #expect(rotated.packets[.alice] == [toAlice])

        // Data arriving through the old key's session comes from an unknown peer.
        var old = oldBob
        let stale = old.send(toAlice, at: clockStart + .seconds(1))
        let datagram = try #require(stale.compactMap { if case let .datagram(bytes, _) = $0 { bytes } else { nil } }.first)
        #expect(pair.alice.receive(datagram, from: EnginePair.Side.bob.source, at: clockStart + .seconds(1)) == [.dropped(.wireGuard(.unknownPeer))])
    }

    @Test("WireGuard drops sources outside AllowedIPs before filtering")
    func spoofedSource() throws {
        var pair = try EnginePair()
        // bob's engine selects a peer by destination alone and ignores the source.
        let spoofed = TestPacket.udp(from: "100.64.0.99", 1, to: "100.64.0.1", 7)
        let delivery = pair.send(spoofed, from: .bob)
        #expect(delivery.packets[.alice] == nil)
        #expect(delivery.drops[.alice] == [.wireGuard(.disallowedSource)])
    }

    @Test("Even a peer advertising a broad prefix as its own cannot use another peer's address as its source")
    func widePrefixPeerCannotSpoofOtherPeer() throws {
        var pair = try EnginePair()
        // bob advertises the entire tailnet range as its own address. carol (100.64.0.3) is another peer of alice.
        let wideBob = makeNodeJSON(
            id: 2, key: pair.publicKey(.bob), addresses: ["100.64.0.2/32", "100.64.0.0/10", "fd7a:115c:a1e0::/48"],
            extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":\#(EnginePair.homeDERP)"#)
        let carol = makeNodeJSON(
            id: 3, key: makeNodeKey(byte: 3), addresses: ["100.64.0.3/32"],
            extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":\#(EnginePair.homeDERP)"#)
        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: [wideBob, carol]), at: clockStart, wallClock: wallClockStart)

        let asCarol = TestPacket.udp(from: "100.64.0.3", 1, to: "100.64.0.1", 7)
        let delivery = pair.send(asCarol, from: .bob)
        #expect(delivery.packets[.alice] == nil)
        #expect(delivery.drops[.alice] == [.wireGuard(.disallowedSource)])

        // Traffic sent from its own address still arrives.
        let asBob = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        #expect(pair.send(asBob, from: .bob, at: clockStart + .milliseconds(1)).packets[.alice] == [asBob])
    }

    @Test("The engine consumes TSMP without passing it up. The sender consumes TSMP from the device, and the receiver consumes TSMP from a peer")
    func tsmpIsConsumed() throws {
        var pair = try EnginePair()
        let tsmp = TestPacket.ipv4(from: "100.64.0.2", to: "100.64.0.1", protocolNumber: 99, transport: Array("p12345678".utf8))
        // TSMP read from the device never goes to WireGuard (contract behavior L4).
        #expect(pair.bob.send(tsmp, at: clockStart) == [.dropped(.consumedControlPacket)])

        // Construct the TSMP from a peer running another implementation directly through the device. Send it as transport after establishing a session.
        _ = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        let datagrams = pair.bob.route(try pair.bob.device.send(tsmp, to: PublicKey(pair.publicKey(.alice)), at: clockStart))
        #expect(!datagrams.isEmpty)
        let delivery = pair.deliver(datagrams, from: .bob)
        #expect(delivery.packets[.alice] == nil)
        #expect(delivery.drops[.alice] == [.consumedControlPacket])
    }

    @Test("Emit datagrams even for peers with a different home DERP or none. Magicsock chooses the route (M-E1)")
    func peersOutsideHomeRegion() throws {
        var pair = try EnginePair()
        let packet = TestPacket.udp(from: "100.64.0.1", 5000, to: "100.64.0.2", 7)
        let otherRegion = makeNodeJSON(id: 2, key: pair.publicKey(.bob), addresses: ["100.64.0.2/32"], extra: #","HomeDERP":2"#)
        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: [otherRegion]), at: clockStart, wallClock: wallClockStart)
        let toRegion2 = pair.alice.send(packet, at: clockStart)
        #expect(toRegion2.count == 1)
        #expect(toRegion2.allSatisfy { if case .datagram(_, to: pair.publicKey(.bob)) = $0 { true } else { false } })

        // Include a peer with a disco key even if its home DERP is 0 (M-E3). A direct route may reach it.
        let noHome = makeNodeJSON(id: 2, key: pair.publicKey(.bob), addresses: ["100.64.0.2/32"], extra: #","DiscoKey":"\#(discoKeyText)""#)
        var fresh = TailnetEngine(nodeKey: pair.aliceKey, discoKey: .zero, now: clockStart, wallClock: wallClockStart)
        _ = fresh.apply(try pair.netmap(for: .alice, peers: [noHome]), at: clockStart, wallClock: wallClockStart)
        #expect(fresh.send(packet, at: clockStart).allSatisfy { if case .datagram = $0 { true } else { false } })
    }

    @Test("Copy disco keys and endpoints from the netmap into EnginePeer unchanged (M-E3)")
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

    @Test("Even when Addresses overlap, send to the AllowedIPs owner of the destination")
    func sendUsesAllowedIPOwner() throws {
        var pair = try EnginePair()
        let addressClaimant = makeNodeJSON(
            id: 2, key: pair.publicKey(.bob), addresses: ["100.64.0.2/32", "100.64.0.3/32"],
            extra: #","AllowedIPs":["100.64.0.2/32"],"HomeDERP":1"#
        )
        let ownerKey = NodePublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey)
        let owner = makeNodeJSON(
            id: 3, key: ownerKey, addresses: ["100.64.0.3/32", "100.64.0.4/32"],
            extra: #","AllowedIPs":["100.64.0.3/32"],"HomeDERP":1"#
        )
        let netmap = try pair.netmap(for: .alice, peers: [addressClaimant, owner])
        _ = pair.alice.apply(netmap, at: clockStart, wallClock: wallClockStart)

        let packet = TestPacket.udp(from: "100.64.0.1", 40000, to: "100.64.0.3", 7)
        let outputs = pair.alice.send(packet, at: clockStart)
        let recipients = outputs.compactMap { output -> NodePublicKey? in
            if case let .datagram(_, to: key) = output { return key }
            return nil
        }
        let sentToOwner = recipients == [ownerKey]
        #expect(sentToOwner)

        let unowned = TestPacket.udp(from: "100.64.0.1", 40000, to: "100.64.0.4", 7)
        let droppedUnowned = pair.alice.send(unowned, at: clockStart) == [.dropped(.noPeerForDestination)]
        #expect(droppedUnowned)
    }

    @Test("Remove the peer at key expiry")
    func peerKeyExpiry() throws {
        var pair = try EnginePair()
        // bob's key expires at wallClockStart + 60 seconds.
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

    @Test("Recheck a distant key expiry daily, and remove the peer when it expires")
    func distantPeerKeyExpiry() throws {
        var pair = try EnginePair()
        let day = Duration.seconds(24 * 60 * 60)
        // For an expiry in year 9999, recheck one day later to avoid overflow when converting to monotonic time.
        let distant = try pair.netmap(for: .alice, peerExtra: #","KeyExpiry":"9999-12-31T00:00:00Z""#)
        _ = pair.alice.apply(distant, at: clockStart, wallClock: wallClockStart)
        #expect(pair.alice.nextDeadline == clockStart + day)
        _ = pair.alice.advance(to: clockStart + day)
        #expect(pair.alice.nextDeadline == clockStart + day + day)

        // For an expiry in one day and 1 second (wallClockStart is 2027-01-15T08:00:00Z), recheck after one day and remove the peer 1 second later.
        let soon = try pair.netmap(for: .alice, peerExtra: #","KeyExpiry":"2027-01-16T08:00:01Z""#)
        _ = pair.alice.apply(soon, at: clockStart, wallClock: wallClockStart)
        #expect(pair.alice.nextDeadline == clockStart + day)
        _ = pair.alice.advance(to: clockStart + day)
        #expect(pair.alice.nextDeadline == clockStart + day + .seconds(1))
        _ = pair.alice.advance(to: clockStart + day + .seconds(1))
        let packet = TestPacket.udp(from: "100.64.0.1", 7, to: "100.64.0.2", 1)
        #expect(pair.alice.send(packet, at: clockStart + day + .seconds(1)) == [.dropped(.noPeerForDestination)])
    }

    @Test("Process WireGuard timers in advance and reflect them in nextDeadline")
    func wireGuardTimers() throws {
        var pair = try EnginePair()
        #expect(pair.alice.nextDeadline == nil)
        // An unanswered initiation sets a retry timer.
        let outputs = pair.alice.send(TestPacket.udp(from: "100.64.0.1", 1, to: "100.64.0.2", 7), at: clockStart)
        #expect(outputs.count == 1)
        let deadline = try #require(pair.alice.nextDeadline)
        #expect(deadline > clockStart)
        let retry = pair.alice.advance(to: deadline)
        #expect(retry.allSatisfy { if case .datagram(_, to: pair.publicKey(.bob)) = $0 { true } else { false } })
        #expect(!retry.isEmpty)
    }

    @Test("Under load, WireGuard emits a cookie reply to return to the source. Retrying with mac2 from the same source establishes a session")
    func cookieReplyUnderLoad() throws {
        var pair = try EnginePair()
        pair.bob.device.handshakeLoad.underLoadUntil = clockStart + .seconds(60)
        let request = TestPacket.udp(from: "100.64.0.1", 40000, to: "100.64.0.2", 7)
        let initiation = pair.alice.send(request, at: clockStart)
        guard case let .datagram(bytes, _)? = initiation.first else {
            Issue.record("Missing initiation, got \(initiation)")
            return
        }
        let answered = pair.bob.receive(bytes, from: EnginePair.Side.alice.source, at: clockStart)
        guard case let .cookieReply(reply)? = answered.first, answered.count == 1 else {
            Issue.record("Expected a cookie reply, got \(answered)")
            return
        }
        #expect(reply.count == 64 && reply[0] == 3)
        #expect(pair.alice.receive(reply, from: EnginePair.Side.bob.source, at: clockStart).isEmpty)

        // The retry initiation includes mac2. From a different source the cookie fails to match, so WireGuard sends another cookie reply.
        let retryAt = try #require(pair.alice.nextDeadline)
        let retry = pair.alice.advance(to: retryAt)
        guard case let .datagram(retried, _)? = retry.first else {
            Issue.record("Missing retry, got \(retry)")
            return
        }
        let elsewhere = TailnetEngine.Source(address: [198, 51, 100, 9, 0x29, 0xA2], host: [198, 51, 100, 9])
        guard case .cookieReply? = pair.bob.receive(retried, from: elsewhere, at: retryAt).first else {
            Issue.record("Accepted mac2 from a different source")
            return
        }
        let delivery = pair.deliver(pair.bob.receive(retried, from: EnginePair.Side.alice.source, at: retryAt), from: .bob, at: retryAt)
        #expect(delivery.drops[.alice] == nil)
        // The session is established. The queued request reaches bob, whose filter drops it because bob has no rules.
        #expect(delivery.drops[.bob] == [.inbound(.noRuleMatched)])
    }

    @Test("The dump omits the node private key")
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

    @Test("Random byte sequences passed to send or receive cause no crash or throw")
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

// MARK: - TSMP disco key advertisements (magicsock contract behaviors T1–T3)

/// A disco key for tests (public value).
private let aliceDisco = DiscoPublicKey(rawValue: [UInt8](repeating: 0xA1, count: 32))!
private let bobDisco = DiscoPublicKey(rawValue: [UInt8](repeating: 0xB0, count: 32))!

extension TailnetEngineTests {
    @Test("Once a session is established, each side receives the other's disco key advertisement. The initiator's advertisement arrives before the queued packet")
    func advertisementsAtSessionStart() throws {
        var pair = try EnginePair(aliceDisco: aliceDisco, bobDisco: bobDisco)
        let request = TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7)
        let delivery = pair.send(request, from: .bob)
        #expect(delivery.advertisements[.alice] == [bobDisco])
        #expect(delivery.advertisements[.bob] == [aliceDisco])
        #expect(delivery.arrivals[.alice] == ["advert", "packet"])
        #expect(delivery.packets[.alice] == [request])
        #expect(delivery.drops.isEmpty)

        // Do not advertise again in the same session.
        let again = pair.send(request, from: .bob, at: clockStart + .seconds(1))
        #expect(again.advertisements.isEmpty)
        // Advertise again when rekey establishes a new session (initiator keypair at 120 seconds).
        let rekeyed = pair.send(request, from: .bob, at: clockStart + .seconds(121))
        #expect(rekeyed.advertisements[.alice] == [bobDisco])
        #expect(rekeyed.advertisements[.bob] == [aliceDisco])
    }

    @Test("The source of an advertisement is a local address in the family of the peer's first address, and the bytes use TSMP 'a' format")
    func advertisementBytes() throws {
        var pair = try EnginePair(aliceDisco: aliceDisco)
        let message = try #require(pair.alice.device.peers[PublicKey(pair.publicKey(.bob))]?.priorityMessage)
        let expected = TSMPDiscoKeyAdvertisement(
            selfAddresses: [IPPrefix("100.64.0.1/32")!, IPPrefix("fd7a:115c:a1e0::1/128")!],
            destination: IPAddress("100.64.0.2")!,
            key: aliceDisco
        )
        #expect(message == expected?.bytes)
        #expect(message.count == 53)
        // A zero disco key (bob) is never advertised.
        #expect(pair.bob.device.peers[PublicKey(pair.publicKey(.alice))]?.priorityMessage == nil)
        // Send an IPv6 advertisement (73 bytes) to an IPv6-only peer.
        let v6Only = makeNodeJSON(
            id: 3, key: NodePublicKey(Curve25519.KeyAgreement.PrivateKey().publicKey), addresses: ["fd7a:115c:a1e0::3/128"],
            extra: #","DiscoKey":"\#(discoKeyText)","HomeDERP":1"#
        )
        _ = pair.alice.apply(try pair.netmap(for: .alice, peers: [v6Only]), at: clockStart, wallClock: wallClockStart)
        let v6Message = try #require(pair.alice.device.peers.values.first?.priorityMessage)
        #expect(v6Message.count == 73)
        #expect(v6Message[0] >> 4 == 6)
    }

    @Test("Skip generating an advertisement if there is no local address of the matching family or the key is zero")
    func noAdvertisementWithoutMatchingAddress() {
        let v4Peer = IPAddress("100.64.0.2")!
        #expect(TSMPDiscoKeyAdvertisement(selfAddresses: [IPPrefix("fd7a:115c:a1e0::1/128")!], destination: v4Peer, key: aliceDisco) == nil)
        // Only single-address prefixes can serve as the source.
        #expect(TSMPDiscoKeyAdvertisement(selfAddresses: [IPPrefix("100.64.0.0/10")!], destination: v4Peer, key: aliceDisco) == nil)
        #expect(TSMPDiscoKeyAdvertisement(selfAddresses: [IPPrefix("100.64.0.1/32")!], destination: v4Peer, key: .zero) == nil)
        // Use the first matching address.
        let chosen = TSMPDiscoKeyAdvertisement(
            selfAddresses: [IPPrefix("fd7a:115c:a1e0::1/128")!, IPPrefix("100.64.0.9/32")!, IPPrefix("100.64.0.1/32")!],
            destination: v4Peer, key: aliceDisco
        )
        #expect(chosen?.source == IPAddress("100.64.0.9"))
    }

    @Test("Ignore advertisements received via unauthenticated paths or with invalid inputs, including sources outside AllowedIPs, packets outside WireGuard, zero keys, and packets from the layer above")
    func unauthenticatedAdvertisementsAreIgnored() throws {
        var pair = try EnginePair()
        _ = pair.send(TestPacket.udp(from: "100.64.0.2", 1, to: "100.64.0.1", 7), from: .bob)
        let alice = PublicKey(pair.publicKey(.alice))

        // bob advertises using another node's source address. The WireGuard source check drops it first.
        let spoofed = try #require(TSMPDiscoKeyAdvertisement(
            selfAddresses: [IPPrefix("100.64.0.99/32")!], destination: IPAddress("100.64.0.1")!, key: bobDisco))
        var delivery = pair.deliver(pair.bob.route(try pair.bob.device.send(spoofed.bytes, to: alice, at: clockStart)), from: .bob)
        #expect(delivery.advertisements.isEmpty)
        #expect(delivery.drops[.alice] == [.wireGuard(.disallowedSource)])

        // The device drops the bare packet without WireGuard encapsulation as malformed.
        let genuine = try #require(TSMPDiscoKeyAdvertisement(
            selfAddresses: [IPPrefix("100.64.0.2/32")!], destination: IPAddress("100.64.0.1")!, key: bobDisco))
        #expect(pair.alice.receive(genuine.bytes, from: EnginePair.Side.bob.source, at: clockStart) == [.dropped(.wireGuard(.malformed))])

        // Consume the zero-key advertisement without using it.
        var zero = genuine.bytes
        zero.replaceSubrange(21..., with: [UInt8](repeating: 0, count: 32))
        delivery = pair.deliver(pair.bob.route(try pair.bob.device.send(zero, to: alice, at: clockStart)), from: .bob)
        #expect(delivery.advertisements.isEmpty)
        #expect(delivery.drops[.alice] == [.consumedControlPacket])

        // Drop advertisements from the device (app or netstack) without sending them over WireGuard (contract behavior L4).
        #expect(pair.bob.send(genuine.bytes, at: clockStart) == [.dropped(.consumedControlPacket)])

        // The same bytes are used when sent through bob's session, showing that the cases above were dropped for other reasons.
        delivery = pair.deliver(pair.bob.route(try pair.bob.device.send(genuine.bytes, to: alice, at: clockStart)), from: .bob)
        #expect(delivery.advertisements[.alice] == [bobDisco])
    }
}
