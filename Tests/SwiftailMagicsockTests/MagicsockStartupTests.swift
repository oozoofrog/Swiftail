import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// Models a real device observation in the state machine (an idle host and a newly started tunnel remain relayed for 25 and 44 seconds after first contact).
// See "Investigation of direct path delay (2026-11-16)" in `docs/contracts/SwiftailMagicsock.md`.

/// Node 0 ("host") is idle for 120 seconds, so periodic STUN has stopped, and node 1 ("tunnel") starts at 120 seconds. Both use home region 7.
/// The host echoes received data. If `hostKnowsTunnel` is nil, the host's netmap has the tunnel's current key and address.
private func lateStartNetwork(hostKnowsTunnel stale: Magicsock.Peer? = nil) throws -> TestNetwork {
    let host = try TestIdentity(1, address: "192.0.2.1:41641")
    let tunnel = try TestIdentity(2, address: "192.0.2.2:50000")
    var network = try TestNetwork([host, tunnel])
    network.nodes[0].echo = true
    let region = Magicsock.Region(id: 7, stunServers: [network.stunServer])
    network.setPeers(0, [stale ?? tunnel.peer(homeDERP: 7, endpoints: [tunnel.address])])
    network.setRegions(0, [region])
    network.run(until: sockTime(120_000))
    #expect(network.nodes[0].sock.netcheck.nextDeadline == nil, "The host's periodic STUN should have stopped")

    network.nodes[1].sock = tunnel.magicsock(at: sockTime(120_000))
    network.setPeers(1, [host.peer(homeDERP: 7, endpoints: [host.address])])
    network.setRegions(1, [region])
    return network
}

@Suite("Magicsock peers that start later")
struct MagicsockStartupTests {
    @Test("With an idle host and a tunnel started 30 seconds earlier, both CallMeMaybe messages follow the first data within 3 seconds without waiting for a periodic round, and both sides become direct within 1 second")
    func firstContactAfterIdle() throws {
        // The host knows only the tunnel's old address. The tunnel's endpoints are also older than 27 seconds, deferring CallMeMaybe until after the round.
        let oldTunnel = try TestIdentity(2, address: "192.0.2.2:49999")
        var network = try lateStartNetwork(hostKnowsTunnel: oldTunnel.peer(homeDERP: 7, endpoints: [oldTunnel.address]))
        let host = network.nodes[0].identity, tunnel = network.nodes[1].identity
        let first = sockTime(150_000)
        network.run(until: first)
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(500))
        network.run(until: first + .seconds(30))

        // Notes §4.8 4.1. Stale endpoints are sent once the immediately started round (up to 3 seconds) finishes. There is no wait for a periodic round (20–26 seconds).
        for (from, to) in [(1, 0), (0, 1)] {
            let callMeMaybe = try #require(network.discoLog.first {
                $0.from == from && $0.to == to && $0.time >= first && $0.message.callMeMaybeEndpoints != nil
            })
            #expect(callMeMaybe.time < first + Netcheck.roundTimeout, "CallMeMaybe from node \(from)")
        }
        let tunnelDirect = try #require(network.pathEvents(1, peer: 0).first { $0.path == .direct(host.address) })
        let hostDirect = try #require(network.pathEvents(0, peer: 1).first { $0.path == .direct(tunnel.address) })
        #expect(tunnelDirect.time < first + .seconds(1))
        #expect(hostDirect.time < first + .seconds(1))
        #expect(network.deadlineViolations == 0)
    }

    @Test("While the host holds the tunnel's old disco key, disco is dropped and the path stays relayed. A new key from netmap makes both sides direct within 1 second")
    func staleDiscoKeyUntilNetmap() throws {
        // The tunnel generates a new disco key at each startup. The host's netmap still has the old key (with the same node key).
        let tunnel = try TestIdentity(2, address: "192.0.2.2:50000")
        let oldDisco = try TestIdentity(3, address: "192.0.2.2:49999").discoPublicKey
        let stale = Magicsock.Peer(key: tunnel.nodeKey, discoKey: oldDisco, homeDERP: 7, endpoints: [tunnel.address])
        var network = try lateStartNetwork(hostKnowsTunnel: stale)
        let host = network.nodes[0].identity
        let first = sockTime(135_000)
        network.run(until: first)
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(500))
        let keyArrives = first + .seconds(25)
        network.run(until: keyArrives)

        // In the meantime data flows over DERP, but neither side gets a direct path. The host drops tunnel disco because its key is unknown,
        // and the tunnel drops host disco because it cannot open packets sealed with the old key (notes §4.2 1, §4.10 4).
        #expect(!network.pathEvents(0, peer: 1).contains { if case .direct = $0.path { true } else { false } })
        #expect(!network.pathEvents(1, peer: 0).contains { if case .direct = $0.path { true } else { false } })
        func drops(_ node: Int, _ reason: Magicsock.Drop) -> Int {
            network.log.filter { $0.node == node && $0.time >= first && $0.output == .dropped(reason) }.count
        }
        #expect(drops(0, .unknownDiscoKey) > 0)
        #expect(drops(1, .malformedDisco) > 0)
        #expect(network.received.contains { $0.node == 0 && $0.time < keyArrives && isTestDatagram($0.bytes) })

        network.setPeers(0, [tunnel.peer(homeDERP: 7, endpoints: [tunnel.address])])
        network.run(until: keyArrives + .seconds(10))

        // The new key clears trust and send history, so the host's path is briefly nil (notes §4.4 3). The next send rediscovers the path.
        #expect(network.pathEvents(0, peer: 1).contains { $0.time == keyArrives && $0.path == nil })
        let hostDirect = try #require(network.pathEvents(0, peer: 1).first { $0.path == .direct(tunnel.address) })
        let tunnelDirect = try #require(network.pathEvents(1, peer: 0).first { $0.path == .direct(host.address) })
        #expect(hostDirect.time < keyArrives + .seconds(1))
        #expect(tunnelDirect.time < keyArrives + .seconds(1))
        #expect(network.deadlineViolations == 0)
    }

    @Test("Even while the host holds the tunnel's old disco key, TSMP advertisements on WireGuard session establishment make both sides direct within 1 second without a netmap update")
    func staleDiscoKeyWithAdvertisement() throws {
        let tunnel = try TestIdentity(2, address: "192.0.2.2:50000")
        let oldDisco = try TestIdentity(3, address: "192.0.2.2:49999").discoPublicKey
        let stale = Magicsock.Peer(key: tunnel.nodeKey, discoKey: oldDisco, homeDERP: 7, endpoints: [tunnel.address])
        var network = try lateStartNetwork(hostKnowsTunnel: stale)
        let host = network.nodes[0].identity
        let first = sockTime(135_000)
        network.run(until: first)
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(500))
        // The tunnel's first data opens a WireGuard handshake over DERP (10 ms each for initiation and response). The initiating tunnel
        // receives the response at +20 ms and sends an advertisement that the host receives at +30 ms. The host confirms the session with that advertisement and sends its own,
        // which the tunnel receives at +40 ms (wireguard-go `device/receive.go`).
        network.run(until: first + .milliseconds(30))
        network.advertiseDiscoKey(from: 1, to: 0)
        network.run(until: first + .milliseconds(40))
        network.advertiseDiscoKey(from: 0, to: 1)
        network.run(until: first + .seconds(10))

        #expect(network.nodes[0].sock.peers[tunnel.nodeKey]?.discoKey == tunnel.discoPublicKey)
        let hostDirect = try #require(network.pathEvents(0, peer: 1).first { $0.path == .direct(tunnel.address) })
        let tunnelDirect = try #require(network.pathEvents(1, peer: 0).first { $0.path == .direct(host.address) })
        #expect(hostDirect.time < first + .seconds(1))
        #expect(tunnelDirect.time < first + .seconds(1))
        #expect(network.deadlineViolations == 0)
    }
}
