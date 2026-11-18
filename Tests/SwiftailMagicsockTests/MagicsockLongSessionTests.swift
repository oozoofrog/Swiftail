import Testing

import SwiftailBase
@testable import SwiftailMagicsock

// Models a real device observation (on the same Wi-Fi, the downloading device saw `relayed` about 100 seconds after direct was established and `direct` 5.8 seconds later)
// in the state machine. See "Investigation results" under "`relayed` about 100 seconds after direct was established" in `docs/contracts/SwiftailMagicsock.md`.

/// Patterns of periodic netmap delivery.
enum NetmapRefresh: CaseIterable, Sendable {
    /// Arrives once at startup.
    case none
    /// The same list arrives every 30 seconds.
    case same
    /// The peer's endpoint list changes every 30 seconds (unreachable addresses are added, removed, and reordered). The reachable address is always present.
    case changing
    /// The device's netmap lacks the host's reachable address, and the host cannot send CallMeMaybe because it has no STUN region and does not know its own endpoints.
    /// The device learns the address only from the source of the host's Ping (a candidate removed 45 seconds after the last Ping).
    case pingLearned
}

/// Node 0 ("host") sends the download. Node 1 ("device") receives it and sends rarely, like ACKs. Both are on the same LAN with home region 7.
private struct DownloadSession {
    var network: TestNetwork
    let host: TestIdentity
    let phone: TestIdentity
    let refresh: NetmapRefresh
    private let unreachable: [IPEndpoint]
    private var refreshCount = 0

    init(latency: Duration, refresh: NetmapRefresh) throws {
        host = try TestIdentity(1, address: "192.168.1.10:41641")
        phone = try TestIdentity(2, address: "192.168.1.20:50000")
        unreachable = [try #require(IPEndpoint("203.0.113.9:41641")), try #require(IPEndpoint("203.0.113.10:41641"))]
        self.refresh = refresh
        network = try TestNetwork([host, phone])
        network.udpLatency = latency
        let region = Magicsock.Region(id: 7, stunServers: [network.stunServer])
        applyNetmap()
        if refresh != .pingLearned {
            network.setRegions(0, [region])
        }
        network.setRegions(1, [region])
    }

    /// Applies the current netmap to both nodes. With `changing`, the list changes on every call.
    mutating func applyNetmap() {
        var hostEndpoints = [host.address], phoneEndpoints = [phone.address]
        switch refresh {
        case .none, .same:
            break
        case .changing:
            if refreshCount % 2 == 1 {
                hostEndpoints = [unreachable[0], host.address, unreachable[1]]
                phoneEndpoints = [unreachable[1], phone.address]
            }
        case .pingLearned:
            hostEndpoints = [unreachable[0]]
        }
        refreshCount += 1
        network.setPeers(0, [phone.peer(homeDERP: 7, endpoints: phoneEndpoints)])
        network.setPeers(1, [host.peer(homeDERP: 7, endpoints: hostEndpoints)])
    }

    /// Runs for `seconds`. If `refresh` is other than `.none`, reapplies netmap every 30 seconds.
    mutating func run(seconds: Int64) {
        let end = network.now + .seconds(seconds)
        while refresh != .none, nextRefresh <= end {
            network.run(until: nextRefresh)
            applyNetmap()
        }
        network.run(until: end)
    }

    private var nextRefresh: ContinuousClock.Instant {
        sockT0 + .seconds(30 * Int64(refreshCount))
    }

    /// Runs one download with one request from the device, then sends from the host every 20 ms and the device every 100 ms for `seconds`.
    mutating func download(seconds: Int64) {
        network.send(from: 1, to: 0)
        network.sendRepeatedly(from: 0, to: 1, every: .milliseconds(20))
        network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(100))
        run(seconds: seconds)
        network.sendRepeatedly(from: 0, to: 1, every: nil)
        network.sendRepeatedly(from: 1, to: 0, every: nil)
    }

    /// Returns the peer path events emitted by node `node`.
    func events(_ node: Int) -> [(time: ContinuousClock.Instant, path: PeerPath?)] {
        network.pathEvents(node, peer: 1 - node)
    }

    /// Returns the times at which the device received the host's Pongs over UDP.
    var pongsAtPhone: [ContinuousClock.Instant] {
        network.discoLog.filter { $0.from == 0 && $0.to == 1 && !$0.viaDERP && $0.message.isPong }.map(\.time)
    }
}

@Suite("Long Magicsock sessions")
struct MagicsockLongSessionTests {
    @Test(
        "Repeating 26 seconds of downloading and 42 seconds of idle time for 300 seconds emits neither relayed nor nil once the path is direct",
        arguments: [2, 10, 30], NetmapRefresh.allCases
    )
    func repeatedDownloads(latencyMilliseconds: Int, refresh: NetmapRefresh) throws {
        var session = try DownloadSession(latency: .milliseconds(Int64(latencyMilliseconds)), refresh: refresh)
        session.run(seconds: 1)
        while session.network.now < sockT0 + .seconds(270) {
            session.download(seconds: 26)
            session.run(seconds: 42)
        }
        session.download(seconds: 26)

        for node in [0, 1] {
            let events = session.events(node)
            let firstDirect = try #require(events.firstIndex { if case .direct = $0.path { true } else { false } }, "Node \(node)")
            #expect(events[firstDirect].time < sockT0 + .seconds(2), "First direct path for node \(node)")
            let later = events[(firstDirect + 1)...].map(\.path)
            #expect(later.allSatisfy { if case .direct = $0 { true } else { false } }, "Node \(node): \(later)")
        }
        if refresh == .pingLearned {
            let learned = session.network.nodes[1].sock.peers[session.host.nodeKey]?.path.candidates.first { $0.address == session.host.address }
            #expect(learned?.lastPingReceived != nil && learned?.fromCallMeMaybe == false, "The device's bestAddr must be a candidate learned from a Ping")
        }
        #expect(session.network.deadlineViolations == 0)
    }

    /// Follows Go's rules. The heartbeat Pings `bestAddr` every 3 seconds (`endpoint.go:926-930`), and a Pong extends trust by 6.5 seconds
    /// (`:2003-2019`). After trust expires, it also sends over DERP (`:635-652`). Thus, if the receiving side loses two consecutive Pongs, it becomes relayed
    /// 6.5 seconds after the last Pong (heartbeat time + 0.5 seconds + round-trip delay) and returns to direct on the first Ping that gets a Pong again.
    @Test("If host Pongs stop during a download, the path becomes relayed 6.5 seconds after the last Pong (trust expires) and direct on a Ping within 5 seconds after the interruption ends")
    func pongLossDuringDownload() throws {
        var session = try DownloadSession(latency: .milliseconds(10), refresh: .none)
        session.run(seconds: 1)
        session.download(seconds: 74)
        // As in measurement 1, lose Pongs for three heartbeats (about 9 seconds) while the download continues.
        let lossStart = session.network.now, lossEnd = lossStart + .seconds(9)
        session.network.pongLoss = (from: 0, during: lossStart..<lossEnd)
        session.download(seconds: 26)

        let events = session.events(1).filter { $0.time >= lossStart }
        #expect(events.count == 2, "\(events)")
        let relayed = try #require(events.first)
        #expect(relayed.path == .relayed(derpRegion: 7))
        let lastPong = try #require(session.pongsAtPhone.last { $0 < relayed.time })
        #expect(relayed.time == lastPong + PeerPathState.trustDuration + .nanoseconds(1))
        let recovered = try #require(events.last)
        #expect(recovered.path == .direct(session.host.address))
        #expect(recovered.time == session.pongsAtPhone.first { $0 >= lossEnd })
        #expect(recovered.time <= lossEnd + PeerPathState.pingInterval + .milliseconds(20))
        // The host stays direct because it receives the device's Pongs.
        #expect(session.events(0).allSatisfy { $0.time < lossStart })
        #expect(session.network.deadlineViolations == 0)
    }

    @Test("Path downgrade reasons include trust expiration, candidate removal, rebinding, a disco key change, idleness, and peer removal")
    func downgradeCauses() throws {
        var session = try DownloadSession(latency: .milliseconds(10), refresh: .none)
        let host = session.host.nodeKey
        session.run(seconds: 1)
        session.network.sendRepeatedly(from: 1, to: 0, every: .milliseconds(100))
        session.run(seconds: 2)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .direct(session.host.address))
        #expect(session.network.nodes[1].sock.downgrade(of: host) == nil)

        // Trust expiration. Drop the host's Pongs.
        session.network.pongLoss = (from: 0, during: session.network.now..<(session.network.now + .seconds(10)))
        session.run(seconds: 9)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .relayed(derpRegion: 7))
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .trustExpired)
        session.run(seconds: 8)
        #expect(session.network.nodes[1].sock.downgrade(of: host) == nil, "Returning to direct clears the reason")

        // Candidate removal. Netmap removes the netmap candidate that is `bestAddr`.
        let elsewhere = try #require(IPEndpoint("203.0.113.9:41641"))
        session.network.setPeers(1, [session.host.peer(homeDERP: 7, endpoints: [elsewhere])])
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .relayed(derpRegion: 7))
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .candidateRemoved)
        session.network.setPeers(1, [session.host.peer(homeDERP: 7, endpoints: [session.host.address])])
        session.run(seconds: 6)

        // Rebinding.
        var random = PathTestRandom(state: 9)
        _ = session.network.nodes[1].sock.rebind(
            localPort: session.phone.address.port, localAddresses: [], loopbackAddresses: [],
            at: session.network.now, using: &random
        )
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .rebind)
        session.run(seconds: 6)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == .direct(session.host.address))

        // Disco key change. The first TSMP advertisement triggers path rediscovery even if it matches the netmap key (as in Go). Clearing send history yields nil.
        session.network.advertiseDiscoKey(from: 0, to: 1)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == nil)
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .discoKeyChanged)

        // Idleness. 45 seconds after the last send.
        session.run(seconds: 1)
        session.network.sendRepeatedly(from: 1, to: 0, every: nil)
        session.run(seconds: 46)
        #expect(session.network.nodes[1].sock.path(to: host, at: session.network.now) == nil)
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .idle)

        // Peer removal.
        session.network.setPeers(1, [])
        #expect(session.network.nodes[1].sock.downgrade(of: host) == .peerRemoved)
    }
}
