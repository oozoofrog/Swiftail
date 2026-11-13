import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import Testing

@Suite("M2 제어 클라이언트 Go 상호 운용", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 M2 관문 시험을 건너뜁니다"), .timeLimit(.minutes(4)))
struct SwiftailControlInteropTests {
    @Test("관문 1: 인증 없이 서버 키 조회부터 등록·맵 수신까지")
    func registrationWithoutAuth() async throws {
        try await withTailnet { _, ready, directory in
            try await withClient(ready: ready, directory: directory) { client in
                let key = try await client.registered()
                let map = try await client.netmap()
                #expect(map.selfNode.key == key)
                #expect(map.selfNode.machineAuthorized)
                let stored = try #require(try NodeIdentityStore(directory: directory).load())
                #expect(stored.nodePublicKey == key, "registered 사건 전에 확정 신원이 저장되어야 한다")
            }
        }
    }

    @Test("관문 1: 인증을 요구하는 서버에 맞는 인증 키로 등록")
    func registrationWithAuth() async throws {
        try await withTailnet { tool, ready, directory in
            let authKey = "tskey-auth-" + UUID().uuidString
            // requireAuth는 대화형 인증 스위치다. authKey만 설정해도 RequireAuthKey 검사가 강제된다.
            _ = try await tool.command(.init(cmd: "setAuth", authKey: authKey), expecting: "auth")
            try await withClient(ready: ready, directory: directory, authKey: authKey) { client in
                let key = try await client.registered()
                let map = try await client.netmap()
                #expect(map.selfNode.key == key)
                #expect(map.selfNode.machineAuthorized)
            }
        }
    }

    @Test("관문 1: 틀린 인증 키는 등록 거절이며 후보 node 키를 확정하지 않는다")
    func rejectsWrongAuth() async throws {
        try await withTailnet { tool, ready, directory in
            _ = try await tool.command(.init(cmd: "setAuth",
                authKey: "tskey-auth-" + UUID().uuidString), expecting: "auth")
            try await withClient(ready: ready, directory: directory,
                authKey: "tskey-auth-" + UUID().uuidString) { client in
                switch try await client.next("틀린 인증 키의 registrationRejected") {
                case .failed(.registrationRejected(let message)):
                    #expect(message == "invalid authkey")
                default: throw GateFailure("틀린 인증 키: registrationRejected 대신 다른 사건")
                }
                let stored = try #require(try NodeIdentityStore(directory: directory).load())
                #expect(stored.nodePublicKey == nil, "거절한 후보 node 키를 저장하면 안 된다")
                let nodes = try await tool.command(.init(cmd: "nodes"), expecting: "nodes")
                #expect(try #require(nodes.nodes).isEmpty, "거절된 노드는 Go 등록 목록에 없어야 한다")
            }
        }
    }

    @Test("관문 2: 자기 주소·Go 피어·DERPMap·DNSConfig·패킷 필터")
    func mapContents() async throws {
        try await withTailnet { tool, ready, directory in
            let peer = try await tool.command(.init(cmd: "addPeer", name: "go-peer-a"), expecting: "peer")
            let peerKey = try #require(peer.nodeKey)
            let peerAddresses = try #require(peer.addresses)
            let derp = try #require(ready.derp)
            try await withClient(ready: ready, directory: directory) { client in
                let key = try await client.registered()
                let map = try await client.netmap()
                #expect(map.selfNode.key == key)
                let ipv4 = try #require(map.selfNode.addresses.first { $0.address.isIPv4 })
                #expect(ipv4.length == 32)
                let tailnetRange = try #require(IPPrefix("100.64.0.0/10"))
                #expect(tailnetRange.contains(ipv4.address))
                #expect(map.selfNode.allowedIPs == map.selfNode.addresses)
                let go = try #require(map.peers.first { $0.key.description == peerKey })
                #expect(Set(go.addresses.map { $0.address.description }) == Set(peerAddresses))
                #expect(go.name.trimmingCharacters(in: CharacterSet(charactersIn: ".")) ==
                    peer.fqdn?.trimmingCharacters(in: CharacterSet(charactersIn: ".")))
                let region = try #require(map.derpMap?.regions?[derp.regionID])
                #expect(region.regionID == derp.regionID)
                #expect(region.regionCode == "test")
                let server = try #require(region.nodes.first)
                #expect(server.hostName == derp.host)
                #expect(server.ipv4 == derp.host)
                #expect(server.derpPort == derp.port)
                #expect(server.stunPort == derp.stunPort)
                #expect(server.insecureForTests)
                let rule = try #require(map.packetFilter.first)
                // Go testcontrol은 전체 허용 규칙 뒤에 ingress capability 규칙을 붙인다.
                #expect(map.packetFilter.count == 2)
                #expect(rule.srcIPs == ["*"])
                let destination = try #require(rule.dstPorts.first)
                #expect(rule.dstPorts.count == 1)
                #expect(destination.ip == "*")
                #expect(destination.ports.first == 0 && destination.ports.last == 65_535)
                let capabilityRule = try #require(map.packetFilter.last)
                #expect(capabilityRule.srcIPs == ["*"])
                #expect(capabilityRule.dstPorts.isEmpty)
                let grant = try #require(capabilityRule.capGrant.first)
                #expect(capabilityRule.capGrant.count == 1)
                #expect(grant.dsts.map(\.description) == ["0.0.0.0/0", "::/0"])
                #expect(grant.caps == ["https://tailscale.com/cap/ingress"])

                // testcontrol 기본 DNSConfig는 nil이다. 명시적인 비어 있지 않은 설정을 주입해 전달을 검증한다.
                #expect(map.dnsConfig == nil)
                let dns = MapInjection.DNS(Resolvers: [.init(Addr: "192.0.2.53")],
                    Domains: [try #require(ready.magicDNSSuffix)], Proxied: true)
                try await tool.inject(.init(DNSConfig: dns), into: key.description)
                let updated = try await client.netmap("주입한 DNSConfig") { $0.dnsConfig?.proxied == true }
                #expect(updated.dnsConfig?.resolvers.map(\.addr) == ["192.0.2.53"])
                #expect(updated.dnsConfig?.domains == dns.Domains)
                #expect(updated.selfNode == map.selfNode)
                #expect(updated.peers == map.peers)
                #expect(updated.derpMap == map.derpMap)
                #expect(updated.packetFilter == map.packetFilter)
            }
        }
    }

    @Test("관문 3: Go 피어 추가와 PeersChanged·Patch·OnlineChange·마지막 피어 제거")
    func peerDeltas() async throws {
        try await withTailnet { tool, ready, directory in
            try await withClient(ready: ready, directory: directory) { client in
                let key = try await client.registered()
                let initial = try await client.netmap()
                #expect(initial.peers.isEmpty)
                let added = try await tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")
                let peerKey = try #require(added.nodeKey)
                let withPeer = try await client.netmap("추가한 Go 피어") {
                    $0.peers.contains { $0.key.description == peerKey }
                }
                let peer = try #require(withPeer.peers.first { $0.key.description == peerKey })
                #expect(Set(peer.addresses.map { $0.address.description }) == Set(try #require(added.addresses)))
                let replacement = MapInjection.Peer(ID: peer.id, Key: peerKey, Name: "changed.tail0001.test.",
                    Addresses: ["100.64.0.99/32"], AllowedIPs: ["100.64.0.99/32"], Online: true)
                try await tool.inject(.init(PeersChanged: [replacement]), into: key.description)
                let changed = try await client.netmap("PeersChanged의 전체 피어 교체") {
                    $0.peers.first?.name == replacement.Name
                }
                #expect(changed.peers.count == 1)
                #expect(changed.peers.first?.id == peer.id)
                #expect(changed.peers.first?.addresses.map(\.description) == replacement.Addresses)
                #expect(changed.peers.first?.online == true)

                try await tool.inject(.init(PeersChangedPatch: [.init(NodeID: peer.id,
                    DERPRegion: 7, Endpoints: ["192.0.2.7:41641"])]), into: key.description)
                let patched = try await client.netmap("PeersChangedPatch의 DERP·Endpoints") {
                    $0.peers.first?.homeDERP == 7
                }
                #expect(patched.peers.first?.endpoints.map(\.description) == ["192.0.2.7:41641"])
                #expect(patched.peers.first?.name == replacement.Name)
                #expect(patched.peers.first?.key == peer.key)
                #expect(patched.peers.first?.addresses == changed.peers.first?.addresses)

                try await tool.inject(.init(OnlineChange: [String(peer.id): false]), into: key.description)
                let offline = try await client.netmap("OnlineChange=false") { $0.peers.first?.online == false }
                #expect(offline.peers.first?.homeDERP == 7)
                #expect(offline.peers.first?.endpoints == patched.peers.first?.endpoints)
                try await tool.inject(.init(OnlineChange: [String(peer.id): true]), into: key.description)
                _ = try await client.netmap("OnlineChange=true") { $0.peers.first?.online == true }

                // removePeer는 서버 등록을 지우지 못하므로 PeersRemoved로 퇴장을 검증한다.
                try await tool.inject(.init(PeersRemoved: [peer.id]), into: key.description)
                let removed = try await client.netmap("PeersRemoved로 마지막 피어 제거") { $0.peers.isEmpty }
                #expect(removed.selfNode == initial.selfNode)
                #expect(removed.derpMap == initial.derpMap)
                #expect(removed.packetFilter == initial.packetFilter)
            }
        }
    }

    @Test("관문 4: 같은 신원 디렉터리로 재시작하면 node 키와 주소가 같다")
    func identitySurvivesRestart() async throws {
        try await withTailnet { tool, ready, directory in
            let url = try #require(ready.controlURL)
            let first = GateClient(serverURL: url, directory: directory)
            let key: NodePublicKey
            let map: Netmap
            do {
                key = try await first.registered()
                map = try await first.netmap()
                await first.stop()
            } catch { await first.stop(); throw error }
            let machine = try #require(try NodeIdentityStore(directory: directory).load()).machinePublicKey
            try await withClient(ready: ready, directory: directory) { second in
                let restartedKey = try await second.registered()
                let restarted = try await second.netmap()
                #expect(restartedKey == key)
                #expect(restarted.selfNode.key == map.selfNode.key)
                #expect(restarted.selfNode.addresses == map.selfNode.addresses)
                #expect(restarted.selfNode.id == map.selfNode.id)
                #expect(restarted.selfNode.machine == machine)
                let nodes = try #require(try await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
                #expect(nodes.count == 1, "재시작으로 별도 노드가 생기면 안 된다")
            }
        }
    }

    @Test("관문 5: 열린 스트림 곁의 상태 갱신이 자기 맵에 반영된다")
    func localStatusKeepsStream() async throws {
        try await withTailnet { _, ready, directory in
            try await withClient(ready: ready, directory: directory) { client in
                _ = try await client.registered()
                _ = try await client.netmap()
                for port: UInt16 in [41641, 41642] {
                    let endpoint = try #require(IPEndpoint("192.0.2.10:\(port)"))
                    let disco = try #require(DiscoPublicKey(rawValue:
                        Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation))
                    await client.client.setLocalStatus(.init(discoKey: disco, endpoints: [endpoint]))
                    let map = try await client.netmap("상태 갱신의 자기 DiscoKey·Endpoints 반영") {
                        $0.selfNode.endpoints == [endpoint] && $0.selfNode.discoKey == disco
                    }
                    #expect(map.selfNode.endpoints == [endpoint])
                    #expect(map.selfNode.discoKey == disco)
                }
            }
        }
    }

    @Test("관문 5 장기: 자연 KeepAlive로 125초 유지한 뒤 새 맵을 받는다", .timeLimit(.minutes(4)))
    func keepAliveBeyondTwoMinutes() async throws {
        try await withTailnet { tool, ready, directory in
            try await withClient(ready: ready, directory: directory) { client in
                _ = try await client.registered()
                let initial = try await client.netmap()
                let started = ContinuousClock.now
                let endpoint = try #require(IPEndpoint("192.0.2.11:41641"))
                await client.client.setLocalStatus(.init(endpoints: [endpoint]))
                _ = try await client.netmap("장기 관측 전 상태 갱신") { $0.selfNode.endpoints == [endpoint] }
                try await client.remainsConnected(until: started + .seconds(125))
                #expect(started.duration(to: .now) > .seconds(120))
                let added = try await tool.command(.init(cmd: "addPeer", name: "go-peer-long"), expecting: "peer")
                let peerKey = try #require(added.nodeKey)
                let final = try await client.netmap("125초 뒤 Go 피어 추가로 발생한 새 맵") {
                    $0.peers.contains { $0.key.description == peerKey }
                }
                #expect(final.selfNode.key == initial.selfNode.key)
                #expect(final.selfNode.endpoints == [endpoint])
            }
        }
    }

    @Test("관문 6: Go nodes와 Go tsnet peerStatus 양쪽에서 Swift 노드를 본다")
    func goObservesSwiftNode() async throws {
        try await withTailnet { tool, ready, directory in
            _ = try await tool.command(.init(cmd: "addPeer", name: "go-observer"), expecting: "peer")
            try await withClient(ready: ready, directory: directory) { client in
                let key = try await client.registered()
                let map = try await client.netmap()
                let expectedAddresses = Set(map.selfNode.addresses.map { $0.address.description })
                let nodes = try #require(try await tool.command(.init(cmd: "nodes"), expecting: "nodes").nodes)
                let swift = try #require(nodes.first { $0.nodeKey == key.description })
                #expect(Set(swift.addresses) == expectedAddresses)
                #expect(swift.name?.hasPrefix("rd-mac-1a2b3c4d.") == true)
                let deadline = ContinuousClock.now + .seconds(20)
                var observedCounts: [Int] = []
                // LocalClient 상태는 비동기 반영된다. 매 명령의 JSON 사건을 기다리며 재조회한다.
                while ContinuousClock.now < deadline {
                    let status = try await tool.command(.init(cmd: "peerStatus", name: "go-observer"), expecting: "peerStatus")
                    let peers = try #require(status.peers)
                    if let swift = peers.first(where: { $0.nodeKey == key.description }) {
                        #expect(Set(swift.addresses) == expectedAddresses)
                        return
                    }
                    observedCounts.append(peers.count)
                }
                throw GateFailure("Go peerStatus의 Swift 노드 대기 20초 초과; 관측 피어 수 \(observedCounts.suffix(10))")
            }
        }
    }
}
