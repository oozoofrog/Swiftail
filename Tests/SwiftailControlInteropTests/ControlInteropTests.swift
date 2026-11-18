import CryptoKit
import Foundation
import SwiftailBase
import SwiftailControl
import Testing

@Suite("M2 control client Go interop", .enabled(if: tailnetBinary != nil,
    "Skipping the M2 gate tests because SWIFTAIL_TAILNET is missing"), .timeLimit(.minutes(4)))
struct SwiftailControlInteropTests {
    @Test("Gate 1: From server key lookup through registration and map receipt without authentication")
    func registrationWithoutAuth() async throws {
        try await withTailnet { _, ready, directory in
            try await withClient(ready: ready, directory: directory) { client in
                let key = try await client.registered()
                let map = try await client.netmap()
                #expect(map.selfNode.key == key)
                #expect(map.selfNode.machineAuthorized)
                let stored = try #require(try NodeIdentityStore(directory: directory).load())
                #expect(stored.nodePublicKey == key, "The committed identity must be stored before the registered event")
            }
        }
    }

    @Test("Gate 1: Registers with the correct auth key against a server that requires authentication")
    func registrationWithAuth() async throws {
        try await withTailnet { tool, ready, directory in
            let authKey = "tskey-auth-" + UUID().uuidString
            // requireAuth switches on interactive authentication. Setting authKey alone still enforces the RequireAuthKey check.
            _ = try await tool.command(.init(cmd: "setAuth", authKey: authKey), expecting: "auth")
            try await withClient(ready: ready, directory: directory, authKey: authKey) { client in
                let key = try await client.registered()
                let map = try await client.netmap()
                #expect(map.selfNode.key == key)
                #expect(map.selfNode.machineAuthorized)
            }
        }
    }

    @Test("Gate 1: A wrong auth key rejects registration without committing the candidate node key")
    func rejectsWrongAuth() async throws {
        try await withTailnet { tool, ready, directory in
            _ = try await tool.command(.init(cmd: "setAuth",
                authKey: "tskey-auth-" + UUID().uuidString), expecting: "auth")
            try await withClient(ready: ready, directory: directory,
                authKey: "tskey-auth-" + UUID().uuidString) { client in
                switch try await client.next("authKeyRejected with the wrong auth key") {
                case .failed(.authKeyRejected(let message)):
                    #expect(message == "invalid authkey")
                default: throw GateFailure("Wrong auth key: Received another event instead of authKeyRejected")
                }
                let stored = try #require(try NodeIdentityStore(directory: directory).load())
                #expect(stored.nodePublicKey == nil, "The rejected candidate node key must not be stored")
                let nodes = try await tool.command(.init(cmd: "nodes"), expecting: "nodes")
                #expect(try #require(nodes.nodes).isEmpty, "The rejected node must be absent from the Go registration list")
            }
        }
    }

    @Test("Gate 2: Own addresses, Go peers, DERPMap, DNSConfig, and packet filter")
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
                // Go testcontrol appends an ingress capability rule after the allow-all rule.
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

                // The default testcontrol DNSConfig is nil. Inject an explicit nonempty configuration to verify delivery.
                #expect(map.dnsConfig == nil)
                let dns = MapInjection.DNS(Resolvers: [.init(Addr: "192.0.2.53")],
                    Domains: [try #require(ready.magicDNSSuffix)], Proxied: true)
                try await tool.inject(.init(DNSConfig: dns), into: key.description)
                let updated = try await client.netmap("Injected DNSConfig") { $0.dnsConfig?.proxied == true }
                #expect(updated.dnsConfig?.resolvers.map(\.addr) == ["192.0.2.53"])
                #expect(updated.dnsConfig?.domains == dns.Domains)
                #expect(updated.selfNode == map.selfNode)
                #expect(updated.peers == map.peers)
                #expect(updated.derpMap == map.derpMap)
                #expect(updated.packetFilter == map.packetFilter)
            }
        }
    }

    @Test("Gate 3: Go peer addition, PeersChanged, Patch, OnlineChange, and removal of the last peer")
    func peerDeltas() async throws {
        try await withTailnet { tool, ready, directory in
            try await withClient(ready: ready, directory: directory) { client in
                let key = try await client.registered()
                let initial = try await client.netmap()
                #expect(initial.peers.isEmpty)
                let added = try await tool.command(.init(cmd: "addPeer", name: "go-peer-b"), expecting: "peer")
                let peerKey = try #require(added.nodeKey)
                let withPeer = try await client.netmap("Added Go peer") {
                    $0.peers.contains { $0.key.description == peerKey }
                }
                let peer = try #require(withPeer.peers.first { $0.key.description == peerKey })
                #expect(Set(peer.addresses.map { $0.address.description }) == Set(try #require(added.addresses)))
                let replacement = MapInjection.Peer(ID: peer.id, Key: peerKey, Name: "changed.tail0001.test.",
                    Addresses: ["100.64.0.99/32"], AllowedIPs: ["100.64.0.99/32"], Online: true)
                try await tool.inject(.init(PeersChanged: [replacement]), into: key.description)
                let changed = try await client.netmap("Full peer replacement through PeersChanged") {
                    $0.peers.first?.name == replacement.Name
                }
                #expect(changed.peers.count == 1)
                #expect(changed.peers.first?.id == peer.id)
                #expect(changed.peers.first?.addresses.map(\.description) == replacement.Addresses)
                #expect(changed.peers.first?.online == true)

                try await tool.inject(.init(PeersChangedPatch: [.init(NodeID: peer.id,
                    DERPRegion: 7, Endpoints: ["192.0.2.7:41641"])]), into: key.description)
                let patched = try await client.netmap("DERP and Endpoints in PeersChangedPatch") {
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

                // removePeer cannot remove the server registration, so verify departure using PeersRemoved.
                try await tool.inject(.init(PeersRemoved: [peer.id]), into: key.description)
                let removed = try await client.netmap("Removal of the last peer through PeersRemoved") { $0.peers.isEmpty }
                #expect(removed.selfNode == initial.selfNode)
                #expect(removed.derpMap == initial.derpMap)
                #expect(removed.packetFilter == initial.packetFilter)
            }
        }
    }

    @Test("Gate 4: Restarting with the same identity directory keeps the same node key and addresses")
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
                #expect(nodes.count == 1, "Restarting must not create a separate node")
            }
        }
    }

    @Test("Gate 5: A state update alongside an open stream appears in the self map")
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
                    let map = try await client.netmap("State update reflected in the self DiscoKey and Endpoints") {
                        $0.selfNode.endpoints == [endpoint] && $0.selfNode.discoKey == disco
                    }
                    #expect(map.selfNode.endpoints == [endpoint])
                    #expect(map.selfNode.discoKey == disco)
                }
            }
        }
    }

    @Test("Gate 5 extended: Keeps the stream open for 125 seconds with natural KeepAlive, then receives a new map", .timeLimit(.minutes(4)))
    func keepAliveBeyondTwoMinutes() async throws {
        try await withTailnet { tool, ready, directory in
            try await withClient(ready: ready, directory: directory) { client in
                _ = try await client.registered()
                let initial = try await client.netmap()
                let started = ContinuousClock.now
                let endpoint = try #require(IPEndpoint("192.0.2.11:41641"))
                await client.client.setLocalStatus(.init(endpoints: [endpoint]))
                _ = try await client.netmap("State update before extended observation") { $0.selfNode.endpoints == [endpoint] }
                try await client.remainsConnected(until: started + .seconds(125))
                #expect(started.duration(to: .now) > .seconds(120))
                let added = try await tool.command(.init(cmd: "addPeer", name: "go-peer-long"), expecting: "peer")
                let peerKey = try #require(added.nodeKey)
                let final = try await client.netmap("New map from adding a Go peer after 125 seconds") {
                    $0.peers.contains { $0.key.description == peerKey }
                }
                #expect(final.selfNode.key == initial.selfNode.key)
                #expect(final.selfNode.endpoints == [endpoint])
            }
        }
    }

    @Test("Gate 6: The Swift node appears in both Go nodes and Go tsnet peerStatus")
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
                // LocalClient state updates asynchronously. Query again after waiting for each command's JSON event.
                while ContinuousClock.now < deadline {
                    let status = try await tool.command(.init(cmd: "peerStatus", name: "go-observer"), expecting: "peerStatus")
                    let peers = try #require(status.peers)
                    if let swift = peers.first(where: { $0.nodeKey == key.description }) {
                        #expect(Set(swift.addresses) == expectedAddresses)
                        return
                    }
                    observedCounts.append(peers.count)
                }
                throw GateFailure("Waited over 20 seconds for the Swift node in Go peerStatus. Observed peer counts \(observedCounts.suffix(10))")
            }
        }
    }
}
