import Foundation
import SwiftailBase
import SwiftailControl
import Testing
@testable import Swiftail

/// `whoIs`: 주소 → 노드 신원(계약 `docs/contracts/SwiftailHost.md` 동작 W1~W6, 단위 시험 1).
@Suite("whoIs: 주소로 노드 신원 찾기", .timeLimit(.minutes(1)))
struct WhoIsTests {
    private typealias Support = WhoIsTestSupport

    private static func address(_ text: String) throws -> IPAddress {
        try #require(IPAddress(text))
    }

    private static func node() throws -> TailnetNode {
        try TailnetNode(configuration: try NodeTestSupport.unusedConfiguration())
    }

    /// `netmap`을 적용한 노드에게 `text` 주소의 신원을 묻는다.
    private static func whoIs(_ text: String, in netmap: Netmap) async throws -> PeerIdentity? {
        let node = try node()
        await node.apply(netmap)
        return await node.whoIs(try address(text))
    }

    // MARK: 찾기

    @Test("자기 주소(IPv4·IPv6)는 자기 노드의 신원이다")
    func selfAddress() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        for text in ["100.64.0.1", "fd7a:115c:a1e0::1"] {
            let identity = try #require(try await Self.whoIs(text, in: netmap))
            #expect(identity == PeerIdentity(
                stableID: "nStableSelf", name: "rd-mac-1a2b3c4d.tail0001.ts.net", computedName: "rd-mac-1a2b3c4d",
                loginName: "alice@example.com"))
        }
    }

    @Test("피어의 IPv4·IPv6 주소는 그 피어의 신원이다")
    func peerAddresses() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        for text in ["100.64.0.2", "fd7a:115c:a1e0::2"] {
            let identity = try #require(try await Self.whoIs(text, in: netmap))
            #expect(identity == PeerIdentity(
                stableID: "nStablePhone", name: "rd-phone-1a2b3c4d.tail0001.ts.net", computedName: "rd-phone-1a2b3c4d",
                loginName: "alice@example.com"))
        }
    }

    @Test("IPv4-mapped IPv6 주소는 IPv4로 바꿔 찾는다")
    func mappedAddress() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        #expect(try await Self.whoIs("::ffff:100.64.0.2", in: netmap)?.stableID == "nStablePhone")
        #expect(try await Self.whoIs("::ffff:100.64.0.1", in: netmap)?.stableID == "nStableSelf")
        // IPv4-mapped가 아닌 ::ffff:0:a.b.c.d나 다른 접두는 바꾸지 않는다.
        #expect(try await Self.whoIs("::100.64.0.2", in: netmap) == nil)
    }

    @Test("모르는 주소는 nil이다")
    func unknownAddress() async throws {
        let netmap = try Support.netmap(peers: [Support.phone])
        for text in ["100.64.0.3", "fd7a:115c:a1e0::3", "8.8.8.8", "0.0.0.0"] {
            #expect(try await Self.whoIs(text, in: netmap) == nil)
        }
    }

    @Test("netmap을 받기 전에는 nil이다")
    func beforeNetmap() async throws {
        let node = try Self.node()
        #expect(await node.whoIs(try Self.address("100.64.0.1")) == nil)
    }

    @Test("서브넷 경로(AllowedIPs)의 주소와 한 주소짜리가 아닌 접두는 찾지 않는다")
    func subnetRoutes() async throws {
        var router = Support.phone
        router.allowedIPs = ["100.64.0.2/32", "fd7a:115c:a1e0::2/128", "192.168.1.0/24", "10.0.0.0/8"]
        router.addresses.append("100.64.9.0/24")
        let netmap = try Support.netmap(peers: [router])
        #expect(try await Self.whoIs("100.64.0.2", in: netmap)?.stableID == "nStablePhone")
        for text in ["192.168.1.5", "192.168.1.0", "10.1.2.3", "100.64.9.0", "100.64.9.7"] {
            #expect(try await Self.whoIs(text, in: netmap) == nil)
        }
    }

    @Test("키가 만료되었거나 오프라인인 피어도 netmap에 있으면 찾는다")
    func expiredAndOfflinePeers() async throws {
        var peer = Support.phone
        peer.expired = true
        peer.online = false
        #expect(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [peer]))?.stableID == "nStablePhone")
    }

    @Test("같은 주소를 가진 노드가 여럿이면 나중 것이 이긴다(자기 노드 다음에 피어를 node ID 순으로)")
    func duplicateAddressLastWins() async throws {
        var first = Support.phone
        first.id = 2
        first.stableID = "nStableFirst"
        var second = Support.phone
        second.id = 3
        second.stableID = "nStableSecond"
        second.key = 0x33
        let netmap = try Support.netmap(peers: [first, second])
        #expect(try await Self.whoIs("100.64.0.2", in: netmap)?.stableID == "nStableSecond")

        var impostor = Support.phone
        impostor.id = 3
        impostor.stableID = "nStableImpostor"
        impostor.key = 0x33
        impostor.addresses = ["100.64.0.1/32"]
        let overSelf = try Support.netmap(peers: [impostor])
        #expect(try await Self.whoIs("100.64.0.1", in: overSelf)?.stableID == "nStableImpostor")
    }

    // MARK: 거절

    @Test("사용자 프로필이 netmap에 없는 노드는 nil이다(다른 노드로 넘어가지 않는다)")
    func missingProfile() async throws {
        var stranger = Support.phone
        stranger.user = 999
        let netmap = try Support.netmap(peers: [stranger])
        #expect(try await Self.whoIs("100.64.0.2", in: netmap) == nil)
        #expect(try await Self.whoIs("100.64.0.1", in: netmap)?.stableID == "nStableSelf")
        // 프로필이 하나도 없으면 자기 노드도 nil이다.
        #expect(try await Self.whoIs("100.64.0.1", in: try Support.netmap(profiles: [])) == nil)
    }

    @Test("StableID가 빈 노드는 nil이다")
    func emptyStableID() async throws {
        var anonymous = Support.phone
        anonymous.stableID = ""
        #expect(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [anonymous])) == nil)
    }

    // MARK: 이름과 사용자

    @Test("이름이 빈 노드는 name이 빈 문자열이고 computedName은 호스트 이름이다")
    func emptyName() async throws {
        var unnamed = Support.phone
        unnamed.name = ""
        unnamed.hostname = "Alice's iPhone.local"
        let identity = try #require(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [unnamed])))
        #expect(identity.name == "")
        #expect(identity.computedName == "alices-iphone")
    }

    @Test("이름도 호스트 이름도 빈 노드의 computedName은 node 공개 키의 텍스트다")
    func emptyNameAndHostname() async throws {
        var unnamed = Support.phone
        unnamed.name = ""
        let identity = try #require(try await Self.whoIs("100.64.0.2", in: try Support.netmap(peers: [unnamed])))
        #expect(identity.computedName == NodeTestSupport.nodeKey(0x22))
    }

    @Test("다른 tailnet에서 공유받은 노드는 끝 점 없는 FQDN을 computedName으로 갖고 소유자의 로그인 이름을 쓴다")
    func sharedFromOtherTailnet() async throws {
        var shared = Support.phone
        shared.name = "rd-shared-9f9f9f9f.tail0002.ts.net."
        shared.user = 202
        let netmap = try Support.netmap(peers: [shared], profiles: [Support.alice, (202, "bob@example.com")])
        let identity = try #require(try await Self.whoIs("100.64.0.2", in: netmap))
        #expect(identity.name == "rd-shared-9f9f9f9f.tail0002.ts.net")
        #expect(identity.computedName == "rd-shared-9f9f9f9f.tail0002.ts.net")
        #expect(identity.loginName == "bob@example.com")
    }

    @Test("태그 노드는 노드를 만든 사용자의 프로필을 그대로 쓴다")
    func taggedNode() async throws {
        var tagged = Support.phone
        tagged.tags = ["tag:phone"]
        tagged.user = 303
        let netmap = try Support.netmap(peers: [tagged], profiles: [Support.alice, (303, "tagged-devices")])
        #expect(try await Self.whoIs("100.64.0.2", in: netmap)?.loginName == "tagged-devices")
    }

    @Test("자기 이름에 점이 없으면 접미사는 그 이름 그대로여서 점 없는 피어 이름은 그대로 남는다")
    func suffixlessSelfName() async throws {
        var bare = Support.selfNode
        bare.name = "mac"
        var peer = Support.phone
        peer.name = "mac"
        let netmap = try Support.netmap(selfNode: bare, peers: [peer])
        // 이름이 접미사와 같으면 레이블 경계가 없어 떼지 않는다.
        #expect(try await Self.whoIs("100.64.0.2", in: netmap)?.computedName == "mac")
    }

    // MARK: netmap이 바뀔 때(동작 W6)

    @Test("netmap이 바뀌면 주소의 주인이 바뀐 대로 답한다")
    func ownerChanges() async throws {
        let node = try Self.node()
        let phoneAddress = try Self.address("100.64.0.2")
        await node.apply(try Support.netmap(peers: [Support.phone]))
        #expect(await node.whoIs(phoneAddress)?.stableID == "nStablePhone")

        // 같은 주소를 다른 노드가 이어받았다.
        var heir = Support.phone
        heir.id = 9
        heir.stableID = "nStableHeir"
        heir.key = 0x99
        heir.name = "rd-heir.tail0001.ts.net."
        await node.apply(try Support.netmap(peers: [heir]))
        let identity = try #require(await node.whoIs(phoneAddress))
        #expect(identity.stableID == "nStableHeir")
        #expect(identity.computedName == "rd-heir")

        // 주인이 같은 채 이름만 바뀌면 새 이름을 본다.
        heir.name = "rd-renamed.tail0001.ts.net."
        await node.apply(try Support.netmap(peers: [heir]))
        #expect(await node.whoIs(phoneAddress)?.computedName == "rd-renamed")
    }

    @Test("피어가 netmap에서 사라지면 그 주소는 nil이 된다")
    func peerDisappears() async throws {
        let node = try Self.node()
        await node.apply(try Support.netmap(peers: [Support.phone]))
        #expect(await node.whoIs(try Self.address("fd7a:115c:a1e0::2")) != nil)
        await node.apply(try Support.netmap())
        #expect(await node.whoIs(try Self.address("fd7a:115c:a1e0::2")) == nil)
        #expect(await node.whoIs(try Self.address("100.64.0.1"))?.stableID == "nStableSelf")
    }

    @Test("주소의 주인이 바뀌어 연결이 peerRemoved로 끝나는 시점에 whoIs는 이미 새 주인을 가리킨다")
    func tableChangesWithConnectionTeardown() async throws {
        try await NetstackTestSupport.withRunningNode(try Support.netmap(peers: [Support.phone])) { node in
            let phoneAddress = try Self.address("100.64.0.2")
            let connector = Task { () async throws -> TailnetConnection in
                try await node.connect(to: "100.64.0.2", port: 80)
            }
            try await NetstackTestSupport.waitUntil("connect가 기다림") { await node.isConnecting }
            #expect(await node.whoIs(phoneAddress)?.stableID == "nStablePhone")

            var heir = Support.phone
            heir.id = 9
            heir.stableID = "nStableHeir"
            heir.key = 0x99
            await node.apply(try Support.netmap(peers: [heir]))
            #expect(await NetstackTestSupport.error { try await connector.value } == .peerRemoved)
            #expect(await node.whoIs(phoneAddress)?.stableID == "nStableHeir")
        }
    }
}
