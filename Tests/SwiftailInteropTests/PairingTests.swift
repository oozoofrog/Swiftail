// M9 페어링 관문 (가)(docs/contracts/SwiftailPairing.md 7절 9~11). 계정 없이 시험 제어 서버와 루프백만 쓴다.
// 여기서 보지 못하는 것: 시험 제어 서버의 인증 키에는 만료·1회용·태그 정책이 없다. 관문 11은 이름 풀이와 터널을 거치지 않는다.

import Foundation
import Network
import Swiftail
import SwiftailBase
import Testing

@testable import SwiftailPairing

@Suite("M9 관문 (가): 시험 제어 서버 위의 페어링", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 M9 페어링 관문을 건너뜁니다"), .serialized, .timeLimit(.minutes(10)))
struct PairingGateTests {
    private static let base = URL(string: "https://example.com/pair")
    /// 누가 봐도 가짜인 인증 키. 시험 제어 서버는 문자열 하나로만 견준다.
    private static let authKey = "tskey-auth-EXAMPLE-0000"

    /// 제안을 링크로 냈다가 다시 읽는다(앱이 QR이나 링크로 넘기는 길).
    private static func throughLink(_ offer: PairingOffer) throws -> PairingOffer {
        try PairingOffer(link: offer.url(base: try #require(base)).absoluteString)
    }

    @Test("관문 9: 제안 → 들어옴 → 승인 → 짝 목록, 거절·틀린 비밀·만료·다시 짝이 됨·확인 숫자")
    func pairsTwoNodes() async throws {
        try await withPairingGate { gate in
            let hostNode = try gate.startNode("host", hostname: "rd-mac-1a2b3c4d")
            let joinerNode = try gate.startNode("joiner", hostname: "rd-phone-5e6f7a8b")
            try await gate.waitUntilPeers(hostNode, joinerNode)
            let hostStatus = await hostNode.node.status
            let joinerStableID = try #require(await joinerNode.node.status.stableID)
            let approver = Approver()

            try await gate.withHost(hostNode, approver: approver) { host in
                // 승인.
                let offer = try await host.openOffer()
                #expect(offer.host == hostStatus.fqdn && offer.port == 4_747 && offer.authKey == nil)
                #expect(offer.expires > Date().addingTimeInterval(295) && offer.expires <= Date().addingTimeInterval(300))
                let codes = ConfirmationCodes()
                let paired = try await netstackDeadline("짝 맺기") {
                    try await PairingJoiner.pair(
                        with: try Self.throughLink(offer), deviceName: "거실 iPad", node: joinerNode.node
                    ) { codes.record($0) }
                }
                #expect(paired.host == hostStatus.fqdn)
                #expect(paired.stableID == hostStatus.stableID)
                #expect(paired.name == (await hostNode.node.whoIs(try #require(hostStatus.addresses.first)))?.computedName)

                let request = try #require(approver.requests.last)
                #expect(approver.requests.count == 1)
                #expect(request.peer.stableID == joinerStableID && request.deviceName == "거실 iPad")
                #expect(codes.all == [request.confirmationCode], "양쪽의 확인 숫자가 같다")
                #expect(request.confirmationCode.count == 6)

                let first = try #require(await host.pairedPeers.first)
                #expect(await host.pairedPeers.count == 1)
                #expect(first.peer == request.peer && first.deviceName == "거실 iPad")
                await gate.tool.checkpoint("M9 9 승인: 짝 목록 1, 양쪽 확인 숫자 일치")

                // 짝이 된 뒤의 연결: 연결의 신원으로 짝 목록에 묻는다.
                let listener = try await hostNode.node.listen(port: 9_300)
                let accepted = Task { try await netstackAccept(listener) }
                let client = try await netstackDeadline("앱 연결") {
                    try await joinerNode.node.connect(to: paired.host, port: 9_300)
                }
                let inbound = try await accepted.value
                let caller = try #require(await hostNode.node.whoIs(inbound.remoteEndpoint.address))
                #expect(await host.pairedPeer(withStableID: caller.stableID) == first)
                #expect(await host.pairedPeer(withStableID: try #require(hostStatus.stableID)) == nil, "자기 자신은 짝이 아니다")
                // 들어온 쪽도 상대가 그 짝인지 본다.
                #expect(await joinerNode.node.whoIs(client.remoteEndpoint.address)?.stableID == paired.stableID)
                await client.abort()
                await inbound.abort()
                await listener.close()
                await gate.tool.checkpoint("M9 9 뒤의 연결: whoIs의 StableID로 pairedPeer가 답함")

                // 제안은 한 번만 쓰인다.
                let reused = await pairingFailure {
                    try await PairingJoiner.pair(with: offer, deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(reused == .rejected)

                // 거절.
                approver.set(.deny)
                let refusedOffer = try await host.openOffer()
                let denied = await pairingFailure {
                    try await PairingJoiner.pair(with: try Self.throughLink(refusedOffer), deviceName: "다른 이름", node: joinerNode.node)
                }
                #expect(denied == .denied)
                #expect(await host.pairedPeers == [first], "거절은 목록을 바꾸지 않는다")
                await gate.tool.checkpoint("M9 9 거절: denied, 목록 그대로")

                // 틀린 비밀: 받아 주지 않고, 제안은 남는다.
                approver.set(.approve)
                let kept = try await host.openOffer()
                var wrongSecret = kept.secret
                wrongSecret[0] ^= 1
                let forged = PairingOffer(
                    host: kept.host, port: kept.port, expires: kept.expires, authKey: nil, secret: wrongSecret)
                let wrong = await pairingFailure {
                    try await PairingJoiner.pair(with: forged, deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(wrong == .rejected)
                #expect(approver.requests.count == 2, "틀린 비밀은 앱에 묻지 않는다")

                // 같은 제안으로 다시 짝이 된다: 항목을 바꾼다.
                let again = try await netstackDeadline("다시 짝 맺기") {
                    try await PairingJoiner.pair(with: try Self.throughLink(kept), deviceName: "새 이름", node: joinerNode.node)
                }
                #expect(again.stableID == paired.stableID && again.pairedAt > paired.pairedAt)
                let replaced = try #require(await host.pairedPeers.first)
                #expect(await host.pairedPeers.count == 1)
                #expect(replaced.peer.stableID == joinerStableID && replaced.deviceName == "새 이름")
                #expect(replaced.pairedAt > first.pairedAt)
                await gate.tool.checkpoint("M9 9 틀린 비밀: rejected·제안 유지, 다시 짝이 됨: 항목 교체")

                // 만료.
                let brief = try await host.openOffer(lifetime: .seconds(1))
                try await Task.sleep(for: .milliseconds(2_100))
                let expired = await pairingFailure {
                    try await PairingJoiner.pair(with: try Self.throughLink(brief), deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(expired == .rejected)

                // 닫은 제안.
                let closed = try await host.openOffer()
                await host.closeOffer()
                let afterClose = await pairingFailure {
                    try await PairingJoiner.pair(with: closed, deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(afterClose == .rejected)
                #expect(approver.requests.count == 3)
                await gate.tool.checkpoint("M9 9 만료·닫힘: rejected")

                // 승인을 기다리는 동안 들어오는 쪽이 그만두면 여는 쪽의 결정 Task가 취소된다(P6, J7).
                approver.set(.wait)
                let pending = try await host.openOffer()
                let waitingCodes = ConfirmationCodes()
                let pairing = Task {
                    await pairingFailure {
                        try await PairingJoiner.pair(with: pending, deviceName: "거실 iPad", node: joinerNode.node) {
                            waitingCodes.record($0)
                        }
                    }
                }
                try await netstackDeadline("확인 숫자 대기") { await waitingCodes.next() }
                pairing.cancel()
                #expect(await pairing.value == .cancelled)
                try await netstackWait("결정 Task의 취소", seconds: 10) { approver.cancelledCount == 1 }
                #expect(await host.pairedPeers == [replaced])
                await gate.tool.checkpoint("M9 9 대기 중 취소: 들어오는 쪽 cancelled, 여는 쪽 결정 Task 취소")
            }

            // 짝 목록은 파일에 남는다.
            let stored = try PairedPeerFile(directory: gate.root.appending(path: "store")).load()
            #expect(stored.peers.map(\.peer.stableID) == [joinerStableID])
        }
    }

    @Test("관문 10: 제안의 인증 키로 새 노드가 등록한 뒤 짝이 된다(다시 걸기 포함)")
    func joinsWithOfferAuthKey() async throws {
        try await withPairingGate(authKey: Self.authKey) { gate in
            let hostNode = try gate.startNode("host", hostname: "rd-mac-1a2b3c4d", authKey: Self.authKey)
            try await netstackWait("여는 노드 running") { await hostNode.node.status.fqdn != nil }
            let approver = Approver()

            try await gate.withHost(hostNode, approver: approver) { host in
                let offer = try Self.throughLink(try await host.openOffer(authKey: Self.authKey))
                #expect(offer.authKey == Self.authKey)

                // 링크를 받은 기기: 제안의 키로 노드를 띄우고, 등록이 끝나기를 기다리지 않고 곧바로 짝을 맺는다.
                let joinerNode = try gate.startNode("joiner", hostname: "rd-phone-5e6f7a8b", authKey: offer.authKey)
                #expect(await joinerNode.node.status.state != .running)
                let started = ContinuousClock.now
                let paired = try await netstackDeadline("인증 키로 들어와 짝 맺기", seconds: 90) {
                    try await PairingJoiner.pair(with: offer, deviceName: "거실 iPad", node: joinerNode.node)
                }
                let elapsed = started.duration(to: .now)
                #expect(elapsed >= .seconds(1), "노드가 돌기 전의 첫 시도는 닿지 못하고, 1초 뒤에 다시 걸었다")
                #expect(paired.stableID == (await hostNode.node.status.stableID))

                let joinerStableID = try #require(await joinerNode.node.status.stableID)
                #expect(await host.pairedPeers.map(\.peer.stableID) == [joinerStableID])
                #expect(approver.requests.map(\.peer.stableID) == [joinerStableID])
                await gate.tool.checkpoint("M9 10 인증 키 가입 뒤 짝이 됨: 경과 \(elapsed)")
            }

            // 대조: 키 없이 띄운 노드는 이 서버에 등록하지 못한다(위의 등록이 키 덕분임을 보인다).
            let stranger = try gate.startNode("stranger", hostname: "rd-pad-9c0d1e2f")
            try await Task.sleep(for: .seconds(3))
            #expect(await stranger.node.status.state != .running)
            #expect(await stranger.node.status.addresses.isEmpty)
        }
    }
}

@Suite("M9 관문 (가): OS 소켓으로 들어오기(루프백)", .serialized, .timeLimit(.minutes(2)))
struct PairingSocketGateTests {
    @Test("관문 11: 루프백 리스너에 물린 여는 쪽 상태 기계와 NWConnection으로 왕복한다")
    func pairsOverLoopbackSocket() async throws {
        let host = try await LoopbackPairingHost.start()
        defer { host.close() }
        // 이 시험에서 "이 기기의 tailnet 주소" 노릇을 하는 루프백 주소. 대역 검사와 인터페이스 금지만 끈다.
        let loopback = try #require(IPAddress("127.0.0.1"))

        // 승인.
        let offer = await host.openOffer()
        let codes = ConfirmationCodes()
        async let serving = host.serveNext(approving: true)
        let paired = try await netstackDeadline("루프백 짝 맺기", seconds: 20) {
            try await PairingJoiner.pair(
                with: offer, deviceName: "거실 iPad", localAddress: loopback, requiringTunnel: false
            ) { codes.record($0) }
        }
        let served = try await serving
        #expect(paired.host == "127.0.0.1")
        #expect(paired.stableID == LoopbackPairingHost.hostIdentity.stableID)
        #expect(paired.name == LoopbackPairingHost.hostIdentity.computedName)
        #expect(served.ending == .paired && served.saved?.deviceName == "거실 iPad")
        #expect(codes.all == [try #require(served.confirmationCode)], "양쪽이 본 연결의 두 끝이 같아 확인 숫자가 같다")

        // 쓰인 제안은 받아 주지 않는다.
        async let second = host.serveNext(approving: true)
        let reused = await pairingFailure {
            try await PairingJoiner.pair(
                with: offer, deviceName: "거실 iPad", localAddress: loopback, requiringTunnel: false) { _ in }
        }
        #expect(reused == .rejected)
        #expect(try await second.ending == .noOffer)

        // 거절.
        let refusedOffer = await host.openOffer()
        async let third = host.serveNext(approving: false)
        let denied = await pairingFailure {
            try await PairingJoiner.pair(
                with: refusedOffer, deviceName: "거실 iPad", localAddress: loopback, requiringTunnel: false) { _ in }
        }
        #expect(denied == .denied)
        #expect(try await third.ending == .denied)

        // 로컬 끝이 앱이 넘긴 주소와 다르면 hello를 보내지 않고 끝난다(J2). 다시 걸지도 않는다.
        let guarded = await host.openOffer()
        async let fourth = host.serveNext(approving: true)
        let elsewhere = try #require(IPAddress("127.0.0.2"))
        let outside = await pairingFailure {
            try await PairingJoiner.pair(
                with: guarded, deviceName: "거실 iPad", localAddress: elsewhere, requiringTunnel: false) { _ in }
        }
        #expect(outside == .notOnTailnet)
        let untouched = try await fourth
        #expect(untouched.receivedByteCount == 0 && untouched.ending == .disconnected)
        #expect(await host.hasOpenOffer)

        // 공개 API가 거는 인터페이스 금지: 루프백으로는 연결이 서지 않는다(터널이 아닌 길로 나가지 못한다).
        let port = try #require(NWEndpoint.Port(rawValue: host.port))
        let barred = SocketPairingTransport(host: "127.0.0.1", port: port, isIPv4: true, tunnelOnly: true)
        let opened = try await netstackDeadline("금지된 인터페이스로 걸기", seconds: 10) { await barred.open() }
        #expect(!opened)
        await barred.close()
        let allowed = SocketPairingTransport(host: "127.0.0.1", port: port, isIPv4: true, tunnelOnly: false)
        #expect(await allowed.open(), "금지를 끄면 같은 곳에 닿는다")
        await allowed.close()
    }
}
