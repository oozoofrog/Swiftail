// M8 Tailnet Lock 관문 (가)(docs/contracts/SwiftailTailnetLock.md 7절 "관문 (가): 계정 없이"의 항목 1~11).
// 계정 없이 testcontrol 사본과 Go tsnet 피어를 상대로, lock이 켜진 tailnet에서 Swift 노드(`TailnetNode`)가 Go 노드와 같은
// 판정을 내는지 끝에서 끝으로 본다. Go 피어끼리의 같은 흐름은 `Tools/interop/cmd/tailnet/lock_test.go`가 본다.
//
// 이 서버로 확인할 수 없어 시험하지 않는 것(보고에도 적는다):
// - 항목 7: "다시 이은 스트림"은 노드를 같은 상태 디렉터리로 다시 띄워 만든다. 도구에 맵 스트림만 끊는 명령이 없고, 주입으로
//   자동 맵이 멈춘 노드는 다시 이어도 자동 맵을 받지 않는다(README `injectMapResponse`). Go 피어는 이 도구로 다시 띄울 수
//   없어, 다시 이은 뒤의 판정은 Go와 견주지 않는다.
// - 항목 9: 이 서버는 재서명한 키 교체가 받아들여지면 옛 키 항목을 지운다. "옛 키가 Go 피어에서 낡은 키로 빠진다"는
//   "새 키가 보이고 옛 키가 보이지 않는다"로만 본다. 낡은 키 판정 자체는 `tkafixtures`의 `peerSets`가 본다.
// - 항목 10: 깨진 bootstrap을 되돌릴 때 서버가 새 맵을 보내므로, 풀린 것이 재시도 타이머(첫 5초) 때문인지 새 netmap 때문인지
//   밖에서 가르지 못한다. 걸린 시간만 남긴다.
// - Go 노드는 깨진 bootstrap에서 lock을 켜지 않고 거르지 않는다(Swiftail은 `.unverified`로 닫는다. 결정 U1·L4의 의도된 차이).
//
// 항목 7은 서버가 맞는 끄기 비밀로 바꾸고 내용이 같은 맵을 다시 보낼 때, Swift와 Go 모두 bootstrap을 다시 불러 lock을
// 끄는지 확인한다. Swift는 할 일이 남아 있으면 KeepAlive가 아닌 맵 응답에서 내용이 같아도 절차를 다시 시도한다(5cde854).

import Foundation
import SwiftailBase
import SwiftailControl
import Testing

@testable import Swiftail

@Suite("M8 관문 (가): Tailnet Lock", .enabled(if: tailnetBinary != nil,
    "SWIFTAIL_TAILNET가 없어 M8 Tailnet Lock 관문을 건너뜁니다"), .serialized, .timeLimit(.minutes(10)))
struct TailnetLockTests {
    @Test("항목 1·2·3·5·6: 부트스트랩, 서명 전 잠김, 서명 뒤 통신, 서명 없는 Go 피어, 사슬이 자란 뒤")
    func signingFlow() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let a = try #require(peers["go-peer-a"]), b = try #require(peers["go-peer-b"])
            let swift = try gate.startNode("swift-s")

            // 항목 1: 부트스트랩. 머리가 서명 기기의 머리(= 서버의 머리)와 같고, 등록 요청의 NLKey가 0이 아니다.
            let locked = try await gate.wait(swift, "항목 1·2: enforcing으로 잠김") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest != nil
            }
            let signer = try await gate.lockStatus("go-peer-a")
            #expect(locked.tailnetLock.head != nil && locked.tailnetLock.head == signer.head, "항목 1: 머리가 Go 서명 기기와 같다")
            #expect(signer.head == signer.controlHead, "항목 1: 서명 기기가 서버 머리에 있다")
            #expect(locked.tailnetLock.issue == nil)
            let selfKey = try #require(await swift.selfKey)
            gate.name(selfKey, "swift-s")
            let registration = try #require(try await gate.registrations().last { $0.nodeKey == selfKey })
            #expect(!registration.nlKey.isEmpty, "항목 1: 등록 요청의 NLKey가 0이 아니다")
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) >= 1, "항목 1: bootstrap RPC를 보냈다")

            // 항목 2: 서명 전의 잠김.
            let request = try #require(locked.tailnetLock.signingRequest)
            #expect(request.nodeKey == selfKey, "항목 2: signingRequest.nodeKey가 등록한 node 키다")
            #expect(request.lockKey == registration.nlKey, "항목 2: signingRequest.lockKey가 등록한 NL 키다")
            try expectLockBeforeRunning(swift, "항목 2")
            for name in ["go-peer-a", "go-peer-b"] {
                let go = try await gate.lockStatus(name)
                #expect(go.filteredPeers?.contains(selfKey) == true, "항목 2: \(name)가 Swift 노드를 거른다")
                #expect(go.visiblePeers?.contains(selfKey) == false)
            }
            #expect(await swift.peerKeys == [a.key, b.key], "항목 2: Swift netmap에 서명된 Go 피어 둘이 남는다")
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 2")
            try await gate.expectSilent("항목 2: 잠긴 Swift → go-peer-a UDP 에코") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.silence)
            }
            try await gate.expectSilent("항목 2: go-peer-a → 잠긴 Swift UDP") {
                try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.silence)
            }

            // 항목 3: 두 값을 문자열 그대로 lockSign에 넣으면 다시 시작 없이 풀린다(F2 요구 3·4).
            let signedAt = swift.recorder.events.count
            _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: request.nodeKey, lockKey: request.lockKey),
                                       expecting: "lockSign")
            try await gate.wait(swift, "항목 3: signingRequest가 nil") {
                $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest == nil
            }
            let unlocked = swift.recorder.events.dropFirst(signedAt).contains {
                if case let .tailnetLockChanged(lock) = $0.event { lock.signingRequest == nil } else { false }
            }
            #expect(unlocked, "항목 3: 같은 run 안에서 signingRequest가 nil인 tailnetLockChanged가 나왔다")
            try await netstackWait("항목 3: Go 피어 둘의 netmap에 Swift 노드", seconds: 30) {
                for name in ["go-peer-a", "go-peer-b"] {
                    guard try await gate.lockStatus(name).visiblePeers?.contains(selfKey) == true else { return false }
                }
                return true
            }
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 3")
            try await gate.expectReachable("항목 3: Swift → go-peer-a UDP 에코") { try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable) }
            try await gate.expectReachable("항목 3: Swift → go-peer-b UDP 에코") { try await gate.udpEcho(from: swift, to: b, within: LockGate.reachable) }
            try await gate.expectReachable("항목 3: Swift SYN → go-peer-a SYN-ACK") { try await gate.tcpHandshake(from: swift, to: a, within: LockGate.reachable) }
            try await gate.expectReachable("항목 3: go-peer-a → Swift UDP") { try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.reachable) }
            try await gate.expectReachable("항목 3: go-peer-a → Swift TCP SYN") { try await gate.goSend("go-peer-a", to: swift, proto: "tcp", within: LockGate.reachable) }

            // 항목 5: 서명 없는 Go 피어.
            let filteredBefore = await swift.status.tailnetLock.filteredPeerCount
            let c = try await gate.addPeer("go-peer-c")
            try await gate.wait(swift, "항목 5: go-peer-c를 거른다") { $0.tailnetLock.filteredPeerCount == filteredBefore + 1 }
            #expect(await !swift.peerKeys.contains(c.key), "항목 5: Swift peers에 서명 없는 피어가 없다")
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 5")
            try await gate.expectReachable("항목 5: (대조) go-peer-a → Swift UDP") { try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.reachable) }
            try await gate.expectSilent("항목 5: go-peer-c → Swift UDP") { try await gate.goSend("go-peer-c", to: swift, proto: "udp", within: LockGate.silence) }
            try await gate.expectSilent("항목 5: go-peer-c → Swift TCP SYN") { try await gate.goSend("go-peer-c", to: swift, proto: "tcp", within: LockGate.silence) }
            try await gate.expectSilent("항목 5: Swift → go-peer-c UDP 에코") { try await gate.udpEcho(from: swift, to: c, within: LockGate.silence) }

            // 항목 6: 사슬이 자란다. b의 키를 더하고, b가 e에 서명하고, b의 키를 빼면 e가 함께 빠진다.
            let bLock = try #require(try await gate.lockStatus("go-peer-b").lockKey)
            let added = try await gate.command(.init(cmd: "lockModify", name: "go-peer-a", addKeys: [bLock]), expecting: "lockModify")
            try await gate.wait(swift, "항목 6: 키를 더한 머리를 따라온다") { $0.tailnetLock.head == added.head }
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 6: 키를 더한 뒤")
            try await netstackWait("항목 6: go-peer-b가 자기 키를 신뢰하는 머리에 닿는다", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-b")
                return status.head == status.controlHead && status.trustedKeys?.contains(bLock) == true
            }
            let e = try await gate.addPeer("go-peer-e")
            try await gate.wait(swift, "항목 6: 서명 전의 go-peer-e를 거른다") { $0.tailnetLock.filteredPeerCount == filteredBefore + 2 }
            _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-b", nodeKey: e.key), expecting: "lockSign")
            try await netstackWait("항목 6: b의 서명으로 go-peer-e가 보인다", seconds: 30) { await swift.peerKeys.contains(e.key) }
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 6: b가 서명한 뒤")
            try await gate.expectReachable("항목 6: Swift → go-peer-e UDP 에코") { try await gate.udpEcho(from: swift, to: e, within: LockGate.reachable) }
            let removed = try await gate.command(.init(cmd: "lockModify", name: "go-peer-a", removeKeys: [bLock]), expecting: "lockModify")
            try await gate.wait(swift, "항목 6: 키를 뺀 머리를 따라온다") { $0.tailnetLock.head == removed.head }
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 6: 키를 뺀 뒤")
            #expect(await !swift.peerKeys.contains(e.key), "항목 6: 뺀 키로만 서명된 피어가 Swift에서 빠진다")
            #expect(try await gate.lockStatus("go-peer-a").filteredPeers?.contains(e.key) == true, "항목 6: Go에서도 빠진다")
            try await gate.expectSilent("항목 6: 키를 뺀 뒤 Swift → go-peer-e UDP 에코") {
                try await gate.udpEcho(from: swift, to: e, within: LockGate.silence)
            }
        }
    }

    @Test("항목 4: 서명된 인증 키로 등록하면 처음부터 잠기지 않는다")
    func wrappedAuthKey() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate)
            let a = try #require(peers["go-peer-a"])
            // 시험 전용 인증 키(testcontrol은 인증 키를 요구하지 않는다). 감싼 결과는 개인 키를 담으므로 어디에도 찍지 않는다.
            let wrapped = try #require(try await gate.command(
                .init(cmd: "lockWrapAuthKey", name: "go-peer-a", authKey: "tskey-auth-tl10gate0001"), expecting: "lockWrapAuthKey").authKey)
            let swift = try gate.startNode("swift-w", authKey: wrapped)
            let joined = try await gate.wait(swift, "항목 4: enforcing·서버 머리") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head != nil
            }
            let signer = try await gate.lockStatus("go-peer-a")
            #expect(joined.tailnetLock.head == signer.controlHead, "항목 4: 사슬이 자란 서버 머리까지 따라왔다")
            #expect(joined.tailnetLock.signingRequest == nil)
            #expect(swift.recorder.lockChanges.allSatisfy { $0.signingRequest == nil }, "항목 4: 한 번도 잠기지 않았다")
            try expectLockBeforeRunning(swift, "항목 4")
            let selfKey = try #require(await swift.selfKey)
            gate.name(selfKey, "swift-w")
            let mine = try await gate.registrations().filter { $0.nodeKey == selfKey }
            #expect(!mine.isEmpty)
            #expect(mine.first?.signature == "accepted", "항목 4: 요청의 서명을 Go가 통과시켰다")
            #expect(mine.allSatisfy { !$0.wrappedKeyTrace }, "항목 4: 요청 본문에 감싼 개인 키의 흔적이 없다")
            #expect(mine.allSatisfy { !$0.nlKey.isEmpty })
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 4")
            #expect(signer.filteredPeers?.contains(selfKey) != true)
            try await gate.expectReachable("항목 4: Swift → go-peer-a UDP 에코") { try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable) }
            try await gate.expectReachable("항목 4: go-peer-a → Swift UDP") { try await gate.goSend("go-peer-a", to: swift, proto: "udp", within: LockGate.reachable) }
        }
    }

    @Test("항목 7: lockDisable — 틀린 비밀이면 enforcing에 머물고, 맞는 비밀이면 꺼지고 파일이 없다")
    func disableWithSecret() async throws {
        try await withLockGate { gate in
            _ = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let swift = try await joinAndSign(gate, "swift-s")
            let selfKey = try #require(await swift.selfKey)
            let c = try await gate.addPeer("go-peer-c")
            try await netstackWait("항목 7: go-peer-c를 거른다", seconds: 30) {
                try await gate.lockStatus("go-peer-b").filteredPeers?.contains(c.key) == true
            }
            try await gate.expectAgreement(swift, with: "go-peer-b", "항목 7: 끄기 전")
            #expect(FileManager.default.fileExists(atPath: swift.lockFile.path), "항목 7: 끄기 전에 tailnet-lock.cbor가 있다")

            // 틀린 비밀: 서버는 껐지만 노드는 lock을 유지한다.
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let wrong = try await gate.command(.init(cmd: "lockDisable", name: "go-peer-a", wrongSecret: true), expecting: "lockDisable")
            #expect(wrong.alreadyDisabled == false)
            try await netstackWait("항목 7: Swift 노드가 끈 뒤의 bootstrap으로 비밀을 받으러 간다", seconds: 30) {
                try await gate.tkaRequestCount("bootstrap", from: selfKey) > bootstraps
            }
            try await netstackWait("항목 7: go-peer-b도 틀린 비밀을 받는다", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-b")
                return status.controlDisabled == true && status.enabled == true
            }
            // 받은 비밀의 검증(Argon2i, 디버그에서 약 2초)이 끝날 시간을 두고, 그동안과 그 뒤에 바뀌지 않는지 본다.
            try await gate.holds(swift, "항목 7: 틀린 비밀 뒤 enforcing에 머문다", seconds: 6) {
                $0.tailnetLock.mode == .enforcing && $0.tailnetLock.filteredPeerCount == 1
            }
            #expect(FileManager.default.fileExists(atPath: swift.lockFile.path), "항목 7: 틀린 비밀 뒤 파일이 남는다")
            #expect(await !swift.peerKeys.contains(c.key))
            #expect(try await gate.lockStatus("go-peer-b").filteredPeers?.contains(c.key) == true, "항목 7: Go도 c를 계속 거른다")
            try await gate.expectAgreement(swift, with: "go-peer-b", "항목 7: 틀린 비밀 뒤")
            try await gate.expectSilent("항목 7: 틀린 비밀 뒤 go-peer-c → Swift UDP") {
                try await gate.goSend("go-peer-c", to: swift, proto: "udp", within: LockGate.silence)
            }

            // 맞는 비밀: 꺼지고, 서명 없는 피어가 다시 보이고, 파일이 없다. 서버는 이미 꺼져 있으므로 도구는 bootstrap이 줄
            // 비밀만 바꾸고 새 맵을 보낸다(README `lockDisable`의 `alreadyDisabled`). 그 맵은 앞의 맵과 내용이 같다.
            let goKey = try #require(try await gate.lockStatus("go-peer-b").nodeKey)
            let goFrom = try await gate.tkaRequestCount("bootstrap", from: goKey)
            let swiftFrom = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let right = try await gate.command(.init(cmd: "lockDisable", name: "go-peer-a"), expecting: "lockDisable")
            #expect(right.alreadyDisabled == true)
            // Go의 판정을 먼저 본다: 같은 내용의 맵을 받고 bootstrap을 다시 불러 맞는 비밀로 끈다
            // (ipnlocal `tkaSyncIfNeeded`는 맵 응답마다 돈다: controlclient/map.go:240, ipnlocal/local.go:2034).
            try await netstackWait("항목 7: go-peer-b가 같은 맵에서 bootstrap을 다시 부른다", seconds: 30) {
                try await gate.tkaRequestCount("bootstrap", from: goKey) > goFrom
            }
            try await netstackWait("항목 7: go-peer-b가 lock을 끄고 c를 본다", seconds: 30) {
                guard try await gate.lockStatus("go-peer-b").enabled == false else { return false }
                let seen = try await gate.command(.init(cmd: "peerStatus", name: "go-peer-b"), expecting: "peerStatus").peers ?? []
                return seen.contains { $0.nodeKey == c.key }
            }
            // 같은 맵은 Swift 노드에도 같은 때 갔다. 다시 시도했다면 그 요청은 Go의 것과 거의 같은 때 온다. 2초를 더 준다.
            try await Task.sleep(for: .seconds(2))
            let swiftRetries = try await gate.tkaRequestCount("bootstrap", from: selfKey) - swiftFrom
            let stuck = gate.describe(await swift.status)
            #expect(swiftRetries > 0, """
                항목 7: Go는 맞는 비밀을 알린 같은 내용의 맵에서 끄기 절차(bootstrap)를 다시 돌아 끄는데, Swift 노드는 다시 \
                시도하지 않는다(bootstrap \(swiftRetries)번, \(stuck))
                """)
            if swiftRetries == 0 {
                // 원인을 가른다: 내용이 다른 맵(새 피어)이 오면 다시 시도해 끄는가. 끈 뒤의 확인을 이어 가려고도 한다.
                _ = try await gate.addPeer("go-peer-y")
                try await gate.wait(swift, "항목 7(가르기): 내용이 다른 맵 뒤 .disabled") { $0.tailnetLock.mode == .disabled }
                await gate.tool.checkpoint("항목 7(가르기): 같은 내용의 맵에서는 다시 시도하지 않고, 내용이 다른 맵에서는 끈다")
            } else {
                try await gate.wait(swift, "항목 7: 맞는 비밀 뒤 .disabled") { $0.tailnetLock.mode == .disabled }
            }
            try await netstackWait("항목 7: Swift 노드가 c를 본다", seconds: 30) { await swift.peerKeys.contains(c.key) }
            #expect(!FileManager.default.fileExists(atPath: swift.lockFile.path), "항목 7: 끈 뒤 tailnet-lock.cbor가 없다")
            #expect(swift.recorder.lockChanges.last?.mode == .disabled, "항목 7: .disabled로 바뀐 tailnetLockChanged가 나왔다")
            try await gate.expectReachable("항목 7: 끈 뒤 go-peer-c → Swift UDP") {
                try await gate.goSend("go-peer-c", to: swift, proto: "udp", within: LockGate.reachable)
            }
            try await gate.expectReachable("항목 7: 끈 뒤 Swift → go-peer-c UDP 에코") {
                try await gate.udpEcho(from: swift, to: c, within: LockGate.reachable)
            }
        }
    }

    @Test("항목 7: TKAInfo 없는 응답 — 도중에는 바뀌지 않고, 다시 이은 스트림의 첫 응답이면 끄기 절차로 간다")
    func disableWithoutTKAInfo() async throws {
        try await withLockGate { gate in
            _ = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let swift = try await joinAndSign(gate, "swift-s")
            let other = try await joinAndSign(gate, "swift-t", hostname: "rd-mac-5e6f7a8b")
            let selfKey = try #require(await swift.selfKey)
            let c = try await gate.addPeer("go-peer-c")
            for node in [swift, other] {
                try await gate.wait(node, "항목 7: go-peer-c를 거른다") { $0.tailnetLock.filteredPeerCount == 1 }
            }

            // 도중 주입(서버의 lock은 켜져 있다): TKAInfo 없는 응답으로는 바뀌지 않는다. 주입한 노드는 그 뒤 자동 맵을
            // 받지 않으므로(README `injectMapResponse`) 다른 Swift 노드에 한다. 자기 Node를 주입하면 KeySignature가 빠져
            // 스스로 잠기므로(주입 도우미의 Node에는 그 필드가 없다) 패킷 필터만 바꾸는 응답을 넣는다.
            let before = await other.status.tailnetLock
            let otherKey = try #require(await other.selfKey)
            let filterBefore = await other.node.lastNetmap?.packetFilter
            try await gate.tool.inject(.init(PacketFilter: [.init(SrcIPs: ["100.64.254.10/32"], IPProto: [17],
                                                                  DstPorts: [.init(IP: "*", Ports: .init(First: 9, Last: 9))])]),
                                       into: otherKey)
            try await netstackWait("항목 7: 주입한 응답이 적용된다", seconds: 25) {
                let filter = await other.node.lastNetmap?.packetFilter
                return filter != nil && filter != filterBefore
            }
            #expect(await other.status.tailnetLock == before, "항목 7: 도중에 주입한 TKAInfo 없는 응답으로 lock 모습이 바뀌지 않는다")

            // 서버가 lock을 끄고 TKAInfo를 싣지 않는다. 이어진 스트림의 Swift 노드와 Go 피어는 그대로 거른다.
            _ = try await gate.command(.init(cmd: "lockDisable", name: "go-peer-a", omitTKAInfo: true), expecting: "lockDisable")
            #expect(try await gate.lockStatus("go-peer-b").controlDisabled == true)
            let x = try await gate.addPeer("go-peer-x")
            try await gate.wait(swift, "항목 7: 서버가 끈 뒤의 맵에서도 새 피어를 거른다") { $0.tailnetLock.filteredPeerCount == 2 }
            #expect(await swift.status.tailnetLock.mode == .enforcing, "항목 7: 도중의 TKAInfo 없는 응답으로 끄지 않는다")
            #expect(FileManager.default.fileExists(atPath: swift.lockFile.path))
            try await netstackWait("항목 7: go-peer-b도 lock을 유지하고 x를 거른다", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-b")
                return status.enabled == true && status.filteredPeers?.contains(x.key) == true
            }
            try await gate.expectAgreement(swift, with: "go-peer-b", "항목 7: 서버가 TKAInfo 없이 끈 뒤")

            // 다시 이은 스트림(같은 상태 디렉터리로 다시 띄운다)의 첫 응답에 TKAInfo가 없으면 끄기 절차로 간다.
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            await swift.stop()
            let restarted = try gate.startNode("swift-s")
            try await gate.wait(restarted, "항목 7: 다시 이은 뒤 .disabled") { $0.state == .running && $0.tailnetLock.mode == .disabled }
            try await netstackWait("항목 7: 서명 없는 c와 x가 보인다", seconds: 30) {
                let keys = await restarted.peerKeys
                return keys.contains(c.key) && keys.contains(x.key)
            }
            #expect(!FileManager.default.fileExists(atPath: restarted.lockFile.path), "항목 7: 끈 뒤 tailnet-lock.cbor가 없다")
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) > bootstraps, "항목 7: 끄기 비밀을 bootstrap으로 받았다")
            try await gate.expectReachable("항목 7: 끈 뒤 go-peer-c → Swift UDP") {
                try await gate.goSend("go-peer-c", to: restarted, proto: "udp", within: LockGate.reachable)
            }
        }
    }

    @Test("항목 8·9: 다시 시작(bootstrap 없이 저장된 상태로, 그사이 자란 사슬은 동기화로), node 키 교체와 재서명")
    func restartAndRotation() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let a = try #require(peers["go-peer-a"]), b = try #require(peers["go-peer-b"])
            let first = try await joinAndSign(gate, "swift-s")
            let selfKey = try #require(await first.selfKey)
            let c = try await gate.addPeer("go-peer-c")
            try await gate.wait(first, "항목 8: go-peer-c를 거른다") { $0.tailnetLock.filteredPeerCount == 1 }
            let head = try #require(await first.status.tailnetLock.head)
            let nlKey = try #require(try await gate.registrations().last { $0.nodeKey == selfKey }?.nlKey)
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let registered = try await gate.registrations().count { $0.nodeKey == selfKey }

            // 항목 8 ①: 사슬이 그대로면 같은 머리로 곧바로 거른다.
            await first.stop()
            let second = try gate.startNode("swift-s")
            try await gate.wait(second, "항목 8: 다시 띄운 뒤 같은 머리로 거른다") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head == head && $0.tailnetLock.signingRequest == nil
            }
            try expectStoredStateFromStart(second, signedPeers: [a.key, b.key], stage: "항목 8 ①")
            #expect(second.recorder.lockChanges.first?.head == head, "항목 8: 첫 lock 모습이 저장된 머리다")
            #expect(await !second.peerKeys.contains(c.key))
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) == bootstraps, "항목 8: 다시 띄운 뒤 bootstrap RPC가 없다")
            let afterSecond = try await gate.registrations().filter { $0.nodeKey == selfKey }
            #expect(afterSecond.count > registered, "항목 8: 다시 띄운 노드가 등록을 보냈다")
            #expect(afterSecond.allSatisfy { $0.nlKey == nlKey }, "항목 8: 같은 NL 키다")
            try await gate.expectAgreement(second, with: "go-peer-a", "항목 8 ①")

            // 항목 8 ②: 멈춘 사이에 사슬이 자라면 저장된 상태에서 동기화로 따라온다.
            await second.stop()
            let bLock = try #require(try await gate.lockStatus("go-peer-b").lockKey)
            let grown = try await gate.command(.init(cmd: "lockModify", name: "go-peer-a", addKeys: [bLock]), expecting: "lockModify")
            #expect(grown.head != head)
            let offers = try await gate.tkaRequestCount("sync/offer", from: selfKey)
            let third = try gate.startNode("swift-s")
            try await gate.wait(third, "항목 8 ②: 자란 머리로 따라온다") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.head == grown.head
            }
            try expectStoredStateFromStart(third, signedPeers: [a.key, b.key], stage: "항목 8 ②")
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) == bootstraps, "항목 8 ②: bootstrap RPC가 없다")
            #expect(try await gate.tkaRequestCount("sync/offer", from: selfKey) > offers, "항목 8 ②: sync/offer로 따라왔다")
            #expect(try await gate.registrations().filter { $0.nodeKey == selfKey }.allSatisfy { $0.nlKey == nlKey })
            try await gate.expectAgreement(third, with: "go-peer-a", "항목 8 ②")

            // 항목 9: 서버가 재서명을 요청하면 새 node 키로 바꾸고, 재서명한 요청의 서명을 Go가 통과시킨다.
            _ = try await gate.command(.init(cmd: "lockRequestResign", nodeKey: selfKey), expecting: "lockRequestResign")
            await third.stop()
            let fourth = try gate.startNode("swift-s")
            var rotated: GoTailnet.LockRegistration?
            try await netstackWait("항목 9: 옛 키를 OldNodeKey로 단 등록", seconds: 30) {
                rotated = try await gate.registrations().last { $0.oldNodeKey == selfKey }
                return rotated != nil
            }
            let rotation = try #require(rotated)
            #expect(rotation.signature == "accepted", "항목 9: 재서명한 요청의 서명을 Go가 통과시켰다 (\(rotation.signatureError))")
            #expect(rotation.nlKey == nlKey, "항목 9: 같은 NL 키다")
            #expect(try await gate.registrations().contains { $0.nodeKey == selfKey && $0.resignRequested }, "항목 9: 서버가 재서명을 요청했다")
            let newKey = rotation.nodeKey
            gate.name(newKey, "swift-s(새 키)")
            #expect(newKey != selfKey)
            try await gate.wait(fourth, "항목 9: 새 키로 잠기지 않고 거른다") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest == nil
            }
            #expect(await fourth.selfKey == newKey)
            try await netstackWait("항목 9: go-peer-a가 새 키를 보고 옛 키를 보지 않는다", seconds: 30) {
                let status = try await gate.lockStatus("go-peer-a")
                let all = Set(status.visiblePeers ?? []).union(status.filteredPeers ?? [])
                return status.visiblePeers?.contains(newKey) == true && !all.contains(selfKey)
            }
            try await gate.expectAgreement(fourth, with: "go-peer-a", "항목 9")
            try await gate.expectReachable("항목 9: 새 키의 Swift → go-peer-a UDP 에코") {
                try await gate.udpEcho(from: fourth, to: a, within: LockGate.reachable)
            }
            try await gate.expectReachable("항목 9: go-peer-a → 새 키의 Swift UDP") {
                try await gate.goSend("go-peer-a", to: fourth, proto: "udp", within: LockGate.reachable)
            }
        }
    }

    @Test("항목 10: 닫힌 쪽 — 깨진 bootstrap은 .unverified·acquiringState, 깨진 저장 파일은 unreadableStoredState, 지우면 다시 부트스트랩")
    func closedSide() async throws {
        try await withLockGate { gate in
            let peers = try await enableLock(gate, alsoSigned: ["go-peer-b"])
            let a = try #require(peers["go-peer-a"])

            // 깨진 bootstrap. 같은 서버에서 Go 노드는 lock을 켜지 못하고 거르지 않는다(의도된 차이. 비교 기록만 남긴다).
            // Swift 노드보다 먼저 더한다: 뒤에 더하면 그 맵이 Swift 노드의 재시도를 한 번 더 일으켜 물러나는 간격이 길어진다.
            try await gate.setBootstrapFault(true)
            let f = try await gate.addPeer("go-peer-f")
            try await netstackWait("항목 10: go-peer-f가 bootstrap을 시도한다", seconds: 30) {
                try await gate.tkaRequestCount("bootstrap", from: f.key) > 0
            }
            let goUnderFault = try await gate.lockStatus("go-peer-f")
            #expect(goUnderFault.enabled == false, "항목 10: (대조) Go는 깨진 bootstrap에서 lock을 켜지 않는다")

            // Swift 노드는 피어를 하나도 올리지 않는다.
            let swift = try gate.startNode("swift-s")
            let closed = try await gate.wait(swift, "항목 10: 깨진 bootstrap에서 .unverified") {
                $0.state == .running && $0.tailnetLock.mode == .unverified
            }
            let selfKey = try #require(await swift.selfKey)
            gate.name(selfKey, "swift-s")
            #expect(closed.tailnetLock.issue == .acquiringState, "항목 10: issue가 .acquiringState")
            let closedPeers = await swift.peerKeys
            #expect(closed.peerCount == 0 && closedPeers.isEmpty, "항목 10: peers가 비어 있다")
            let others = try await gate.registeredKeys().subtracting([selfKey])
            #expect(closed.tailnetLock.filteredPeerCount == others.count, "항목 10: filteredPeerCount가 서버가 알린 피어 수")
            #expect(closed.tailnetLock.head == nil && closed.tailnetLock.signingRequest == nil)
            try await gate.expectSilent("항목 10: .unverified의 Swift → go-peer-a UDP 에코") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.silence)
            }
            await gate.tool.checkpoint("항목 10: 깨진 bootstrap — Swift .unverified·피어 0, Go enabled=\(goUnderFault.enabled ?? false)")

            // 되돌리면 다음 재시도에 .enforcing이 된다. 재시도 간격은 실패마다 5초에서 두 배씩 는다(TL-7, 상한 300초).
            // 되돌릴 때 서버가 보내는 맵은 내용이 같아(Go는 그 맵에서 곧바로 다시 시도한다) Swift 노드는 타이머를 기다린다.
            let failures = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            #expect(failures >= 1)
            let backoff = min(5 * (1 << min(max(failures - 1, 0), 6)), 300)
            let restored = ContinuousClock.now
            try await gate.setBootstrapFault(false)
            let recovered = try await gate.wait(swift, "항목 10: 되돌린 뒤 다음 재시도(실패 \(failures)번, 간격 \(backoff)초 이하)에 .enforcing",
                                                seconds: backoff + 10) {
                $0.tailnetLock.mode == .enforcing && $0.tailnetLock.issue == nil
            }
            await gate.tool.checkpoint("""
                항목 10: 되돌린 뒤 .enforcing까지 \(restored.duration(to: .now).formatted(.units(allowed: [.milliseconds]))) \
                (그전 bootstrap 실패 \(failures)번, 다음 간격 \(backoff)초 이하)
                """)
            let request = try #require(recovered.tailnetLock.signingRequest, "항목 10: 서명 전이라 잠겨 있다")
            let controlHead = try await gate.lockStatus("go-peer-a").controlHead
            #expect(recovered.tailnetLock.head == controlHead, "항목 10: 되돌린 뒤 서버 머리")
            try await gate.expectAgreement(swift, with: "go-peer-a", "항목 10: 되돌린 뒤")
            _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: request.nodeKey, lockKey: request.lockKey),
                                       expecting: "lockSign")
            try await gate.wait(swift, "항목 10: 서명 뒤 풀린다") { $0.tailnetLock.signingRequest == nil && $0.tailnetLock.mode == .enforcing }
            try await gate.expectReachable("항목 10: 서명 뒤 Swift → go-peer-a UDP 에코") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable)
            }
            let nlKey = try #require(try await gate.registrations().last { $0.nodeKey == selfKey }?.nlKey)

            // 저장 파일을 깨뜨리고 다시 띄우면 .unverified·unreadableStoredState다.
            await swift.stop()
            var stored = try Data(contentsOf: swift.lockFile)
            stored[stored.count / 2] ^= 0xff
            try stored.write(to: swift.lockFile)
            let broken = try gate.startNode("swift-s")
            let unreadable = try await gate.wait(broken, "항목 10: 깨진 저장 파일에서 .unverified") {
                $0.state == .running && $0.tailnetLock.mode == .unverified
            }
            #expect(unreadable.tailnetLock.issue == .unreadableStoredState, "항목 10: issue가 .unreadableStoredState")
            let brokenPeers = await broken.peerKeys
            #expect(unreadable.peerCount == 0 && brokenPeers.isEmpty, "항목 10: peers가 비어 있다")
            try await gate.holds(broken, "항목 10: 깨진 저장 파일은 스스로 풀리지 않는다", seconds: 7) {
                $0.tailnetLock.mode == .unverified && $0.tailnetLock.issue == .unreadableStoredState
            }
            try await gate.expectSilent("항목 10: 깨진 저장 파일의 Swift → go-peer-a UDP 에코") {
                try await gate.udpEcho(from: broken, to: a, within: LockGate.silence)
            }

            // lock 상태 파일만 지우면 새 노드가 부트스트랩부터 해서 풀린다(같은 NL 키, 서명은 그대로 유효).
            await broken.stop()
            try ControlClient.removeTailnetLockState(inDirectory: broken.directory)
            #expect(!FileManager.default.fileExists(atPath: broken.lockFile.path))
            let bootstraps = try await gate.tkaRequestCount("bootstrap", from: selfKey)
            let fresh = try gate.startNode("swift-s")
            try await gate.wait(fresh, "항목 10: 지운 뒤 부트스트랩해서 .enforcing·서명됨") {
                $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest == nil && $0.tailnetLock.issue == nil
            }
            #expect(try await gate.tkaRequestCount("bootstrap", from: selfKey) > bootstraps, "항목 10: 부트스트랩부터 했다")
            #expect(await fresh.selfKey == selfKey)
            #expect(try await gate.registrations().last { $0.nodeKey == selfKey }?.nlKey == nlKey, "항목 10: 같은 NL 키다")
            try await gate.expectAgreement(fresh, with: "go-peer-a", "항목 10: 지운 뒤")
            try await gate.expectReachable("항목 10: 지운 뒤 Swift → go-peer-a UDP 에코") {
                try await gate.udpEcho(from: fresh, to: a, within: LockGate.reachable)
            }
        }
    }

    @Test("항목 11: lock 없는 tailnet — .disabled이고 TKA RPC가 나가지 않는다")
    func noLock() async throws {
        try await withLockGate(capability: false) { gate in
            let a = try await gate.addPeer("go-peer-a")
            let swift = try gate.startNode("swift-s")
            try await gate.wait(swift, "항목 11: running·피어 하나") { $0.state == .running && $0.peerCount == 1 }
            try await gate.expectReachable("항목 11: Swift → go-peer-a UDP 에코") {
                try await gate.udpEcho(from: swift, to: a, within: LockGate.reachable)
            }
            #expect(await swift.status.tailnetLock == TailnetLockStatus(), "항목 11: mode가 .disabled이고 나머지는 기본값")
            #expect(swift.recorder.lockChanges.isEmpty, "항목 11: tailnetLockChanged가 나오지 않는다")
            #expect(try await gate.tkaRequests().isEmpty, "항목 11: TKA RPC가 없다")

            // capability만 있고 lock을 켜지 않은 tailnet(TKAInfo 없음)도 같다.
            _ = try await gate.command(.init(cmd: "setLockCapability", enabled: true), expecting: "lockCapability")
            _ = try await gate.addPeer("go-peer-b")
            try await gate.wait(swift, "항목 11: capability를 실은 뒤의 맵(피어 둘)") { $0.peerCount == 2 }
            try await gate.holds(swift, "항목 11: capability만으로는 .disabled", seconds: 3) { $0.tailnetLock.mode == .disabled }
            #expect(swift.recorder.lockChanges.isEmpty)
            #expect(try await gate.tkaRequests().isEmpty, "항목 11: capability만 있을 때도 TKA RPC가 없다")
            #expect(try await gate.lockStatus("go-peer-a").enabled == false)
        }
    }
}

/// lock을 켠다: 서명 기기 `go-peer-a`와 켤 때 함께 서명되는 `alsoSigned` 피어를 더하고 `lockInit`. 피어들이 서버 머리에 닿고
/// 자기가 서명된 것을 본 뒤 돌아온다.
private func enableLock(_ gate: LockGate, alsoSigned: [String] = []) async throws -> [String: GatePeer] {
    var peers: [String: GatePeer] = [:]
    for name in ["go-peer-a"] + alsoSigned { peers[name] = try await gate.addPeer(name) }
    let started = try await gate.command(.init(cmd: "lockInit", name: "go-peer-a"), expecting: "lockInit")
    #expect(started.enabled == true && started.head == started.controlHead && started.nodeKeySigned == true)
    for name in alsoSigned {
        try await netstackWait("lock 켜기: \(name)가 부트스트랩하고 서명된 자기를 본다", seconds: 45) {
            let status = try await gate.lockStatus(name)
            return status.enabled == true && status.head == status.controlHead && status.nodeKeySigned == true
        }
    }
    return peers
}

/// 새 Swift 노드를 띄워 잠긴 것을 보고, 서명 요청의 두 값을 그대로 `lockSign`에 넣어 풀리게 한다.
private func joinAndSign(_ gate: LockGate, _ label: String, hostname: String = "rd-mac-1a2b3c4d") async throws -> LockNode {
    let node = try gate.startNode(label, hostname: hostname)
    let locked = try await gate.wait(node, "\(label): 잠김") {
        $0.state == .running && $0.tailnetLock.mode == .enforcing && $0.tailnetLock.signingRequest != nil
    }
    let request = try #require(locked.tailnetLock.signingRequest)
    gate.name(request.nodeKey, label)
    _ = try await gate.command(.init(cmd: "lockSign", name: "go-peer-a", nodeKey: request.nodeKey, lockKey: request.lockKey),
                               expecting: "lockSign")
    try await gate.wait(node, "\(label): 서명 뒤 풀림") { $0.tailnetLock.signingRequest == nil && $0.tailnetLock.mode == .enforcing }
    return node
}

/// F2 요구 1: 첫 `.running`과 lock 정보 사이에 틈이 없다. 같은 netmap의 `tailnetLockChanged`가 `stateChanged(.running)`보다
/// 먼저이고, `.running`을 받은 뒤 읽은 `status`에 lock 모습이 이미 있다.
private func expectLockBeforeRunning(_ node: LockNode, _ stage: String) throws {
    let entries = node.recorder.events
    let lockIndex = entries.firstIndex { if case .tailnetLockChanged = $0.event { true } else { false } }
    let runningIndex = try #require(entries.firstIndex { $0.event == .stateChanged(.running) }, "\(stage): .running 사건")
    #expect(lockIndex.map { $0 < runningIndex } == true, "\(stage): tailnetLockChanged가 첫 .running보다 먼저다")
    #expect(entries[runningIndex].status.tailnetLock.mode != .disabled, "\(stage): .running 뒤의 status에 lock 모습이 있다")
}

/// 다시 띄운 노드가 처음부터 저장된 상태로 걸렀다: 한 번도 `.unverified`·`.disabled`로 lock 모습을 내지 않았고, 어느 사건 뒤의
/// `status`에도 서명된 피어보다 많은 피어가 없었다.
private func expectStoredStateFromStart(_ node: LockNode, signedPeers: Set<String>, stage: String) throws {
    let changes = node.recorder.lockChanges
    #expect(!changes.isEmpty && changes.allSatisfy { $0.mode == .enforcing }, "\(stage): 처음부터 .enforcing이다")
    #expect(node.recorder.events.allSatisfy { $0.status.peerCount <= signedPeers.count }, "\(stage): 서명 없는 피어가 한 번도 올라오지 않았다")
    try expectLockBeforeRunning(node, stage)
}
