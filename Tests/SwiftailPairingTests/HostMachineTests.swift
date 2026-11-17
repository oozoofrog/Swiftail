import Foundation
import Swiftail
import Testing
@testable import SwiftailPairing

/// 여는 쪽 상태 기계(계약 동작 P1~P9. 7절 시험 3). 시각과 난수를 직접 넘겨 결정적으로 돌린다.
@Suite("여는 쪽 상태 기계")
struct HostMachineTests {
    private typealias Rehearsal = PairingRehearsal
    private static let id = PairingRehearsal.sessionID

    /// 이름 칸에 `name`의 바이트를 그대로 넣은 `hello`. 검증을 거치지 않는다.
    private static func rawHello(name: [UInt8], prefix: [UInt8] = Array("SWPR".utf8) + [1]) -> [UInt8] {
        prefix + Sample.joinerNonce + [UInt8(truncatingIfNeeded: name.count)] + name
    }

    /// 제안이 열린 기계에 연결 `id`를 받아 `proof`까지 맞춘다. 결정 요청의 할 일을 돌려준다.
    private static func prove(
        _ machine: inout PairingHostMachine, id: PairingHostMachine.SessionID, offer: PairingOffer,
        at now: ContinuousClock.Instant
    ) throws -> [PairingHostMachine.Action] {
        _ = machine.accept(
            id, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce, at: now)
        var joiner = PairingJoinerSession(
            offer: offer, deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: now + .seconds(60))
        let challenge = machine.receive(joiner.hello, on: id, wallClock: Sample.wallClock, now: now)
        let proof = joiner.receive(challenge.sentBytes, at: now)
        return machine.receive(proof.sentBytes, on: id, wallClock: Sample.wallClock, now: now)
    }

    // MARK: 정상

    @Test("정상: hello → challenge → proof → accepted·결정 요청 → 저장 → 승인")
    func pairs() throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        #expect(HostStep.steps(challenge) == [.send([0] + Sample.hostNonce)])
        #expect(rehearsal.machine.hasOpenOffer, "증명이 오기 전에는 제안이 그대로다")

        let proof = rehearsal.toJoiner(challenge.sentBytes)
        let accepted = HostStep.steps(rehearsal.toHost(proof.sentBytes))
        #expect(accepted.count == 2)
        guard case .send(let acceptedBytes) = accepted[0],
              case .requestDecision("nEXAMPLEJOINER", "rd-phone-5e6f7a8b", let hostCode) = accepted[1]
        else {
            Issue.record("accepted와 결정 요청이 나와야 한다: \(accepted)")
            return
        }
        #expect(acceptedBytes.count == 32)
        #expect(hostCode.count == 6 && hostCode.allSatisfy(\.isNumber))
        #expect(!rehearsal.machine.hasOpenOffer, "맞는 증명이 온 그 자리에서 제안을 쓴 것으로 한다(P4)")
        #expect(rehearsal.toJoiner(acceptedBytes).confirmationCode == hostCode, "양쪽의 확인 숫자가 같다")

        let decided = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        let peer = PairedPeer(peer: Sample.joinerIdentity, deviceName: "rd-phone-5e6f7a8b", pairedAt: Sample.wallClock)
        #expect(HostStep.steps(decided) == [.save(peer)], "저장한 뒤에야 승인을 보낸다(P7)")
        #expect(rehearsal.machine.deadline(of: Self.id) == nil)

        let saved = rehearsal.machine.saved(Self.id, succeeded: true)
        #expect(HostStep.steps(saved).last == .finish(.paired))
        #expect(rehearsal.machine.sessionCount == 0)
        let approval = PairingJoinerSession.Approval(stableID: "nEXAMPLEHOST", name: "rd-mac-1a2b3c4d")
        #expect(rehearsal.toJoiner(saved.sentBytes).result == .success(approval))
    }

    @Test("한 바이트씩 와도 같다")
    func acceptsFragmentedMessages() throws {
        var rehearsal = try Rehearsal()
        var challenge: [PairingHostMachine.Action] = []
        for byte in rehearsal.joiner.hello {
            #expect(challenge.isEmpty)
            challenge = rehearsal.toHost([byte])
        }
        let proof = rehearsal.toJoiner(challenge.sentBytes).sentBytes
        var accepted: [PairingHostMachine.Action] = []
        for byte in proof {
            #expect(accepted.isEmpty)
            accepted = rehearsal.toHost([byte])
        }
        #expect(accepted.count == 2)
    }

    @Test("승인할 때의 신원을 짝으로 적는다(이름은 그때의 사본)")
    func savesCurrentIdentity() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        var renamed = Sample.joinerIdentity
        renamed.computedName = "rd-phone-renamed"
        let decided = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: renamed, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(
            HostStep.steps(decided)
                == [.save(PairedPeer(peer: renamed, deviceName: "rd-phone-5e6f7a8b", pairedAt: Sample.wallClock))])
    }

    @Test("표시 이름이 64바이트를 넘으면 글자 경계에서 잘라 보낸다")
    func truncatesHostName() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        var host = Sample.hostIdentity
        host.computedName = String(repeating: "표", count: 30)   // 90바이트
        _ = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: host, at: Sample.wallClock)
        let saved = rehearsal.machine.saved(Self.id, succeeded: true)
        let approval = PairingJoinerSession.Approval(stableID: "nEXAMPLEHOST", name: String(repeating: "표", count: 21))
        #expect(rehearsal.toJoiner(saved.sentBytes).result == .success(approval))
    }

    // MARK: 받기 (P1, P8)

    @Test("신원을 모르는 상대는 올리지 않는다(P1)")
    func refusesUnknownPeer() throws {
        var machine = PairingHostMachine()
        machine.open(Sample.offer())
        let actions = machine.accept(
            1, from: nil, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce, at: .now)
        #expect(HostStep.steps(actions) == [.finish(.unknownPeer)])
        #expect(machine.sessionCount == 0)
        #expect(machine.receive([1], on: 1, wallClock: Sample.wallClock, now: .now).isEmpty)
    }

    @Test("절차 중인 연결은 8개까지다. 넘으면 받자마자 닫고, 자리가 나면 다시 받는다")
    func limitsSessions() throws {
        var machine = PairingHostMachine()
        let endpoints = try Sample.endpoints()
        for id in UInt64(0)..<8 {
            #expect(machine.accept(id, from: Sample.joinerIdentity, endpoints: endpoints, nonce: Sample.hostNonce, at: .now).isEmpty)
        }
        let ninth = machine.accept(8, from: Sample.joinerIdentity, endpoints: endpoints, nonce: Sample.hostNonce, at: .now)
        #expect(HostStep.steps(ninth) == [.finish(.limitReached)])
        #expect(machine.sessionCount == 8)

        #expect(HostStep.steps(machine.connectionEnded(3)) == [.finish(.disconnected)])
        #expect(machine.accept(9, from: Sample.joinerIdentity, endpoints: endpoints, nonce: Sample.hostNonce, at: .now).isEmpty)
        #expect(machine.sessionCount == 8)
    }

    // MARK: 제안 (P2~P4, P9)

    @Test("열린 제안이 없으면 hello를 읽은 뒤 상태 1을 보내고 닫는다(P2)")
    func reportsNoOffer() throws {
        var rehearsal = try Rehearsal()
        rehearsal.machine.closeOffer()
        #expect(rehearsal.toHost(Array(rehearsal.joiner.hello.dropLast())).isEmpty, "hello가 다 오기 전에는 말하지 않는다")
        let actions = rehearsal.toHost([rehearsal.joiner.hello.last ?? 0])
        #expect(HostStep.steps(actions) == [.send([1] + Sample.hostNonce), .finish(.noOffer)])
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.rejected))
    }

    @Test("만료된 제안도 상태 1이다. 만료 시각 바로 전까지는 쓴다")
    func reportsExpiredOffer() throws {
        var live = try Rehearsal()
        let before = live.toHost(live.joiner.hello, wallClock: Sample.expires.addingTimeInterval(-0.001))
        #expect(HostStep.steps(before) == [.send([0] + Sample.hostNonce)])

        var expired = try Rehearsal()
        let after = expired.toHost(expired.joiner.hello, wallClock: Sample.expires)
        #expect(HostStep.steps(after) == [.send([1] + Sample.hostNonce), .finish(.noOffer)])
        #expect(expired.machine.hasOpenOffer, "만료를 보았다고 지우지는 않는다")
    }

    @Test("틀린 증명에는 아무것도 보내지 않고 닫는다. 제안은 남아 다음 연결이 쓴다(P3)")
    func keepsOfferAfterWrongProof() throws {
        let wrong = Sample.offer(secret: [UInt8](repeating: 0x5B, count: 32))
        var rehearsal = try Rehearsal()
        var stranger = PairingJoinerSession(
            offer: wrong, deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: rehearsal.start + .seconds(60))
        let challenge = rehearsal.toHost(stranger.hello)
        let proof = stranger.receive(challenge.sentBytes, at: rehearsal.start)
        #expect(HostStep.steps(rehearsal.toHost(proof.sentBytes)) == [.finish(.wrongProof)])
        #expect(rehearsal.machine.hasOpenOffer)
        #expect(stranger.connectionEnded().result == .failure(.rejected))

        let accepted = try Self.prove(&rehearsal.machine, id: 2, offer: Sample.offer(), at: rehearsal.start)
        #expect(accepted.count == 2, "같은 제안으로 맞는 증명을 낸 연결은 받아들인다")
    }

    @Test("제안은 한 번만 쓰인다. 같은 비밀의 다른 연결은 그 뒤로 받아 주지 않는다(P4)")
    func consumesOfferOnce() throws {
        var rehearsal = try Rehearsal()
        // 둘째 연결도 제안이 열려 있을 때 challenge를 받았다.
        _ = rehearsal.machine.accept(
            2, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce,
            at: rehearsal.start)
        var second = PairingJoinerSession(
            offer: Sample.offer(), deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: rehearsal.start + .seconds(60))
        let challenge = rehearsal.machine.receive(second.hello, on: 2, wallClock: Sample.wallClock, now: rehearsal.start)
        let secondProof = second.receive(challenge.sentBytes, at: rehearsal.start)

        _ = try rehearsal.reachDecision()
        let late = rehearsal.machine.receive(
            secondProof.sentBytes, on: 2, wallClock: Sample.wallClock, now: rehearsal.start)
        #expect(HostStep.steps(late) == [.finish(.noOffer)], "맞는 증명이어도 이미 쓰인 제안이다")

        _ = rehearsal.machine.accept(
            3, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce,
            at: rehearsal.start)
        let third = rehearsal.machine.receive(second.hello, on: 3, wallClock: Sample.wallClock, now: rehearsal.start)
        #expect(HostStep.steps(third) == [.send([1] + Sample.hostNonce), .finish(.noOffer)])
    }

    @Test("hello와 proof 사이에 제안이 바뀌거나 닫히거나 만료되면 말없이 닫는다", arguments: ["바뀜", "닫힘", "만료"])
    func rejectsProofForStaleOffer(change: String) throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes)
        var wallClock = Sample.wallClock
        switch change {
        case "바뀜": rehearsal.machine.open(Sample.offer(secret: [UInt8](repeating: 0x77, count: 32)))
        case "닫힘": rehearsal.machine.closeOffer()
        default: wallClock = Sample.expires
        }
        #expect(HostStep.steps(rehearsal.toHost(proof.sentBytes, wallClock: wallClock)) == [.finish(.noOffer)])
        #expect(rehearsal.machine.hasOpenOffer == (change != "닫힘"), "새로 연 제안과 만료된 제안은 건드리지 않는다")
    }

    @Test("새 제안을 열면 앞의 것은 그 자리에서 못 쓴다(P9)")
    func replacesOffer() throws {
        var machine = PairingHostMachine()
        let old = Sample.offer()
        let new = Sample.offer(secret: [UInt8](repeating: 0x77, count: 32))
        machine.open(old)
        machine.open(new)
        #expect(HostStep.steps(try Self.prove(&machine, id: 1, offer: old, at: .now)) == [.finish(.wrongProof)])
        #expect(try Self.prove(&machine, id: 2, offer: new, at: .now).count == 2)
    }

    // MARK: 메시지의 길이와 차례 (P8)

    @Test("hello 뒤에 바이트가 더 오면 위반이다")
    func rejectsOverlongHello() throws {
        var rehearsal = try Rehearsal()
        #expect(HostStep.steps(rehearsal.toHost(rehearsal.joiner.hello + [0])) == [.finish(.malformed)])
        #expect(rehearsal.machine.sessionCount == 0)
    }

    @Test("challenge를 보낸 뒤 proof보다 긴 바이트가 오면 위반이다")
    func rejectsOverlongProof() throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes).sentBytes
        #expect(HostStep.steps(rehearsal.toHost(proof + [0])) == [.finish(.malformed)])
        #expect(rehearsal.machine.hasOpenOffer)
    }

    @Test("글자를 잇는 서식 문자(U+200C, U+200D)가 든 기기 이름은 받는다", arguments: ["\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} iPad", "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}"])
    func acceptsJoinedDeviceName(name: String) {
        #expect(DeviceName(name)?.text == name)
    }

    @Test(
        "규격과 다른 hello는 challenge 없이 닫는다",
        arguments: [
            [0x00],                                                                   // 첫 바이트부터 표식이 아니다
            Array("SWPX".utf8),
            HostMachineTests.rawHello(name: Array("a".utf8), prefix: Array("SWPR".utf8) + [2]),   // 모르는 판
            HostMachineTests.rawHello(name: []),                                                   // 이름 길이 0
            HostMachineTests.rawHello(name: [UInt8](repeating: 0x61, count: 65)),                  // 이름 길이 65
            HostMachineTests.rawHello(name: [0xFF, 0xFE]),                                         // UTF-8이 아니다
            HostMachineTests.rawHello(name: [0xC3]),                                               // 잘린 UTF-8
            HostMachineTests.rawHello(name: Array("a\u{07}b".utf8)),                               // 제어 문자(Cc)
            HostMachineTests.rawHello(name: Array("a\nb".utf8)),
            HostMachineTests.rawHello(name: Array("a\u{7F}".utf8)),
            HostMachineTests.rawHello(name: Array("a\u{202E}b".utf8)),                             // 방향 바꿈(Cf)
            HostMachineTests.rawHello(name: Array("a\u{200B}b".utf8)),                             // 폭 없는 공백(Cf)
            HostMachineTests.rawHello(name: Array("a\u{FEFF}".utf8)),
        ])
    func rejectsMalformedHello(bytes: [UInt8]) throws {
        var rehearsal = try Rehearsal()
        #expect(HostStep.steps(rehearsal.toHost(bytes)) == [.finish(.malformed)])
        #expect(rehearsal.machine.hasOpenOffer)
    }

    @Test("이름의 경계: 1바이트, 64바이트, 여러 글자")
    func acceptsDeviceNames() throws {
        for name in ["a", String(repeating: "a", count: 64), "거실 iPad", "Zoë’s 📱"] {
            var rehearsal = try Rehearsal()
            let actions = rehearsal.toHost(Self.rawHello(name: Array(name.utf8)))
            #expect(HostStep.steps(actions) == [.send([0] + Sample.hostNonce)], "\(name)")
        }
    }

    @Test("잘린 메시지에서 끊기면 닫는다")
    func closesOnTruncatedMessage() throws {
        var rehearsal = try Rehearsal()
        #expect(rehearsal.toHost(Array(rehearsal.joiner.hello.prefix(20))).isEmpty)
        #expect(HostStep.steps(rehearsal.machine.connectionEnded(Self.id)) == [.finish(.disconnected)])
        #expect(rehearsal.machine.connectionEnded(Self.id).isEmpty, "끝난 연결의 사건은 버린다")
    }

    // MARK: 기한 (P5, P8)

    @Test("연결을 받은 때부터 10초 안에 proof가 오지 않으면 말없이 닫는다")
    func timesOutBeforeProof() throws {
        var silent = try Rehearsal()
        #expect(silent.machine.deadline(of: Self.id) == silent.start + .seconds(10))
        #expect(silent.machine.advance(Self.id, to: silent.start + .milliseconds(9_999)).isEmpty)
        #expect(HostStep.steps(silent.machine.advance(Self.id, to: silent.start + .seconds(10))) == [.finish(.proofTimedOut)])

        // hello가 늦게 와도 기한은 받은 때부터다.
        var slow = try Rehearsal()
        _ = slow.machine.receive(slow.joiner.hello, on: Self.id, wallClock: Sample.wallClock, now: slow.start + .seconds(9))
        #expect(slow.machine.deadline(of: Self.id) == slow.start + .seconds(10))
        #expect(HostStep.steps(slow.machine.advance(Self.id, to: slow.start + .seconds(10))) == [.finish(.proofTimedOut)])
        #expect(slow.machine.hasOpenOffer)
    }

    @Test("120초 안에 결정이 없으면 상태 3을 보내고 닫는다(P5)")
    func timesOutWaitingForDecision() throws {
        var rehearsal = try Rehearsal()
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes)
        let provedAt = rehearsal.start + .seconds(7)
        let accepted = rehearsal.machine.receive(proof.sentBytes, on: Self.id, wallClock: Sample.wallClock, now: provedAt)
        _ = rehearsal.toJoiner(accepted.sentBytes)

        #expect(rehearsal.machine.deadline(of: Self.id) == provedAt + .seconds(120))
        #expect(rehearsal.machine.advance(Self.id, to: rehearsal.start + .seconds(10)).isEmpty, "증명의 기한은 이제 없다")
        #expect(rehearsal.machine.advance(Self.id, to: provedAt + .milliseconds(119_999)).isEmpty)
        let actions = rehearsal.machine.advance(Self.id, to: provedAt + .seconds(120))
        #expect(HostStep.steps(actions).last == .finish(.decisionTimedOut))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.timedOut))
        // 늦게 온 결정은 버린다.
        let late = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(late.isEmpty)
    }

    // MARK: 결정 (P5~P7)

    @Test("앱이 거절하면 상태 2를 보내고 닫는다")
    func denies() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        let actions = rehearsal.machine.decided(
            Self.id, approved: false, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(HostStep.steps(actions).last == .finish(.denied))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
    }

    @Test("결정을 기다리는 동안 끊기거나 바이트가 오면 닫는다. 가장자리가 결정 Task를 취소한다(P6)", arguments: [true, false])
    func closesWhenPeerLeavesDuringDecision(byEnding: Bool) throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        let actions = byEnding ? rehearsal.machine.connectionEnded(Self.id) : rehearsal.toHost([0])
        #expect(HostStep.steps(actions) == [.finish(.disconnected)], "보내는 것 없이 끝난다")
        let late = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(late.isEmpty, "끝난 연결의 승인은 짝을 만들지 않는다")
    }

    @Test("결정을 기다리는 동안 제안을 닫거나 새로 열어도 그 결정은 계속된다(P6)", arguments: [true, false])
    func decisionSurvivesOfferChange(closing: Bool) throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        if closing {
            rehearsal.machine.closeOffer()
        } else {
            rehearsal.machine.open(Sample.offer(secret: [UInt8](repeating: 0x77, count: 32)))
        }
        let saved = rehearsal.approve()
        #expect(HostStep.steps(saved).last == .finish(.paired))
        #expect(rehearsal.toJoiner(saved.sentBytes).result != nil)
        #expect(rehearsal.machine.hasOpenOffer == !closing)
    }

    @Test("승인하는 순간 상대의 StableID가 달라졌거나 신원이 없으면 저장하지 않고 상태 2다(P7)", arguments: [true, false])
    func deniesWhenIdentityChanged(missing: Bool) throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        var other = Sample.joinerIdentity
        other.stableID = "nEXAMPLEOTHER"
        let actions = rehearsal.machine.decided(
            Self.id, approved: true, currentPeer: missing ? nil : other, host: Sample.hostIdentity, at: Sample.wallClock)
        #expect(HostStep.steps(actions).count == 2)
        #expect(HostStep.steps(actions).last == .finish(.identityChanged))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
    }

    @Test("알려 줄 자기 신원이 없으면 저장하지 않고 상태 2다")
    func deniesWithoutHostIdentity() throws {
        for host in [nil, PeerIdentity(stableID: "", name: "", computedName: "", loginName: ""),
                     PeerIdentity(stableID: "n\u{7F}", name: "", computedName: "", loginName: "")] {
            var rehearsal = try Rehearsal()
            _ = try rehearsal.reachDecision()
            let actions = rehearsal.machine.decided(
                Self.id, approved: true, currentPeer: Sample.joinerIdentity, host: host, at: Sample.wallClock)
            #expect(HostStep.steps(actions).last == .finish(.hostIdentityUnknown))
            #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
        }
    }

    @Test("저장에 실패하면 상태 2다(P7)")
    func deniesWhenStoreFails() throws {
        var rehearsal = try Rehearsal()
        _ = try rehearsal.reachDecision()
        let actions = rehearsal.approve(saving: false)
        #expect(HostStep.steps(actions).last == .finish(.storeFailed))
        #expect(rehearsal.toJoiner(actions.sentBytes).result == .failure(.denied))
        #expect(rehearsal.machine.sessionCount == 0)
    }
}
