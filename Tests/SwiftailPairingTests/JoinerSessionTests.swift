import Foundation
import SwiftailBase
import Testing
@testable import SwiftailPairing

/// 들어오는 쪽 상태 기계(계약 동작 J2~J5. 7절 시험 4).
@Suite("들어오는 쪽 상태 기계")
struct JoinerSessionTests {
    private typealias Rehearsal = PairingRehearsal
    private typealias Approval = PairingJoinerSession.Approval

    /// 여는 쪽이 `Sample`의 값으로 만들 T.
    private static func transcript() throws -> PairingTranscript {
        PairingTranscript(
            joinerNonce: Sample.joinerNonce, hostNonce: Sample.hostNonce, offerHost: Sample.host,
            offerPort: Sample.port, deviceName: Array("rd-phone-5e6f7a8b".utf8), endpoints: try Sample.endpoints())
    }

    /// 본문에 맞는 HMAC을 붙인 `decision`.
    private static func signed(_ body: [UInt8]) throws -> [UInt8] {
        body + (try transcript()).decisionCode(for: body, secret: Sample.secret)
    }

    private static func approvedBody(stableID: [UInt8], name: [UInt8]) -> [UInt8] {
        [1, UInt8(truncatingIfNeeded: stableID.count)] + stableID + [UInt8(truncatingIfNeeded: name.count)] + name
    }

    /// `accepted`까지 맞아 결정을 기다리는 연결.
    private static func waitingJoiner(at now: ContinuousClock.Instant = .now) throws -> PairingJoinerSession {
        var joiner = PairingJoinerSession(
            offer: Sample.offer(), deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(), challengeDeadline: now + .seconds(60))
        let proof = joiner.receive([0] + Sample.hostNonce, at: now)
        #expect(proof.sentBytes == Sample.joinerNonce + (try transcript()).proof(secret: Sample.secret))
        let waiting = joiner.receive(try transcript().accepted(secret: Sample.secret), at: now)
        #expect(waiting.confirmationCode == (try transcript()).confirmationCode(secret: Sample.secret))
        return joiner
    }

    // MARK: challenge (J3)

    @Test("challenge의 상태 1이면 rejected, 모르는 상태나 남는 바이트는 위반이다")
    func readsChallenge() throws {
        var refused = try Rehearsal().joiner
        #expect(refused.receive([1] + Sample.hostNonce, at: .now) == [.finish(.failure(.rejected))])

        var unknown = try Rehearsal().joiner
        #expect(unknown.receive([2], at: .now) == [.finish(.failure(.protocolViolation))])

        var overlong = try Rehearsal().joiner
        #expect(overlong.receive([0] + Sample.hostNonce + [0], at: .now) == [.finish(.failure(.protocolViolation))])

        var partial = try Rehearsal().joiner
        #expect(partial.receive([0] + Sample.hostNonce.dropLast(), at: .now).isEmpty, "다 올 때까지 기다린다")
        #expect(partial.receive([0x22], at: .now).sentBytes.count == 64)
    }

    @Test("hello에는 nonce가 아니라 그 약속이 실린다. nonce는 challenge를 받은 뒤 proof에서 연다")
    func commitsToNonceBeforeChallenge() throws {
        var joiner = try Rehearsal().joiner
        let commitment = PairingTranscript.commitment(to: Sample.joinerNonce)
        #expect(joiner.hello == Array("SWPR".utf8) + [2] + commitment + [17] + Array("rd-phone-5e6f7a8b".utf8))
        #expect(commitment != Sample.joinerNonce)

        let proof = joiner.receive([0] + Sample.hostNonce, at: .now).sentBytes
        #expect(Array(proof.prefix(32)) == Sample.joinerNonce)
    }

    @Test("연결이 끝난 때에 따라: challenge 전은 unreachable, proof 뒤는 rejected, 결정 대기 중은 위반")
    func classifiesConnectionEnd() throws {
        var early = try Rehearsal().joiner
        #expect(early.connectionEnded() == [.finish(.failure(.unreachable))])
        #expect(early.connectionEnded().isEmpty && early.deadline == nil, "끝난 뒤의 사건은 버린다")

        var proved = try Rehearsal().joiner
        _ = proved.receive([0] + Sample.hostNonce, at: .now)
        #expect(proved.connectionEnded() == [.finish(.failure(.rejected))])

        var waiting = try Self.waitingJoiner()
        #expect(waiting.connectionEnded() == [.finish(.failure(.protocolViolation))])
    }

    // MARK: accepted (J4)

    @Test("틀린 accepted면 hostNotVerified이고 확인 숫자를 내지 않는다")
    func rejectsWrongAccepted() throws {
        var accepted = try Self.transcript().accepted(secret: Sample.secret)
        accepted[31] ^= 1
        var joiner = try Rehearsal().joiner
        _ = joiner.receive([0] + Sample.hostNonce, at: .now)
        #expect(joiner.receive(accepted, at: .now) == [.finish(.failure(.hostNotVerified))])

        // 다른 꼬리표의 값(proof)을 되돌려 보내도 맞지 않는다.
        var echoed = try Rehearsal().joiner
        let proof = echoed.receive([0] + Sample.hostNonce, at: .now).sentBytes
        #expect(echoed.receive(Array(proof.suffix(32)), at: .now) == [.finish(.failure(.hostNotVerified))])
    }

    @Test("accepted와 decision이 한 덩어리로 와도 차례대로 읽는다")
    func readsCoalescedMessages() throws {
        var joiner = try Rehearsal().joiner
        _ = joiner.receive([0] + Sample.hostNonce, at: .now)
        let transcript = try Self.transcript()
        let actions = joiner.receive(transcript.accepted(secret: Sample.secret) + (try Self.signed([2])), at: .now)
        #expect(
            actions == [
                .awaitingApproval(confirmationCode: transcript.confirmationCode(secret: Sample.secret)),
                .finish(.failure(.denied)),
            ])
    }

    // MARK: decision (J5)

    @Test("승인, 거절, 시간 초과")
    func readsDecisions() throws {
        var approved = try Self.waitingJoiner()
        let body = Self.approvedBody(stableID: Array("nEXAMPLEHOST".utf8), name: Array("거실 Mac".utf8))
        #expect(
            approved.receive(try Self.signed(body), at: .now)
                == [.finish(.success(Approval(stableID: "nEXAMPLEHOST", name: "거실 Mac")))])

        var unnamed = try Self.waitingJoiner()
        let bare = Self.approvedBody(stableID: Array("n".utf8), name: [])
        #expect(unnamed.receive(try Self.signed(bare), at: .now) == [.finish(.success(Approval(stableID: "n", name: "")))])

        var denied = try Self.waitingJoiner()
        #expect(denied.receive(try Self.signed([2]), at: .now) == [.finish(.failure(.denied))])
        var timedOut = try Self.waitingJoiner()
        #expect(timedOut.receive(try Self.signed([3]), at: .now) == [.finish(.failure(.timedOut))])
    }

    @Test("decision의 HMAC이 틀리면 hostNotVerified다. 본문만 바꿔도 걸린다")
    func rejectsWrongDecisionCode() throws {
        var flipped = try Self.signed([2])
        flipped[32] ^= 0x80
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive(flipped, at: .now) == [.finish(.failure(.hostNotVerified))])

        // 거절(2)의 HMAC을 시간 초과(3)에 붙인다.
        var swapped = try Self.signed([2])
        swapped[0] = 3
        var second = try Self.waitingJoiner()
        #expect(second.receive(swapped, at: .now) == [.finish(.failure(.hostNotVerified))])

        // 승인의 StableID 한 글자를 바꾼다.
        var renamed = try Self.signed(Self.approvedBody(stableID: Array("nEXAMPLEHOST".utf8), name: Array("mac".utf8)))
        renamed[2] = UInt8(ascii: "m")
        var third = try Self.waitingJoiner()
        #expect(third.receive(renamed, at: .now) == [.finish(.failure(.hostNotVerified))])

        // 다른 비밀로 만든 HMAC.
        let foreign = [2] + (try Self.transcript()).decisionCode(for: [2], secret: [UInt8](repeating: 0x5B, count: 32))
        var fourth = try Self.waitingJoiner()
        #expect(fourth.receive(foreign, at: .now) == [.finish(.failure(.hostNotVerified))])
    }

    @Test("모르는 상태는 위반이다", arguments: [UInt8(0), 4, 0xFF])
    func rejectsUnknownStatus(status: UInt8) throws {
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive([status], at: .now) == [.finish(.failure(.protocolViolation))])
    }

    @Test(
        "HMAC이 맞아도 내용이 규격과 다르면 위반이다",
        arguments: [
            JoinerSessionTests.approvedBody(stableID: [], name: Array("mac".utf8)),                         // StableID 길이 0
            JoinerSessionTests.approvedBody(stableID: Array("n\u{7F}".utf8), name: []),                     // 인쇄할 수 없는 ASCII
            JoinerSessionTests.approvedBody(stableID: Array("n\n".utf8), name: []),
            JoinerSessionTests.approvedBody(stableID: Array("né".utf8), name: []),                          // ASCII가 아니다
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: [UInt8](repeating: 0x61, count: 65)),   // 이름 65바이트
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: [0xFF]),                       // UTF-8이 아니다
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: [0xED, 0xA0, 0x80]),           // 대리 부호
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: Array("a\u{202E}b".utf8)),     // Cf
            JoinerSessionTests.approvedBody(stableID: Array("n".utf8), name: Array("a\u{1B}[2J".utf8)),     // Cc
        ])
    func rejectsInvalidApproval(body: [UInt8]) throws {
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive(try Self.signed(body), at: .now) == [.finish(.failure(.protocolViolation))])
    }

    @Test("decision 뒤에 바이트가 더 오면 위반이다")
    func rejectsTrailingBytes() throws {
        var joiner = try Self.waitingJoiner()
        #expect(joiner.receive(try Self.signed([2]) + [0], at: .now) == [.finish(.failure(.protocolViolation))])
    }

    @Test("StableID의 경계: 255바이트")
    func acceptsLongestStableID() throws {
        let stableID = [UInt8](repeating: UInt8(ascii: "n"), count: 255)
        let name = Array(String(repeating: "a", count: 64).utf8)
        var joiner = try Self.waitingJoiner()
        let message = try Self.signed(Self.approvedBody(stableID: stableID, name: name))
        var result: Result<Approval, PairingError>?
        for byte in message {
            #expect(result == nil)
            result = joiner.receive([byte], at: .now).result
        }
        #expect(result == .success(Approval(stableID: String(repeating: "n", count: 255), name: String(repeating: "a", count: 64))))
    }

    // MARK: 기한 (J1, J4)

    @Test("challenge 전의 기한은 받은 그대로이고 넘으면 unreachable이다")
    func timesOutBeforeChallenge() throws {
        var rehearsal = try Rehearsal()
        #expect(rehearsal.joiner.deadline == rehearsal.start + .seconds(60))
        #expect(rehearsal.joiner.advance(to: rehearsal.start + .seconds(59)).isEmpty)
        #expect(rehearsal.joiner.advance(to: rehearsal.start + .seconds(60)) == [.finish(.failure(.unreachable))])
    }

    @Test("proof를 보낸 때부터 130초 안에 decision이 없으면 timedOut이다")
    func timesOutWaitingForDecision() throws {
        let start = ContinuousClock.now
        var joiner = try Self.waitingJoiner(at: start + .seconds(5))
        #expect(joiner.deadline == start + .seconds(135))
        #expect(joiner.advance(to: start + .seconds(60)).isEmpty, "challenge의 기한은 이제 없다")
        #expect(joiner.advance(to: start + .milliseconds(134_999)).isEmpty)
        #expect(joiner.advance(to: start + .seconds(135)) == [.finish(.failure(.timedOut))])
        #expect(joiner.receive(try Self.signed([2]), at: start + .seconds(136)).isEmpty, "끝난 뒤의 바이트는 버린다")
    }

    // MARK: 연결의 두 끝 (5절, J2)

    @Test("중간에 낀 노드가 바이트를 넘겨주면 두 쪽이 본 끝이 달라 증명이 맞지 않는다")
    func relayedProofDoesNotVerify() throws {
        // 들어오는 쪽은 중계 노드(100.64.0.9)를 여는 쪽으로 보고, 여는 쪽은 중계 노드를 들어오는 쪽으로 본다.
        var rehearsal = try Rehearsal(
            hostSees: try Sample.endpoints(joiner: "100.64.0.9:50000", host: "100.64.0.1:4747"),
            joinerSees: try Sample.endpoints(joiner: "100.64.0.2:49152", host: "100.64.0.9:4747"))
        let challenge = rehearsal.toHost(rehearsal.joiner.hello)
        let proof = rehearsal.toJoiner(challenge.sentBytes)
        #expect(HostStep.steps(rehearsal.toHost(proof.sentBytes)) == [.finish(.wrongProof)])
        #expect(rehearsal.machine.hasOpenOffer)
    }

    @Test("끝 하나만 달라도 T와 네 값이 모두 달라진다", arguments: [
        ("100.64.0.3:49152", "100.64.0.1:4747"), ("100.64.0.2:49153", "100.64.0.1:4747"),
        ("100.64.0.2:49152", "100.64.0.4:4747"), ("100.64.0.2:49152", "100.64.0.1:4748"),
        ("[fd7a:115c:a1e0::2]:49152", "100.64.0.1:4747"),
    ])
    func transcriptBindsEndpoints(joiner: String, host: String) throws {
        let base = try Self.transcript()
        let other = PairingTranscript(
            joinerNonce: Sample.joinerNonce, hostNonce: Sample.hostNonce, offerHost: Sample.host,
            offerPort: Sample.port, deviceName: Array("rd-phone-5e6f7a8b".utf8),
            endpoints: try Sample.endpoints(joiner: joiner, host: host))
        #expect(other.bytes.count == 198 && other.bytes != base.bytes)
        #expect(other.proof(secret: Sample.secret) != base.proof(secret: Sample.secret))
        #expect(other.accepted(secret: Sample.secret) != base.accepted(secret: Sample.secret))
        #expect(other.decisionCode(for: [2], secret: Sample.secret) != base.decisionCode(for: [2], secret: Sample.secret))

        // 들어오는 쪽이 다른 끝을 보았으면 여는 쪽의 accepted도 받아들이지 않는다.
        var session = PairingJoinerSession(
            offer: Sample.offer(), deviceName: try Sample.deviceName(), nonce: Sample.joinerNonce,
            endpoints: try Sample.endpoints(joiner: joiner, host: host), challengeDeadline: .now + .seconds(60))
        _ = session.receive([0] + Sample.hostNonce, at: .now)
        #expect(session.receive(base.accepted(secret: Sample.secret), at: .now) == [.finish(.failure(.hostNotVerified))])
    }

    @Test("IPv4와 그 IPv4-mapped IPv6는 T에서 같은 16바이트다")
    func mapsIPv4() throws {
        let mapped = PairingTranscript(
            joinerNonce: Sample.joinerNonce, hostNonce: Sample.hostNonce, offerHost: Sample.host,
            offerPort: Sample.port, deviceName: Array("rd-phone-5e6f7a8b".utf8),
            endpoints: try Sample.endpoints(joiner: "[::ffff:100.64.0.2]:49152", host: "[::ffff:100.64.0.1]:4747"))
        #expect(mapped == (try Self.transcript()))
    }

    @Test(
        "tailnet 주소인가(J2)",
        arguments: [
            ("100.64.0.1", true), ("100.127.255.255", true), ("100.100.100.100", true), ("::ffff:100.64.0.1", true),
            ("fd7a:115c:a1e0::1", true), ("fd7a:115c:a1e0:ab12:4843:cd96:6264:1", true),
            ("100.63.255.255", false), ("100.128.0.0", false), ("101.64.0.1", false), ("127.0.0.1", false),
            ("192.168.0.1", false), ("10.0.0.1", false), ("::ffff:127.0.0.1", false), ("::1", false),
            ("fd7a:115c:a1e1::1", false), ("fe80::1", false), ("2001:db8::1", false),
        ])
    func recognizesTailnetAddresses(address: String, expected: Bool) throws {
        #expect(PairingEndpoints.isTailnetAddress(try #require(IPAddress(address))) == expected)
    }

    @Test("로컬 끝이 이 기기의 tailnet 주소이고 원격 끝이 tailnet 대역일 때만 터널을 거친 연결로 본다(J2)")
    func requiresLocalAddressAndTailnetPeer() throws {
        let local = try #require(IPAddress("100.64.0.2"))
        let local6 = try #require(IPAddress("fd7a:115c:a1e0::2"))
        #expect(try Sample.endpoints().isOnTailnet(localAddress: local))
        #expect(try Sample.endpoints(joiner: "[::ffff:100.64.0.2]:49152").isOnTailnet(localAddress: local))
        #expect(
            try Sample.endpoints(joiner: "[fd7a:115c:a1e0::2]:49152", host: "[fd7a:115c:a1e0::1]:4747")
                .isOnTailnet(localAddress: local6))

        // 터널이 꺼진 채 같은 대역을 쓰는 로컬 네트워크: 두 끝이 모두 100.64.0.0/10이지만 로컬 끝이 이 기기의 주소가 아니다.
        #expect(try !Sample.endpoints(joiner: "100.64.0.77:49152").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(joiner: "[fd7a:115c:a1e0::2]:49152").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(joiner: "192.168.0.7:49152").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(host: "203.0.113.5:4747").isOnTailnet(localAddress: local))
        #expect(try !Sample.endpoints(host: "192.168.0.1:4747").isOnTailnet(localAddress: local))
    }

    @Test("localAddress가 tailnet 대역 밖이면 걸지 않고 invalidConfiguration이다", arguments: ["192.168.0.7", "127.0.0.1", "100.128.0.1", "fe80::1"])
    func rejectsLocalAddressOutsideTailnet(address: String) async throws {
        let localAddress = try #require(IPAddress(address))
        let error = await pairingError {
            try await PairingJoiner.pair(with: Sample.offer(), deviceName: "rd-phone-5e6f7a8b", localAddress: localAddress)
        }
        guard case .invalidConfiguration = error else {
            Issue.record("invalidConfiguration이어야 한다: \(String(describing: error))")
            return
        }
    }
}
