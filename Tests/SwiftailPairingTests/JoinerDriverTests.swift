import Foundation
import Synchronization
import Testing
@testable import SwiftailPairing

/// 들어오는 쪽의 가장자리(`PairingJoiner.join`): 다시 걸기(J1), 취소(J7), 확인 숫자 알림, 여는 쪽 확인(J6).
/// 연결은 여는 쪽 상태 기계를 물린 메모리 안의 것이다(계약 7절 시험 4의 "취소").
@Suite("들어오는 쪽 구동", .timeLimit(.minutes(1)))
struct JoinerDriverTests {
    /// 여는 쪽 상태 기계가 답하는 가짜 연결.
    final class RehearsedHost: PairingTransport {
        /// 여는 쪽 앱의 답. nil이면 답하지 않는다(승인을 기다리는 채로 둔다).
        let decision: Bool?
        private let machine: Mutex<PairingHostMachine>
        private let replies: AsyncStream<[UInt8]>
        private let continuation: AsyncStream<[UInt8]>.Continuation
        private let closed = Mutex(false)
        private let requested = Mutex<String?>(nil)

        init(offer: PairingOffer = Sample.offer(), decision: Bool? = true) throws {
            var machine = PairingHostMachine()
            machine.open(offer)
            _ = machine.accept(
                1, from: Sample.joinerIdentity, endpoints: try Sample.endpoints(), nonce: Sample.hostNonce, at: .now)
            self.machine = Mutex(machine)
            self.decision = decision
            (replies, continuation) = AsyncStream.makeStream(of: [UInt8].self)
        }

        var isClosed: Bool { closed.withLock { $0 } }
        /// 여는 쪽이 앱에 보인 확인 숫자.
        var confirmationCode: String? { requested.withLock { $0 } }

        func send(_ bytes: [UInt8]) async {
            let actions = machine.withLock { machine in
                var actions = machine.receive(bytes, on: 1, wallClock: Sample.wallClock, now: .now)
                if case .requestDecision? = actions.last, let decision {
                    actions += machine.decided(
                        1, approved: decision, currentPeer: Sample.joinerIdentity, host: Sample.hostIdentity,
                        at: Sample.wallClock)
                    if case .save? = actions.last { actions += machine.saved(1, succeeded: true) }
                }
                return actions
            }
            for action in actions {
                switch action {
                case .send(let reply): continuation.yield(reply)
                case .requestDecision(let request): requested.withLock { $0 = request.confirmationCode }
                case .finish: continuation.finish()
                case .save: break
                }
            }
        }

        func receive() async -> [UInt8]? {
            for await reply in replies { return reply }
            return nil
        }

        func close() async {
            closed.withLock { $0 = true }
        }
    }

    /// 받자마자 닫는 연결(여는 쪽이 이 노드를 아직 몰라 읽지 않고 닫는 경우).
    struct ClosedAtOnce: PairingTransport {
        func receive() async -> [UInt8]? { nil }
        func send(_ bytes: [UInt8]) async {}
        func close() async {}
    }

    /// 차례대로 내놓을 걸기 결과.
    final class Dialer: Sendable {
        private let results: Mutex<[PairingJoiner.Dialed]>
        private let calls = Mutex(0)

        init(_ results: [PairingJoiner.Dialed]) {
            self.results = Mutex(results)
        }

        var callCount: Int { calls.withLock { $0 } }

        func dial() -> PairingJoiner.Dialed {
            calls.withLock { $0 += 1 }
            return results.withLock { $0.isEmpty ? .unreachable : $0.removeFirst() }
        }
    }

    private static func join(
        _ dialer: Dialer, deviceName: String = "rd-phone-5e6f7a8b",
        awaitingApproval: @escaping @Sendable (String) -> Void = { _ in },
        verifyHost: @escaping @Sendable (String, PairingEndpoints) async -> Bool = { _, _ in true }
    ) async throws(PairingError) -> PairedHost {
        try await PairingJoiner.join(
            Sample.offer(), deviceName: deviceName, awaitingApproval: awaitingApproval, dial: { dialer.dial() },
            verifyHost: verifyHost)
    }

    @Test("승인되면 짝을 돌려주고, 확인 숫자는 여는 쪽이 본 것과 같고 한 번만 알린다")
    func pairs() async throws {
        let host = try RehearsedHost()
        let dialer = Dialer([.connected(host, try Sample.endpoints())])
        let codes = Mutex<[String]>([])
        let before = Date()
        let paired = try await Self.join(dialer) { code in codes.withLock { $0.append(code) } }
        #expect(paired.host == Sample.host)
        #expect(paired.stableID == "nEXAMPLEHOST" && paired.name == "rd-mac-1a2b3c4d")
        #expect(paired.pairedAt >= before && paired.pairedAt <= Date())
        #expect(codes.withLock { $0 } == [try #require(host.confirmationCode)])
        #expect(host.isClosed && dialer.callCount == 1)
    }

    @Test("PairedHost는 Codable로 보관한다")
    func pairedHostRoundTrips() async throws {
        let paired = try await Self.join(Dialer([.connected(try RehearsedHost(), try Sample.endpoints())]))
        let decoded = try JSONDecoder().decode(PairedHost.self, from: try JSONEncoder().encode(paired))
        #expect(decoded == paired)
    }

    @Test("기기 이름이 맞지 않으면 걸지 않는다", arguments: ["", String(repeating: "a", count: 65), "a\u{202E}b", "a\nb"])
    func rejectsDeviceName(name: String) async {
        let dialer = Dialer([])
        let error = await pairingError { try await Self.join(dialer, deviceName: name) }
        guard case .invalidConfiguration = error else {
            Issue.record("invalidConfiguration이어야 한다: \(String(describing: error))")
            return
        }
        #expect(dialer.callCount == 0)
    }

    @Test("닿지 못하면 1초 뒤에 다시 건다: 걸지 못함, 읽지 않고 닫힘, 그다음 성공(J1)")
    func redials() async throws {
        let host = try RehearsedHost()
        let dialer = Dialer([.unreachable, .connected(ClosedAtOnce(), try Sample.endpoints()), .connected(host, try Sample.endpoints())])
        let started = ContinuousClock.now
        let paired = try await Self.join(dialer)
        #expect(paired.stableID == "nEXAMPLEHOST")
        #expect(dialer.callCount == 3)
        #expect(started.duration(to: .now) >= .seconds(2), "두 번 다시 걸었다")
    }

    @Test("다시 걸어도 소용없는 실패는 그대로 낸다", arguments: [PairingError.notOnTailnet, .invalidConfiguration("시험")])
    func doesNotRedialAfterFailure(failure: PairingError) async {
        let dialer = Dialer([.failed(failure)])
        #expect(await pairingError { try await Self.join(dialer) } == failure)
        #expect(dialer.callCount == 1)
    }

    @Test("challenge를 받은 뒤의 실패에는 다시 걸지 않는다")
    func doesNotRedialAfterChallenge() async throws {
        let closedOffer = try RehearsedHost(offer: Sample.offer(expires: Sample.wallClock))   // 만료: 상태 1
        let dialer = Dialer([.connected(closedOffer, try Sample.endpoints())])
        #expect(await pairingError { try await Self.join(dialer) } == .rejected)
        #expect(dialer.callCount == 1 && closedOffer.isClosed)

        let wrongSecret = try RehearsedHost(offer: Sample.offer(secret: [UInt8](repeating: 0x5B, count: 32)))
        let second = Dialer([.connected(wrongSecret, try Sample.endpoints())])
        #expect(await pairingError { try await Self.join(second) } == .rejected)
        #expect(second.callCount == 1)
    }

    @Test("거절은 denied다")
    func reportsDenial() async throws {
        let host = try RehearsedHost(decision: false)
        let error = await pairingError { try await Self.join(Dialer([.connected(host, try Sample.endpoints())])) }
        #expect(error == .denied && host.isClosed)
    }

    @Test("승인된 StableID가 연결 상대의 것이 아니면 hostNotVerified다(J6)")
    func verifiesHostIdentity() async throws {
        let host = try RehearsedHost()
        let asked = Mutex<[String]>([])
        let error = await pairingError {
            try await Self.join(
                Dialer([.connected(host, try Sample.endpoints())]),
                verifyHost: { stableID, _ in
                    asked.withLock { $0.append(stableID) }
                    return false
                })
        }
        #expect(error == .hostNotVerified && host.isClosed)
        #expect(asked.withLock { $0 } == ["nEXAMPLEHOST"])
    }

    @Test("승인을 기다리는 동안 취소하면 연결을 끊고 cancelled다(J7)")
    func cancelsWhileAwaitingApproval() async throws {
        let host = try RehearsedHost(decision: nil)
        let dialer = Dialer([.connected(host, try Sample.endpoints())])
        let (waiting, signal) = AsyncStream.makeStream(of: Void.self)
        let pairing = Task {
            await pairingError { try await Self.join(dialer) { _ in signal.yield() } }
        }
        for await _ in waiting { break }
        #expect(!host.isClosed)
        pairing.cancel()
        #expect(await pairing.value == .cancelled)
        #expect(host.isClosed && dialer.callCount == 1)
    }

    @Test("다시 걸기를 기다리는 동안 취소해도 cancelled다")
    func cancelsWhileRedialing() async throws {
        let dialer = Dialer([])
        let pairing = Task { await pairingError { try await Self.join(dialer) } }
        while dialer.callCount == 0 { try await Task.sleep(for: .milliseconds(5)) }
        pairing.cancel()
        #expect(await pairing.value == .cancelled)
        #expect(dialer.callCount == 1)
    }
}
