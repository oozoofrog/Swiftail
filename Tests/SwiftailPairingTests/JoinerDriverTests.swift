import Foundation
import Synchronization
import Testing
@testable import SwiftailPairing

/// Tests the joiner edge (`PairingJoiner.join`): retries (J1), cancellation (J7), SAS notification, and host verification (J6).
/// The in-memory connection is wired to the host state machine (contract §7 test 4, cancellation).
@Suite("Joiner driver", .timeLimit(.minutes(1)))
struct JoinerDriverTests {
    /// A fake connection that uses the host state machine to respond.
    final class RehearsedHost: PairingTransport {
        /// The host app's response. A nil value sends no response and leaves approval pending.
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
        /// The SAS that the host showed the app.
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

    /// A connection that closes immediately on acceptance, as when the host does not yet know this node and closes without reading.
    struct ClosedAtOnce: PairingTransport {
        func receive() async -> [UInt8]? { nil }
        func send(_ bytes: [UInt8]) async {}
        func close() async {}
    }

    /// The dial results to return in order.
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

    @Test("Approval returns the paired peer and reports the same SAS the host saw, exactly once")
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

    @Test("PairedHost is stored using Codable")
    func pairedHostRoundTrips() async throws {
        let paired = try await Self.join(Dialer([.connected(try RehearsedHost(), try Sample.endpoints())]))
        let decoded = try JSONDecoder().decode(PairedHost.self, from: try JSONEncoder().encode(paired))
        #expect(decoded == paired)
    }

    @Test("An invalid device name prevents dialing", arguments: ["", String(repeating: "a", count: 65), "a\u{202E}b", "a\nb"])
    func rejectsDeviceName(name: String) async {
        let dialer = Dialer([])
        let error = await pairingError { try await Self.join(dialer, deviceName: name) }
        guard case .invalidConfiguration = error else {
            Issue.record("Expected invalidConfiguration: \(String(describing: error))")
            return
        }
        #expect(dialer.callCount == 0)
    }

    @Test("An unreachable host is retried after 1 second: dial failure, close without reading, then success (J1)")
    func redials() async throws {
        let host = try RehearsedHost()
        let dialer = Dialer([.unreachable, .connected(ClosedAtOnce(), try Sample.endpoints()), .connected(host, try Sample.endpoints())])
        let started = ContinuousClock.now
        let paired = try await Self.join(dialer)
        #expect(paired.stableID == "nEXAMPLEHOST")
        #expect(dialer.callCount == 3)
        #expect(started.duration(to: .now) >= .seconds(2), "Dialing was retried twice")
    }

    @Test("Nonretryable failures are returned unchanged", arguments: [PairingError.notOnTailnet, .invalidConfiguration("test")])
    func doesNotRedialAfterFailure(failure: PairingError) async {
        let dialer = Dialer([.failed(failure)])
        #expect(await pairingError { try await Self.join(dialer) } == failure)
        #expect(dialer.callCount == 1)
    }

    @Test("Failure after receiving challenge never retries")
    func doesNotRedialAfterChallenge() async throws {
        let closedOffer = try RehearsedHost(offer: Sample.offer(expires: Sample.wallClock))   // Expired: status 1
        let dialer = Dialer([.connected(closedOffer, try Sample.endpoints())])
        #expect(await pairingError { try await Self.join(dialer) } == .rejected)
        #expect(dialer.callCount == 1 && closedOffer.isClosed)

        let wrongSecret = try RehearsedHost(offer: Sample.offer(secret: [UInt8](repeating: 0x5B, count: 32)))
        let second = Dialer([.connected(wrongSecret, try Sample.endpoints())])
        #expect(await pairingError { try await Self.join(second) } == .rejected)
        #expect(second.callCount == 1)
    }

    @Test("Rejection returns denied")
    func reportsDenial() async throws {
        let host = try RehearsedHost(decision: false)
        let error = await pairingError { try await Self.join(Dialer([.connected(host, try Sample.endpoints())])) }
        #expect(error == .denied && host.isClosed)
    }

    @Test("Approval with a StableID other than the connected peer's returns hostNotVerified (J6)")
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

    @Test("Canceling while waiting for approval closes the connection and returns cancelled (J7)")
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

    @Test("Canceling while waiting to retry also returns cancelled")
    func cancelsWhileRedialing() async throws {
        let dialer = Dialer([])
        let pairing = Task { await pairingError { try await Self.join(dialer) } }
        while dialer.callCount == 0 { try await Task.sleep(for: .milliseconds(5)) }
        pairing.cancel()
        #expect(await pairing.value == .cancelled)
        #expect(dialer.callCount == 1)
    }
}
