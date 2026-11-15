// 구동 함수 `issueCertificate`: 상태 기계를 전송·시계·TXT 올리기와 함께 끝까지 돌리고, 취소되면 멈춘다.

import Foundation
import Synchronization
import Testing

@testable import SwiftailCertificates

@Suite("ACME 구동 함수")
struct ACMEIssuanceTests {
    @Test("가짜 전송과 시계로 발급을 끝까지 돌린다")
    func runsToCompletion() async throws {
        let transport = QueueTransport(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization() + [
            Steps.readOrder(Body.order("ready")),
            Exchange.post(Fake.finalizeURL, 200, Body.order("processing")).header("Retry-After", "3"),
            Steps.readOrder(Body.order("valid", certificate: Fake.certificateURL)),
            Steps.download,
        ])
        let clock = Mutex(Fake.start)
        let published = Mutex<[String]>([])
        let result = try await issueCertificate(
            with: ACMEScript().flow,
            transport: transport,
            now: { clock.withLock { $0 } },
            sleep: { until in clock.withLock { $0 = max($0, until) } },
            publishTXT: { name, _ in
                published.withLock { $0.append(name) }
                return nil
            }
        )
        #expect(result == .issued(certificateChainPEM: Fake.chainPEM, accountURL: Fake.accountURL))
        #expect(published.withLock { $0 } == ["_acme-challenge." + Fake.domainName])
        #expect(clock.withLock { $0 } == Fake.start.addingTimeInterval(3))
        #expect(transport.remaining == 0)
    }

    @Test("TXT 올리기의 실패가 결과가 된다")
    func publishFailure() async throws {
        let transport = QueueTransport(Steps.accountFound + [Steps.newOrder(Body.order("pending"))] + Steps.pendingAuthorization())
        let result = try await issueCertificate(
            with: ACMEScript().flow,
            transport: transport,
            now: { Fake.start },
            sleep: { _ in },
            publishTXT: { _, _ in .network("control") }
        )
        #expect(result == .failed(.network("control"), retryNotBefore: nil, accountURL: Fake.accountURL))
    }

    @Test("기다리는 중에 취소되면 CancellationError를 던지고 요청을 더 보내지 않는다")
    func cancellation() async throws {
        let transport = QueueTransport(Steps.accountFound + [
            Steps.newOrder(Body.order("ready")),
            .post(Fake.finalizeURL, 200, Body.order("processing")),
        ])
        let task = Task {
            try await issueCertificate(
                with: ACMEScript().flow,
                transport: transport,
                now: { Date() },
                sleep: { (_: Date) async throws(CancellationError) in
                    // 실제로 오래 기다린다. 취소가 깨운다.
                    try await sleepUntil(Date().addingTimeInterval(3600))
                },
                publishTXT: { _, _ in nil }
            )
        }
        while transport.remaining > 0 {
            try await Task.sleep(for: .milliseconds(5))
        }
        task.cancel()
        await #expect(throws: CancellationError.self) {
            _ = try await task.value
        }
        #expect(transport.sent == 5)
    }
}

/// 받은 요청에 교환을 차례로 돌려주는 전송. 요청의 모양은 `ACMEScript`가 따로 본다.
private final class QueueTransport: ACMETransport {
    private let state: Mutex<(queue: [Exchange], sent: Int, nonce: Int)>

    init(_ exchanges: [Exchange]) {
        state = Mutex((exchanges, 0, 0))
    }

    var remaining: Int { state.withLock { $0.queue.count } }
    var sent: Int { state.withLock { $0.sent } }

    func send(_ request: ACMEHTTPRequest) async throws(ACMETransportError) -> ACMEHTTPResponse {
        try state.withLock { (state) throws(ACMETransportError) -> ACMEHTTPResponse in
            state.sent += 1
            guard !state.queue.isEmpty else { throw .network }
            let exchange = state.queue.removeFirst()
            var headers = exchange.headers
            if case .fresh = exchange.nonce {
                state.nonce += 1
                headers.append(.init(name: "Replay-Nonce", value: "nonce-\(state.nonce)"))
            }
            return ACMEHTTPResponse(status: exchange.status, headers: headers, body: exchange.body)
        }
    }
}
