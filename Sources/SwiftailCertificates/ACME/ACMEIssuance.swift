import Foundation

/// 주문 절차(`ACMEOrderFlow`)를 전송·시계·TXT 올리기와 함께 끝까지 돌린다. 가장자리의 구동 함수다.
///
/// 절차가 낸 일을 차례로 한다: 요청을 `transport`로 보내고, 기다림은 `sleep(until:)`으로 기다리고, TXT는
/// `publishTXT`로 올린다. 시각은 입력을 넘길 때마다 `now()`로 새로 읽는다(긴 기다림 뒤의 시각. 계약 동작 R6).
/// 새 Task를 만들지 않고 부른 Task 안에서 돈다(구조적 동시성).
///
/// - Parameters:
///   - flow: 시작하지 않은 절차.
///   - transport: ACME 서버와의 HTTP 왕복.
///   - now: 벽시계. 기본은 `Date()`.
///   - sleep: 그 시각까지 기다린다. 취소되면 `CancellationError`를 던진다. 기본은 `Task.sleep`.
///   - publishTXT: `_acme-challenge.<이름>`의 TXT 레코드를 올린다(제어 서버의 `set-dns`). 올렸으면 nil, 아니면 실패의
///     종류(`controlRejected`, `network` 등)를 돌려준다. 그 실패가 이 시도의 결과가 된다. (`CertificateFailure`는 계약의
///     공개 선언대로 `Error`가 아니어서 던지지 않고 돌려준다.)
/// - Returns: 발급의 결과. 실패도 결과로 돌려준다.
/// - Throws: 부른 Task가 취소되면 `CancellationError`. 취소된 뒤에는 요청을 더 보내지 않는다.
func issueCertificate(
    with flow: ACMEOrderFlow,
    transport: some ACMETransport,
    now: @Sendable () -> Date = { Date() },
    sleep: @Sendable (_ until: Date) async throws(CancellationError) -> Void = sleepUntil,
    publishTXT: @Sendable (_ name: String, _ value: String) async -> CertificateFailure?
) async throws(CancellationError) -> ACMEIssuanceResult {
    var flow = flow
    var step = flow.start(at: now())
    while true {
        try checkCancellation()
        switch step {
        case .finished(let result):
            return result
        case .send(let request):
            let response: ACMEHTTPResponse
            do {
                response = try await transport.send(request)
            } catch {
                try checkCancellation()
                step = flow.transportFailed(error, at: now())
                continue
            }
            try checkCancellation()
            step = flow.receive(response, at: now())
        case .wait(let until):
            try await sleep(until)
            step = flow.resume(at: now())
        case .publishTXT(let name, let value):
            let failure = await publishTXT(name, value)
            try checkCancellation()
            if let failure {
                step = flow.txtPublishingFailed(failure, at: now())
            } else {
                step = flow.txtPublished(at: now())
            }
        }
    }
}

/// 기본 기다림: 지금부터 그 시각까지 `Task.sleep`.
@Sendable
func sleepUntil(_ date: Date) async throws(CancellationError) {
    let interval = date.timeIntervalSinceNow
    guard interval > 0 else { return }
    do {
        try await Task.sleep(for: .seconds(interval))
    } catch {
        throw CancellationError()
    }
}

private func checkCancellation() throws(CancellationError) {
    if Task.isCancelled {
        throw CancellationError()
    }
}
