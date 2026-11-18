import Foundation

/// Drives the order flow (`ACMEOrderFlow`) to completion with transport, a clock, and TXT publication. This function drives the flow at the edge.
///
/// Performs each emitted action in order. Sends requests through `transport`, waits with `sleep(until:)`, and publishes TXT records
/// through `publishTXT`. Reads `now()` afresh for each input (including the time after a long wait, contract behavior R6).
/// Runs within the calling Task without creating a new Task (structured concurrency).
///
/// - Parameters:
///   - flow: An unstarted order flow.
///   - transport: The HTTP round trip to the ACME server.
///   - now: The wall clock. Defaults to `Date()`.
///   - sleep: Waits until the given time. Throws `CancellationError` on cancellation. Defaults to `Task.sleep`.
///   - publishTXT: Publishes the TXT record for `_acme-challenge.<name>` using the control server's `set-dns`. Returns nil on success or
///     the failure kind (`controlRejected`, `network`, etc.) on failure. That failure becomes this attempt's result. (The public contract
///     declaration of CertificateFailure does not conform to `Error`, so the function returns it.)
/// - Returns: The issuance result, including failures.
/// - Throws: `CancellationError` if the calling Task is canceled. No further requests go out after cancellation.
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

/// Waits from now until the given time with `Task.sleep` by default.
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
