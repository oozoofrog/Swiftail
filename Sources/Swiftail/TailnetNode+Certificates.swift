import Foundation
import SwiftailControl
import Synchronization

/// 인증서 관리자(`SwiftailCertificates.CertificateManager`)가 발급 조건을 판단하는 데 쓰는 노드의 사실.
///
/// 계약 `docs/contracts/SwiftailHost.md` 동작 C1의 네 조건이 읽는 값만 담는다. 판단(어느 실패인지)은 관리자가 한다.
package struct CertificateFacts: Sendable, Equatable {
    /// 노드가 `.running`이다.
    package var isRunning: Bool
    /// 자기 MagicDNS 이름에서 끝의 점을 뗀 것(`rd-mac-1a2b3c4d.tail0001.ts.net`). netmap 전이나 이름이 없으면 nil.
    package var fqdn: String?
    /// ts.net 인증서를 받을 수 있는 이름(netmap `DNSConfig.CertDomains`). netmap·`DNSConfig` 전이면 비어 있다.
    package var certDomains: [String]
    /// tailnet에서 MagicDNS가 켜져 있다(netmap `DNSConfig.Proxied`). Go `ipnstate.TailnetStatus.MagicDNSEnabled`의
    /// 출처와 같다(`ipn/ipnlocal/local.go` `updateStatus`: `MagicDNSEnabled = nm.DNS.Proxied`).
    package var isMagicDNSEnabled: Bool

    /// 값을 그대로 담는다. 관리자의 시험과, 노드가 멈춘 뒤의 사실을 만드는 데 쓴다.
    package init(isRunning: Bool, fqdn: String?, certDomains: [String], isMagicDNSEnabled: Bool) {
        (self.isRunning, self.fqdn, self.certDomains, self.isMagicDNSEnabled) = (isRunning, fqdn, certDomains, isMagicDNSEnabled)
    }

    /// 노드의 상태와 마지막 netmap에서 읽는다.
    init(state: NodeState, netmap: Netmap?) {
        let status = NodeStatus(state: state, netmap: netmap, networkSettings: nil)
        isRunning = state == .running
        fqdn = status.fqdn
        certDomains = status.certDomains
        isMagicDNSEnabled = netmap?.dnsConfig?.proxied ?? false
    }
}

/// 인증서 타깃이 노드의 안쪽에 닿는 `package` 접점. 계약 `docs/contracts/SwiftailHost.md` 8절 머리의 선언, 동작 D·C1.
extension TailnetNode {
    /// ACME DNS-01의 레코드 접두. 이 접두 + 자기 cert 도메인만 올린다(동작 D4).
    static let acmeChallengePrefix = "_acme-challenge."

    /// 자기 cert 도메인의 ACME DNS-01 TXT 레코드를 제어 서버에 올린다. 제어 서버가 답하면 돌아온다.
    ///
    /// `name`은 `_acme-challenge.` + 자기 FQDN(끝 점 없음)이어야 하고, 그 FQDN이 지금 netmap의 cert 도메인에 있어야 한다.
    /// 이름과 값은 로그와 오류 문자열에 남지 않는다(동작 K2).
    ///
    /// - Throws: 노드가 `.running`이 아니거나 `run()` 밖이면 `connection`. 이름이 위 조건에 맞지 않으면
    ///   `invalidConfiguration`. 그 밖은 `ControlClient.setDNS(name:value:)`의 실패(60초 기한은 `connection`,
    ///   200이 아닌 응답은 `http(status:)`).
    package func setDNS(name: String, value: String) async throws(ControlError) {
        let facts = CertificateFacts(state: stateMachine.state, netmap: lastNetmap)
        guard facts.isRunning else { throw .connection("노드가 running이 아니다") }
        // 바이트로 견준다. `String`의 `==`는 유니코드 정준 동치라서, 같다고 판정한 이름과 실제로 보내는 바이트가 다를 수 있다.
        guard let fqdn = facts.fqdn, facts.certDomains.contains(fqdn),
              name.utf8.elementsEqual((Self.acmeChallengePrefix + fqdn).utf8)
        else {
            throw .invalidConfiguration("set-dns 이름이 자기 cert 도메인의 ACME 레코드가 아니다")
        }
        guard let control else { throw .connection("노드가 running이 아니다") }
        try await control.setDNS(name: name, value: value)
    }

    /// 상태·자기 이름·cert 도메인·MagicDNS 켬 가운데 하나라도 바뀔 때마다 새 사실. 구독하면 지금 값부터 나온다.
    ///
    /// 읽지 않은 것은 가장 새 것 하나만 남는다. 구독자는 하나(인증서 관리자)다: 읽을 때마다 새 흐름을 내고 앞서 낸 흐름은
    /// 끝낸다(관리자를 멈추고 같은 노드에 새로 두어도 지금 값부터 받는다). `run()`이 끝나면 흐름도 끝난다.
    package nonisolated var certificateFacts: AsyncStream<CertificateFacts> { certificateFactsPublisher.subscribe() }

    /// 노드의 상태 디렉터리. 인증서 관리자가 그 아래 `certs/`에 저장한다.
    package nonisolated var stateDirectory: URL { configuration.stateDirectory }

    /// 지금의 사실이 마지막으로 낸 것과 다르면 낸다. 상태나 netmap이 바뀐 자리에서 부른다.
    func publishCertificateFacts() {
        certificateFactsPublisher.publish(CertificateFacts(state: stateMachine.state, netmap: lastNetmap))
    }
}

/// `certificateFacts`의 구독 하나를 쥔다. 구독(`nonisolated`)과 내기(노드 actor)가 다른 곳에서 불리므로 잠금으로 지킨다.
final class CertificateFactsPublisher: Sendable {
    private struct State {
        var latest: CertificateFacts
        var continuation: AsyncStream<CertificateFacts>.Continuation?
        var isFinished = false
    }

    private let state: Mutex<State>

    init(_ initial: CertificateFacts) {
        state = Mutex(State(latest: initial))
    }

    /// 새 구독. 지금 값부터 나온다. 앞선 구독의 흐름은 끝난다. `finish()` 뒤에는 마지막 값만 내고 끝난다.
    func subscribe() -> AsyncStream<CertificateFacts> {
        let (stream, continuation) = AsyncStream.makeStream(of: CertificateFacts.self, bufferingPolicy: .bufferingNewest(1))
        state.withLock { state in
            state.continuation?.finish()
            continuation.yield(state.latest)
            if state.isFinished {
                continuation.finish()
            } else {
                state.continuation = continuation
            }
        }
        return stream
    }

    /// 마지막으로 낸 것과 다르면 낸다.
    func publish(_ facts: CertificateFacts) {
        state.withLock { state in
            guard !state.isFinished, facts != state.latest else { return }
            state.latest = facts
            state.continuation?.yield(facts)
        }
    }

    /// 흐름을 끝낸다(`run()`이 끝날 때).
    func finish() {
        state.withLock { state in
            state.isFinished = true
            state.continuation?.finish()
            state.continuation = nil
        }
    }
}
