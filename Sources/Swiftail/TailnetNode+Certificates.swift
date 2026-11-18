import Foundation
import SwiftailControl
import Synchronization

/// Node facts the certificate manager (`SwiftailCertificates.CertificateManager`) uses to evaluate issuance requirements.
///
/// Contains only the values read by the four conditions in contract `docs/contracts/SwiftailHost.md` behavior C1. The
/// manager decides which condition failed.
package struct CertificateFacts: Sendable, Equatable {
    /// The node is `.running`.
    package var isRunning: Bool
    /// The local MagicDNS name with its trailing dot removed (`rd-mac-1a2b3c4d.tail0001.ts.net`). Nil before a netmap
    /// or if the name is missing.
    package var fqdn: String?
    /// Names eligible for ts.net certificates (netmap `DNSConfig.CertDomains`). Empty before a netmap or `DNSConfig`.
    package var certDomains: [String]
    /// MagicDNS is enabled on the tailnet (netmap `DNSConfig.Proxied`). Uses the same origin as Go
    /// `ipnstate.TailnetStatus.MagicDNSEnabled` (`updateStatus` in `ipn/ipnlocal/local.go`,
    /// `MagicDNSEnabled = nm.DNS.Proxied`).
    package var isMagicDNSEnabled: Bool

    /// Stores the values as supplied. Used by the manager's tests and to create facts after the node stops.
    package init(isRunning: Bool, fqdn: String?, certDomains: [String], isMagicDNSEnabled: Bool) {
        (self.isRunning, self.fqdn, self.certDomains, self.isMagicDNSEnabled) = (isRunning, fqdn, certDomains, isMagicDNSEnabled)
    }

    /// Reads from the node state and last netmap.
    init(state: NodeState, netmap: Netmap?) {
        let status = NodeStatus(state: state, netmap: netmap, networkSettings: nil)
        isRunning = state == .running
        fqdn = status.fqdn
        certDomains = status.certDomains
        isMagicDNSEnabled = netmap?.dnsConfig?.proxied ?? false
    }
}

/// The `package` entry point for the certificate target to access node internals. Contract
/// `docs/contracts/SwiftailHost.md`, declaration at the start of §8, behaviors D and C1.
extension TailnetNode {
    /// The ACME DNS-01 record prefix. Publishes only this prefix plus the local cert domain (behavior D4).
    static let acmeChallengePrefix = "_acme-challenge."

    /// Publishes the ACME DNS-01 TXT record for the local cert domain to the control server. Returns when the control server replies.
    ///
    /// `name` must be `_acme-challenge.` plus the local FQDN without a trailing dot, and that FQDN must be among the
    /// current netmap's cert domains. The name and value are omitted from logs and error strings (behavior K2).
    ///
    /// - Throws: `connection` if the node is not `.running` or is outside `run()`, and `invalidConfiguration` if the
    ///   name fails the condition above. Otherwise throws failures from `ControlClient.setDNS(name:value:)`
    ///   (`connection` at the 60-second deadline or `http(status:)` for a response other than 200).
    package func setDNS(name: String, value: String) async throws(ControlError) {
        let facts = CertificateFacts(state: stateMachine.state, netmap: lastNetmap)
        guard facts.isRunning else { throw .connection("Node is not running") }
        // Compare bytes. `String`'s `==` uses Unicode canonical equivalence, so a name it deems equal may have different bytes on the wire.
        guard let fqdn = facts.fqdn, facts.certDomains.contains(fqdn),
              name.utf8.elementsEqual((Self.acmeChallengePrefix + fqdn).utf8)
        else {
            throw .invalidConfiguration("The set-dns name is not the ACME record for the node's own cert domain")
        }
        guard let control else { throw .connection("Node is not running") }
        try await control.setDNS(name: name, value: value)
    }

    /// New facts whenever state, local name, cert domains, or MagicDNS enablement changes. Subscription starts with the current value.
    ///
    /// Keeps only the newest unread value. There is one subscriber, the certificate manager. Each access returns a new
    /// stream and ends the previous one, so replacing a stopped manager on the same node starts with the current value.
    /// The stream ends when `run()` ends.
    package nonisolated var certificateFacts: AsyncStream<CertificateFacts> { certificateFactsPublisher.subscribe() }

    /// The node's state directory. The certificate manager stores files in `certs/` beneath it.
    package nonisolated var stateDirectory: URL { configuration.stateDirectory }

    /// Publishes the current facts if they differ from the last published ones. Called where state or netmap changes.
    func publishCertificateFacts() {
        certificateFactsPublisher.publish(CertificateFacts(state: stateMachine.state, netmap: lastNetmap))
    }
}

/// Holds one `certificateFacts` subscription. A lock protects it because subscription (`nonisolated`) and publication
/// (node actor) are called from different contexts.
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

    /// Creates a new subscription starting with the current value and ends the previous stream. After `finish()`, emits
    /// only the last value and ends.
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

    /// Publishes a value if it differs from the last one.
    func publish(_ facts: CertificateFacts) {
        state.withLock { state in
            guard !state.isFinished, facts != state.latest else { return }
            state.latest = facts
            state.continuation?.yield(facts)
        }
    }

    /// Ends the stream when `run()` ends.
    func finish() {
        state.withLock { state in
            state.isFinished = true
            state.continuation?.finish()
            state.continuation = nil
        }
    }
}
