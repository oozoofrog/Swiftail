import CoreGraphics
import Foundation
import Observation
import Swiftail
import SwiftailPairing

/// Acts as the host. Opens offers, asks the user to approve joining devices, maintains the paired peer list, and returns greetings only to paired peers.
///
/// `start(on:)` creates a `PairingHost` on the node and `stop()` shuts it down. Between them, one TaskGroup in `serve` handles the work:
///
/// ```
/// serve
///  ├ PairingHost.run()   Pairing port (4747). Cancels the other tasks when it finishes
///  ├ greet               Example of a connection after pairing (4748)
///  └ PairingHost.events  Reloads the paired peer list when it changes
/// ```
@MainActor @Observable
final class HostModel {
    /// An approval request awaiting the user's response.
    struct Approval: Identifiable {
        let id: UUID
        let request: PairingRequest
        fileprivate let answer: CheckedContinuation<Bool, Never>
    }

    /// An offer shown on screen. The link and QR code are secret.
    struct OpenOffer {
        let url: URL
        let qrCode: CGImage?
        let expires: Date
        let carriesAuthKey: Bool
    }

    static let pairingPort: UInt16 = 4747
    static let greetingPort: UInt16 = 4748
    /// The offer link prefix. It must match the URL scheme in `Info.plist` to open the joiner app.
    static let linkBase: URL = {
        guard let url = URL(string: "swiftail-demo://pair") else { preconditionFailure("The fixed link prefix is a valid URL") }
        return url
    }()

    /// Whether the host is running.
    var isRunning: Bool { host != nil }
    private(set) var offer: OpenOffer?
    /// The number of offers opened on this host and the number reported by `.opened` events. State events belong to the current offer only when the counts match.
    @ObservationIgnored private var openedOffers = 0
    @ObservationIgnored private var announcedOffers = 0
    private(set) var approvals: [Approval] = []
    private(set) var peers: [PairedPeer] = []
    /// The saved OAuth client ID, or nil if absent.
    private(set) var oauthClientID = OAuthClientKeychain.load()?.id
    /// Guidance for the most recent failure.
    var message: String?

    private let log: EventLog
    private let automation: Automation?
    private var host: PairingHost?
    /// The node to which `host` is bound.
    private var hostedNode: TailnetNode?
    private var serving: Task<Void, Never>?

    init(log: EventLog, automation: Automation?) {
        self.log = log
        self.automation = automation
    }

    // MARK: Lifecycle

    /// Runs the host on `node`. Does nothing if already running on that node. Stops any host on another node first
    /// (a `PairingHost` is bound to one node, and two hosts cannot share a paired peer list directory).
    func start(on node: TailnetNode) async {
        guard hostedNode !== node else { return }
        await stop()
        do throws(PairingError) {
            let host = try await PairingHost(node: node, port: Self.pairingPort, storeDirectory: Storage.pairingStore) {
                [weak self] request in await self?.decide(request) ?? false
            }
            self.host = host
            hostedNode = node
            openedOffers = 0
            announcedOffers = 0
            peers = await host.pairedPeers
            log.record(.host, "started", "Paired peers: \(peers.count)")
            serving = Task { await self.serve(host, on: node) }
        } catch {
            fail("started", error)
        }
    }

    func stop() async {
        serving?.cancel()
        await serving?.value
    }

    /// Runs until `PairingHost.run()` completes. Returns on cancellation or when the node stops.
    private func serve(_ host: PairingHost, on node: TailnetNode) async {
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await self.greet(host, on: node) }
            group.addTask {
                for await event in host.events {
                    switch event {
                    case .pairedPeerAdded, .pairedPeerRemoved: await self.refreshPeers(from: host)
                    case .offerChanged(let state): await self.offerChanged(state)
                    }
                }
            }
            do throws(PairingError) {
                try await host.run()
            } catch {
                fail("run", error)
            }
            group.cancelAll()
        }
        self.host = nil
        hostedNode = nil
        serving = nil
        offer = nil
    }

    // MARK: Offer

    /// Reflects offer events in the UI. The QR code and link disappear when the offer is used, expires, or closes (the link contains a secret).
    /// Events arrive in order, so state events belong to the offer on screen only when the number of received `.opened` events matches the number of opens.
    private func offerChanged(_ state: PairingHost.OfferState) {
        switch state {
        case .opened: announcedOffers += 1
        case .used, .expired, .closed:
            if announcedOffers == openedOffers { offer = nil }
        }
    }

    func openOffer(lifetime: Duration, authKey: String?) async {
        guard let host else { return }
        message = nil
        do throws(PairingError) {
            let offer = try await host.openOffer(lifetime: lifetime, authKey: authKey)
            openedOffers += 1
            let url = offer.url(base: Self.linkBase)
            self.offer = OpenOffer(
                url: url, qrCode: offer.qrCode(base: Self.linkBase), expires: offer.expires, carriesAuthKey: authKey != nil)
            log.record(
                .host, "offer-opened", "Lifetime \(lifetime.components.seconds) seconds, auth key \(authKey == nil ? "absent" : "present")")
            if automation?.writesOfferLink == true {
                let written = (try? Data(url.absoluteString.utf8).write(to: Storage.offerLink, options: .atomic)) != nil
                log.record(.host, "offer-link-file", written ? "Written" : "Could not write")
            }
        } catch {
            fail("offer-opened", error)
        }
    }

    /// Creates a single-use auth key with the saved OAuth client and includes it in the offer. The key has the same lifetime as the offer.
    func openOfferWithIssuedKey(lifetime: Duration) async {
        guard let client = OAuthClientKeychain.load() else {
            message = "Save an OAuth client first."
            return
        }
        message = nil
        do throws(AuthKeyIssueError) {
            let issued = try await AuthKeyIssuer(client: client).issue(lifetime: lifetime)
            log.record(.host, "auth-key-issued", "Succeeded")
            await openOffer(lifetime: lifetime, authKey: issued.key)
        } catch {
            message = error.guidance
            log.record(.host, "auth-key-issued", "Failed: \(error)")
        }
    }

    func closeOffer() async {
        await host?.closeOffer()
        offer = nil
        log.record(.host, "offer-closed", "Closed")
    }

    // MARK: OAuth Client

    /// Validates the format and saves the client in the keychain. Tags are comma-separated.
    func saveOAuthClient(id: String, secret: String, tags: String) {
        let client = TailscaleOAuthClient(
            id: id.trimmingCharacters(in: .whitespaces), secret: secret.trimmingCharacters(in: .whitespaces),
            tags: tags.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) })
        do throws(AuthKeyIssueError) {
            _ = try AuthKeyIssuer(client: client)
        } catch {
            message = error.guidance
            return
        }
        guard OAuthClientKeychain.save(client) else {
            message = "Could not save to the keychain."
            return
        }
        message = nil
        oauthClientID = client.id
    }

    func removeOAuthClient() {
        OAuthClientKeychain.remove()
        oauthClientID = nil
    }

    // MARK: Approval

    /// Implements `decide` for `PairingHost`. Waits for the user's response. If the peer disconnects or 120 seconds elapse, this Task is canceled,
    /// and it dismisses the approval screen and returns immediately.
    private func decide(_ request: PairingRequest) async -> Bool {
        // The earlier `.used` event clears the used offer's QR code. Clearing it here would clear any new offer opened in the meantime.
        log.record(
            .host, "approval-requested",
            automation?.logsConfirmationCode == true ? "SAS \(request.confirmationCode)" : "Waiting for the user's response")
        if automation?.approvesAutomatically == true {
            log.record(.host, "approval", "Automatically approved")
            return true
        }
        let id = UUID()
        return await withTaskCancellationHandler {
            await withCheckedContinuation { continuation in
                approvals.append(Approval(id: id, request: request, answer: continuation))
            }
        } onCancel: {
            Task { @MainActor in self.answer(id, approved: false, by: "Canceled (peer disconnected or timed out)") }
        }
    }

    func approve(_ approval: Approval) { answer(approval.id, approved: true, by: "Approved") }
    func deny(_ approval: Approval) { answer(approval.id, approved: false, by: "Denied") }

    private func answer(_ id: UUID, approved: Bool, by result: String) {
        guard let index = approvals.firstIndex(where: { $0.id == id }) else { return }
        approvals.remove(at: index).answer.resume(returning: approved)
        log.record(.host, "approval", result)
    }

    // MARK: Paired Peer List

    func remove(_ peer: PairedPeer) async {
        guard let host else { return }
        do throws(PairingError) {
            try await host.removePairedPeer(withStableID: peer.peer.stableID)
            log.record(.host, "peer-removed", "Removed")
        } catch {
            fail("peer-removed", error)
        }
    }

    private func refreshPeers(from host: PairingHost) async {
        let latest = await host.pairedPeers
        guard latest != peers else { return }
        // A peer has paired for the first time or the same node has paired again (in which case the entry's `pairedAt` changes).
        if latest.contains(where: { !peers.contains($0) }) {
            log.record(.host, "paired", "Paired peers: \(latest.count)")
        }
        peers = latest
    }

    // MARK: Connection After Pairing

    /// Listens on the greeting port. Looks up the remote peer with `whoIs` and returns a line only if the peer is in the paired peer list.
    private func greet(_ host: PairingHost, on node: TailnetNode) async {
        let listener: TailnetListener
        do throws(ConnectionError) {
            listener = try await node.listen(port: Self.greetingPort)
        } catch {
            log.record(.host, "greeting-listen", "Failed: \(error)")
            return
        }
        await withDiscardingTaskGroup { group in
            for await connection in listener {
                group.addTask { await self.greet(connection, host: host, node: node) }
            }
        }
        await listener.close()
    }

    private func greet(_ connection: TailnetConnection, host: PairingHost, node: TailnetNode) async {
        guard let identity = await node.whoIs(connection.remoteEndpoint.address),
            let peer = await host.pairedPeer(withStableID: identity.stableID)
        else {
            await connection.abort()
            log.record(.host, "greeting", "Denied: peer is not paired")
            return
        }
        do throws(ConnectionError) {
            try await connection.write(Array("Hello, \(peer.deviceName)\n".utf8))
            await connection.close()
            log.record(.host, "greeting", "Sent")
        } catch {
            await connection.abort()
            log.record(.host, "greeting", "Failed: \(error)")
        }
    }

    private func fail(_ event: String, _ error: PairingError) {
        message = error.guidance
        log.record(.host, event, "Failed: \(error)")
    }
}
