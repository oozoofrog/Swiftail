import Foundation
import Observation
import Swiftail
import SwiftailPairing

/// Acts as the joiner. Reads the offer, asks the user to confirm it, pairs, and tries connecting to the paired host.
@MainActor @Observable
final class JoinerModel {
    enum Phase: Equatable {
        case idle
        /// Waits for the node to join the tailnet and reach the host.
        case connecting
        /// The host has been verified. Compare this number with the number on the host screen.
        case awaitingApproval(confirmationCode: String)
        case paired
        case failed(String)
    }

    /// The name of this device as shown on the host's approval screen. The peer receives it unchanged.
    var deviceName = JoinerModel.defaultDeviceName
    /// An offer that has been read but has yet to be confirmed by the user. Links can come from anywhere, so show `host` and ask for confirmation (contract §3).
    private(set) var pendingOffer: PairingOffer?
    private(set) var phase = Phase.idle
    private(set) var pairedHost: PairedHost?
    /// The result of the most recent "Check Connection" action.
    private(set) var connectionCheck: String?
    /// Guidance for a link that could not be read.
    private(set) var linkMessage: String?

    private let node: NodeModel
    private let log: EventLog
    private let automation: Automation?
    private var pairing: Task<Void, Never>?

    init(node: NodeModel, log: EventLog, automation: Automation?) {
        self.node = node
        self.log = log
        self.automation = automation
        if let data = try? Data(contentsOf: Storage.pairedHost) {
            pairedHost = try? Self.decoder.decode(PairedHost.self, from: data)
        }
    }

    // MARK: Receiving an Offer

    /// Reads an offer from a scanned QR code, pasted text, or a URL. The string is omitted from the log.
    ///
    /// - Parameter source: How the offer arrived (`qr`, `paste`, `url`). This value is logged.
    func receive(link: String, source: String) {
        do throws(PairingOfferError) {
            pendingOffer = try PairingOffer(link: link.trimmingCharacters(in: .whitespacesAndNewlines))
            linkMessage = nil
            log.record(.joiner, "offer-received", "\(source): Read")
        } catch {
            linkMessage = error.guidance
            log.record(.joiner, "offer-received", "\(source): Failed (\(error))")
        }
    }

    func discardOffer() {
        pendingOffer = nil
    }

    // MARK: Pairing

    /// The user has seen the host in the offer and chosen to proceed.
    func confirmOffer() {
        guard let offer = pendingOffer, pairing == nil else { return }
        pendingOffer = nil
        pairing = Task {
            await self.pair(with: offer)
            self.pairing = nil
        }
    }

    func cancelPairing() {
        pairing?.cancel()
    }

    private func pair(with offer: PairingOffer) async {
        phase = .connecting
        connectionCheck = nil
        // A node already on the tailnet skips the offer's auth key. The key is passed to the node once and is never stored (contract §3).
        if node.node == nil { node.start(authKey: offer.authKey) }
        guard let running = await node.waitUntilRunning() else {
            // If registration failed, the key may still be unused. Restore the offer so it can be retried.
            pendingOffer = offer
            phase = .failed(node.failure ?? "The node stopped before connecting to the tailnet.")
            log.record(.joiner, "pair", "Failed: node did not connect")
            return
        }
        let logsCode = automation?.logsConfirmationCode == true
        do throws(PairingError) {
            let paired = try await PairingJoiner.pair(with: offer, deviceName: deviceName, node: running) { code in
                Task { @MainActor in
                    // Keep the approval if it arrived first.
                    guard self.phase == .connecting else { return }
                    self.phase = .awaitingApproval(confirmationCode: code)
                    self.log.record(.joiner, "awaiting-approval", logsCode ? "SAS \(code)" : "Waiting for the host's approval")
                }
            }
            pairedHost = paired
            let saved = (try? Self.encoder.encode(paired).write(to: Storage.pairedHost, options: .atomic)) != nil
            phase = .paired
            log.record(.joiner, "pair", saved ? "Paired" : "Paired (could not save)")
        } catch {
            // An offer that ended before reaching the host was unused. The same offer can be retried after the locked node is signed.
            // The host has already used an offer that reached the SAS stage, so leave that offer consumed.
            if phase == .connecting, error == .unreachable || error == .cancelled { pendingOffer = offer }
            phase = .failed(error.guidance)
            log.record(.joiner, "pair", "Failed: \(error)")
        }
    }

    // MARK: Connection After Pairing

    /// Connects to the host's greeting port and receives one line. Uses the `StableID` from `whoIs` to verify that the remote peer is paired.
    func checkConnection() async {
        guard let pairedHost else { return }
        guard let running = node.node else {
            connectionCheck = "Start the node first."
            return
        }
        connectionCheck = "Connecting"
        do throws(ConnectionError) {
            let connection = try await running.connect(to: pairedHost.host, port: HostModel.greetingPort)
            guard await running.whoIs(connection.remoteEndpoint.address)?.stableID == pairedHost.stableID else {
                await connection.abort()
                finishCheck("The remote peer is not the paired host. The connection was closed.", log: "Failed: StableID mismatch")
                return
            }
            var greeting: [UInt8] = []
            while greeting.count < 256, let bytes = try await connection.read(upTo: 256) { greeting += bytes }
            await connection.close()
            let text = String(decoding: greeting, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            finishCheck(text.isEmpty ? "The host closed the connection without sending a greeting." : "Received greeting: \(text)", log: text.isEmpty ? "Empty response" : "Received greeting (StableID matched)")
        } catch {
            finishCheck(error.guidance, log: "Failed: \(error)")
        }
    }

    private func finishCheck(_ text: String, log result: String) {
        connectionCheck = text
        log.record(.joiner, "connection-check", result)
    }

    private static var defaultDeviceName: String {
        #if os(macOS)
        "Mac"
        #else
        "iPhone"
        #endif
    }

    private static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        return encoder
    }()

    private static let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601
        return decoder
    }()
}
