// M9 pairing gate (a) (docs/contracts/SwiftailPairing.md §7, 9–11). Uses only the test control server and loopback, with no account.
// This gate cannot verify expiry, single-use, or tag policy because the test control server's auth keys have none. Gate 11 bypasses name resolution and the tunnel.

import Foundation
import Network
import Swiftail
import SwiftailBase
import Testing

@testable import SwiftailPairing

@Suite("M9 gate (a): pairing on the test control server", .enabled(if: tailnetBinary != nil,
    "Skipping the M9 pairing gate because SWIFTAIL_TAILNET is missing"), .serialized, .timeLimit(.minutes(10)))
struct PairingGateTests {
    private static let base = URL(string: "https://example.com/pair")
    /// An obviously fake auth key. The test control server compares it to a single string.
    private static let authKey = "tskey-auth-EXAMPLE-0000"

    /// Exports the offer as a link and reads it back, as when the app shares an offer via QR or a link.
    private static func throughLink(_ offer: PairingOffer) throws -> PairingOffer {
        try PairingOffer(link: offer.url(base: try #require(base)).absoluteString)
    }

    @Test("Gate 9: offer → join → approve → paired peer list, with denial, wrong secret, expiry, re-pairing, and SAS")
    func pairsTwoNodes() async throws {
        try await withPairingGate { gate in
            let hostNode = try gate.startNode("host", hostname: "rd-mac-1a2b3c4d")
            let joinerNode = try gate.startNode("joiner", hostname: "rd-phone-5e6f7a8b")
            try await gate.waitUntilPeers(hostNode, joinerNode)
            let hostStatus = await hostNode.node.status
            let joinerStableID = try #require(await joinerNode.node.status.stableID)
            let approver = Approver()

            try await gate.withHost(hostNode, approver: approver) { host in
                // Approve.
                let offer = try await host.openOffer()
                #expect(offer.host == hostStatus.fqdn && offer.port == 4_747 && offer.authKey == nil)
                #expect(offer.expires > Date().addingTimeInterval(295) && offer.expires <= Date().addingTimeInterval(300))
                let codes = ConfirmationCodes()
                let paired = try await netstackDeadline("Pairing") {
                    try await PairingJoiner.pair(
                        with: try Self.throughLink(offer), deviceName: "거실 iPad", node: joinerNode.node
                    ) { codes.record($0) }
                }
                #expect(paired.host == hostStatus.fqdn)
                #expect(paired.stableID == hostStatus.stableID)
                #expect(paired.name == (await hostNode.node.whoIs(try #require(hostStatus.addresses.first)))?.computedName)

                let request = try #require(approver.requests.last)
                #expect(approver.requests.count == 1)
                #expect(request.peer.stableID == joinerStableID && request.deviceName == "거실 iPad")
                #expect(codes.all == [request.confirmationCode], "Both sides have the same SAS")
                #expect(request.confirmationCode.count == 6)

                let first = try #require(await host.pairedPeers.first)
                #expect(await host.pairedPeers.count == 1)
                #expect(first.peer == request.peer && first.deviceName == "거실 iPad")
                await gate.tool.checkpoint("M9 9 approval: 1 paired peer, SAS matches on both sides")

                // For a connection after pairing, query the paired peer list using the connection's identity.
                let listener = try await hostNode.node.listen(port: 9_300)
                let accepted = Task { try await netstackAccept(listener) }
                let client = try await netstackDeadline("App connection") {
                    try await joinerNode.node.connect(to: paired.host, port: 9_300)
                }
                let inbound = try await accepted.value
                let caller = try #require(await hostNode.node.whoIs(inbound.remoteEndpoint.address))
                #expect(await host.pairedPeer(withStableID: caller.stableID) == first)
                #expect(await host.pairedPeer(withStableID: try #require(hostStatus.stableID)) == nil, "The host is not its own paired peer")
                // The joiner also checks whether the remote is its paired peer.
                #expect(await joinerNode.node.whoIs(client.remoteEndpoint.address)?.stableID == paired.stableID)
                await client.abort()
                await inbound.abort()
                await listener.close()
                await gate.tool.checkpoint("M9 9 connection after pairing: pairedPeer found the peer by the StableID from whoIs")

                // An offer can be used only once.
                let reused = await pairingFailure {
                    try await PairingJoiner.pair(with: offer, deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(reused == .rejected)

                // Deny.
                approver.set(.deny)
                let refusedOffer = try await host.openOffer()
                let denied = await pairingFailure {
                    try await PairingJoiner.pair(with: try Self.throughLink(refusedOffer), deviceName: "다른 이름", node: joinerNode.node)
                }
                #expect(denied == .denied)
                #expect(await host.pairedPeers == [first], "Denial leaves the list unchanged")
                await gate.tool.checkpoint("M9 9 denial: denied, list unchanged")

                // Reject the wrong secret and keep the offer.
                approver.set(.approve)
                let kept = try await host.openOffer()
                var wrongSecret = kept.secret
                wrongSecret[0] ^= 1
                let forged = PairingOffer(
                    host: kept.host, port: kept.port, expires: kept.expires, authKey: nil, secret: wrongSecret)
                let wrong = await pairingFailure {
                    try await PairingJoiner.pair(with: forged, deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(wrong == .rejected)
                #expect(approver.requests.count == 2, "A wrong secret does not prompt the app")

                // Pair again with the same offer and replace the entry.
                let again = try await netstackDeadline("Re-pairing") {
                    try await PairingJoiner.pair(with: try Self.throughLink(kept), deviceName: "새 이름", node: joinerNode.node)
                }
                #expect(again.stableID == paired.stableID && again.pairedAt > paired.pairedAt)
                let replaced = try #require(await host.pairedPeers.first)
                #expect(await host.pairedPeers.count == 1)
                #expect(replaced.peer.stableID == joinerStableID && replaced.deviceName == "새 이름")
                #expect(replaced.pairedAt > first.pairedAt)
                await gate.tool.checkpoint("M9 9 wrong secret: rejected, offer kept. Re-pairing replaces the entry")

                // Expiry.
                let brief = try await host.openOffer(lifetime: .seconds(1))
                try await Task.sleep(for: .milliseconds(2_100))
                let expired = await pairingFailure {
                    try await PairingJoiner.pair(with: try Self.throughLink(brief), deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(expired == .rejected)

                // Closed offer.
                let closed = try await host.openOffer()
                await host.closeOffer()
                let afterClose = await pairingFailure {
                    try await PairingJoiner.pair(with: closed, deviceName: "거실 iPad", node: joinerNode.node)
                }
                #expect(afterClose == .rejected)
                #expect(approver.requests.count == 3)
                await gate.tool.checkpoint("M9 9 expired and closed: rejected")

                // If the joiner stops while waiting for approval, the host's decision Task is canceled (P6, J7).
                approver.set(.wait)
                let pending = try await host.openOffer()
                let waitingCodes = ConfirmationCodes()
                let pairing = Task {
                    await pairingFailure {
                        try await PairingJoiner.pair(with: pending, deviceName: "거실 iPad", node: joinerNode.node) {
                            waitingCodes.record($0)
                        }
                    }
                }
                try await netstackDeadline("Waiting for the SAS") { await waitingCodes.next() }
                pairing.cancel()
                #expect(await pairing.value == .cancelled)
                try await netstackWait("Cancellation of the decision Task", seconds: 10) { approver.cancelledCount == 1 }
                #expect(await host.pairedPeers == [replaced])
                await gate.tool.checkpoint("M9 9 cancellation while waiting: joiner cancelled, host decision Task canceled")
            }

            // The paired peer list persists on disk.
            let stored = try PairedPeerFile(directory: gate.root.appending(path: "store")).load()
            #expect(stored.peers.map(\.peer.stableID) == [joinerStableID])
        }
    }

    @Test("Gate 10: a new node registers with the offer's auth key and then pairs (including a redial)")
    func joinsWithOfferAuthKey() async throws {
        try await withPairingGate(authKey: Self.authKey) { gate in
            let hostNode = try gate.startNode("host", hostname: "rd-mac-1a2b3c4d", authKey: Self.authKey)
            try await netstackWait("Host node running") { await hostNode.node.status.fqdn != nil }
            let approver = Approver()

            try await gate.withHost(hostNode, approver: approver) { host in
                let offer = try Self.throughLink(try await host.openOffer(authKey: Self.authKey))
                #expect(offer.authKey == Self.authKey)

                // On the device that received the link, start a node using the offer's key and pair immediately without waiting for registration.
                let joinerNode = try gate.startNode("joiner", hostname: "rd-phone-5e6f7a8b", authKey: offer.authKey)
                #expect(await joinerNode.node.status.state != .running)
                let started = ContinuousClock.now
                let paired = try await netstackDeadline("Joining and pairing with an auth key", seconds: 90) {
                    try await PairingJoiner.pair(with: offer, deviceName: "거실 iPad", node: joinerNode.node)
                }
                let elapsed = started.duration(to: .now)
                #expect(elapsed >= .seconds(1), "The first attempt cannot connect before the node runs, and it redials after 1 second")
                #expect(paired.stableID == (await hostNode.node.status.stableID))

                let joinerStableID = try #require(await joinerNode.node.status.stableID)
                #expect(await host.pairedPeers.map(\.peer.stableID) == [joinerStableID])
                #expect(approver.requests.map(\.peer.stableID) == [joinerStableID])
                await gate.tool.checkpoint("M9 10 paired after joining with an auth key: elapsed \(elapsed)")
            }

            // Control: a node started without a key cannot register with this server, showing that the key enabled registration above.
            let stranger = try gate.startNode("stranger", hostname: "rd-pad-9c0d1e2f")
            try await Task.sleep(for: .seconds(3))
            #expect(await stranger.node.status.state != .running)
            #expect(await stranger.node.status.addresses.isEmpty)
        }
    }
}

@Suite("M9 gate (a): joining over an OS socket (loopback)", .serialized, .timeLimit(.minutes(2)))
struct PairingSocketGateTests {
    @Test("Gate 11: exchanges messages over NWConnection with the host state machine attached to a loopback listener")
    func pairsOverLoopbackSocket() async throws {
        let host = try await LoopbackPairingHost.start()
        defer { host.close() }
        // The loopback address acts as this device's tailnet address in the test. Disable only the address range check and interface restriction.
        let loopback = try #require(IPAddress("127.0.0.1"))

        // Approve.
        let offer = await host.openOffer()
        let codes = ConfirmationCodes()
        async let serving = host.serveNext(approving: true)
        let paired = try await netstackDeadline("Pairing over loopback", seconds: 20) {
            try await PairingJoiner.pair(
                with: offer, deviceName: "거실 iPad", localAddress: loopback, requiringTunnel: false
            ) { codes.record($0) }
        }
        let served = try await serving
        #expect(paired.host == "127.0.0.1")
        #expect(paired.stableID == LoopbackPairingHost.hostIdentity.stableID)
        #expect(paired.name == LoopbackPairingHost.hostIdentity.computedName)
        #expect(served.ending == .paired && served.saved?.deviceName == "거실 iPad")
        #expect(codes.all == [try #require(served.confirmationCode)], "Both sides see the same two connection endpoints, so their SAS matches")

        // Reject an offer that has already been used.
        async let second = host.serveNext(approving: true)
        let reused = await pairingFailure {
            try await PairingJoiner.pair(
                with: offer, deviceName: "거실 iPad", localAddress: loopback, requiringTunnel: false) { _ in }
        }
        #expect(reused == .rejected)
        #expect(try await second.ending == .noOffer)

        // Deny.
        let refusedOffer = await host.openOffer()
        async let third = host.serveNext(approving: false)
        let denied = await pairingFailure {
            try await PairingJoiner.pair(
                with: refusedOffer, deviceName: "거실 iPad", localAddress: loopback, requiringTunnel: false) { _ in }
        }
        #expect(denied == .denied)
        #expect(try await third.ending == .denied)

        // If the local endpoint differs from the address the app supplied, end without sending hello (J2). Do not redial.
        let guarded = await host.openOffer()
        async let fourth = host.serveNext(approving: true)
        let elsewhere = try #require(IPAddress("127.0.0.2"))
        let outside = await pairingFailure {
            try await PairingJoiner.pair(
                with: guarded, deviceName: "거실 iPad", localAddress: elsewhere, requiringTunnel: false) { _ in }
        }
        #expect(outside == .notOnTailnet)
        let untouched = try await fourth
        #expect(untouched.receivedByteCount == 0 && untouched.ending == .disconnected)
        #expect(await host.hasOpenOffer)

        // The public API restricts the interface, so loopback cannot connect (traffic cannot leave over a non-tunnel path).
        let port = try #require(NWEndpoint.Port(rawValue: host.port))
        let barred = SocketPairingTransport(host: "127.0.0.1", port: port, isIPv4: true, tunnelOnly: true)
        let opened = try await netstackDeadline("Dialing over a prohibited interface", seconds: 10) { await barred.open() }
        #expect(!opened)
        await barred.close()
        let allowed = SocketPairingTransport(host: "127.0.0.1", port: port, isIPv4: true, tunnelOnly: false)
        #expect(await allowed.open(), "Disabling the restriction reaches the same destination")
        await allowed.close()
    }
}
