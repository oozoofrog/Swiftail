// Names types in the public pairing API using only `import Swiftail` and `import SwiftailPairing`. This file imports
// no other modules. It uses the `Swiftail` alias for `SwiftailBase`'s `IPAddress`.

import Foundation
import Swiftail
import SwiftailPairing
import Testing

@Suite("Types available with only import Swiftail and SwiftailPairing")
struct PairingReexportedTypesTests {
    @Test("Names types from other modules that appear in the public pairing API")
    func names() throws {
        let identity = PeerIdentity(
            stableID: "nEXAMPLEJOINER", name: "rd-phone-5e6f7a8b.tail0001.ts.net", computedName: "rd-phone-5e6f7a8b",
            loginName: "alice@example.com")
        let event: PairingHost.Event = .pairedPeerRemoved(stableID: identity.stableID)
        let state: PairingHost.OfferState = .used
        #expect(event != .offerChanged(state))

        let localAddress: IPAddress = try #require(IPAddress("100.64.0.1"))
        let join: (PairingOffer, String, IPAddress) async throws(PairingError) -> PairedHost = { offer, name, address in
            try await PairingJoiner.pair(with: offer, deviceName: name, localAddress: address)
        }
        let host: (TailnetNode, URL) async throws(PairingError) -> PairingHost = { node, directory in
            try await PairingHost(node: node, port: 4747, storeDirectory: directory) { _ in false }
        }
        _ = (localAddress, join, host)
    }
}
