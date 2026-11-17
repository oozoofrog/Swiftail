// `import Swiftail`과 `import SwiftailPairing`만으로 페어링 공개 API에 나오는 타입의 이름을 쓴다. 이 파일은 다른 모듈을
// 가져오지 않는다(`SwiftailBase`의 `IPAddress`는 `Swiftail`의 별명으로 쓴다).

import Foundation
import Swiftail
import SwiftailPairing
import Testing

@Suite("import Swiftail·SwiftailPairing만으로 쓰는 타입")
struct PairingReexportedTypesTests {
    @Test("페어링 공개 API에 나오는 다른 모듈의 타입을 이름으로 쓴다")
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
