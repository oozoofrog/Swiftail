import Testing

import SwiftailBase
import SwiftailMagicsock

@Suite("PeerPath")
struct PeerPathTests {
    @Test("Direct and DERP paths are distinguishable by value")
    func equality() throws {
        let endpoint = try #require(IPEndpoint("192.0.2.1:41641"))
        let other = try #require(IPEndpoint("192.0.2.1:41642"))
        #expect(PeerPath.direct(endpoint) == .direct(endpoint))
        #expect(PeerPath.direct(endpoint) != .direct(other))
        #expect(PeerPath.relayed(derpRegion: 1) == .relayed(derpRegion: 1))
        #expect(PeerPath.relayed(derpRegion: 1) != .relayed(derpRegion: 0))
        #expect(PeerPath.direct(endpoint) != .relayed(derpRegion: 1))
    }
}
