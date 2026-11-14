import Testing

import SwiftailBase
import SwiftailMagicsock

@Suite("PeerPath")
struct PeerPathTests {
    @Test("직접과 DERP 경로는 값으로 구분된다")
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
