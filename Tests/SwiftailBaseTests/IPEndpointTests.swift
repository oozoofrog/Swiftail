import Testing

import SwiftailBase

@Suite("IPEndpoint")
struct IPEndpointTests {
    @Test("IP:port", arguments: ["192.0.2.1:41641", "[2001:db8::1]:41641", "[fd7a:115c:a1e0::1]:0", "0.0.0.0:65535"])
    func endpoints(_ text: String) throws {
        #expect(try #require(IPEndpoint(text)).description == text)
    }

    @Test("Rejection of invalid IP:port strings", arguments: [
        "", ":1", "192.0.2.1", "192.0.2.1:", "192.0.2.1:65536", "192.0.2.1:+1", "192.0.2.1:-1", "2001:db8::1:41641",
        "[192.0.2.1]:1", "[2001:db8::1]", "[2001:db8::1%en0]:1", "[]:1", "[:1", "192.0.2.1:123456",
    ])
    func endpointRejected(_ text: String) {
        #expect(IPEndpoint(text) == nil)
    }
}
