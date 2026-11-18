// Checks that values holding keys do not leak them through `print`, `debugPrint`, or `dump`.
//
// `CustomStringConvertible` alone cannot hide values from `dump`, which uses Mirror to inspect stored properties.
// Public types that hold keys therefore hide their children with `CustomReflectable`.

import CryptoKit
import Foundation
import Testing

@testable import SwiftailControl

@Suite("Output that keeps secrets hidden")
struct SecretReflectionTests {
    private typealias V = TransportVectors

    /// Concatenates the output of `String(describing:)`, `String(reflecting:)`, and `dump`.
    private func renderings(of value: Any) -> String {
        var dumped = ""
        dump(value, to: &dumped)
        return String(describing: value) + "\n" + String(reflecting: value) + "\n" + dumped
    }

    @Test("Handshake state does not expose key material")
    func handshake() throws {
        let output = renderings(of: try V.handshake())
        // Array elements and key bytes are not printed one per line.
        #expect(!output.contains("chainingKey"))
        #expect(!output.contains("machineKey"))
        #expect(!output.contains("ephemeral"))
        #expect(output.split(separator: "\n").count <= 3)
    }

    @Test("The transport session does not expose keys")
    func session() throws {
        let output = renderings(of: try V.clientSession())
        #expect(!output.contains("key"))
        #expect(output.split(separator: "\n").count <= 3)
    }

    @Test("Configuration does not expose the auth key")
    func configuration() throws {
        let secret = "tskey-auth-EXAMPLE-0000"
        let configuration = ControlClient.Configuration(
            serverURL: try #require(URL(string: "http://127.0.0.1:9911")),
            hostname: "rd-mac-1a2b3c4d",
            authKey: secret
        )
        let output = renderings(of: configuration)
        #expect(!output.contains(secret))
        #expect(output.contains("rd-mac-1a2b3c4d"))
    }
}
