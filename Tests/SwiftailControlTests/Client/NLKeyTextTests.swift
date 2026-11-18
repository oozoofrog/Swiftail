// Compares NL key (tailnet lock key) text representations against Go reference values. Contract `docs/contracts/SwiftailTailnetLock.md`, behavior R1, notes
// `docs/protocol-notes/tailnet-lock.md` 3.8.
//
// The reference values come from the `text` array in `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json` (go1.27.3, tailscale.com v1.104.6, `tkafixtures` tool).
// The 14 `nlPublic.*` and `nlPrivate.*` cases are copied verbatim. That file is a resource in another test target, so it is not read here.
// The keys are the tool's public, test-only values. Go rejected the input if the result (`output`) is nil.

import CryptoKit
import SwiftailBase
import Testing

@testable import SwiftailControl

@Suite("NL key text: Go reference values")
struct NLKeyTextTests {
    struct GoCase: Sendable, CustomTestStringConvertible {
        var name: String
        var kind: String
        var input: String
        var output: String?
        var testDescription: String { name }
    }

    static let cases: [GoCase] = [
        GoCase(name: "nlpub-encode", kind: "nlPublic.encode", input: "206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93", output: "nlpub:206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93"),
        GoCase(name: "tlpub-encode", kind: "nlPublic.encodeCLI", input: "206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93", output: "tlpub:206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93"),
        GoCase(name: "nlpub-decode", kind: "nlPublic.decode", input: "nlpub:206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93", output: "206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93"),
        GoCase(name: "tlpub-decode", kind: "nlPublic.decode", input: "tlpub:206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93", output: "206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93"),
        GoCase(name: "nlpub-decode-uppercase", kind: "nlPublic.decode", input: "nlpub:206D77C593A7CAB48BE6E743643C593B1075A222A53D9A7C83FB295BA3DA0E93", output: "206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93"),
        GoCase(name: "nlpub-decode-no-prefix", kind: "nlPublic.decode", input: "206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93", output: nil),
        GoCase(name: "nlpub-decode-short", kind: "nlPublic.decode", input: "nlpub:206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e", output: nil),
        GoCase(name: "nlpub-decode-long", kind: "nlPublic.decode", input: "nlpub:206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e9300", output: nil),
        GoCase(name: "nlpub-decode-nlpriv-prefix", kind: "nlPublic.decode", input: "nlpriv:206d77c593a7cab48be6e743643c593b1075a222a53d9a7c83fb295ba3da0e93", output: nil),
        GoCase(name: "nlpriv-encode", kind: "nlPrivate.encode", input: "d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5ca", output: "nlpriv:d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5caeea291d210cd96c16600e331c931c130d142e0b0fd9ddcfa1fcfb756e6a00438"),
        GoCase(name: "nlpriv-decode", kind: "nlPrivate.decode", input: "nlpriv:d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5caeea291d210cd96c16600e331c931c130d142e0b0fd9ddcfa1fcfb756e6a00438", output: "nlpriv:d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5caeea291d210cd96c16600e331c931c130d142e0b0fd9ddcfa1fcfb756e6a00438"),
        GoCase(name: "nlpriv-decode-seed-only", kind: "nlPrivate.decode", input: "nlpriv:d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5ca", output: nil),
        GoCase(name: "nlpriv-decode-nlpub-prefix", kind: "nlPrivate.decode", input: "nlpub:d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5caeea291d210cd96c16600e331c931c130d142e0b0fd9ddcfa1fcfb756e6a00438", output: nil),
        GoCase(name: "nlpriv-decode-wrong-public-half", kind: "nlPrivate.decode", input: "nlpriv:d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5ca0000000000000000000000000000000000000000000000000000000000000000", output: "nlpriv:d132274d5c925219b42ed925e1b1c8aed8b70c35cd1ba669de00a9f56c9dd5ca0000000000000000000000000000000000000000000000000000000000000000"),
    ]

    /// Cases where Swiftail differs from Go, with the reasons. Go accepts both and Swiftail rejects both.
    static let intendedDifferences: [String: String] = [
        // Behavior R1: The key is corrupt if its last 32 bytes differ from the public key derived from its seed.
        "nlpriv-decode-wrong-public-half": "R1",
        // Swiftail reads NL public keys only from the wire (JSON), where the representation is `nlpub:`. It only writes `tlpub:`.
        "tlpub-decode": "No reader",
    ]

    @Test("Matches Go reference values and rejects the intentional differences", arguments: cases)
    func matchesGo(_ fixture: GoCase) throws {
        let expected = Self.intendedDifferences[fixture.name] == nil ? fixture.output : nil
        let input = [UInt8](hex: fixture.input)
        if Self.intendedDifferences[fixture.name] != nil { #expect(fixture.output != nil, "The intentional differences are inputs that Go accepts") }
        switch fixture.kind {
        case "nlPublic.encode":
            let key = try #require(input.flatMap { NLPublicKey(rawValue: $0) })
            #expect(key.description == expected)
        case "nlPublic.encodeCLI":
            let key = try #require(input.flatMap { NLPublicKey(rawValue: $0) })
            #expect(key.commandLineDescription == expected)
        case "nlPublic.decode":
            #expect(NLPublicKey(fixture.input)?.rawValue.hex == expected)
        case "nlPrivate.encode":
            let key = try Curve25519.Signing.PrivateKey(rawRepresentation: try #require(input))
            #expect(NodeIdentityStore.text(key) == expected)
        case "nlPrivate.decode":
            #expect(NodeIdentityStore.lockKey(fixture.input).map(NodeIdentityStore.text) == expected)
        default:
            Issue.record("Unknown kind \(fixture.kind)")
        }
    }

    @Test("Derives the same NL public key bytes from the seed as Go")
    func publicKeyFromSeed() throws {
        let encoded = try #require(Self.cases.first { $0.kind == "nlPrivate.encode" })
        let seed = try #require([UInt8](hex: encoded.input))
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let identity = NodeIdentity(machineKey: .init(), nodeKey: nil, lockKey: key)
        #expect(try #require(encoded.output).hasSuffix(identity.lockPublicKey.rawValue.hex))
    }
}
