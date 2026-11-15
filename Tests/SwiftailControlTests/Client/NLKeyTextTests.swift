// NL 키(tailnet lock 키)의 텍스트 표기를 Go 기준값과 견준다. 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 R1, 노트
// `docs/protocol-notes/tailnet-lock.md` 3.8.
//
// 기준값은 `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json`(go1.27.3, tailscale.com v1.104.6, `tkafixtures` 도구)의 `text`
// 배열 가운데 `nlPublic.*`·`nlPrivate.*` 14개를 그대로 옮겨 적었다. 그 파일은 다른 시험 타깃의 리소스라 읽지 않는다.
// 키는 도구의 공개된 시험 전용 값이다. 결과(`output`)가 nil이면 Go가 거절한 것이다.

import CryptoKit
import SwiftailBase
import Testing

@testable import SwiftailControl

@Suite("NL 키 텍스트: Go 기준값")
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

    /// Swiftail이 Go와 다르게 판정하는 것과 그 까닭. 둘 다 Go는 받고 Swiftail은 거절한다.
    static let intendedDifferences: [String: String] = [
        // 동작 R1: 뒤 32바이트가 시드로 만든 공개 키와 다르면 손상이다.
        "nlpriv-decode-wrong-public-half": "R1",
        // Swiftail은 NL 공개 키를 와이어(JSON)에서만 읽고, 와이어의 표기는 `nlpub:`다. `tlpub:`는 쓰기만 한다.
        "tlpub-decode": "읽는 곳 없음",
    ]

    @Test("Go 기준값과 같다(의도된 차이는 거절)", arguments: cases)
    func matchesGo(_ fixture: GoCase) throws {
        let expected = Self.intendedDifferences[fixture.name] == nil ? fixture.output : nil
        let input = [UInt8](hex: fixture.input)
        if Self.intendedDifferences[fixture.name] != nil { #expect(fixture.output != nil, "의도된 차이는 Go가 받는 입력이다") }
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
            Issue.record("모르는 종류 \(fixture.kind)")
        }
    }

    @Test("NL 공개 키는 시드에서 Go와 같은 바이트로 나온다")
    func publicKeyFromSeed() throws {
        let encoded = try #require(Self.cases.first { $0.kind == "nlPrivate.encode" })
        let seed = try #require([UInt8](hex: encoded.input))
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: seed)
        let identity = NodeIdentity(machineKey: .init(), nodeKey: nil, lockKey: key)
        #expect(try #require(encoded.output).hasSuffix(identity.lockPublicKey.rawValue.hex))
    }
}
