import CryptoKit
import Foundation
import SwiftailBase
import Synchronization
import Testing

@testable import SwiftailTKA

/// The complete `Fixtures/tka-fixtures.json` (outcomes from running Go `tka`. See the `tkafixtures` section of `Tools/interop/README.md` for the format).
/// Only the comparison tests (`GoComparisonTests`) use this type. It reads the fixtures separately to avoid depending on other unit tests' fixture types.
struct GoFixture: Decodable, Sendable {
    struct Reference: Decodable, Sendable {
        let go: String
        let tailscale: String
    }

    struct Key: Decodable, Sendable {
        let role: String
        let index: Int
        let seed: String
        let `private`: String
        let `public`: String
        let text: String
    }

    struct KeyValue: Decodable, Sendable {
        let kind: UInt8
        let votes: UInt64
        let `public`: String?
        let meta: [String: String]?
    }

    /// Go Authority state (`Head`, `Keys`, and `StateIDs`, with disablement values from the checkpoint nearest the head).
    struct Snapshot: Decodable, Sendable {
        let head: String
        let keys: [KeyValue]
        let disablementValues: [String]?
        let stateID1: String
        let stateID2: String
    }

    struct Authority: Decodable, Sendable {
        let name: String
        let aums: [String]
        let head: String
        let state: Snapshot
    }

    struct Text: Decodable, Sendable {
        let name: String
        let kind: String
        let input: String
        let ok: Bool
        let output: String?
        let error: String?
    }

    struct Encoding: Decodable, Sendable {
        /// Holds both Key and State fields. `type` selects between them.
        struct Value: Decodable, Sendable {
            let kind: UInt8?
            let votes: UInt64?
            let `public`: String?
            let meta: [String: String]?
            let lastAUMHash: String?
            let disablementValues: [String]?
            let keys: [KeyValue]?
            let stateID1: String?
            let stateID2: String?
        }

        let name: String
        let type: String
        let value: Value
        let encoded: String
    }

    struct CBORCase: Decodable, Sendable {
        let name: String
        let type: String
        let input: String
        let decoded: Bool
        let staticValid: Bool?
        let accepted: Bool
        let error: String?
        let reencoded: String?
        let canonical: Bool
        let hash: String?
        let sigHash: String?
    }

    struct ChainStep: Decodable, Sendable {
        let name: String
        let aums: [String]
        let ok: Bool
        let error: String?
        let after: Snapshot
    }

    struct Chain: Decodable, Sendable {
        let name: String
        let bootstrap: String
        let bootstrapOK: Bool
        let bootstrapError: String?
        let initial: Snapshot?
        let steps: [ChainStep]
    }

    struct Offer: Decodable, Sendable {
        let head: String
        let ancestors: [String]
        let headText: String
        let ancestorsText: [String]
    }

    struct Missing: Decodable, Sendable {
        let ok: Bool
        let error: String?
        let count: Int
        let digest: String
        let hashes: [String]?
    }

    struct SyncSide: Decodable, Sendable {
        let aums: [Int]
        let offer: Offer
        let missing: Missing
        let informOK: Bool
        let informError: String?
        let headAfter: String
    }

    struct SyncCase: Decodable, Sendable {
        let name: String
        let local: SyncSide
        let remote: SyncSide
    }

    struct SyncGroup: Decodable, Sendable {
        let name: String
        let pool: [String]
        let cases: [SyncCase]
    }

    struct Rotation: Decodable, Sendable, Equatable {
        let prevNodeKeys: [String]
        let initialKind: UInt8
        let initialWrappingPubkey: String?
    }

    /// `NodeKeyAuthorizedWithDetails` outcome.
    struct Verdict: Decodable, Sendable {
        let authorized: Bool
        let error: String?
        let rotation: Rotation?
    }

    struct Signature: Decodable, Sendable {
        let name: String
        let authority: String
        let nodeKey: String
        let nks: String
        let sigHash: String?
        let authorized: Bool
        let error: String?
        let rotation: Rotation?
    }

    struct Peer: Decodable, Sendable {
        let nodeKey: String
        let signature: String
        let unsignedPeerAPIOnly: Bool
    }

    struct PeerSet: Decodable, Sendable {
        let name: String
        let authority: String
        let peers: [Peer]
        let kept: [String]
        let runs: Int
    }

    struct UnorderedPeerSet: Decodable, Sendable {
        let name: String
        let authority: String
        let peers: [Peer]
        let runs: Int
        let outcomes: [[String]]
    }

    struct Disablement: Decodable, Sendable {
        let name: String
        let authority: String
        let secret: String
        let kdf: String
        let valid: Bool
    }

    struct AuthKey: Decodable, Sendable {
        let name: String
        let input: String
        let authKey: String
        let isWrapped: Bool
        let returnedInput: Bool
        let credential: String?
        let privateKeyLength: Int
        let nodeKey: String?
        let sign: String?
        let signError: String?
        let nks: String?
        let authority: String?
        let verdict: Verdict?
    }

    struct Resign: Decodable, Sendable {
        let name: String
        let authority: String
        let nlKey: String
        let oldNKS: String
        let nodeKey: String
        let ok: Bool
        let error: String?
        let result: String?
        let sigHash: String?
        let sameAsOld: Bool
        let depth: Int
        let verdict: Verdict?
    }

    struct LimitStep: Decodable, Sendable {
        let name: String
        let aums: [Int]
        let ok: Bool
        let error: String?
        let head: String
    }

    struct LimitCase: Decodable, Sendable {
        let name: String
        let baseCount: Int
        let baseHead: String
        let steps: [LimitStep]
    }

    struct LimitGroup: Decodable, Sendable {
        let name: String
        let pool: String
        let extra: [String]
        let cases: [LimitCase]
    }

    struct Padded: Decodable, Sendable {
        let name: String
        let kind: String
        let base: String
        let padKey: UInt64
        let padLength: Int
        let length: Int
        let authority: String?
        let nodeKey: String?
        let nlKey: String?
        let controlValue: String?
        let privateKey: String?
        let ok: Bool
        let error: String?
        let head: String?
        let sigHash: String?
        let verdict: Verdict?
    }

    struct Opened: Decodable, Sendable {
        let name: String
        let checkpoint: String
        let openOK: Bool
        let openError: String?
        let nodeKey: String
        let nks: String
        let authorized: Bool
        let error: String?
        let rotation: Rotation?
    }

    let reference: Reference
    let caseCount: Int
    let keys: [Key]
    let authorities: [Authority]
    let text: [Text]
    let encodings: [Encoding]
    let cbor: [CBORCase]
    let chains: [Chain]
    let sync: [SyncGroup]
    let signatures: [Signature]
    let peerSets: [PeerSet]
    let disablement: [Disablement]
    let authKeys: [AuthKey]
    let resign: [Resign]
    let unorderedPeerSets: [UnorderedPeerSet]
    let limits: [LimitGroup]
    let padded: [Padded]
    let openedStates: [Opened]
    /// Chains and NKS cases added by the TL-11a review and compared by `TKAReviewTests`.
    let reviewChains: [Chain]
    let reviewSignatures: [Signature]

    /// Top-level array names. Any other array in the fixture contains rows left out of the comparison.
    static let sectionNames: Set<String> = [
        "keys", "authorities", "text", "encodings", "cbor", "chains", "sync", "signatures", "peerSets", "disablement",
        "authKeys", "resign", "unorderedPeerSets", "limits", "padded", "openedStates", "reviewChains", "reviewSignatures",
    ]

    /// Row counts included in `caseCount`. Inputs `keys` and `authorities` do not count. `sync` and `limits` count nested `cases`.
    var countedRows: [String: Int] {
        [
            "text": text.count, "encodings": encodings.count, "cbor": cbor.count, "chains": chains.count,
            "sync": sync.reduce(0) { $0 + $1.cases.count }, "signatures": signatures.count, "peerSets": peerSets.count,
            "disablement": disablement.count, "authKeys": authKeys.count, "resign": resign.count,
            "unorderedPeerSets": unorderedPeerSets.count, "limits": limits.reduce(0) { $0 + $1.cases.count },
            "padded": padded.count, "openedStates": openedStates.count, "reviewChains": reviewChains.count,
            "reviewSignatures": reviewSignatures.count,
        ]
    }

    static var url: URL {
        get throws { try #require(Bundle.module.url(forResource: "tka-fixtures", withExtension: "json", subdirectory: "Fixtures")) }
    }

    struct LoadError: Error, Sendable, CustomStringConvertible {
        let description: String
    }

    /// Reads once (1.3MB). Stores failures as strings (`any Error` is not Sendable).
    static let loaded: Result<GoFixture, LoadError> = {
        do {
            return .success(try JSONDecoder().decode(GoFixture.self, from: Data(contentsOf: try url)))
        } catch {
            return .failure(LoadError(description: "\(error)"))
        }
    }()

    static func load() throws -> GoFixture { try loaded.get() }
}

// MARK: Per-row results and totals

/// The result of comparing one row.
enum Comparison: Sendable {
    /// Same outcome as Go, with identical bytes, head, and state for accepted inputs.
    case same
    /// Go produces different answers across runs, and Swift gives one of them.
    case oneOfGoOutcomes
    /// An intended difference specified by the contract (behavior and decision IDs). The comparison has already checked the expected Swift result for this row.
    case intended(String)
    /// This test target has no Swift surface for this row. A unit in another target covers it.
    case noSurface(String)
    /// Differs from Go without a contract provision. The test fails.
    case mismatch(String)
}

/// Counts compared rows per array and prints one summary after the last row, including for cases run in parallel.
enum ComparisonTally {
    private struct Counts {
        var compared = 0
        var same = 0
        var oneOfGoOutcomes = 0
        var intended: [String: Int] = [:]
        var noSurface: [String: Int] = [:]
        var mismatches: [String] = []
    }

    private static let counts = Mutex<[String: Counts]>([:])

    /// Records one row for `section`. Records an issue on a mismatch. Prints the array summary on the `total`th recording.
    static func record(
        _ comparison: Comparison, section: String, row: String, total: Int, sourceLocation: SourceLocation = #_sourceLocation
    ) {
        if case .mismatch(let detail) = comparison {
            Issue.record("\(section)/\(row): differs from Go: \(detail)", sourceLocation: sourceLocation)
        }
        let summary: String? = counts.withLock { all in
            var c = all[section, default: Counts()]
            c.compared += 1
            switch comparison {
            case .same: c.same += 1
            case .oneOfGoOutcomes: c.oneOfGoOutcomes += 1
            case .intended(let code): c.intended[code, default: 0] += 1
            case .noSurface(let unit): c.noSurface[unit, default: 0] += 1
            case .mismatch: c.mismatches.append(row)
            }
            all[section] = c
            guard c.compared == total else { return nil }
            func list(_ d: [String: Int]) -> String { d.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", ") }
            return "Go comparison \(section): rows \(c.compared), matches \(c.same)"
                + (c.oneOfGoOutcomes > 0 ? ", one of several Go outcomes \(c.oneOfGoOutcomes)" : "")
                + ", intended differences \(c.intended.values.reduce(0, +))" + (c.intended.isEmpty ? "" : " (\(list(c.intended)))")
                + (c.noSurface.isEmpty ? "" : ", no surface \(c.noSurface.values.reduce(0, +)) (\(list(c.noSurface)))")
                + ", mismatches \(c.mismatches.count)" + (c.mismatches.isEmpty ? "" : " \(c.mismatches)")
        }
        if let summary { print(summary) }
    }
}

// MARK: Helpers

enum GoComparison {
    static func bytes(_ hex: String) -> [UInt8] {
        var out: [UInt8] = []
        out.reserveCapacity(hex.utf8.count / 2)
        var high: UInt8?
        for character in hex.utf8 {
            let value: UInt8
            switch character {
            case UInt8(ascii: "0")...UInt8(ascii: "9"): value = character - UInt8(ascii: "0")
            case UInt8(ascii: "a")...UInt8(ascii: "f"): value = character - UInt8(ascii: "a") + 10
            default:
                Issue.record("Invalid hex")
                return []
            }
            if let h = high {
                out.append(h << 4 | value)
                high = nil
            } else {
                high = value
            }
        }
        if high != nil { Issue.record("Odd hex length") }
        return out
    }

    static func hex(_ bytes: some Sequence<UInt8>) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func aum(_ hex: String) throws(TKAError) -> AUM { try AUM(decoding: bytes(hex)) }

    static func nodeKey(_ hex: String) throws -> NodePublicKey { try #require(NodePublicKey(rawValue: bytes(hex))) }

    /// Bootstraps with the first AUM and admits the rest in a group, as the tool builds a Go Authority.
    static func authority(_ aums: [AUM]) throws(TKAError) -> Authority {
        guard let first = aums.first else { throw .emptyUpdate }
        var authority = try Authority(bootstrappingWith: first)
        if aums.count > 1 { try authority.inform(Array(aums.dropFirst())) }
        return authority
    }

    static func authority(named name: String, in fixture: GoFixture) throws -> Authority {
        let entry = try #require(fixture.authorities.first { $0.name == name })
        return try authority(entry.aums.map { hex throws(TKAError) in try aum(hex) })
    }

    /// Describes differences from the Go `Snapshot\). Returns nil for a match.
    static func difference(_ authority: Authority, _ expected: Snapshot) -> String? {
        let state = authority.state
        var differences: [String] = []
        if hex(authority.head.bytes) != expected.head { differences.append("head") }
        if state.lastAUMHash != authority.head { differences.append("lastAUMHash") }
        if state.disablementValues.map(hex) != (expected.disablementValues ?? []) { differences.append("disablement values") }
        if String(state.stateID1) != expected.stateID1 || String(state.stateID2) != expected.stateID2 { differences.append("StateID") }
        if state.keys.count != expected.keys.count {
            differences.append("key count")
        } else {
            for (key, value) in zip(state.keys, expected.keys) where difference(key, value) != nil {
                differences.append("key \(difference(key, value) ?? "")")
            }
        }
        return differences.isEmpty ? nil : differences.joined(separator: ", ")
    }

    /// Treats Go's nil and empty `Meta` as equivalent because encoding omits both.
    static func difference(_ key: TrustedKey, _ expected: KeyValue) -> String? {
        if key.kind != expected.kind || key.votes != expected.votes { return "kind and Votes" }
        if key.publicKey.map(hex) != expected.public { return "public key" }
        let meta = Dictionary(key.meta.map { (String(decoding: $0.key, as: UTF8.self), String(decoding: $0.value, as: UTF8.self)) }) { a, _ in a }
        return meta == (expected.meta ?? [:]) ? nil : "Meta"
    }

    typealias Snapshot = GoFixture.Snapshot
    typealias KeyValue = GoFixture.KeyValue

    /// Compares Swift `authorize` to Go's outcome and history in Go's format. Returns nil for a match.
    static func difference(_ state: AuthorityState, nodeKey: NodePublicKey, nks: [UInt8], expected: GoFixture.Verdict) -> String? {
        let swift = Result { () throws(TKAError) in try state.authorize(nodeKey, keySignature: nks) }
        switch swift {
        case .failure:
            return expected.authorized ? "Swift denies authorization" : nil
        case .success(let details):
            guard expected.authorized else { return "Swift authorizes (Go: \(expected.error ?? ""))" }
            return difference(details, expected.rotation)
        }
    }

    static func difference(_ details: RotationDetails?, _ expected: GoFixture.Rotation?) -> String? {
        switch (details, expected) {
        case (nil, nil): return nil
        case (let details?, let expected?):
            let wrapping = details.initialSignature.wrappingPublicKey
            let same =
                details.previousNodeKeys.map { hex($0.rawValue) } == expected.prevNodeKeys
                && details.initialSignature.kind == expected.initialKind
                && hex(wrapping) == (expected.initialWrappingPubkey ?? "")
            return same ? nil : "history"
        default:
            return "history presence"
        }
    }

    static func verdict(authorized: Bool, error: String?, rotation: GoFixture.Rotation?) -> GoFixture.Verdict {
        GoFixture.Verdict(authorized: authorized, error: error, rotation: rotation)
    }

    /// Bytes matching the tool's `padTo`: map header + 1 ‖ base[1...] ‖ uint(padKey) ‖ bstr(0 × padLength).
    static func padded(_ item: GoFixture.Padded) -> [UInt8] {
        let base = bytes(item.base)
        guard let first = base.first, (0xa0...0xb6).contains(first) else {
            Issue.record("\(item.name): map header is not one byte")
            return []
        }
        var writer = CBORWriter()
        writer.unsigned(item.padKey)
        writer.byteString([UInt8](repeating: 0, count: item.padLength))
        return [first + 1] + base.dropFirst() + writer.bytes
    }

    /// Looks up an Ed25519 private key by seed string in fixture `keys`.
    static func signingKey(seed: String, in fixture: GoFixture) throws -> Curve25519.Signing.PrivateKey {
        let key = try #require(fixture.keys.first { $0.seed == seed })
        return try Curve25519.Signing.PrivateKey(rawRepresentation: bytes(key.private))
    }

    /// Writes standard base64 without padding (`RawStdEncoding`).
    static func rawBase64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
