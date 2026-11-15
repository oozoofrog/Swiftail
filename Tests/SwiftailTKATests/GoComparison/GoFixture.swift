import CryptoKit
import Foundation
import SwiftailBase
import Synchronization
import Testing

@testable import SwiftailTKA

/// `Fixtures/tka-fixtures.json`(Go `tka`를 실행한 판정. 모양은 `Tools/interop/README.md`의 `tkafixtures` 절) 전체.
/// 대조 시험(`GoComparisonTests`)만 쓴다. 다른 단위 시험의 자료 타입에 기대지 않으려고 따로 읽는다.
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

    /// Go Authority의 상태(`Head`·`Keys`·`StateIDs`, 끄기 값은 머리 쪽 첫 체크포인트의 것).
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
        /// Key와 State의 필드를 함께 담는다(`type`이 어느 쪽인지 정한다).
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

    /// `NodeKeyAuthorizedWithDetails`의 판정.
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

    /// 최상위 배열의 이름. 자료에 이것 말고 다른 배열이 있으면 대조하지 않은 줄이 생긴 것이다.
    static let sectionNames: Set<String> = [
        "keys", "authorities", "text", "encodings", "cbor", "chains", "sync", "signatures", "peerSets", "disablement",
        "authKeys", "resign", "unorderedPeerSets", "limits", "padded", "openedStates",
    ]

    /// `caseCount`에 드는 줄의 수(`keys`·`authorities`는 입력이라 세지 않는다. `sync`·`limits`는 안쪽 `cases`).
    var countedRows: [String: Int] {
        [
            "text": text.count, "encodings": encodings.count, "cbor": cbor.count, "chains": chains.count,
            "sync": sync.reduce(0) { $0 + $1.cases.count }, "signatures": signatures.count, "peerSets": peerSets.count,
            "disablement": disablement.count, "authKeys": authKeys.count, "resign": resign.count,
            "unorderedPeerSets": unorderedPeerSets.count, "limits": limits.reduce(0) { $0 + $1.cases.count },
            "padded": padded.count, "openedStates": openedStates.count,
        ]
    }

    static var url: URL {
        get throws { try #require(Bundle.module.url(forResource: "tka-fixtures", withExtension: "json", subdirectory: "Fixtures")) }
    }

    struct LoadError: Error, Sendable, CustomStringConvertible {
        let description: String
    }

    /// 한 번만 읽는다(1.3MB). 실패는 문자열로 쥔다(`any Error`는 Sendable이 아니다).
    static let loaded: Result<GoFixture, LoadError> = {
        do {
            return .success(try JSONDecoder().decode(GoFixture.self, from: Data(contentsOf: try url)))
        } catch {
            return .failure(LoadError(description: "\(error)"))
        }
    }()

    static func load() throws -> GoFixture { try loaded.get() }
}

// MARK: 줄마다의 결과와 집계

/// 한 줄을 견준 결과.
enum Comparison: Sendable {
    /// Go와 같은 판정(받아들인 것은 같은 바이트·머리·상태).
    case same
    /// Go가 실행마다 다른 답을 내고 Swift의 답이 그 가운데 하나다.
    case oneOfGoOutcomes
    /// 계약이 정한 의도된 차이(동작·결정 번호). 그 줄에서 Swift가 낼 답은 견주는 쪽이 이미 확인했다.
    case intended(String)
    /// 이 시험 타깃에 Swift 표면이 없다(다른 타깃의 단위가 맡는다).
    case noSurface(String)
    /// Go와 다르고 계약이 정하지 않았다. 시험이 실패한다.
    case mismatch(String)
}

/// 배열마다 견준 줄 수를 모아, 마지막 줄을 견주면 한 번 출력한다(병렬로 도는 사례도 한 줄로 모인다).
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

    /// `section`의 줄 하나를 기록한다. 어긋남이면 이슈를 남긴다. `total`번째 기록에서 그 배열의 요약을 출력한다.
    static func record(
        _ comparison: Comparison, section: String, row: String, total: Int, sourceLocation: SourceLocation = #_sourceLocation
    ) {
        if case .mismatch(let detail) = comparison {
            Issue.record("\(section)/\(row): Go와 다르다: \(detail)", sourceLocation: sourceLocation)
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
            return "Go 대조 \(section): 줄 \(c.compared), 같음 \(c.same)"
                + (c.oneOfGoOutcomes > 0 ? ", Go의 여러 답 가운데 하나 \(c.oneOfGoOutcomes)" : "")
                + ", 의도된 차이 \(c.intended.values.reduce(0, +))" + (c.intended.isEmpty ? "" : " (\(list(c.intended)))")
                + (c.noSurface.isEmpty ? "" : ", 표면 없음 \(c.noSurface.values.reduce(0, +)) (\(list(c.noSurface)))")
                + ", 어긋남 \(c.mismatches.count)" + (c.mismatches.isEmpty ? "" : " \(c.mismatches)")
        }
        if let summary { print(summary) }
    }
}

// MARK: 도우미

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
                Issue.record("16진이 아니다")
                return []
            }
            if let h = high {
                out.append(h << 4 | value)
                high = nil
            } else {
                high = value
            }
        }
        if high != nil { Issue.record("16진의 길이가 홀수다") }
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

    /// 첫 것으로 부트스트랩하고 나머지를 한 묶음으로 들인다(도구가 Go Authority를 만드는 방식).
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

    /// Go의 `Snapshot`과 다른 곳을 글로 적는다. 같으면 nil.
    static func difference(_ authority: Authority, _ expected: Snapshot) -> String? {
        let state = authority.state
        var differences: [String] = []
        if hex(authority.head.bytes) != expected.head { differences.append("머리") }
        if state.lastAUMHash != authority.head { differences.append("lastAUMHash") }
        if state.disablementValues.map(hex) != (expected.disablementValues ?? []) { differences.append("끄기 값") }
        if String(state.stateID1) != expected.stateID1 || String(state.stateID2) != expected.stateID2 { differences.append("StateID") }
        if state.keys.count != expected.keys.count {
            differences.append("키 수")
        } else {
            for (key, value) in zip(state.keys, expected.keys) where difference(key, value) != nil {
                differences.append("키 \(difference(key, value) ?? "")")
            }
        }
        return differences.isEmpty ? nil : differences.joined(separator: ", ")
    }

    /// Go의 nil `Meta`와 빈 `Meta`는 인코딩에서 둘 다 빠지므로 같게 본다.
    static func difference(_ key: TrustedKey, _ expected: KeyValue) -> String? {
        if key.kind != expected.kind || key.votes != expected.votes { return "종류·Votes" }
        if key.publicKey.map(hex) != expected.public { return "공개 키" }
        let meta = Dictionary(key.meta.map { (String(decoding: $0.key, as: UTF8.self), String(decoding: $0.value, as: UTF8.self)) }) { a, _ in a }
        return meta == (expected.meta ?? [:]) ? nil : "Meta"
    }

    typealias Snapshot = GoFixture.Snapshot
    typealias KeyValue = GoFixture.KeyValue

    /// Swift `authorize`의 판정을 Go의 모양(인가 여부, 내력)으로 견준다. 같으면 nil.
    static func difference(_ state: AuthorityState, nodeKey: NodePublicKey, nks: [UInt8], expected: GoFixture.Verdict) -> String? {
        let swift = Result { () throws(TKAError) in try state.authorize(nodeKey, keySignature: nks) }
        switch swift {
        case .failure:
            return expected.authorized ? "Swift는 인가하지 않는다" : nil
        case .success(let details):
            guard expected.authorized else { return "Swift는 인가한다(Go: \(expected.error ?? ""))" }
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
            return same ? nil : "내력"
        default:
            return "내력의 유무"
        }
    }

    static func verdict(authorized: Bool, error: String?, rotation: GoFixture.Rotation?) -> GoFixture.Verdict {
        GoFixture.Verdict(authorized: authorized, error: error, rotation: rotation)
    }

    /// 도구의 `padTo`와 같은 바이트: 맵 머리 + 1 ‖ base[1...] ‖ uint(padKey) ‖ bstr(0 × padLength).
    static func padded(_ item: GoFixture.Padded) -> [UInt8] {
        let base = bytes(item.base)
        guard let first = base.first, (0xa0...0xb6).contains(first) else {
            Issue.record("\(item.name): 맵 머리가 한 바이트가 아니다")
            return []
        }
        var writer = CBORWriter()
        writer.unsigned(item.padKey)
        writer.byteString([UInt8](repeating: 0, count: item.padLength))
        return [first + 1] + base.dropFirst() + writer.bytes
    }

    /// 자료의 `keys`에서 seed 문자열로 Ed25519 개인 키를 찾는다.
    static func signingKey(seed: String, in fixture: GoFixture) throws -> Curve25519.Signing.PrivateKey {
        let key = try #require(fixture.keys.first { $0.seed == seed })
        return try Curve25519.Signing.PrivateKey(rawRepresentation: bytes(key.private))
    }

    /// 패딩 없는 표준 base64(`RawStdEncoding`)로 쓴다.
    static func rawBase64(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }
}
