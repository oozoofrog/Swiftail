import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// Go `tka`의 판정(`Fixtures/tka-fixtures.json`)과 Swift 구현의 판정을 모든 줄에서 견준다(계약 7절 "Go 기준값 대조", TL-5).
///
/// 구현 세션들의 단위 시험과 따로, 계약과 자료와 도구만 보고 썼다. 판정은 뒤 단위(TL-6·TL-7)가 쓸 `package` 표면으로 얻는다:
/// `AUM(decoding:)`·`validate()`·`serialized()`·`hash`·`signatureHash`, `NodeKeySignature(decoding:)`, `AUMHash(text:)`,
/// `Authority(bootstrappingWith:)`·`inform`·`syncOffer`·`missingAUMs`·`isValidDisablement`, `AuthorityState.authorize`·`admitted`,
/// `WrappedAuthKey(parsing:)`·`keySignature(for:)`, `NodeKeySignature.resigned`. 시험 자료를 만드는 데만 내부 선언(멤버별 생성자,
/// `binaryForm`)을 쓴다.
///
/// 줄마다 "같아야 하는 것"은 각 시험의 주석에 적었다. 계약이 정한 의도된 차이는 건너뛰지 않고 그 줄에서 Swift가 내야 하는 답을
/// 확인한 뒤 번호(동작·결정)로 센다. 배열마다 한 번 "줄, 같음, 의도된 차이(번호별), 어긋남"을 출력한다.
@Suite("Go 대조: tka-fixtures.json의 모든 줄")
struct GoComparisonTests {
    typealias G = GoComparison

    // MARK: 목록

    /// 자료의 최상위 배열이 이 시험이 아는 것뿐이고, 줄 수의 합이 `caseCount`다(빠진 배열이 없다).
    @Test("배열 목록과 caseCount")
    func inventory() throws {
        let data = try Data(contentsOf: try GoFixture.url)
        let object = try #require(try JSONSerialization.jsonObject(with: data) as? [String: Any])
        #expect(Set(object.keys) == GoFixture.sectionNames.union(["reference", "caseCount"]))
        let fixture = try GoFixture.load()
        #expect(fixture.reference.tailscale == "v1.104.6")
        let rows = fixture.countedRows
        #expect(rows.values.reduce(0, +) == fixture.caseCount)
        print(
            "Go 대조 caseCount \(fixture.caseCount) = "
                + rows.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: " + ")
        )
    }

    // MARK: 입력(keys, authorities)

    /// 시험 키: 씨앗 = SHA-256(seed 문자열), Ed25519 공개 키, node 키(X25519) 공개 키와 `nodekey:` 텍스트가 Go와 같다.
    /// `tlpub:` 텍스트는 이 타깃에 표면이 없다(SwiftailControl, TL-6·TL-7).
    @Test("keys: 시험 키의 유도")
    func keys() throws {
        let fixture = try GoFixture.load()
        for key in fixture.keys {
            let seed = Array(SHA256.hash(data: Array(key.seed.utf8)))
            var problems: [String] = []
            if G.hex(seed) != key.private { problems.append("씨앗") }
            switch key.role {
            case "node":
                let publicKey = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: seed).publicKey
                if G.hex(publicKey.rawRepresentation) != key.public { problems.append("공개 키") }
                if NodePublicKey(publicKey).description != key.text { problems.append("텍스트") }
            case "disablement":
                break
            default:
                let publicKey = try Curve25519.Signing.PrivateKey(rawRepresentation: seed).publicKey
                if G.hex(publicKey.rawRepresentation) != key.public { problems.append("공개 키") }
            }
            ComparisonTally.record(
                problems.isEmpty ? .same : .mismatch(problems.joined(separator: ", ")), section: "keys",
                row: "\(key.role)/\(key.index)", total: fixture.keys.count
            )
        }
    }

    /// 판정에 쓰는 신뢰 상태: 부트스트랩 + 한 묶음의 들이기 뒤 머리와 상태가 Go와 같다.
    @Test("authorities: 판정에 쓰는 신뢰 상태")
    func authorities() throws {
        let fixture = try GoFixture.load()
        for entry in fixture.authorities {
            let authority = Result { () throws(TKAError) in try G.authority(entry.aums.map { hex throws(TKAError) in try G.aum(hex) }) }
            let comparison: Comparison
            switch authority {
            case .failure(let error): comparison = .mismatch("Swift가 거절한다: \(error)")
            case .success(let authority):
                comparison = G.difference(authority, entry.state).map { .mismatch($0) } ?? .same
            }
            ComparisonTally.record(comparison, section: "authorities", row: entry.name, total: fixture.authorities.count)
        }
    }

    // MARK: text

    /// 줄바꿈이 섞인 `AUMHash` 텍스트. Go `UnmarshalText`는 길이를 줄바꿈을 지우기 전의 글자 수로 보고(`DecodedLen(52) = 32`),
    /// `base32.Decode`는 `\r`·`\n`을 지운 뒤 남은 50·51·48자를 읽어 31·30바이트만 채우고 나머지를 0으로 둔다(`tka/aum.go:33-41`).
    /// 계약은 이것을 정하지 않았다(5절 TL-2 "Go와 맞출지 대조 뒤에 정한다"). 어긋남으로 남긴다.
    static let aumHashLineBreakRows: Set<String> = [
        "aum-hash-50-chars-crlf", "aum-hash-50-chars-lf-lf", "aum-hash-50-chars-cr-cr", "aum-hash-crlf-inside",
        "aum-hash-leading-lf-lf", "aum-hash-48-chars-4-lf", "aum-hash-51-chars-lf", "aum-hash-52-chars-lf",
        "aum-hash-52-chars-lf-inside",
    ]

    /// `AUMHash`의 쓰기·읽기(판정과, 받으면 같은 32바이트), node 키의 텍스트와 이진 형식(`np` ‖ 32바이트).
    /// `nlpub:`·`tlpub:`·`nlpriv:`는 SwiftailControl의 표면이다(TL-6. `nlpriv`의 뒤 32바이트 검사는 의도된 차이 R1).
    @Test("text: AUMHash 텍스트와 키 텍스트")
    func text() throws {
        let fixture = try GoFixture.load()
        for item in fixture.text where !Self.aumHashLineBreakRows.contains(item.name) {
            ComparisonTally.record(Self.compareText(item), section: "text", row: item.name, total: fixture.text.count)
        }
    }

    /// Go는 길이를 줄바꿈을 지우기 전의 글자 수로 재고 지운 뒤에 읽어, 31·30바이트만 채운 **원래와 다른 해시**로 받는다
    /// (`tka/aum.go:33-41`). Swiftail은 52자 알파벳만 받는다(계약 동작 D10).
    @Test("text: 줄바꿈이 섞인 AUMHash 텍스트는 거절한다(Go는 잘린 해시로 받는다. 의도된 차이 D10)")
    func aumHashLineBreaks() throws {
        let fixture = try GoFixture.load()
        for item in fixture.text where Self.aumHashLineBreakRows.contains(item.name) {
            let comparison: Comparison = AUMHash(text: item.input) != nil
                ? .mismatch("Swift가 줄바꿈이 섞인 텍스트를 받았다")
                : item.ok ? .intended("D10") : .same
            ComparisonTally.record(comparison, section: "text", row: item.name, total: fixture.text.count)
        }
    }

    static func compareText(_ item: GoFixture.Text) -> Comparison {
        func check(_ same: Bool, _ detail: @autoclosure () -> String) -> Comparison { same ? .same : .mismatch(detail()) }
        switch item.kind {
        case "aumHash.encode":
            let text = AUMHash(G.bytes(item.input))?.text
            return check(text == item.output, "Swift \(text ?? "nil")")
        case "aumHash.decode":
            let hash = AUMHash(text: item.input)
            return check(
                (hash != nil) == item.ok && (hash == nil || hash.map { G.hex($0.bytes) } == item.output),
                "Go \(item.ok ? "받음 \(item.output ?? "")" : "거절"), Swift \(hash.map { "받음 \(G.hex($0.bytes))" } ?? "거절")"
            )
        case "nodePublic.encode":
            return check(NodePublicKey(rawValue: G.bytes(item.input))?.description == item.output, "텍스트")
        case "nodePublic.binary":
            return check(NodePublicKey(rawValue: G.bytes(item.input)).map { G.hex($0.binaryForm) } == item.output, "이진 형식")
        default:
            return .noSurface("SwiftailControl의 NL 키(TL-6)")
        }
    }

    // MARK: encodings

    /// Key·State 하나의 정준 바이트. Swift는 둘을 따로 쓰는 표면이 없으므로 AUM에 넣어 쓴다(AddKey `a3 0101 02f6 03 <Key>`,
    /// Checkpoint `a3 0105 02f6 05 <State>`). Go의 nil 배열(`f6`)은 Swiftail이 빈 배열(`80`)로 쓴다(의도된 차이 E6).
    @Test("encodings: Key·State의 정준 바이트")
    func encodings() throws {
        let fixture = try GoFixture.load()
        for item in fixture.encodings {
            let value = item.value
            let comparison: Comparison
            if item.type == "key" {
                let key = try Self.trustedKey(value.kind, value.votes, value.public, value.meta)
                let written = G.hex(AUM(messageKind: 1, prevAUMHash: nil, key: key).serialized())
                comparison = written == "a3010102f603" + item.encoded ? .same : .mismatch("Swift \(written)")
            } else {
                let state = AuthorityState(
                    lastAUMHash: value.lastAUMHash.flatMap { AUMHash(G.bytes($0)) },
                    disablementValues: (value.disablementValues ?? []).map(G.bytes),
                    keys: try (value.keys ?? []).map { try Self.trustedKey($0.kind, $0.votes, $0.public, $0.meta) },
                    stateID1: try #require(UInt64(value.stateID1 ?? "")),
                    stateID2: try #require(UInt64(value.stateID2 ?? ""))
                )
                let written = G.hex(AUM(messageKind: 5, prevAUMHash: nil, state: state).serialized())
                let goBytes = "a3010502f605" + item.encoded
                if value.disablementValues == nil || value.keys == nil {
                    // E6: State 바이트에서 Go의 nil 배열 자리만 `80`으로 바꾼 것이어야 한다(배열이 null인 State는 원소가 없다).
                    var expected = item.encoded
                    if value.disablementValues == nil { expected = expected.replacingOccurrences(of: "02f6", with: "0280") }
                    if value.keys == nil { expected = expected.replacingOccurrences(of: "03f6", with: "0380") }
                    comparison = written == "a3010502f605" + expected ? .intended("E6") : .mismatch("Swift \(written)")
                } else {
                    comparison = written == goBytes ? .same : .mismatch("Swift \(written)")
                }
            }
            ComparisonTally.record(comparison, section: "encodings", row: item.name, total: fixture.encodings.count)
        }
    }

    static func trustedKey(_ kind: UInt8?, _ votes: UInt64?, _ publicKey: String?, _ meta: [String: String]?) throws -> TrustedKey {
        TrustedKey(
            kind: try #require(kind), votes: try #require(votes), publicKey: publicKey.map(G.bytes),
            meta: (meta ?? [:]).map { MetaEntry(key: Array($0.key.utf8), value: Array($0.value.utf8)) }
        )
    }

    // MARK: cbor

    /// 체크포인트 `State`의 null이 아닌 `LastAUMHash`: Go는 읽은 뒤 정적 검사에서, Swiftail은 디코딩에서 거절한다(동작 D8).
    static let decodingD8: Set<String> = ["accept/checkpoint-last-aum-hash-2-bytes", "value/checkpoint-last-aum-hash"]

    /// AUM: Swift의 "디코딩 + 정적 검사 통과"가 Go의 `accepted`와 같다. 디코딩 단계의 판정도 같다(D8만 예외).
    /// Go가 받아들인 것은 다시 쓴 바이트·`Hash`·`SigHash`가 같다(동작 E5). 둘 다 거절한 것의 다시 쓴 바이트는 견주지 않고, 다르면
    /// E6으로 센다(계약 7절: 정적 검사를 통과하지 못하는 입력은 판정만). NKS: 디코딩 판정이 같고, 읽힌 것은 다시 쓴 바이트와
    /// `SigHash`가 같다.
    @Test("cbor: 디코딩·정적 검사·정준 바이트·해시")
    func cbor() throws {
        let fixture = try GoFixture.load()
        for item in fixture.cbor {
            ComparisonTally.record(Self.compareCBOR(item), section: "cbor", row: item.name, total: fixture.cbor.count)
        }
    }

    static func compareCBOR(_ item: GoFixture.CBORCase) -> Comparison {
        let input = G.bytes(item.input)
        if item.type == "nks" {
            let decoded = Result { () throws(TKAError) in try NodeKeySignature(decoding: input) }
            switch decoded {
            case .failure(let error):
                return item.decoded ? .mismatch("Go는 읽는다, Swift \(error)") : .same
            case .success(let signature):
                guard item.decoded else { return .mismatch("Go는 거절한다(\(item.error ?? "")), Swift는 읽는다") }
                let same = G.hex(signature.serialized()) == item.reencoded && G.hex(signature.signatureHash) == item.sigHash
                return same ? .same : .mismatch("다시 쓴 바이트 \(G.hex(signature.serialized()))")
            }
        }
        let decoded = Result { () throws(TKAError) in try AUM(decoding: input) }
        switch decoded {
        case .failure(let error):
            if !item.decoded { return .same }
            if decodingD8.contains(item.name), error == .invalidStructure, item.staticValid == false, !item.accepted {
                return .intended("D8")
            }
            return .mismatch("Go는 읽는다, Swift \(error)")
        case .success(let aum):
            guard item.decoded else { return .mismatch("Go는 거절한다(\(item.error ?? "")), Swift는 읽는다") }
            let valid = (try? aum.validate()) != nil
            guard valid == item.accepted else {
                return .mismatch("정적 검사: Go \(item.accepted), Swift \(valid)")
            }
            let reencoded = G.hex(aum.serialized())
            if item.accepted {
                let same = reencoded == item.reencoded && G.hex(aum.hash.bytes) == item.hash && G.hex(aum.signatureHash) == item.sigHash
                return same ? .same : .mismatch("다시 쓴 바이트 \(reencoded)")
            }
            return reencoded == item.reencoded ? .same : .intended("E6")
        }
    }

    // MARK: chains

    /// 사슬마다(한 줄): 부트스트랩 판정과 처음 상태, 단계마다 들이기의 판정과 그 뒤의 머리·상태(키·Votes·Meta·끄기 값·StateID).
    @Test("chains: 부트스트랩과 단계마다의 판정·머리·상태")
    func chains() throws {
        let fixture = try GoFixture.load()
        for chain in fixture.chains {
            ComparisonTally.record(Self.compareChain(chain), section: "chains", row: chain.name, total: fixture.chains.count)
        }
    }

    static func compareChain(_ chain: GoFixture.Chain) -> Comparison {
        let bootstrapped = Result { () throws(TKAError) in try Authority(bootstrappingWith: G.aum(chain.bootstrap)) }
        guard case .success(var authority) = bootstrapped else {
            return chain.bootstrapOK ? .mismatch("부트스트랩: Swift \(bootstrapped)") : .same
        }
        guard chain.bootstrapOK else { return .mismatch("부트스트랩: Go는 거절한다(\(chain.bootstrapError ?? ""))") }
        var problems: [String] = []
        if let initial = chain.initial, let difference = G.difference(authority, initial) { problems.append("처음 \(difference)") }
        for step in chain.steps {
            let result = Result { () throws(TKAError) in try authority.inform(step.aums.map { hex throws(TKAError) in try G.aum(hex) }) }
            let ok = if case .success = result { true } else { false }
            if ok != step.ok { problems.append("\(step.name) 판정: Go \(step.ok) \(step.error ?? ""), Swift \(result)") }
            if let difference = G.difference(authority, step.after) { problems.append("\(step.name) \(difference)") }
        }
        return problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; "))
    }

    // MARK: sync

    static let syncCaseNames: [String] =
        (try? GoFixture.load()).map { $0.sync.flatMap { group in group.cases.map { "\(group.name)/\($0.name)" } } } ?? []

    /// 사례마다: 양쪽의 제안(머리, 조상 목록, 그 base32 텍스트), 상대 제안에 대한 `MissingAUMs`(성공 여부, 수, 해시 목록과 그 SHA-256),
    /// 상대의 목록을 들인 판정과 그 뒤의 머리. Go처럼 양쪽의 목록을 먼저 다 계산한 뒤 들인다(동작 Y4·Y5).
    @Test("sync: 제안·MissingAUMs·들인 뒤의 머리", .timeLimit(.minutes(10)), arguments: syncCaseNames)
    func sync(_ name: String) throws {
        let fixture = try GoFixture.load()
        let group = try #require(fixture.sync.first { name.hasPrefix("\($0.name)/") })
        let syncCase = try #require(group.cases.first { "\(group.name)/\($0.name)" == name })
        let pool = try group.pool.map { hex throws(TKAError) in try G.aum(hex) }
        var local = try G.authority(syncCase.local.aums.map { pool[$0] })
        var remote = try G.authority(syncCase.remote.aums.map { pool[$0] })
        var problems: [String] = []
        let localOffer = local.syncOffer()
        let remoteOffer = remote.syncOffer()
        for (label, offer, expected) in [("local", localOffer, syncCase.local.offer), ("remote", remoteOffer, syncCase.remote.offer)] {
            let same =
                G.hex(offer.head.bytes) == expected.head && offer.ancestors.map { G.hex($0.bytes) } == expected.ancestors
                && offer.head.text == expected.headText && offer.ancestors.map(\.text) == expected.ancestorsText
            if !same { problems.append("\(label) 제안") }
        }
        let localSends = Result { () throws(TKAError) in try local.missingAUMs(for: remoteOffer) }
        let remoteSends = Result { () throws(TKAError) in try remote.missingAUMs(for: localOffer) }
        for (label, sends, expected) in [("local", localSends, syncCase.local.missing), ("remote", remoteSends, syncCase.remote.missing)] {
            switch sends {
            case .failure(let error):
                if expected.ok { problems.append("\(label) MissingAUMs: Swift \(error)") }
            case .success(let aums):
                guard expected.ok else {
                    problems.append("\(label) MissingAUMs: Go는 실패한다(\(expected.error ?? ""))")
                    continue
                }
                let hashes = aums.map(\.hash.bytes)
                let digest = G.hex(SHA256.hash(data: hashes.flatMap { $0 }))
                if hashes.count != expected.count || digest != expected.digest
                    || (expected.hashes.map { $0 != hashes.map(G.hex) } ?? false)
                {
                    problems.append("\(label) MissingAUMs: Go \(expected.count)개, Swift \(hashes.count)개")
                }
            }
        }
        func receive(_ sends: Result<[AUM], TKAError>, into authority: inout Authority, expected: GoFixture.SyncSide, _ label: String) {
            var ok = true
            if case .success(let aums) = sends, !aums.isEmpty {
                do { try authority.inform(aums) } catch { ok = false }
            }
            if ok != expected.informOK { problems.append("\(label) 들이기: Go \(expected.informOK) \(expected.informError ?? "")") }
            if G.hex(authority.head.bytes) != expected.headAfter { problems.append("\(label) 들인 뒤 머리") }
        }
        receive(remoteSends, into: &local, expected: syncCase.local, "local")
        receive(localSends, into: &remote, expected: syncCase.remote, "remote")
        ComparisonTally.record(
            problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; ")), section: "sync", row: name,
            total: Self.syncCaseNames.count
        )
    }

    // MARK: signatures

    /// 줄마다: `authorize`의 판정(인가 여부)과, 통과한 rotation이면 내력(`PrevNodeKeys` 순서, 처음 서명의 종류·`WrappingPubkey`).
    /// Go가 NKS를 읽었으면 Swift도 읽고 `SigHash`가 같다.
    @Test("signatures: NKS 판정과 내력")
    func signatures() throws {
        let fixture = try GoFixture.load()
        var states: [String: AuthorityState] = [:]
        for item in fixture.signatures {
            if states[item.authority] == nil { states[item.authority] = try G.authority(named: item.authority, in: fixture).state }
            let state = try #require(states[item.authority])
            var problems: [String] = []
            let nks = G.bytes(item.nks)
            if let goHash = item.sigHash {
                let swiftHash = (try? NodeKeySignature(decoding: nks)).map { G.hex($0.signatureHash) }
                if swiftHash != goHash { problems.append("SigHash: Swift \(swiftHash ?? "읽지 못함")") }
            }
            let verdict = G.verdict(authorized: item.authorized, error: item.error, rotation: item.rotation)
            if let difference = G.difference(state, nodeKey: try G.nodeKey(item.nodeKey), nks: nks, expected: verdict) {
                problems.append("\(difference) (Go: \(item.error ?? "인가"))")
            }
            ComparisonTally.record(
                problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; ")), section: "signatures", row: item.name,
                total: fixture.signatures.count
            )
        }
    }

    // MARK: peerSets

    static func peers(_ peers: [GoFixture.Peer]) throws -> [PeerCredential] {
        try peers.map {
            PeerCredential(nodeKey: try G.nodeKey($0.nodeKey), keySignature: G.bytes($0.signature), unsignedPeerAPIOnly: $0.unsignedPeerAPIOnly)
        }
    }

    static func kept(_ state: AuthorityState, _ peers: [PeerCredential]) -> [String] {
        zip(peers, state.admitted(peers)).filter(\.1).map { G.hex($0.0.nodeKey.rawValue) }
    }

    /// 줄마다: `admitted`가 남긴 피어의 node 키와 순서가 Go `tkaFilterNetmapLocked`가 남긴 것과 같다. Go는 같은 입력을 `runs`번
    /// 돌려 늘 같은 답을 냈다(도구가 확인한다).
    @Test("peerSets: 남는 피어와 순서")
    func peerSets() throws {
        let fixture = try GoFixture.load()
        for item in fixture.peerSets {
            let kept = Self.kept(try G.authority(named: item.authority, in: fixture).state, try Self.peers(item.peers))
            let comparison: Comparison = kept == item.kept && item.runs > 1 ? .same : .mismatch("Swift \(kept)")
            ComparisonTally.record(comparison, section: "peerSets", row: item.name, total: fixture.peerSets.count)
        }
    }

    /// Go의 답이 실행마다 갈리는 입력(같은 node 키가 서로 다른 회전 키의 묶음에 든다: `rotationTracker.obsoleteKeys`가 맵을
    /// 돈다). Swift의 답은 그 가운데 하나여야 한다(계약 5절 TL-4: Swiftail은 묶음이 처음 나온 피어의 순서로 본다).
    @Test("unorderedPeerSets: Go의 여러 답 가운데 하나")
    func unorderedPeerSets() throws {
        let fixture = try GoFixture.load()
        for item in fixture.unorderedPeerSets {
            let kept = Self.kept(try G.authority(named: item.authority, in: fixture).state, try Self.peers(item.peers))
            let comparison: Comparison =
                item.outcomes.contains(kept) ? (item.outcomes.count > 1 ? .oneOfGoOutcomes : .same) : .mismatch("Swift \(kept)")
            print("Go 대조 unorderedPeerSets/\(item.name): Go \(item.runs)번 실행의 서로 다른 답 \(item.outcomes.count)개, Swift \(kept)")
            ComparisonTally.record(comparison, section: "unorderedPeerSets", row: item.name, total: fixture.unorderedPeerSets.count)
        }
    }

    // MARK: disablement

    static let disablementNames: [String] = (try? GoFixture.load())?.disablement.map(\.name) ?? []

    /// 줄마다: 그 상태의 끄기 값에 Go `DisablementKDF` 값이 드는지가 `ValidDisablement`와 같고, Swift `isValidDisablement`가 같은 판정이다.
    @Test("disablement: 끄기 비밀의 판정", .timeLimit(.minutes(5)), arguments: disablementNames)
    func disablement(_ name: String) throws {
        let fixture = try GoFixture.load()
        let item = try #require(fixture.disablement.first { $0.name == name })
        let authority = try G.authority(named: item.authority, in: fixture)
        let containsKDF = authority.state.disablementValues.contains(G.bytes(item.kdf))
        let valid = authority.isValidDisablement(secret: G.bytes(item.secret))
        ComparisonTally.record(
            valid == item.valid && containsKDF == item.valid ? .same : .mismatch("Swift \(valid)"), section: "disablement", row: name,
            total: Self.disablementNames.count
        )
    }

    // MARK: authKeys

    /// Go가 받아들이지만 Swiftail이 해석에서 거절하는 감싼 인증 키(동작 R3, 결정 L12·L13). 서버로 아무것도 보내지 않고
    /// `invalidConfiguration`으로 끝난다(가용성만 닫힌 쪽이다. 서명 권한 상태의 판정과는 무관하다).
    static let authKeyRejections: [String: String] = [
        // L12: Go는 원문 전체(개인 키 포함)를 인증 키로 돌려준다.
        "missing-dash": "L12", "padded-base64": "L12", "url-alphabet-key": "L12", "extra-dash": "L12",
        "credential-not-cbor": "L12", "empty-parts": "L12",
        // L12(TL-4가 더함): Go `RawStdEncoding`은 남는 비트를 보지 않고 줄바꿈을 건너뛰어 서명까지 만든다. Swiftail은 정규형만 받는다.
        "credential-trailing-bits": "L12", "key-trailing-bits": "L12", "credential-lf": "L12", "key-crlf": "L12",
        "key-trailing-lf": "L12",
        // L13: B가 64바이트가 아니면 Go는 서명에서 panic한다. 뒤 32바이트가 다르면 검증되지 않는 서명을 만든다.
        "key-63-bytes": "L13", "key-65-bytes": "L13", "key-32-bytes": "L13", "key-public-half-mismatch": "L13",
        // R3: credential이 아닌 A, A의 WrappingPubkey와 다른 키.
        "credential-direct-kind": "R3", "credential-wrapping-other-key": "R3",
    ]

    /// 줄마다: `--TL`이 없으면 평범한 인증 키(nil). Go가 감싼 키로 읽고 서명한 것은 Swift도 읽어 같은 앞부분·같은 credential이고,
    /// 같은 node 키에 만든 서명이 같은 `SigHash`이며 Go가 그 상태로 낸 판정과 같은 판정이다(CryptoKit 서명은 바이트가 매번 다르다).
    /// 의도된 차이의 줄은 Swift가 `invalidAuthKey`를 던지는지 본다.
    @Test("authKeys: 감싼 인증 키의 해석과 서명")
    func authKeys() throws {
        let fixture = try GoFixture.load()
        for item in fixture.authKeys {
            ComparisonTally.record(try Self.compareAuthKey(item, fixture), section: "authKeys", row: item.name, total: fixture.authKeys.count)
        }
    }

    static func compareAuthKey(_ item: GoFixture.AuthKey, _ fixture: GoFixture) throws -> Comparison {
        let parsed = Result { () throws(TKAError) in try WrappedAuthKey(parsing: item.input) }
        if let code = authKeyRejections[item.name] {
            guard case .failure(.invalidAuthKey) = parsed else { return .mismatch("Swift가 거절하지 않는다: \(parsed)") }
            return .intended(code)
        }
        if !item.isWrapped {
            guard case .success(nil) = parsed, item.authKey == item.input else { return .mismatch("Go는 평범한 인증 키, Swift \(parsed)") }
            return .same
        }
        guard case .success(let key?) = parsed else { return .mismatch("Go는 감싼 키로 읽는다, Swift \(parsed)") }
        guard item.sign == "ok", key.controlValue == item.authKey, G.hex(key.credential.serialized()) == item.credential else {
            return .mismatch("앞부분·credential")
        }
        let nodeKey = try G.nodeKey(try #require(item.nodeKey))
        let made = try key.keySignature(for: nodeKey)
        let goSignature = try NodeKeySignature(decoding: G.bytes(try #require(item.nks)))
        guard try NodeKeySignature(decoding: made).signatureHash == goSignature.signatureHash else { return .mismatch("SigHash") }
        if let authority = item.authority, let verdict = item.verdict {
            let state = try G.authority(named: authority, in: fixture).state
            if let difference = G.difference(state, nodeKey: nodeKey, nks: made, expected: verdict) { return .mismatch(difference) }
        }
        return .same
    }

    // MARK: resign

    /// 줄마다: Go가 만들면 Swift도 만들고, 옛 것을 그대로 썼는지·깊이·안쪽 node 키들이 같으며, 줄이지 않은 것은 `SigHash`까지 같다.
    /// Swift가 만든 서명은 Go가 자기 결과로 낸 판정과 같은 판정이다. Go가 실패하면 Swift도 던진다.
    ///
    /// 의도된 차이(계약 5절 "독립 검토에서 고치는 것: 제어의 절차 (TL-11b)" 항목 1): Swiftail은 이미 자기 NL 키로 서명한 사슬만
    /// 다시 서명한다. Go는 옛 서명을 검사하지 않고 만든다. 그 줄에서 Swift는 `invalidSignature`(rotation 겹이 NL 키로 검증되지
    /// 않음)나 `untrustedSigner`(맨 안쪽 `WrappingPubkey`가 NL 키가 아님)를 던지고, Go가 만든 것은 Go의 판정에서도 인가되지 않는다
    /// (다른 노드가 보는 판정은 같다: 둘 다 잠긴다).
    static let resignIntended: [String: TKAError] = [
        // 옛 direct의 회전 키는 nl/0이고 재서명하는 노드의 NL 키는 nl/1이다.
        "direct-wrapping-is-other-key": .untrustedSigner,
        "direct-no-wrapping": .untrustedSigner,
        // rotation은 감싼 키(서명된 인증 키)가 서명했다.
        "credential-chain": .invalidSignature,
    ]

    @Test("resign: 재서명")
    func resign() throws {
        let fixture = try GoFixture.load()
        for item in fixture.resign {
            ComparisonTally.record(try Self.compareResign(item, fixture), section: "resign", row: item.name, total: fixture.resign.count)
        }
    }

    static func publicKeys(_ signature: NodeKeySignature) -> [[UInt8]] {
        var out: [[UInt8]] = []
        var current: NodeKeySignature? = signature
        while let s = current {
            out.append(s.publicKey)
            current = s.nested
        }
        return out
    }

    static func compareResign(_ item: GoFixture.Resign, _ fixture: GoFixture) throws -> Comparison {
        let lockKey = try G.signingKey(seed: item.nlKey, in: fixture)
        let nodeKey = try G.nodeKey(item.nodeKey)
        let old = G.bytes(item.oldNKS)
        let made = Result { () throws(TKAError) in try NodeKeySignature.resigned(old, for: nodeKey, with: lockKey) }
        guard item.ok else {
            if case .success = made { return .mismatch("Go는 실패한다(\(item.error ?? "")), Swift는 만든다") }
            return .same
        }
        if let refusal = resignIntended[item.name] {
            guard case .failure(refusal) = made, item.verdict?.authorized == false else { return .mismatch("Swift \(made)") }
            return .intended("TL-11b 1")
        }
        guard case .success(let bytes) = made else { return .mismatch("Swift \(made)") }
        let result = try NodeKeySignature(decoding: bytes)
        let goResult = try NodeKeySignature(decoding: G.bytes(try #require(item.result)))
        var depth = 0
        var cursor: NodeKeySignature? = result
        while let s = cursor { depth += 1; cursor = s.nested }
        guard (bytes == old) == item.sameAsOld, depth == item.depth, publicKeys(result) == publicKeys(goResult) else {
            return .mismatch("모양(그대로·깊이·node 키)")
        }
        if (goResult.nested == (try? NodeKeySignature(decoding: old)) || item.sameAsOld), G.hex(result.signatureHash) != item.sigHash {
            return .mismatch("SigHash")
        }
        let state = try G.authority(named: item.authority, in: fixture).state
        if let verdict = item.verdict, let difference = G.difference(state, nodeKey: nodeKey, nks: bytes, expected: verdict) {
            return .mismatch(difference)
        }
        return .same
    }

    // MARK: limits

    static let limitCaseNames: [String] = (try? GoFixture.load())?.limits.flatMap { g in g.cases.map { "\(g.name)/\($0.name)" } } ?? []

    /// 의도된 차이 F7: Go는 빠른 길이 아닌 들이기마다 뿌리부터 2,000회 한도로 다시 계산하고(`computeChainCandidates`,
    /// `tka/tka.go:84-118`, 커밋한 뒤라 실패한 AUM이 저장소에 남는다), Swiftail은 뿌리부터의 재계산에 한도를 두지 않는다.
    /// 그 단계에서 Swift는 받아들이고, 머리는 갈래 규칙(가중치·종류가 같아 해시가 작은 쪽)으로 고른 pool 번호의 것이다.
    static let limitF7Heads: [String: [[Int]]] = [
        "long-chain/fork-at-depth-2000": [[2000, 2004]],
        "long-chain/held-and-new-at-depth-2000": [[2000], [2000]],
        "long-chain/fork-parent-path-2000": [[2001, 2005]],
    ]

    /// 사례마다: 같은 바탕(pool의 앞 `baseCount`개)의 머리가 같고, 단계마다 들이기의 판정과 머리가 Go와 같다. F7의 단계는 위 표대로.
    /// 부모 상태 찾기의 한도(체크포인트부터 2,000개는 되고 2,001개는 실패)는 Go와 Swift 모두 그대로다.
    @Test("limits: 뿌리에서 2,000개가 넘는 사슬", .timeLimit(.minutes(10)), arguments: limitCaseNames)
    func limits(_ name: String) throws {
        let fixture = try GoFixture.load()
        let group = try #require(fixture.limits.first { name.hasPrefix("\($0.name)/") })
        let limitCase = try #require(group.cases.first { "\(group.name)/\($0.name)" == name })
        let poolGroup = try #require(fixture.sync.first { $0.name == group.pool })
        let pool = try (poolGroup.pool + group.extra).map { hex throws(TKAError) in try G.aum(hex) }
        var authority = try G.authority(Array(pool[..<limitCase.baseCount]))
        var problems: [String] = []
        var intended = false
        if G.hex(authority.head.bytes) != limitCase.baseHead { problems.append("바탕의 머리") }
        for (index, step) in limitCase.steps.enumerated() {
            let result = Result { () throws(TKAError) in try authority.inform(step.aums.map { pool[$0] }) }
            let ok = if case .success = result { true } else { false }
            if let tips = Self.limitF7Heads[name]?[index], !step.ok, step.error?.contains("computing candidates") == true {
                let expected = tips.map { pool[$0].hash }.min { $0.bytes.lexicographicallyPrecedes($1.bytes) }
                if ok, authority.head == expected { intended = true } else { problems.append("\(step.name) F7: Swift \(result)") }
                continue
            }
            if ok != step.ok { problems.append("\(step.name) 판정: Go \(step.ok) \(step.error ?? ""), Swift \(result)") }
            if G.hex(authority.head.bytes) != step.head { problems.append("\(step.name) 머리") }
        }
        let comparison: Comparison = !problems.isEmpty ? .mismatch(problems.joined(separator: "; ")) : intended ? .intended("F7") : .same
        ComparisonTally.record(comparison, section: "limits", row: name, total: Self.limitCaseNames.count)
    }

    // MARK: padded

    /// Swiftail의 바이트 한도(동작 M)를 넘긴 입력. Go에는 이 한도가 없어 모두 받아들인다. 그 줄에서 Swift가 낼 답:
    /// - NKS 8,193바이트: 인가하지 않는다(그 피어는 빠진다). 닫힌 쪽(가용성).
    /// - 재서명의 옛 서명 8,193바이트: `limitExceeded`(서명 없이 등록, 동작 R5 ①). 닫힌 쪽(가용성).
    /// - AUM 524,289바이트: `limitExceeded`(결정 L16). **Go가 받는 것을 거절해 사슬을 따라가지 못하는 쪽**이다. 다만 채운 것은 모르는
    ///   필드라 해시가 같고, 제어 서버는 AUM을 덧붙이지 않고 아예 주지 않을 수도 있으므로 새로 생기는 공격 능력은 아니다.
    /// - credential 8,193바이트의 인증 키: `invalidAuthKey`(동작 R3·M). 닫힌 쪽(가용성).
    static let paddedIntended: [String: String] = [
        "nks-direct-8193-bytes": "M", "resign-old-8193-bytes": "M·R5", "aum-noop-524289-bytes": "M·L16",
        "auth-key-credential-8193-bytes": "M",
    ]

    @Test("padded: Swiftail 바이트 한도의 경계")
    func padded() throws {
        let fixture = try GoFixture.load()
        for item in fixture.padded {
            ComparisonTally.record(try Self.comparePadded(item, fixture), section: "padded", row: item.name, total: fixture.padded.count)
        }
    }

    static func comparePadded(_ item: GoFixture.Padded, _ fixture: GoFixture) throws -> Comparison {
        let input = G.padded(item)
        guard input.count == item.length else { return .mismatch("만든 입력의 길이 \(input.count)") }
        let intended = paddedIntended[item.name]
        let authority = try G.authority(named: try #require(item.authority), in: fixture)
        switch item.kind {
        case "authorize":
            let verdict = try #require(item.verdict)
            let nodeKey = try G.nodeKey(try #require(item.nodeKey))
            if let intended {
                let swift = Result { () throws(TKAError) in try authority.state.authorize(nodeKey, keySignature: input) }
                guard case .failure(.unauthorized) = swift, verdict.authorized else { return .mismatch("Swift \(swift)") }
                return .intended(intended)
            }
            return G.difference(authority.state, nodeKey: nodeKey, nks: input, expected: verdict).map { .mismatch($0) } ?? .same
        case "resign":
            let nodeKey = try G.nodeKey(try #require(item.nodeKey))
            let lockKey = try G.signingKey(seed: try #require(item.nlKey), in: fixture)
            let made = Result { () throws(TKAError) in try NodeKeySignature.resigned(input, for: nodeKey, with: lockKey) }
            guard let intended, item.ok, case .failure(.limitExceeded) = made else { return .mismatch("Swift \(made)") }
            return .intended(intended)
        case "inform":
            var next = authority
            let result = Result { () throws(TKAError) in try next.inform([AUM(decoding: input)]) }
            if let intended {
                guard item.ok, case .failure(.limitExceeded) = result, next.head == authority.head else { return .mismatch("Swift \(result)") }
                return .intended(intended)
            }
            let ok = if case .success = result { true } else { false }
            return ok == item.ok && G.hex(next.head.bytes) == item.head ? .same : .mismatch("Swift \(result)")
        case "authKey":
            let text = try #require(item.controlValue) + "--TL" + G.rawBase64(input) + "-" + G.rawBase64(G.bytes(try #require(item.privateKey)))
            let parsed = Result { () throws(TKAError) in try WrappedAuthKey(parsing: text) }
            guard let intended, item.ok, case .failure(.invalidAuthKey) = parsed else { return .mismatch("Swift \(parsed)") }
            return .intended(intended)
        default:
            return .mismatch("모르는 종류 \(item.kind)")
        }
    }

    // MARK: openedStates

    /// `Key25519`가 아닌 키가 든 상태(Go는 `tka.Open`이 다시 검증하지 않아 열린다. Swiftail은 열 때 다시 검증해 이런 상태를 쥐지
    /// 않는다, 결정 L14). 판정 함수 `AuthorityState.authorize`만 견준다: 체크포인트를 디코딩만 한 상태로 부르면 Go `GetKey`처럼
    /// 그런 키를 앞에서 만나면 인가하지 않고, 뒤에 있으면 인가한다.
    @Test("openedStates: Key25519가 아닌 키가 든 상태에서 GetKey")
    func openedStates() throws {
        let fixture = try GoFixture.load()
        for item in fixture.openedStates {
            let state = try #require(try G.aum(item.checkpoint).state)
            let verdict = G.verdict(authorized: item.authorized, error: item.error, rotation: item.rotation)
            var comparison: Comparison = item.openOK
                ? G.difference(state, nodeKey: try G.nodeKey(item.nodeKey), nks: G.bytes(item.nks), expected: verdict).map { .mismatch($0) } ?? .same
                : .mismatch("Go가 열지 못했다(\(item.openError ?? ""))")
            // Swiftail은 이 체크포인트로 상태를 만들지 않는다(정적 검사에서 떨어진다).
            if (try? Authority(bootstrappingWith: G.aum(item.checkpoint))) != nil { comparison = .mismatch("Swift가 부트스트랩한다") }
            ComparisonTally.record(comparison, section: "openedStates", row: item.name, total: fixture.openedStates.count)
        }
    }

    // MARK: 새로 뽑아 견주기

    /// `sh Scripts/build-interop-tools.sh tkafixtures`가 출력한 도구 경로. 도구는 `Tools/interop`에서, README의 환경
    /// (`GOCACHE`·`GOMODCACHE`·`GOFLAGS`)으로 돌아야 한다(피어 집합의 overlay 빌드가 그 go.mod를 쓴다).
    static let fixtureTool = ProcessInfo.processInfo.environment["SWIFTAIL_TKAFIXTURES"].flatMap { $0.isEmpty ? nil : $0 }

    @Test(
        "Go 도구로 새로 뽑은 자료가 저장된 자료와 바이트까지 같다(SWIFTAIL_TKAFIXTURES가 없으면 건너뜀)",
        .enabled(if: fixtureTool != nil), .timeLimit(.minutes(5))
    )
    func freshGoFixtures() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let process = Process()
        process.executableURL = URL(fileURLWithPath: try #require(Self.fixtureTool))
        process.currentDirectoryURL = root.appendingPathComponent("Tools/interop")
        let pipe = Pipe()
        process.standardOutput = pipe
        try process.run()
        let fresh = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        #expect(process.terminationStatus == 0)
        let stored = try Data(contentsOf: try GoFixture.url)
        #expect(fresh == stored, "저장된 tka-fixtures.json이 도구 출력과 다르다(\(fresh.count)바이트, 저장 \(stored.count)바이트)")
    }
}
