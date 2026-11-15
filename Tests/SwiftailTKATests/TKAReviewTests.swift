import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// TL-11a 검토(`SwiftailTKA` 보안 검토)의 재현과, 검토가 `tkafixtures`에 더한 Go 판정(`reviewChains`·`reviewSignatures`)의 대조.
///
/// **실패하는 시험이 발견이다.** 각 시험의 주석에 입력을 쥔 쪽(제어 서버·신뢰 키 보유자·피어)과 Go의 답을 어떻게 얻었는지
/// 적었다. 라이브러리 코드는 고치지 않았다.
@Suite("TL-11a 검토: SwiftailTKA")
struct TKAReviewTests {
    typealias G = GoComparison
    typealias T = AuthorityTesting

    static var isOptimized: Bool {
        #if DEBUG
            false
        #else
            true
        #endif
    }

    // MARK: Go 대조(검토가 더한 줄)

    /// 서명 목록만 다른 같은 AUM(변종), 같은 나무를 다른 묶음·순서로, 지운 키를 다시 더하기, Votes·Meta 경계, 진 갈래의
    /// 체크포인트, 부모 해시가 32바이트가 아닌 부트스트랩 등 22개 사슬. 단계마다 판정·머리·상태가 Go와 같다.
    @Test("reviewChains: 검토가 더한 사슬의 판정·머리·상태", .timeLimit(.minutes(10)))
    func reviewChains() throws {
        let fixture = try GoFixture.load()
        for chain in fixture.reviewChains {
            ComparisonTally.record(
                GoComparisonTests.compareChain(chain), section: "reviewChains", row: chain.name, total: fixture.reviewChains.count
            )
        }
    }

    /// 길이가 틀린 서명, 33바이트 회전 키, 같은 node 키로의 회전, 바깥 KeyID, 지운 키의 credential, credential을 감싼
    /// rotation 위의 rotation, 잘린·비최단 NKS 등 15개. 판정·내력·SigHash가 Go와 같다.
    @Test("reviewSignatures: 검토가 더한 NKS의 판정과 내력")
    func reviewSignatures() throws {
        let fixture = try GoFixture.load()
        var states: [String: AuthorityState] = [:]
        for item in fixture.reviewSignatures {
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
                problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; ")), section: "reviewSignatures",
                row: item.name, total: fixture.reviewSignatures.count
            )
        }
    }

    // MARK: 발견 1 — 빈 Meta만 있는 UpdateKey는 들인 뒤 다시 열리지 않는다

    /// 입력을 쥔 쪽: 신뢰 키 보유자. UpdateKey{KeyID}의 SigHash에 서명하고, 보낼 때 `07a0`(빈 Meta)을 붙인다.
    ///
    /// 받은 값은 `meta == []`라 정적 검사(UpdateKey는 Votes나 Meta가 있어야 한다)를 통과하고 Go도 Swift도 받아들인다
    /// (`reviewChains`의 `review/votes-and-meta-bounds/update-meta-empty-wire-only`). 그런데 정준 바이트는 빈 Meta를 빼므로,
    /// 저장소(`TailnetLockStore`: `serialized()`를 적고 `AUM(decoding:)`으로 읽는다)에서 다시 읽은 AUM은 Votes도 Meta도 없어
    /// 정적 검사에 떨어진다. 결정 L14의 재검증 때문에 `Authority(opening:)`이 던지고, 노드는 다시 시작할 때마다 `.unverified`
    /// (피어 없음, 동작 T4는 다시 시도하지 않는다)가 된다. 앱이 상태 파일을 지울 때까지 풀리지 않는다.
    ///
    /// Go의 답: `tka.Open`은 저장소를 다시 검증하지 않아 같은 사슬을 연다. 임시 Go 프로그램(`eyebuild dir tl11a-review`의
    /// `probe/main.go`, FS chonk에 Bootstrap → `07a0` UpdateKey를 Inform → 새 `ChonkDir`로 `Open`)의 출력:
    /// `wire Meta nil=false, StaticValidate=<nil>` / `inform ok` / `open ok`(머리 같음) /
    /// `stored Meta nil=true, StaticValidate=UpdateKey AUMs must contain an update to votes or key metadata`.
    @Test("발견 1: 빈 Meta(07a0)만 있는 UpdateKey를 들인 상태가 저장 뒤 다시 열린다")
    func emptyMetaUpdateKeySurvivesReopen() throws {
        let fixture = try GoFixture.load()
        let chain = try #require(fixture.reviewChains.first { $0.name == "review/votes-and-meta-bounds" })
        var authority = try Authority(bootstrappingWith: G.aum(chain.bootstrap))
        for step in chain.steps where step.ok {
            try authority.inform(step.aums.map { hex throws(TKAError) in try G.aum(hex) })
            if step.name == "update-meta-empty-wire-only" { break }
        }
        let wire = try #require(authority.aums.last)
        #expect(wire.messageKind == AUM.Kind.updateKey && wire.meta == [] && wire.votes == nil)

        // 저장소가 하는 대로 정준 바이트를 적고 다시 읽는다.
        let stored = try authority.aums.map { aum throws(TKAError) in try AUM(decoding: aum.serialized()) }
        #expect(stored.last?.hash == wire.hash, "해시는 같다(빈 Meta는 해시에 들지 않는다)")
        do {
            let reopened = try Authority(opening: stored, bootstrap: authority.bootstrap)
            #expect(reopened.head == authority.head)
        } catch {
            Issue.record("받아들인 사슬을 다시 열지 못한다: \(error). Go `tka.Open`은 연다")
        }
    }

    // MARK: 발견 2 — 제어 서버가 서명 목록만 바꾼 AUM으로 저장 한도를 채워 lock 상태를 얼린다

    /// 입력을 쥔 쪽: 제어 서버(서명 키가 없다).
    ///
    /// AUM의 해시는 서명 목록을 담고, 서명 목록은 검증만 통과하면 되므로(같은 서명 되풀이, 일부만, 순서 바꿈) 신뢰 키 서명이
    /// 붙은 AUM 하나에서 서로 다른 해시의 "유효한" 형제 AUM을 얼마든지 만들 수 있다. Go와 Swift 모두 그것을 받아들인다
    /// (`reviewChains`의 `review/duplicate-signature-variant-*`, `review/signature-order-variant`). Go는 쥐는 AUM 수에 한도가
    /// 없지만(`tka/tka.go:584-665`의 `InformIdempotent`) Swiftail은 4,096개·16MiB에서 묶음을 통째로 거절한다(동작 M, 결정
    /// L7·L16). 그래서 서버가 변종으로 한도를 채우면 그 뒤의 **모든** AUM(키 제거, 복구 체크포인트)이 `limitExceeded`로
    /// 떨어지고, 노드는 상태 파일을 지울 때까지 지워진 키를 계속 믿는다. 서버가 AUM을 주지 않는 것과 달리 서버가 정상으로
    /// 돌아와도 풀리지 않고, 같은 서버에서 받는 Go 노드는 영향이 없다.
    ///
    /// 재현: 키 64개, 그 64개가 서명한 NoOp 하나, 서버가 그 서명들로 만든 순서쌍 4,094개(검증 8,252번). 실제 tailnet의 AUM은
    /// 서명이 하나라 변종의 서명 수가 늘어날 뿐이다(`[s]×k`, 바이트 한도 16MiB를 k ≈ 570까지로 채운다).
    ///
    /// Go의 답: 같은 모양의 임시 Go 프로그램(`eyebuild dir tl11a-review`의 `probe2/main.go`, ChonkMem)의 출력은
    /// `variants inform: <nil>` / `remove-key inform: <nil>` / `removed key still trusted: false keys: 63`이다.
    @Test("발견 2: 서명 목록 변종으로 한도가 찬 뒤에도 신뢰 키의 RemoveKey를 따라간다", .timeLimit(.minutes(10)))
    func controlServerCannotFreezeAuthority() throws {
        let signers = (0..<64).map { _ in T.Signer() }
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState(signers.map { $0.trusted() }), by: [signers[0]]))
        let original = T.noOp(after: authority.head, by: signers)
        try authority.inform([original])

        // 서버가 쥔 것은 original의 서명 64개뿐이다. 그것으로 서명 둘짜리 목록을 만든다.
        let room = Authority.maximumAUMCount - authority.aums.count
        var variants: [AUM] = []
        for first in original.signatures {
            for second in original.signatures where variants.count < room {
                var variant = original
                variant.signatures = [first, second]
                variants.append(variant)
            }
        }
        #expect(Set(variants.map(\.hash)).count == room, "서로 다른 AUM이다")
        try authority.inform(variants)
        #expect(authority.aums.count == Authority.maximumAUMCount)

        // 신뢰 키가 머리 위에서 signers[1]을 지운다. Go는 받아들이고 키를 지운다.
        let removal = T.removeKey(signers[1].publicKey, after: authority.head, by: [signers[0]])
        let error = T.informError(&authority, [removal])
        #expect(error == nil, "서버가 만든 변종 \(room)개 뒤에 RemoveKey가 거절된다: \(String(describing: error))")
        #expect(authority.state.key(withID: signers[1].publicKey) == nil, "지운 키를 계속 믿는다")
    }

    // MARK: 발견 3 — 서버의 조상 목록이 MissingAUMs 계산을 부풀린다

    /// 입력을 쥔 쪽: 제어 서버. sync/offer 응답의 `Ancestors`는 개수 한도가 없고(본문 8MiB ≈ 152,000개), `missingAUMs`는 목록을
    /// 앞에서부터 보며 로컬에 있는 조상마다 `state(at:)`(체크포인트까지 거꾸로 가며 다시 적용)과 앞으로 감기를 한다. 진 갈래의
    /// AUM(서버가 서명 목록 변종으로 언제든 만든다)을 되풀이해 넣으면 조상마다 그 깊이만큼 일하고 교차는 끝내 없다. Go도 같은
    /// 반복이다(`tka/sync.go:188-209`, Go의 본문 한도는 512MiB). `ControlClient`는 actor 위에서 이것을 부른다.
    ///
    /// 시험은 조상 하나의 비용을 재고 8MiB 응답으로 늘려 적는다. 릴리스에서 한 번의 동기화가 1초를 넘으면 실패한다.
    @Test("발견 3: 진 갈래 AUM을 되풀이한 조상 목록의 MissingAUMs 비용", .timeLimit(.minutes(10)))
    func missingAUMsAncestorAmplification() throws {
        let signer = T.Signer()
        let depth = Self.isOptimized ? 1_999 : 49
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([signer.trusted()]), by: [signer]))
        let chain = T.noOpChain(after: authority.head, count: depth, by: signer)
        try authority.inform(chain)
        let last = try #require(chain.last)
        // 진 갈래: 마지막 NoOp의 서명을 되풀이한 변종 가운데 해시가 더 큰 것.
        let losing = try #require(
            (2...64).lazy.map { count in
                var variant = last
                variant.signatures = Array(repeating: last.signatures[0], count: count)
                return variant
            }.first { last.hash.bytes.lexicographicallyPrecedes($0.hash.bytes) }
        )
        try authority.inform([losing])
        #expect(authority.head == last.hash)

        let unknown = try #require(AUMHash(Array(repeating: 0x5a, count: 32)))
        let ancestorCount = Self.isOptimized ? 2_000 : 20
        let offer = SyncOffer(head: unknown, ancestors: Array(repeating: losing.hash, count: ancestorCount))
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            #expect(throws: TKAError.noIntersection) { try authority.missingAUMs(for: offer) }
        }
        let perAncestor = elapsed / ancestorCount
        let worstCount = 8 * 1_024 * 1_024 / 55  // `"<52자>",` 하나가 55바이트
        let worst = perAncestor * worstCount
        print("TL-11a 측정 조상 증폭: 깊이 \(depth), 조상 \(ancestorCount)개 \(elapsed), 하나 \(perAncestor), 8MiB(\(worstCount)개) ≈ \(worst)")
        if Self.isOptimized {
            #expect(worst < .seconds(1), "제어 서버 하나의 sync/offer 응답으로 actor가 \(worst) 막힌다")
        }
    }

    // MARK: 퍼저

    /// 결정적 의사 난수(SplitMix64). 퍼저가 같은 입력을 되풀이하도록 씨앗을 고정한다.
    struct SplitMix64: RandomNumberGenerator {
        var state: UInt64
        mutating func next() -> UInt64 {
            state &+= 0x9e37_79b9_7f4a_7c15
            var z = state
            z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
            z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
            return z ^ (z >> 31)
        }
    }

    /// AUM·NKS마다 바꾼 입력의 수. 환경 변수 `TL11A_FUZZ_ROUNDS`로 늘린다(검토는 디버그 20,000·릴리스 200,000으로 돌렸다).
    static let fuzzRounds = ProcessInfo.processInfo.environment["TL11A_FUZZ_ROUNDS"].flatMap(Int.init) ?? 3_000

    /// CBOR 머리로 의미가 있는 바이트(긴 길이, 길이 미정, break, 단순값, 태그, 텍스트).
    static let interestingBytes: [UInt8] = [
        0x00, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1f, 0x20, 0x3b, 0x40, 0x58, 0x5a, 0x5b, 0x5f, 0x60, 0x7b, 0x7f, 0x80, 0x98,
        0x9b, 0x9f, 0xa0, 0xb8, 0xbb, 0xbf, 0xc0, 0xd8, 0xe0, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfb, 0xff,
    ]

    /// 바이트를 1~4번 바꾼다: 비트 뒤집기, 바이트 바꾸기, 자르기, 넣기, 조각 되풀이, 다른 입력과 잇기, 덧붙이기.
    static func mutate(_ input: [UInt8], pool: [[UInt8]], using rng: inout SplitMix64) -> [UInt8] {
        var bytes = input
        for _ in 0..<Int.random(in: 1...4, using: &rng) {
            switch Int.random(in: 0..<8, using: &rng) {
            case 0 where !bytes.isEmpty:
                bytes[Int.random(in: bytes.indices, using: &rng)] ^= 1 << UInt8.random(in: 0..<8, using: &rng)
            case 1 where !bytes.isEmpty:
                bytes[Int.random(in: bytes.indices, using: &rng)] = UInt8.random(in: .min ... .max, using: &rng)
            case 2 where !bytes.isEmpty:
                bytes.removeLast(Int.random(in: 1...bytes.count, using: &rng))
            case 3:
                bytes.insert(interestingBytes[Int.random(in: interestingBytes.indices, using: &rng)], at: Int.random(in: 0...bytes.count, using: &rng))
            case 4 where !bytes.isEmpty:
                let start = Int.random(in: bytes.indices, using: &rng)
                let end = Int.random(in: start...min(bytes.count, start + 24), using: &rng)
                bytes.insert(contentsOf: bytes[start..<end], at: Int.random(in: 0...bytes.count, using: &rng))
            case 5:
                let other = pool[Int.random(in: pool.indices, using: &rng)]
                let cut = Int.random(in: 0...bytes.count, using: &rng)
                bytes = Array(bytes[..<cut]) + other[Int.random(in: 0...other.count, using: &rng)...]
            case 6:
                bytes += (0..<Int.random(in: 1...8, using: &rng)).map { _ in UInt8.random(in: .min ... .max, using: &rng) }
            default:
                guard !bytes.isEmpty else { continue }
                bytes[Int.random(in: bytes.indices, using: &rng)] = interestingBytes[Int.random(in: interestingBytes.indices, using: &rng)]
            }
        }
        return bytes
    }

    /// `package` 진입점 모두에 Go 자료의 유효·무효 입력을 바꾼 것을 넣는다. 트랩이 나면 시험 프로세스가 죽는다(그것이 발견이다).
    ///
    /// 불변 조건도 본다: 정적 검사를 통과한 AUM은 정준 바이트로 다시 읽어도 통과하고 해시가 같다(발견 1의 일반형),
    /// 읽힌 NKS는 정준 바이트로 다시 읽으면 같은 값이다.
    @Test("퍼저: package 진입점에 뒤집고 자르고 이은 입력", .timeLimit(.minutes(10)))
    func fuzzEntryPoints() throws {
        let fixture = try GoFixture.load()
        var rng = SplitMix64(state: 0x5449_4c31_3161)
        let small = { (bytes: [UInt8]) in bytes.count <= 16 * 1_024 }
        let aumPool =
            (fixture.cbor.filter { $0.type == "aum" }.map { G.bytes($0.input) }
            + (fixture.chains + fixture.reviewChains).flatMap { [G.bytes($0.bootstrap)] + $0.steps.flatMap { $0.aums.map(G.bytes) } })
            .filter(small)
        let nksPool =
            ((fixture.signatures + fixture.reviewSignatures).map { G.bytes($0.nks) }
            + fixture.cbor.filter { $0.type == "nks" }.map { G.bytes($0.input) }).filter(small)
        let authority = try G.authority(named: "nks-base", in: fixture)
        let forked = try #require(fixture.reviewChains.first { $0.name == "review/same-tree-split" })
        var syncAuthority = try Authority(bootstrappingWith: G.aum(forked.bootstrap))
        for step in forked.steps where step.ok { try syncAuthority.inform(step.aums.map { hex throws(TKAError) in try G.aum(hex) }) }
        let nodeKeys = try fixture.signatures.map { try G.nodeKey($0.nodeKey) }
        let lockKey = Curve25519.Signing.PrivateKey()
        var counts: [String: Int] = [:]

        for _ in 0..<Self.fuzzRounds {
            let bytes = Self.mutate(aumPool[Int.random(in: aumPool.indices, using: &rng)], pool: aumPool, using: &rng)
            counts["aum", default: 0] += 1
            _ = try? CBOR.decode(bytes)
            guard let aum = try? AUM(decoding: bytes) else { continue }
            counts["aum decoded", default: 0] += 1
            _ = aum.hash
            _ = aum.signatureHash
            if (try? aum.validate()) != nil {
                counts["aum valid", default: 0] += 1
                let again = try? AUM(decoding: aum.serialized())
                if again?.hash != aum.hash || (try? again?.validate()) == nil {
                    // 발견 1의 모양(빈 Meta만 있는 UpdateKey)은 따로 센다. 그 밖의 모양이 나오면 새 발견이다.
                    if aum.messageKind == AUM.Kind.updateKey, aum.meta == [], aum.votes == nil {
                        counts["aum 발견 1의 모양", default: 0] += 1
                    } else {
                        Issue.record("정준 바이트로 다시 읽으면 달라진다: \(G.hex(bytes))")
                    }
                }
            }
            var copy = authority
            if (try? copy.inform([aum])) != nil { counts["aum informed", default: 0] += 1 }
            var syncCopy = syncAuthority
            if (try? syncCopy.inform([aum])) != nil { counts["aum informed (sync)", default: 0] += 1 }
        }

        for index in 0..<Self.fuzzRounds {
            let bytes = Self.mutate(nksPool[Int.random(in: nksPool.indices, using: &rng)], pool: nksPool, using: &rng)
            counts["nks", default: 0] += 1
            let nodeKey = nodeKeys[index % nodeKeys.count]
            if let signature = try? NodeKeySignature(decoding: bytes) {
                counts["nks decoded", default: 0] += 1
                _ = signature.signatureHash
                #expect((try? NodeKeySignature(decoding: signature.serialized())) == signature, "NKS 정준 바이트: \(G.hex(bytes))")
            }
            if (try? authority.state.authorize(nodeKey, keySignature: bytes)) != nil { counts["nks authorized", default: 0] += 1 }
            if index % 10 == 0, (try? NodeKeySignature.resigned(bytes, for: nodeKey, with: lockKey)) != nil {
                counts["nks resigned", default: 0] += 1
            }
        }

        for _ in 0..<300 {
            let peers = (0..<4).map { _ in
                PeerCredential(
                    nodeKey: nodeKeys[Int.random(in: nodeKeys.indices, using: &rng)],
                    keySignature: Self.mutate(nksPool[Int.random(in: nksPool.indices, using: &rng)], pool: nksPool, using: &rng),
                    unsignedPeerAPIOnly: Bool.random(using: &rng)
                )
            }
            #expect(authority.state.admitted(peers).count == peers.count)
        }

        let texts = fixture.text.filter { $0.kind == "aumHash.decode" }.map { Array($0.input.utf8) }
        for _ in 0..<3_000 {
            _ = AUMHash(text: String(decoding: Self.mutate(texts[Int.random(in: texts.indices, using: &rng)], pool: texts, using: &rng), as: UTF8.self))
        }

        let authKeys = fixture.authKeys.map { Array($0.input.utf8) }
        for _ in 0..<1_000 {
            let text = String(decoding: Self.mutate(authKeys[Int.random(in: authKeys.indices, using: &rng)], pool: authKeys, using: &rng), as: UTF8.self)
            if let wrapped = try? WrappedAuthKey(parsing: text) {
                counts["authKey parsed", default: 0] += 1
                _ = try? wrapped.keySignature(for: nodeKeys[0])
            }
        }

        let known = syncAuthority.aums.map(\.hash)
        for _ in 0..<500 {
            let pick = { (rng: inout SplitMix64) -> AUMHash in
                Bool.random(using: &rng)
                    ? known[Int.random(in: known.indices, using: &rng)]
                    : AUMHash((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &rng) }) ?? known[0]
            }
            let offer = SyncOffer(head: pick(&rng), ancestors: (0..<Int.random(in: 0...6, using: &rng)).map { _ in pick(&rng) })
            if (try? syncAuthority.missingAUMs(for: offer)) != nil { counts["missingAUMs ok", default: 0] += 1 }
        }

        let stored = syncAuthority.aums
        for _ in 0..<200 {
            var copy = stored
            switch Int.random(in: 0..<4, using: &rng) {
            case 0: copy.shuffle(using: &rng)
            case 1: copy.remove(at: Int.random(in: copy.indices, using: &rng))
            case 2: copy.append(copy[Int.random(in: copy.indices, using: &rng)])
            default:
                let index = Int.random(in: copy.indices, using: &rng)
                if let mutated = try? AUM(decoding: Self.mutate(copy[index].serialized(), pool: aumPool, using: &rng)) { copy[index] = mutated }
            }
            let root = Bool.random(using: &rng) ? syncAuthority.bootstrap : copy[Int.random(in: copy.indices, using: &rng)].hash
            if (try? Authority(opening: copy, bootstrap: root)) != nil { counts["opened", default: 0] += 1 }
        }

        let disablement = try G.authority(named: "disablement", in: fixture)
        for length in [0, 7] {
            #expect(!disablement.isValidDisablement(secret: (0..<length).map { _ in UInt8.random(in: .min ... .max, using: &rng) }))
        }
        print("TL-11a 퍼저: " + counts.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", "))
    }

    // MARK: 비밀

    /// 감싼 인증 키의 개인 키와 인증 키 앞부분이 `description`·`String(reflecting:)`·`dump`·`Mirror`에 나오지 않는다(동작 K2).
    @Test("비밀: WrappedAuthKey는 어느 표기에도 키를 드러내지 않는다")
    func wrappedAuthKeyHidesSecrets() throws {
        let fixture = try GoFixture.load()
        let item = try #require(fixture.authKeys.first { $0.isWrapped && $0.privateKeyLength == 64 && $0.verdict?.authorized == true })
        let wrapped = try #require(try WrappedAuthKey(parsing: item.input))
        var dumped = ""
        dump(wrapped, to: &dumped)
        let marker = try #require(item.input.range(of: "--TL"))
        let suffix = String(item.input[marker.upperBound...])
        let renderings = ["\(wrapped)", String(reflecting: wrapped), dumped, String(describing: Mirror(reflecting: wrapped).children.map(\.value))]
        for rendering in renderings {
            #expect(!rendering.contains(wrapped.controlValue) && !rendering.contains(suffix) && !rendering.contains("--TL"), "\(rendering)")
        }
        #expect(Mirror(reflecting: wrapped).children.isEmpty)
    }

    // MARK: 릴리스 측정

    /// 최악에 가까운 입력의 시간(릴리스 빌드에서만 돈다. 디버그의 순수 Swift Ed25519는 60~100배 느리다).
    /// 결과는 표준 출력의 `TL-11a 측정` 줄이다. 판정은 하지 않는다.
    @Test("측정: 릴리스 빌드의 최악 입력 시간", .enabled(if: isOptimized), .timeLimit(.minutes(20)))
    func releaseMeasurements() throws {
        let clock = ContinuousClock()
        let signer = T.Signer()
        let root = T.checkpoint(T.checkpointState([signer.trusted()]), by: [signer])
        let base = try Authority(bootstrappingWith: root)

        // 1. 한 묶음 4,095개(한도 끝)의 직선 사슬.
        let chain = T.noOpChain(after: base.head, count: Authority.maximumAUMCount - 1, by: signer)
        var linear = base
        print("TL-11a 측정 들이기 NoOp 4,095개 한 묶음: \(clock.measure { try? linear.inform(chain) }), 머리 \(linear.aums.count)")

        // 2. 그 저장소를 다시 열기(L14: 서명까지 재검증).
        let stored = linear.aums
        print("TL-11a 측정 다시 열기 4,096개: \(clock.measure { _ = try? Authority(opening: stored, bootstrap: base.bootstrap) })")

        // 3. 신뢰 키 서명을 4,096번 되풀이한 AUM 하나(약 420KiB, 제어 서버가 만들 수 있다).
        var heavy = T.noOp(after: base.head, by: [signer])
        heavy.signatures = Array(repeating: heavy.signatures[0], count: 4_096)
        var heavyAuthority = base
        let heavyBytes = heavy.serialized().count
        print("TL-11a 측정 서명 4,096개짜리 AUM(\(heavyBytes)바이트) 들이기: \(clock.measure { try? heavyAuthority.inform([heavy]) })")

        // 4. AddKey 4,095개 한 묶음(신뢰 키 보유자): `inform`은 AUM마다 상태 전체를 쥔다(키 배열 복사 O(n²)).
        // 마지막 AddKey는 5의 서명 키다(신뢰 키 목록의 맨 뒤).
        let lastKey = Curve25519.Signing.PrivateKey()
        var parent = base.head
        var addKeys: [AUM] = []
        for index in 0..<(Authority.maximumAUMCount - 1) {
            let isLast = index == Authority.maximumAUMCount - 2
            let publicKey = isLast ? Array(lastKey.publicKey.rawRepresentation) : (0..<32).map { _ in UInt8.random(in: .min ... .max) }
            let aum = T.addKey(TrustedKey(kind: 1, votes: 1, publicKey: publicKey), after: parent, by: [signer])
            addKeys.append(aum)
            parent = aum.hash
        }
        var keyed = base
        let before = Self.maximumResidentBytes()
        let addKeyTime = clock.measure { try? keyed.inform(addKeys) }
        let after = Self.maximumResidentBytes()
        print("TL-11a 측정 AddKey 4,095개 한 묶음: \(addKeyTime), 키 \(keyed.state.keys.count)개, 최대 RSS \(before / 1_048_576)MiB → \(after / 1_048_576)MiB")

        // 5. 키 4,096개 상태에서 피어 1,000개(direct 서명, 서명 키가 맨 뒤) 거르기.
        let peers = try (0..<1_000).map { _ in
            let node = try #require(NodePublicKey(rawValue: Array(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation)))
            var signature = NodeKeySignature(kind: NodeKeySignature.Kind.direct, publicKey: node.binaryForm, keyID: Array(lastKey.publicKey.rawRepresentation))
            try signature.sign(with: lastKey)
            return PeerCredential(nodeKey: node, keySignature: signature.serialized(), unsignedPeerAPIOnly: false)
        }
        let crowdedState = keyed.state
        print("TL-11a 측정 피어 1,000개 거르기(키 \(crowdedState.keys.count)개): \(clock.measure { _ = crowdedState.admitted(peers) })")
    }

    /// 발견 3을 Go 클라이언트가 만드는 사슬(50개마다 체크포인트, `tka/builder.go:123`)의 깊이 49로 잰다(릴리스).
    @Test("측정: 깊이 49의 조상 증폭", .enabled(if: isOptimized))
    func ancestorAmplificationAtCheckpointInterval() throws {
        let signer = T.Signer()
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([signer.trusted()]), by: [signer]))
        let chain = T.noOpChain(after: authority.head, count: 49, by: signer)
        try authority.inform(chain)
        let last = try #require(chain.last)
        var losing = last
        losing.signatures = [last.signatures[0], last.signatures[0]]
        try authority.inform([losing])
        let losingHash = authority.head == losing.hash ? last.hash : losing.hash
        let unknown = try #require(AUMHash(Array(repeating: 0x5a, count: 32)))
        let count = 8 * 1_024 * 1_024 / 55
        let offer = SyncOffer(head: unknown, ancestors: Array(repeating: losingHash, count: count))
        let elapsed = ContinuousClock().measure { _ = try? authority.missingAUMs(for: offer) }
        print("TL-11a 측정 조상 증폭: 깊이 49, 조상 \(count)개(8MiB): \(elapsed)")
    }

    /// 이 프로세스의 최대 상주 메모리(macOS의 `ru_maxrss`는 바이트).
    static func maximumResidentBytes() -> Int {
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        return Int(usage.ru_maxrss)
    }
}
