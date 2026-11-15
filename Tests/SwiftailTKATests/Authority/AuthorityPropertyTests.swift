import Testing

@testable import SwiftailTKA

/// 들이기의 성질(차례와 무관한 머리, 다시 들이기, 다시 열기), 한도의 경계(동작 F7·M), 망가진 입력.
@Suite("서명 권한 상태 기계: 성질과 한도")
struct AuthorityPropertyTests {
    typealias T = AuthorityTesting

    /// 갈래가 여럿이고 키가 더해지고 지워지는 AUM 나무. `updates`는 만든 차례(부모가 먼저)다.
    struct Tree {
        let root: AUM
        let updates: [AUM]
        /// `updates`를 만든 차례대로 하나씩 들인 것.
        let reference: Authority
    }

    static func randomTree(count: Int, random: inout CBORTesting.Random) throws -> Tree {
        var signers = (0..<3).map { _ in T.Signer() }
        let keys = signers.enumerated().map { $1.trusted(votes: UInt64($0 + 1)) }
        let root = T.checkpoint(T.checkpointState(keys), by: [signers[0]])
        var builder = try Authority(bootstrappingWith: root)
        var updates: [AUM] = []
        while updates.count < count {
            let parent = try #require(builder.hashes.randomElement(using: &random))
            let state = try builder.state(at: parent, iterationLimit: Authority.maximumScanIterations)
            let trusted = signers.filter { state.key(withID: $0.publicKey) != nil }
            var chosen = trusted.filter { _ in Bool.random(using: &random) }
            if chosen.isEmpty { chosen = [try #require(trusted.first)] }

            let update: AUM
            switch Int.random(in: 0..<4, using: &random) {
            case 0 where state.keys.count > 1:
                let removed = try #require(state.keys.randomElement(using: &random)?.publicKey)
                update = T.removeKey(removed, after: parent, by: chosen)
            case 1:
                let added = T.Signer()
                signers.append(added)
                update = T.addKey(added.trusted(votes: UInt64.random(in: 1...3, using: &random)), after: parent, by: chosen)
            default:
                update = T.noOp(after: parent, by: chosen)
            }
            try builder.inform([update])
            updates.append(update)
        }
        return Tree(root: root, updates: updates, reference: builder)
    }

    /// 부모가 먼저 오는 임의의 차례.
    static func parentFirstOrder(_ updates: [AUM], root: AUMHash, random: inout CBORTesting.Random) -> [AUM] {
        var placed: Set<AUMHash> = [root]
        var remaining = updates
        var order: [AUM] = []
        while let pick = remaining.indices.filter({ remaining[$0].parentHash.map(placed.contains) ?? false })
            .randomElement(using: &random)
        {
            let update = remaining.remove(at: pick)
            placed.insert(update.hash)
            order.append(update)
        }
        return order
    }

    static func expectSame(_ authority: Authority, _ reference: Authority, sourceLocation: SourceLocation = #_sourceLocation) {
        #expect(authority.head == reference.head, sourceLocation: sourceLocation)
        #expect(authority.state == reference.state, sourceLocation: sourceLocation)
        #expect(Set(authority.hashes) == Set(reference.hashes), sourceLocation: sourceLocation)
    }

    /// 같은 AUM 집합을 부모가 먼저인 어떤 차례로, 어떤 묶음으로 나눠 들여도 머리와 상태가 같다.
    @Test(arguments: [UInt64(1), 2, 3])
    func headDoesNotDependOnOrder(seed: UInt64) throws {
        var random = CBORTesting.Random(state: seed)
        let tree = try Self.randomTree(count: 40, random: &random)
        for _ in 0..<4 {
            var authority = try Authority(bootstrappingWith: tree.root)
            var order = Self.parentFirstOrder(tree.updates, root: authority.bootstrap, random: &random)[...]
            #expect(order.count == tree.updates.count)
            while !order.isEmpty {
                let size = Int.random(in: 1...6, using: &random)
                try authority.inform(Array(order.prefix(size)))
                order = order.dropFirst(size)
            }
            Self.expectSame(authority, tree.reference)
        }
    }

    /// 이미 쥔 AUM을 다시 들여도(어떤 부분 집합이든) 상태가 같고, 다시 열면 같은 머리와 상태다.
    @Test func reinformingAndReopening() throws {
        var random = CBORTesting.Random(state: 7)
        let tree = try Self.randomTree(count: 30, random: &random)
        var authority = tree.reference
        for _ in 0..<5 {
            let subset = tree.updates.filter { _ in Bool.random(using: &random) } + [tree.updates[0]]
            try authority.inform(subset.shuffled(using: &random))
            Self.expectSame(authority, tree.reference)
            #expect(authority.aums == tree.reference.aums)
        }
        let reopened = try Authority(opening: tree.reference.aums.shuffled(using: &random), bootstrap: tree.reference.bootstrap)
        Self.expectSame(reopened, tree.reference)
    }

    /// 한 번에 들이는 AUM 수의 한도(4,096개)는 검증 전에 본다.
    @Test func batchCountLimit() throws {
        let a = T.Signer()
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        let update = T.noOp(after: authority.head, by: [a])
        #expect(T.informError(&authority, Array(repeating: update, count: Authority.maximumBatchCount + 1)) == .limitExceeded)
        try authority.inform(Array(repeating: update, count: Authority.maximumBatchCount))
        #expect(authority.aums.count == 2)
    }

    /// 부모 상태를 찾아 거꾸로 가는 한도(체크포인트를 포함해 2,000개)와 쥐는 AUM 수의 한도(4,096개)의 경계.
    @Test func scanAndCountLimits() throws {
        let a = T.Signer()
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        // 뿌리 다음 N1…N2001. 머리 사슬로 들이면 부모 상태를 찾지 않는다.
        let chain = T.noOpChain(after: authority.head, count: 2_001, by: a)
        try authority.inform(chain)
        #expect(authority.head == chain[2_000].hash)

        // N2000(머리가 아님)의 자식: N2000…N1과 뿌리, 2,001개 → 한도를 넘는다. N1999의 자식: 2,000개 → 된다.
        #expect(T.informError(&authority, [T.noOp(after: chain[1_999].hash, by: [a])]) == .iterationLimit)
        try authority.inform([T.noOp(after: chain[1_998].hash, by: [a])])
        #expect(authority.aums.count == 2_003)

        // 4,096개까지 채우고, 하나 더는 통째로 거절한다.
        let rest = T.noOpChain(after: authority.head, count: Authority.maximumAUMCount - 2_003, by: a)
        try authority.inform(rest)
        #expect(authority.aums.count == Authority.maximumAUMCount)
        let before = authority
        #expect(T.informError(&authority, [T.noOp(after: authority.head, by: [a])]) == .limitExceeded)
        #expect(authority.aums == before.aums && authority.head == before.head)
        // 이미 쥔 것만 든 묶음은 한도에 걸리지 않는다.
        try authority.inform([rest[0]])
    }

    /// 쥐는 AUM의 정준 바이트 합 한도(16MiB). 키 512개에 `Meta`를 채운 체크포인트(약 280KiB)를 잇는다.
    @Test func byteLimit() throws {
        let a = T.Signer()
        var random = CBORTesting.Random(state: 11)
        let meta = [MetaEntry(key: Array("m".utf8), value: Array(repeating: UInt8(ascii: "x"), count: 511))]
        var keys = [a.trusted()]
        while keys.count < AuthorityState.maximumKeyCount {
            let publicKey = (0..<32).map { _ in UInt8.random(in: 0...255, using: &random) }
            keys.append(TrustedKey(kind: 1, votes: 1, publicKey: publicKey, meta: meta))
        }
        let state = T.checkpointState(keys)
        var authority = try Authority(bootstrappingWith: T.checkpoint(state, by: [a]))
        var total = authority.aums[0].serialized().count
        while true {
            let next = T.checkpoint(state, parent: authority.head, by: [a])
            let count = next.serialized().count
            let before = authority
            if let error = T.informError(&authority, [next]) {
                #expect(error == .limitExceeded)
                #expect(total + count > Authority.maximumByteCount)
                #expect(authority.aums == before.aums && authority.head == before.head)
                #expect(throws: TKAError.limitExceeded) {
                    try Authority(opening: authority.aums + [next], bootstrap: authority.bootstrap)
                }
                break
            }
            total += count
            #expect(total <= Authority.maximumByteCount)
        }
        #expect(authority.aums.count > 50)
    }

    /// 들일 AUM의 바이트를 한 바이트씩 망가뜨려도 죽지 않고, 받아들이는 것은 정준 형태가 같은 AUM뿐이다.
    @Test func corruptedBytesAreRejected() throws {
        let a = T.Signer()
        let authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted()]), by: [a]))
        let original = T.addKey(T.Signer().trusted(votes: 3), after: authority.head, by: [a])
        let bytes = original.serialized()
        for index in bytes.indices {
            for flip in [UInt8(0x01), 0x80, 0xff] {
                var corrupted = bytes
                corrupted[index] ^= flip
                guard let update = try? AUM(decoding: corrupted) else { continue }
                var copy = authority
                if T.informError(&copy, [update]) == nil {
                    #expect(update.hash == original.hash, "바이트 \(index)에 \(flip)")
                }
            }
        }
    }
}
