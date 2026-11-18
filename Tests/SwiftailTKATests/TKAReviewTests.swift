import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import Testing

@testable import SwiftailTKA

/// Regression tests for three findings from the TL-11a review (the `SwiftailTKA` security review), plus comparison with the Go outcomes the review added to `tkafixtures`
/// (`reviewChains` and `reviewSignatures`).
///
/// The review reproduced the inputs for findings 1–3, addressed by items 1–3 under Fixes from independent review: Pure logic (TL-11a) in contract §5. Each test's
/// comments identify who controls the input (control server, trusted key holder, or peer) and how the Go result was obtained.
@Suite("TL-11a review: SwiftailTKA")
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

    // MARK: Go comparison (rows added by the review)

    /// 22 chains including variants of the same AUM that differ only in the signature list, different groups and orders for the same tree, re-adding a removed key, Votes and Meta boundaries,
    /// checkpoints on losing branches, and bootstrapping with a parent hash of a length other than 32 bytes. Each step matches Go's outcome, head, and state.
    @Test("reviewChains: Outcomes, head, and state for chains added by the review", .timeLimit(.minutes(10)))
    func reviewChains() throws {
        let fixture = try GoFixture.load()
        for chain in fixture.reviewChains {
            ComparisonTally.record(
                GoComparisonTests.compareChain(chain), section: "reviewChains", row: chain.name, total: fixture.reviewChains.count
            )
        }
    }

    /// 15 cases including wrong-length signatures, 33-byte rotation keys, rotation to the same node key, outer KeyID, credentials from removed keys, rotation wrapping
    /// a rotation over a credential, and truncated or non-shortest NKS. Outcomes, history, and SigHash match Go.
    @Test("reviewSignatures: Outcomes and history for NKS cases added by the review")
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
                if swiftHash != goHash { problems.append("SigHash: Swift \(swiftHash ?? "decode failed")") }
            }
            let verdict = G.verdict(authorized: item.authorized, error: item.error, rotation: item.rotation)
            if let difference = G.difference(state, nodeKey: try G.nodeKey(item.nodeKey), nks: nks, expected: verdict) {
                problems.append("\(difference) (Go: \(item.error ?? "authorized"))")
            }
            ComparisonTally.record(
                problems.isEmpty ? .same : .mismatch(problems.joined(separator: "; ")), section: "reviewSignatures",
                row: item.name, total: fixture.reviewSignatures.count
            )
        }
    }

    // MARK: Finding 1 — State admitting an UpdateKey with only empty Meta failed to reopen (fixed by item 2)

    /// Input controlled by a trusted key holder. Sign the SigHash of UpdateKey{KeyID} and append `07a0` (empty Meta) when sending.
    ///
    /// The received value has `meta == []`, so it passes static validation (UpdateKey requires Votes or Meta), and Go and Swift both accept it
    /// (`review/votes-and-meta-bounds/update-meta-empty-wire-only` in `reviewChains`). Canonical bytes omit empty Meta, so
    /// an AUM read back from storage (`TailnetLockStore` writes `serialized()` and reads with `AUM(decoding:)`) has neither Votes nor Meta
    /// and fails static validation. Before the fix, decision L14's reverification caused `Authority(opening:)` to throw on each node restart, leaving it
    /// stuck in `.unverified` (no peers). Reopening now checks only parents and signatures (item 2).
    ///
    /// Go outcome: `tka.Open` opens the same chain because it skips reverification of storage. Output from a temporary Go program (`probe/main.go` in
    /// `eyebuild dir tl11a-review`: Bootstrap in FS chonk → Inform the `07a0` UpdateKey → `Open` with a new `ChonkDir`):
    /// `wire Meta nil=false, StaticValidate=<nil>` / `inform ok` / `open ok` (same head) /
    /// `stored Meta nil=true, StaticValidate=UpdateKey AUMs must contain an update to votes or key metadata`.
    ///
    /// The reopened state differs only in that key's `Meta`. Empty `Meta` in the received AUM clears the key's `Meta` (`update.Meta != nil`
    /// in Go `state.go:206`). The AUM read back from canonical bytes lacks `Meta` and keeps the old value. Go behaves the same: its FS store writes CBOR AUMs
    /// (`tka/tailchonk.go:658-673`, `Meta` uses omitempty) and `Open` reapplies them (verified against the original source, unverified by running Go).
    /// `Meta` does not affect the outcome.
    @Test("Finding 1 (item 2): State admitting an UpdateKey with only empty Meta (07a0) reopens after storage")
    func emptyMetaUpdateKeySurvivesReopen() throws {
        let fixture = try GoFixture.load()
        let chain = try #require(fixture.reviewChains.first { $0.name == "review/votes-and-meta-bounds" })
        var authority = try Authority(bootstrappingWith: G.aum(chain.bootstrap))
        var previous = authority.state
        for step in chain.steps where step.ok {
            previous = authority.state
            try authority.inform(step.aums.map { hex throws(TKAError) in try G.aum(hex) })
            if step.name == "update-meta-empty-wire-only" { break }
        }
        let wire = try #require(authority.aums.last)
        let keyID = try #require(wire.keyID)
        let previousMeta = try #require(previous.key(withID: keyID)?.meta)
        #expect(!previousMeta.isEmpty && authority.state.key(withID: keyID)?.meta == [])
        #expect(wire.messageKind == AUM.Kind.updateKey && wire.meta == [] && wire.votes == nil)

        // Write and reread canonical bytes as the store does.
        let stored = try authority.aums.map { aum throws(TKAError) in try AUM(decoding: aum.serialized()) }
        #expect(stored.last?.hash == wire.hash, "The hashes match because empty Meta is excluded from the hash")
        #expect(throws: TKAError.invalidAUM, "The reread AUM fails static validation") { try stored.last?.validate() }
        do {
            let reopened = try Authority(opening: stored, bootstrap: authority.bootstrap)
            var expected = authority.state
            for index in expected.keys.indices where expected.keys[index].keyID == keyID {
                expected.keys[index].meta = previousMeta
            }
            #expect(reopened.head == authority.head && reopened.state == expected)
        } catch {
            Issue.record("Could not reopen an accepted chain: \(error). Go tka.Open opens it")
        }
    }

    // MARK: Finding 2 — The control server filled storage with AUMs differing only in signature lists and froze lock state (fixed by item 1)

    /// Input controlled by the control server, which has no signing key.
    ///
    /// The AUM hash includes the signature list, and the list only needs to pass verification (it can repeat, omit, or reorder signatures). One AUM with trusted key signatures
    /// can therefore yield arbitrarily many valid sibling AUMs with distinct hashes. Go and Swift both accept them
    /// (`review/duplicate-signature-variant-*` and `review/signature-order-variant` in `reviewChains`). Go has no limit on retained AUM count
    /// (`InformIdempotent` in `tka/tka.go:584-665`). Swiftail rejected whole groups at 4,096 retained AUMs or 16MiB. If the
    /// server filled the limit with variants, **every** subsequent AUM, including key removal and recovery checkpoints, failed with `limitExceeded`, and the node
    /// continued trusting removed keys until its state files were deleted. Limits now apply only to the active chain, and excess variants outside that chain are discarded
    /// (item 1).
    ///
    /// Reproduction: 64 keys, one NoOp signed by all 64, and 4,094 ordered pairs of those signatures created by the server (8,252 verifications). AUMs on real tailnets
    /// have one signature, so the variants only grow in signature count (`[s]×k`, filling the 16MiB byte limit up to k ≈ 570).
    ///
    /// Go outcome: a temporary Go program with the same structure (`probe2/main.go` in `eyebuild dir tl11a-review`, ChonkMem) outputs
    /// `variants inform: <nil>` / `remove-key inform: <nil>` / `removed key still trusted: false keys: 63`. The subsequent checkpoint was
    /// not run in Go. `InformIdempotent` has no count check and accepts it through the same path as RemoveKey (verified against the original source).
    @Test("Finding 2 (item 1): Follows a trusted key's RemoveKey and checkpoint even after signature list variants fill the limit", .timeLimit(.minutes(10)))
    func controlServerCannotFreezeAuthority() throws {
        let signers = (0..<64).map { _ in T.Signer() }
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState(signers.map { $0.trusted() }), by: [signers[0]]))
        let original = T.noOp(after: authority.head, by: signers)
        try authority.inform([original])

        // The server only has original's 64 signatures. It uses those signatures to make lists of two.
        let room = Authority.maximumAUMCount - authority.aums.count
        var variants: [AUM] = []
        for first in original.signatures {
            for second in original.signatures where variants.count < room {
                var variant = original
                variant.signatures = [first, second]
                variants.append(variant)
            }
        }
        #expect(Set(variants.map(\.hash)).count == room, "The AUMs are distinct")
        try authority.inform(variants)
        #expect(authority.aums.count == Authority.maximumAUMCount)

        #expect(authority.head == original.hash, "The variants with two signatures lose to the original with 64")

        // A trusted key removes signers[1] at the head and includes a checkpoint. Go accepts it and removes the key.
        let removal = T.removeKey(signers[1].publicKey, after: authority.head, by: [signers[0]])
        let error = T.informError(&authority, [removal])
        #expect(error == nil, "RemoveKey rejected after \(room) server-created variants: \(String(describing: error))")
        #expect(authority.state.key(withID: signers[1].publicKey) == nil, "The removed key is still trusted")
        #expect(authority.state.keys.count == 63)
        let remaining = T.checkpointState(signers.filter { $0.publicKey != signers[1].publicKey }.map { $0.trusted() })
        let checkpoint = T.checkpoint(remaining, parent: authority.head, by: [signers[0]])
        try authority.inform([checkpoint])
        #expect(authority.head == checkpoint.hash && authority.state.keys.count == 63)

        // The active chain (root, original, RemoveKey, and checkpoint) remains, and two later variants were discarded.
        #expect(authority.aums.count == Authority.maximumAUMCount)
        #expect(T.activeChain(of: authority).map(\.hash) == [checkpoint.hash, removal.hash, original.hash, authority.bootstrap])
        let kept = Set(authority.aums.map(\.hash))
        #expect(variants.dropLast(2).allSatisfy { kept.contains($0.hash) } && variants.suffix(2).allSatisfy { !kept.contains($0.hash) })
        let reopened = try Authority(opening: authority.aums, bootstrap: authority.bootstrap)
        #expect(reopened.head == authority.head && reopened.state == authority.state)
    }

    // MARK: Finding 3 — The server's ancestor list inflated MissingAUMs computation (fixed by item 3)

    /// Input controlled by the control server. The sync/offer response's `Ancestors` has no count limit (8MiB body ≈ 152,000 entries), and `missingAUMs` reads the list
    /// from the start. For each ancestor present locally it runs `state(at:)` (walks backward to a checkpoint and reapplies updates) and fast-forwards. Inserting repeated AUMs
    /// from a losing branch (which the server can always produce as signature list variants) causes work proportional to each ancestor's depth and never finds an intersection. Go uses the same
    /// loop (`tka/sync.go:188-209`, Go's body limit is 512MiB). `ControlClient` calls it on the actor. Before the fix,
    /// one 8MiB response took 71 seconds in the worst case in release. Now it deduplicates ancestors and checks up to 1,001 (item 3).
    ///
    /// The test passes and times a list with as many repetitions as fit in an 8MiB response (about 152,000). It fails if release takes more than 1 second.
    @Test("Finding 3 (item 3): MissingAUMs cost for an ancestor list repeating a losing-branch AUM", .timeLimit(.minutes(10)))
    func missingAUMsAncestorAmplification() throws {
        let signer = T.Signer()
        let depth = Self.isOptimized ? 1_999 : 49
        var authority = try Authority(bootstrappingWith: T.checkpoint(T.checkpointState([signer.trusted()]), by: [signer]))
        let chain = T.noOpChain(after: authority.head, count: depth, by: signer)
        try authority.inform(chain)
        let last = try #require(chain.last)
        // Losing branch: the variant with the higher hash that repeats the last NoOp's signature.
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
        let worstCount = 8 * 1_024 * 1_024 / 55  // One `"<52 characters>",` takes 55 bytes
        let offer = SyncOffer(head: unknown, ancestors: Array(repeating: losing.hash, count: worstCount))
        let elapsed = ContinuousClock().measure {
            #expect(throws: TKAError.noIntersection) { try authority.missingAUMs(for: offer) }
        }
        print("TL-11a measurement, ancestor amplification: depth \(depth), \(worstCount) repetitions of one ancestor (8MiB): \(elapsed)")
        if Self.isOptimized {
            #expect(elapsed < .seconds(1), "One control server sync/offer response blocks the actor for \(elapsed)")
        }
    }

    /// Remaining worst case for finding 3: place 1,001 distinct losing-branch AUMs (signature list variants) each 1,998 AUMs below a checkpoint and use their hashes
    /// as the ancestor list. Deduplication still checks all 1,001. The result is the TL-11a measurement line on standard output (release).
    @Test("Measurement: MissingAUMs for 1,001 distinct losing-branch ancestors", .enabled(if: isOptimized), .timeLimit(.minutes(10)))
    func distinctLosingAncestors() throws {
        let a = T.Signer()
        let b = T.Signer()
        var authority = try Authority(
            bootstrappingWith: T.checkpoint(T.checkpointState([a.trusted(), b.trusted()]), by: [a])
        )
        let chain = T.noOpChain(after: authority.head, count: 1_998, by: a)
        try authority.inform(chain)
        let last = try #require(chain.last)
        var tip = T.noOp(after: last.hash, by: [a, b])
        // Variants that replace the signature list with a binary string of a and b. Each starts with b, so they differ from one another and from the original (`[a, b]`).
        let variants = (2..<1_200).map { number in
            var variant = tip
            variant.signatures = String(number, radix: 2).map { $0 == "1" ? tip.signatures[1] : tip.signatures[0] }
            return variant
        }
        try authority.inform([tip] + variants)
        tip = try #require(([tip] + variants).first { $0.hash == authority.head })
        let losing = variants.filter { $0.hash != tip.hash }.prefix(Authority.maximumSyncAncestorCount).map(\.hash)
        #expect(losing.count == Authority.maximumSyncAncestorCount)
        let unknown = try #require(AUMHash(Array(repeating: 0x5a, count: 32)))
        let offer = SyncOffer(head: unknown, ancestors: losing + [authority.bootstrap])
        var result: Result<[AUM], TKAError> = .success([])
        let elapsed = ContinuousClock().measure { result = Result { () throws(TKAError) in try authority.missingAUMs(for: offer) } }
        #expect(throws: TKAError.noIntersection, "The root at position 1,002 is not checked") { try result.get() }
        print("TL-11a measurement, ancestor amplification: depth 1,999, \(losing.count) distinct losing-branch ancestors: \(elapsed)")
    }

    // MARK: Fuzzer

    /// Deterministic pseudorandom numbers (SplitMix64). Fix the seed so the fuzzer repeats its inputs.
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

    /// Number of mutations per AUM or NKS. Increase it with `TL11A_FUZZ_ROUNDS` (the review ran 20,000 in debug and 200,000 in release).
    static let fuzzRounds = ProcessInfo.processInfo.environment["TL11A_FUZZ_ROUNDS"].flatMap(Int.init) ?? 3_000

    /// Bytes with meaning as CBOR headers: long lengths, indefinite lengths, break, simple values, tags, and text.
    static let interestingBytes: [UInt8] = [
        0x00, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1f, 0x20, 0x3b, 0x40, 0x58, 0x5a, 0x5b, 0x5f, 0x60, 0x7b, 0x7f, 0x80, 0x98,
        0x9b, 0x9f, 0xa0, 0xb8, 0xbb, 0xbf, 0xc0, 0xd8, 0xe0, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfb, 0xff,
    ]

    /// Applies 1–4 mutations: flip a bit, change a byte, truncate, insert, repeat a slice, join with another input, or append.
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

    /// Feeds mutated valid and invalid Go fixtures to every `package` entry point. A trap kills the test process and counts as a finding.
    ///
    /// Also checks invariants: an AUM that passes static validation still passes after decoding canonical bytes and keeps its hash (generalization of finding 1),
    /// and a decoded NKS has the same value after decoding its canonical bytes.
    @Test("Fuzzer: Flipped, truncated, and concatenated inputs at package entry points", .timeLimit(.minutes(10)))
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
                    // Count the form from finding 1 (UpdateKey with only empty Meta) separately. Any other form is a new finding.
                    if aum.messageKind == AUM.Kind.updateKey, aum.meta == [], aum.votes == nil {
                        counts["aum form from finding 1", default: 0] += 1
                    } else {
                        Issue.record("Changes after decoding canonical bytes: \(G.hex(bytes))")
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
                #expect((try? NodeKeySignature(decoding: signature.serialized())) == signature, "NKS canonical bytes: \(G.hex(bytes))")
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
        print("TL-11a fuzzer: " + counts.sorted { $0.key < $1.key }.map { "\($0.key) \($0.value)" }.joined(separator: ", "))
    }

    // MARK: Secrets

    /// The private key and auth key prefix of a wrapped auth key never appear in `description`, `String(reflecting:)`, `dump`, or `Mirror` (behavior K2).
    @Test("Secrets: WrappedAuthKey reveals neither key in any representation")
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

    // MARK: Release measurements

    /// Timing for near-worst-case inputs. Runs only in release builds because pure Swift Ed25519 is 60–100 times slower in debug.
    /// Results appear in TL-11a measurement lines on standard output. No pass/fail judgment is made.
    @Test("Measurement: Worst-case input timing in a release build", .enabled(if: isOptimized), .timeLimit(.minutes(20)))
    func releaseMeasurements() throws {
        let clock = ContinuousClock()
        let signer = T.Signer()
        let root = T.checkpoint(T.checkpointState([signer.trusted()]), by: [signer])
        let base = try Authority(bootstrappingWith: root)

        // 1. A linear chain in one group of 4,095, at the limit.
        let chain = T.noOpChain(after: base.head, count: Authority.maximumAUMCount - 1, by: signer)
        var linear = base
        print("TL-11a measurement, admit one group of 4,095 NoOps: \(clock.measure { try? linear.inform(chain) }), head \(linear.aums.count)")

        // 2. Reopen that store (L14: reverify signatures as well).
        let stored = linear.aums
        print("TL-11a measurement, reopen 4,096 AUMs: \(clock.measure { _ = try? Authority(opening: stored, bootstrap: base.bootstrap) })")

        // 3. One AUM that repeats a trusted key signature 4,096 times (about 420KiB, a control server can construct it).
        var heavy = T.noOp(after: base.head, by: [signer])
        heavy.signatures = Array(repeating: heavy.signatures[0], count: 4_096)
        var heavyAuthority = base
        let heavyBytes = heavy.serialized().count
        print("TL-11a measurement, admit an AUM with 4,096 signatures (\(heavyBytes) bytes): \(clock.measure { try? heavyAuthority.inform([heavy]) })")

        // 4. One group of 4,095 AddKeys (trusted key holder): `inform` retains the entire state for every AUM (O(n²) key array copying).
        // The final AddKey is the signing key for 5, last in the trusted key list.
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
        print("TL-11a measurement, one group of 4,095 AddKeys: \(addKeyTime), \(keyed.state.keys.count) keys, peak RSS \(before / 1_048_576)MiB → \(after / 1_048_576)MiB")

        // 5. Filter 1,000 peers with a state of 4,096 keys (direct signatures, signing key last).
        let peers = try (0..<1_000).map { _ in
            let node = try #require(NodePublicKey(rawValue: Array(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation)))
            var signature = NodeKeySignature(kind: NodeKeySignature.Kind.direct, publicKey: node.binaryForm, keyID: Array(lastKey.publicKey.rawRepresentation))
            try signature.sign(with: lastKey)
            return PeerCredential(nodeKey: node, keySignature: signature.serialized(), unsignedPeerAPIOnly: false)
        }
        let crowdedState = keyed.state
        print("TL-11a measurement, filter 1,000 peers (\(crowdedState.keys.count) keys): \(clock.measure { _ = crowdedState.admitted(peers) })")
    }

    /// Measure finding 3 at depth 49 (release), the depth in chains the Go client builds (checkpoint every 50 AUMs, `tka/builder.go:123`).
    @Test("Measurement: Ancestor amplification at depth 49", .enabled(if: isOptimized))
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
        print("TL-11a measurement, ancestor amplification: depth 49, \(count) ancestors (8MiB): \(elapsed)")
    }

    /// Peak resident memory for this process (macOS `ru_maxrss` is in bytes).
    static func maximumResidentBytes() -> Int {
        var usage = rusage()
        getrusage(RUSAGE_SELF, &usage)
        return Int(usage.ru_maxrss)
    }
}
