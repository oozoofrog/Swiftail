import CryptoKit
import Foundation
import Testing

@testable import SwiftailTKA

/// Three arrays for the signing authority state machine (`chains`, `sync`, and `disablement`) and the `authorities` referenced by `disablement`,
/// from `Fixtures/tka-fixtures.json` (outcomes from running Go `tka`, `tkafixtures` section of `Tools/interop/README.md`).
struct AuthorityFixtureFile: Decodable {
    typealias KeyValue = ModelFixtureFile.KeyValue

    struct StateValue: Decodable {
        let head: String
        let keys: [KeyValue]?
        let disablementValues: [String]?
        let stateID1: String
        let stateID2: String
    }

    struct Chain: Decodable {
        struct Step: Decodable {
            let name: String
            let aums: [String]
            let ok: Bool
            let after: StateValue?
        }

        let name: String
        let bootstrap: String
        let bootstrapOK: Bool
        let initial: StateValue?
        let steps: [Step]
    }

    struct SyncGroup: Decodable {
        struct Case: Decodable {
            let name: String
            let local: Side
            let remote: Side
        }

        struct Side: Decodable {
            let aums: [Int]
            let offer: Offer
            let missing: Missing
            let informOK: Bool
            let headAfter: String
        }

        struct Offer: Decodable {
            let head: String
            let ancestors: [String]
            let headText: String
            let ancestorsText: [String]
        }

        struct Missing: Decodable {
            let ok: Bool
            let count: Int
            /// SHA-256 of the 32-byte hashes concatenated in order.
            let digest: String
            /// Present only for counts of 100 or fewer.
            let hashes: [String]?
        }

        let name: String
        let pool: [String]
        let cases: [Case]
    }

    struct NamedAuthority: Decodable {
        let name: String
        /// The first is the bootstrap, and the rest form one `Inform` group.
        let aums: [String]
        let head: String
    }

    struct Disablement: Decodable {
        let name: String
        let authority: String
        let secret: String
        let valid: Bool
    }

    let chains: [Chain]
    let sync: [SyncGroup]
    let authorities: [NamedAuthority]
    let disablement: [Disablement]

    static func load() throws -> AuthorityFixtureFile {
        let url = try #require(Bundle.module.url(forResource: "tka-fixtures", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode(AuthorityFixtureFile.self, from: Data(contentsOf: url))
    }
}

@Suite("Signing authority state machine matches Go outcomes (tka-fixtures.json)")
struct AuthorityFixtureTests {
    /// All steps of the 19 chains match Go's bootstrap outcome, admission outcome, head, and state.
    @Test func chains() throws {
        let file = try AuthorityFixtureFile.load()
        #expect(file.chains.count == 20)
        var stepCount = 0
        for chain in file.chains {
            let bootstrapped = Result { () throws(TKAError) in
                try Authority(bootstrappingWith: AUM(decoding: ModelTesting.bytes(chain.bootstrap)))
            }
            guard case var .success(authority) = bootstrapped else {
                #expect(!chain.bootstrapOK, "\(chain.name): Bootstrap was rejected: \(bootstrapped)")
                continue
            }
            #expect(chain.bootstrapOK, "\(chain.name): Go rejects bootstrap")
            if let initial = chain.initial {
                AuthorityTesting.expect(authority, matches: initial, "\(chain.name) initial")
            }
            for step in chain.steps {
                stepCount += 1
                let label = "\(chain.name)/\(step.name)"
                let result = Result { () throws(TKAError) in
                    try authority.inform(step.aums.map { hex throws(TKAError) in try AUM(decoding: ModelTesting.bytes(hex)) })
                }
                let succeeded = if case .success = result { true } else { false }
                #expect(succeeded == step.ok, "\(label): \(result)")
                if let after = step.after {
                    AuthorityTesting.expect(authority, matches: after, label)
                }
            }
        }
        #expect(stepCount == 88)
    }

    /// Names of synchronization cases (`group/case`) and disablement secret cases. Run each case independently for parallel verification (thousands of signatures are verified).
    static let syncCaseNames: [String] =
        (try? AuthorityFixtureFile.load()).map { file in
            file.sync.flatMap { group in group.cases.map { "\(group.name)/\($0.name)" } }
        } ?? []
    static let disablementCaseNames: [String] = (try? AuthorityFixtureFile.load())?.disablement.map(\.name) ?? []

    @Test func caseCounts() {
        #expect(Self.syncCaseNames.count == 16)
        #expect(Self.disablementCaseNames.count == 9)
    }

    /// The offers on both sides, `MissingAUMs` for the peer's offer, admission outcome for the peer's list, and head all match Go.
    @Test(arguments: syncCaseNames)
    func synchronization(_ name: String) throws {
        let file = try AuthorityFixtureFile.load()
        let group = try #require(file.sync.first { name.hasPrefix("\($0.name)/") })
        let syncCase = try #require(group.cases.first { "\(group.name)/\($0.name)" == name })
        let pool = try group.pool.map { hex throws(TKAError) in try AUM(decoding: ModelTesting.bytes(hex)) }
        var local = try AuthorityTesting.authority(syncCase.local.aums.map { pool[$0] })
        var remote = try AuthorityTesting.authority(syncCase.remote.aums.map { pool[$0] })
        let localOffer = local.syncOffer()
        let remoteOffer = remote.syncOffer()
        expect(localOffer, matches: syncCase.local.offer, "\(name) local")
        expect(remoteOffer, matches: syncCase.remote.offer, "\(name) remote")

        let localSends = Result { () throws(TKAError) in try local.missingAUMs(for: remoteOffer) }
        let remoteSends = Result { () throws(TKAError) in try remote.missingAUMs(for: localOffer) }
        expect(localSends, matches: syncCase.local.missing, "\(name) local")
        expect(remoteSends, matches: syncCase.remote.missing, "\(name) remote")

        receive(remoteSends, into: &local, expected: syncCase.local, "\(name) local")
        receive(localSends, into: &remote, expected: syncCase.remote, "\(name) remote")
    }

    /// Disablement secret outcomes match Go (reference `0xa5` × 32, one of several disablement values, an incorrect secret, an empty secret, and before and after a checkpoint).
    @Test(arguments: disablementCaseNames)
    func disablement(_ name: String) throws {
        let file = try AuthorityFixtureFile.load()
        let entry = try #require(file.disablement.first { $0.name == name })
        let named = try #require(file.authorities.first { $0.name == entry.authority })
        let authority = try AuthorityTesting.authority(
            named.aums.map { hex throws(TKAError) in try AUM(decoding: ModelTesting.bytes(hex)) }
        )
        #expect(ModelTesting.hex(authority.head.bytes) == named.head)
        #expect(authority.isValidDisablement(secret: ModelTesting.bytes(entry.secret)) == entry.valid)
    }

    /// Bootstrapping with the genesis checkpoint from the Go test file (note §7.1, `tka/aum_test.go:181`) makes its hash the head (note §8.1).
    @Test func goTestGenesis() throws {
        let file = try AuthorityFixtureFile.load()
        let chain = try #require(file.chains.first { $0.name == "bootstrap/go-test-genesis" })
        let genesis = try AUM(decoding: ModelTesting.bytes(chain.bootstrap))
        #expect(genesis.serialized().count == 558)
        let authority = try Authority(bootstrappingWith: genesis)
        #expect(
            ModelTesting.hex(authority.head.bytes) == "4a6313e0cd0d696c7ff9c737ea6fa3abcf77e382e9df0c834f3d1e16b3baeea8"
        )
        #expect(authority.head.text == "JJRRHYGNBVUWY77ZY436U35DVPHXPY4C5HPQZA2PHUPBNM5252UA")
        #expect(authority.state.keys.count == 2 && authority.state.disablementValues.count == 10)
    }

    // MARK: Comparison

    private func expect(_ offer: SyncOffer, matches expected: AuthorityFixtureFile.SyncGroup.Offer, _ label: String) {
        #expect(ModelTesting.hex(offer.head.bytes) == expected.head, "\(label) offered head")
        #expect(offer.ancestors.map { ModelTesting.hex($0.bytes) } == expected.ancestors, "\(label) ancestors")
        #expect(offer.head.text == expected.headText, "\(label) head text")
        #expect(offer.ancestors.map(\.text) == expected.ancestorsText, "\(label) ancestor text")
    }

    private func expect(
        _ result: Result<[AUM], TKAError>, matches expected: AuthorityFixtureFile.SyncGroup.Missing, _ label: String
    ) {
        guard case let .success(missing) = result else {
            #expect(!expected.ok, "\(label): MissingAUMs failed: \(result)")
            return
        }
        #expect(expected.ok, "\(label): MissingAUMs fails in Go")
        let hashes = missing.map(\.hash.bytes)
        #expect(missing.count == expected.count, "\(label) count")
        #expect(ModelTesting.hex(Array(SHA256.hash(data: hashes.flatMap { $0 }))) == expected.digest, "\(label) summary")
        if let expectedHashes = expected.hashes {
            #expect(hashes.map(ModelTesting.hex) == expectedHashes, "\(label) list")
        }
    }

    /// As with the Go tool, admit only when the peer's computation succeeded and its list is nonempty.
    private func receive(
        _ sent: Result<[AUM], TKAError>, into authority: inout Authority,
        expected: AuthorityFixtureFile.SyncGroup.Side, _ label: String
    ) {
        var informed = true
        if case let .success(aums) = sent, !aums.isEmpty {
            do throws(TKAError) { try authority.inform(aums) } catch { informed = false }
        }
        #expect(informed == expected.informOK, "\(label) admission")
        #expect(ModelTesting.hex(authority.head.bytes) == expected.headAfter, "\(label) head after admission")
    }
}
