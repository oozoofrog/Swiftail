import CryptoKit
import Foundation
import Testing

@testable import SwiftailTKA

/// `Fixtures/tka-fixtures.json`(Go `tka`를 실행한 판정, `Tools/interop/README.md`의 `tkafixtures` 절) 가운데 서명 권한
/// 상태 기계에 해당하는 배열 셋(`chains`, `sync`, `disablement`)과 `disablement`가 가리키는 `authorities`.
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
            /// 해시 32바이트를 차례로 이은 것의 SHA-256.
            let digest: String
            /// 100개 이하일 때만 있다.
            let hashes: [String]?
        }

        let name: String
        let pool: [String]
        let cases: [Case]
    }

    struct NamedAuthority: Decodable {
        let name: String
        /// 첫 것이 부트스트랩, 나머지는 한 묶음의 `Inform`.
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

@Suite("Go 판정(tka-fixtures.json)과 같은 서명 권한 상태 기계")
struct AuthorityFixtureTests {
    /// 사슬 19개의 모든 단계에서 부트스트랩 판정, 들이기 판정, 머리, 상태가 Go와 같다.
    @Test func chains() throws {
        let file = try AuthorityFixtureFile.load()
        #expect(file.chains.count == 19)
        var stepCount = 0
        for chain in file.chains {
            let bootstrapped = Result { () throws(TKAError) in
                try Authority(bootstrappingWith: AUM(decoding: ModelTesting.bytes(chain.bootstrap)))
            }
            guard case var .success(authority) = bootstrapped else {
                #expect(!chain.bootstrapOK, "\(chain.name): 부트스트랩이 거절되었다 \(bootstrapped)")
                continue
            }
            #expect(chain.bootstrapOK, "\(chain.name): Go는 부트스트랩을 거절한다")
            if let initial = chain.initial {
                AuthorityTesting.expect(authority, matches: initial, "\(chain.name) 처음")
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
        #expect(stepCount == 82)
    }

    /// 동기화 사례(`그룹/사례`)와 끄기 비밀 사례의 이름. 사례마다 따로 돌려 병렬로 검증한다(서명 검증이 수천 번이다).
    static let syncCaseNames: [String] =
        (try? AuthorityFixtureFile.load()).map { file in
            file.sync.flatMap { group in group.cases.map { "\(group.name)/\($0.name)" } }
        } ?? []
    static let disablementCaseNames: [String] = (try? AuthorityFixtureFile.load())?.disablement.map(\.name) ?? []

    @Test func caseCounts() {
        #expect(Self.syncCaseNames.count == 14)
        #expect(Self.disablementCaseNames.count == 9)
    }

    /// 양쪽의 제안, 상대 제안에 대한 `MissingAUMs`, 상대 목록을 들인 판정과 머리가 Go와 같다.
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

    /// 끄기 비밀의 판정이 Go와 같다(기준값 `0xa5` × 32, 여러 끄기 값 가운데 하나, 틀린 것, 빈 비밀, 체크포인트 앞뒤).
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

    /// Go 시험 파일의 genesis 체크포인트(노트 7.1, `tka/aum_test.go:181`)로 부트스트랩하면 머리가 그 해시다(노트 8.1).
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

    // MARK: 견주기

    private func expect(_ offer: SyncOffer, matches expected: AuthorityFixtureFile.SyncGroup.Offer, _ label: String) {
        #expect(ModelTesting.hex(offer.head.bytes) == expected.head, "\(label) 제안 머리")
        #expect(offer.ancestors.map { ModelTesting.hex($0.bytes) } == expected.ancestors, "\(label) 조상")
        #expect(offer.head.text == expected.headText, "\(label) 머리 텍스트")
        #expect(offer.ancestors.map(\.text) == expected.ancestorsText, "\(label) 조상 텍스트")
    }

    private func expect(
        _ result: Result<[AUM], TKAError>, matches expected: AuthorityFixtureFile.SyncGroup.Missing, _ label: String
    ) {
        guard case let .success(missing) = result else {
            #expect(!expected.ok, "\(label): MissingAUMs가 실패했다 \(result)")
            return
        }
        #expect(expected.ok, "\(label): Go는 MissingAUMs가 실패한다")
        let hashes = missing.map(\.hash.bytes)
        #expect(missing.count == expected.count, "\(label) 수")
        #expect(ModelTesting.hex(Array(SHA256.hash(data: hashes.flatMap { $0 }))) == expected.digest, "\(label) 요약")
        if let expectedHashes = expected.hashes {
            #expect(hashes.map(ModelTesting.hex) == expectedHashes, "\(label) 목록")
        }
    }

    /// Go 도구와 같이 상대의 계산이 성공했고 목록이 비지 않았을 때만 들인다.
    private func receive(
        _ sent: Result<[AUM], TKAError>, into authority: inout Authority,
        expected: AuthorityFixtureFile.SyncGroup.Side, _ label: String
    ) {
        var informed = true
        if case let .success(aums) = sent, !aums.isEmpty {
            do throws(TKAError) { try authority.inform(aums) } catch { informed = false }
        }
        #expect(informed == expected.informOK, "\(label) 들이기")
        #expect(ModelTesting.hex(authority.head.bytes) == expected.headAfter, "\(label) 들인 뒤 머리")
    }
}
