import Foundation
import Swiftail
import Testing
@testable import SwiftailPairing

/// 짝 목록(계약 6절, 동작 S1~S5. 7절 시험 5).
@Suite("짝 목록")
struct PairedPeerStoreTests {
    private static func peer(
        _ stableID: String, deviceName: String = "rd-phone-5e6f7a8b", pairedAt: TimeInterval = 1_900_000_000
    ) -> PairedPeer {
        PairedPeer(
            peer: PeerIdentity(
                stableID: stableID, name: "rd-phone-5e6f7a8b.tail0001.ts.net", computedName: "rd-phone-5e6f7a8b",
                loginName: "alice@example.com"),
            deviceName: deviceName, pairedAt: Date(timeIntervalSince1970: pairedAt))
    }

    private static func record(_ stableID: String) -> String {
        #"{"stableID":"\#(stableID)","name":"rd-phone-5e6f7a8b.tail0001.ts.net","computedName":"rd-phone-5e6f7a8b","#
            + #""loginName":"alice@example.com","deviceName":"rd-phone-5e6f7a8b","pairedAt":1900000000}"#
    }

    private static func file(version: Int = 1, _ records: [String]) -> Data {
        Data(#"{"version":\#(version),"peers":[\#(records.joined(separator: ","))]}"#.utf8)
    }

    /// 빈 임시 디렉터리를 만들어 넘기고, 끝나면 지운다.
    private static func withDirectory<T>(_ body: (URL) async throws -> T) async throws -> T {
        let directory = Sample.temporaryDirectory()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        return try await body(directory)
    }

    private static func node(_ directory: URL, device: TunnelDevice = .inProcess) throws -> TailnetNode {
        try TailnetNode(
            configuration: NodeConfiguration(
                stateDirectory: directory.appending(path: "node"), hostname: "rd-mac-1a2b3c4d",
                controlURL: try #require(URL(string: "http://127.0.0.1:9"))),
            device: device)
    }

    private static func host(_ node: TailnetNode, port: UInt16 = 4747, store: URL) async throws(PairingError) -> PairingHost {
        try await PairingHost(node: node, port: port, storeDirectory: store) { _ in false }
    }

    // MARK: 목록 (S1, S4)

    @Test("같은 StableID가 다시 짝이 되면 그 자리의 항목을 바꾼다")
    func replacesSameStableID() {
        var list = PairedPeerList()
        let again = Self.peer("nA", deviceName: "새 이름", pairedAt: 1_900_000_500)
        let inserted = [list.insert(Self.peer("nA")), list.insert(Self.peer("nB")), list.insert(again)]
        #expect(inserted == [true, true, true])
        #expect(list.peers == [again, Self.peer("nB")])
        #expect(list.peer(withStableID: "nA") == again)
        #expect(list.peer(withStableID: "nC") == nil)
        #expect(list.peer(withStableID: "na") == nil, "StableID는 글자 그대로 견준다")
    }

    @Test("256개까지다. 가득 차면 새 짝은 넣지 않고, 있는 짝을 바꾸는 것은 된다")
    func limitsCount() {
        var list = PairedPeerList()
        let filled = (0..<256).map { list.insert(Self.peer("n\($0)")) }
        #expect(filled.allSatisfy { $0 })
        let overflow = list.insert(Self.peer("nNew"))
        #expect(!overflow)
        #expect(list.peers.count == 256 && list.peer(withStableID: "nNew") == nil)
        let replaced = list.insert(Self.peer("n7", deviceName: "바뀐 이름"))
        #expect(replaced && list.peer(withStableID: "n7")?.deviceName == "바뀐 이름")
        let removed = [list.remove(stableID: "n0"), list.remove(stableID: "n0")]
        #expect(removed == [true, false])
        let afterRemoval = list.insert(Self.peer("nNew"))
        #expect(afterRemoval && list.peers.count == 256)
    }

    // MARK: 파일 (S2, S3)

    @Test("저장한 목록을 다시 읽으면 같다")
    func roundTrips() async throws {
        try await Self.withDirectory { directory in
            let file = PairedPeerFile(directory: directory)
            var list = PairedPeerList()
            _ = list.insert(Self.peer("nA", deviceName: "거실 \"iPad\"", pairedAt: 1_900_000_000.25))
            _ = list.insert(Self.peer("nB"))
            try file.save(list)
            #expect(try file.load() == list)

            let text = try String(contentsOf: directory.appending(path: "paired-peers.json"), encoding: .utf8)
            #expect(text.hasPrefix(#"{"peers":[{"#) && text.hasSuffix(#""version":1}"#), "판과 peers 배열이 있다")
        }
    }

    @Test("파일이 없으면 빈 목록이고, 디렉터리가 없으면 첫 저장 때 만든다")
    func startsEmpty() async throws {
        try await Self.withDirectory { directory in
            let file = PairedPeerFile(directory: directory.appending(path: "pairing/store"))
            #expect(try file.load() == PairedPeerList())
            var list = PairedPeerList()
            _ = list.insert(Self.peer("nA"))
            try file.save(list)
            #expect(try file.load() == list)
        }
    }

    @Test("파일은 0600이고, 바꿔치기한 뒤 임시 파일이 남지 않는다")
    func writesPrivateFileAtomically() async throws {
        try await Self.withDirectory { directory in
            let file = PairedPeerFile(directory: directory)
            var list = PairedPeerList()
            for stableID in ["nA", "nB", "nC"] {
                _ = list.insert(Self.peer(stableID))
                try file.save(list)
            }
            let path = directory.appending(path: "paired-peers.json").path
            let attributes = try FileManager.default.attributesOfItem(atPath: path)
            #expect(attributes[.posixPermissions] as? Int == 0o600)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == ["paired-peers.json"])
        }
    }

    @Test("모르는 필드는 넘긴다")
    func ignoresUnknownFields() async throws {
        try await Self.withDirectory { directory in
            let record = Self.record("nA").dropLast() + #","future":{"x":[1,2]}}"#
            let contents = #"{"version":1,"note":"x","peers":[\#(record)]}"#
            try Data(contents.utf8).write(to: directory.appending(path: "paired-peers.json"))
            #expect(try PairedPeerFile(directory: directory).load().peers == [Self.peer("nA")])
        }
    }

    private static let unreadable: [(String, Data)] = [
        ("빈 파일", Data()),
        ("JSON이 아님", Data("짝 목록".utf8)),
        ("잘린 JSON", file([record("nA")]).dropLast(3)),
        ("다른 version", file(version: 2, [record("nA")])),
        ("version이 없음", Data(#"{"peers":[]}"#.utf8)),
        ("peers가 없음", Data(#"{"version":1}"#.utf8)),
        ("빈 StableID", file([record("nA"), record("")])),
        ("겹친 StableID", file([record("nA"), record("nB"), record("nA")])),
        ("필드가 빠진 항목", Data(#"{"version":1,"peers":[{"stableID":"nA"}]}"#.utf8)),
        ("257개", file((0..<257).map { record("n\($0)") })),
        ("1MiB 초과", Data((#"{"version":1,"peers":[],"pad":""# + String(repeating: "a", count: 1 << 20) + #""}"#).utf8)),
    ]

    @Test("읽지 못하는 파일은 빈 목록으로 보지 않고 실패한다(S3)", arguments: unreadable.map(\.0))
    func refusesUnreadableFile(label: String) async throws {
        let contents = try #require(Self.unreadable.first { $0.0 == label }?.1)
        try await Self.withDirectory { directory in
            let url = directory.appending(path: "paired-peers.json")
            try contents.write(to: url)
            #expect(await pairingError { try PairedPeerFile(directory: directory).load() } == .storeUnreadable)
            // 호스트도 만들어지지 않고, 파일은 그대로다.
            let node = try Self.node(directory)
            #expect(await pairingError { try await Self.host(node, store: directory) } == .storeUnreadable)
            #expect(try Data(contentsOf: url) == contents)
        }
    }

    @Test("한도의 경계: 256개와 1MiB는 읽는다")
    func readsAtLimits() async throws {
        try await Self.withDirectory { directory in
            let url = directory.appending(path: "paired-peers.json")
            try Self.file((0..<256).map { Self.record("n\($0)") }).write(to: url)
            #expect(try PairedPeerFile(directory: directory).load().peers.count == 256)

            let frame = #"{"version":1,"peers":[],"pad":""}"#
            let padded = #"{"version":1,"peers":[],"pad":""# + String(repeating: "a", count: (1 << 20) - frame.utf8.count) + #""}"#
            #expect(padded.utf8.count == 1 << 20)
            try Data(padded.utf8).write(to: url)
            #expect(try PairedPeerFile(directory: directory).load() == PairedPeerList())
        }
    }

    @Test("심볼릭 링크는 따라가지 않는다")
    func refusesSymbolicLink() async throws {
        try await Self.withDirectory { directory in
            let target = directory.appending(path: "elsewhere.json")
            try Self.file([Self.record("nA")]).write(to: target)
            try FileManager.default.createSymbolicLink(
                at: directory.appending(path: "paired-peers.json"), withDestinationURL: target)
            #expect(await pairingError { try PairedPeerFile(directory: directory).load() } == .storeUnreadable)
        }
    }

    @Test("쓰지 못하면 storeWriteFailed이고 옛 파일은 그대로다")
    func reportsWriteFailure() async throws {
        try await Self.withDirectory { directory in
            // 디렉터리 자리에 파일이 있다.
            let blocked = directory.appending(path: "not-a-directory")
            try Data().write(to: blocked)
            var list = PairedPeerList()
            _ = list.insert(Self.peer("nA"))
            #expect(await pairingError { try PairedPeerFile(directory: blocked).save(list) } == .storeWriteFailed)

            // 쓸 수 없는 디렉터리.
            let locked = directory.appending(path: "locked")
            try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: true)
            let file = PairedPeerFile(directory: locked)
            try file.save(list)
            try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: locked.path)
            defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: locked.path) }
            var larger = list
            _ = larger.insert(Self.peer("nB"))
            #expect(await pairingError { try file.save(larger) } == .storeWriteFailed)
            #expect(try file.load() == list)
        }
    }

    // MARK: 호스트 (S5, 5절의 init·openOffer)

    @Test("같은 디렉터리를 쓰는 호스트는 한 프로세스에 하나다. 버려지면 풀린다")
    func claimsStoreDirectory() async throws {
        try await Self.withDirectory { directory in
            let node = try Self.node(directory)
            let store = directory.appending(path: "store")
            var first: PairingHost? = try await Self.host(node, store: store)
            // 같은 디렉터리의 다른 표기도 같은 것으로 본다.
            for same in [store, directory.appending(path: "store/"), directory.appending(path: "x/../store")] {
                #expect(await pairingError { try await Self.host(node, port: 4748, store: same) } == .storeInUse)
            }
            let other = try await Self.host(node, port: 4748, store: directory.appending(path: "other"))
            #expect(await other.pairedPeers.isEmpty)
            #expect(await first?.pairedPeers.isEmpty == true)
            first = nil
            _ = try await Self.host(node, store: store)
        }
    }

    @Test("심볼릭 링크를 거친 경로도, 디렉터리가 생기기 전후에 같은 것으로 본다")
    func claimsStoreDirectoryThroughSymlink() async throws {
        try await Self.withDirectory { directory in
            let node = try Self.node(directory)
            let real = directory.appending(path: "real")
            let link = directory.appending(path: "link")
            try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
            let first = try await Self.host(node, store: link.appending(path: "store"))
            for same in [link.appending(path: "store"), real.appending(path: "store")] {
                #expect(await pairingError { try await Self.host(node, port: 4748, store: same) } == .storeInUse)
            }
            #expect(await first.pairedPeers.isEmpty)
        }
    }

    @Test("장치가 .inProcess가 아니거나 포트가 0이면 만들지 못하고, 디렉터리를 쥐지도 않는다")
    func validatesConfiguration() async throws {
        try await Self.withDirectory { directory in
            let store = directory.appending(path: "store")
            for (node, port) in [(try Self.node(directory, device: .memory()), UInt16(4747)), (try Self.node(directory), 0)] {
                guard case .invalidConfiguration = await pairingError({ try await Self.host(node, port: port, store: store) }) else {
                    Issue.record("invalidConfiguration이어야 한다")
                    continue
                }
            }
            _ = try await Self.host(try Self.node(directory), store: store)
        }
    }

    @Test("저장된 짝을 읽어 답하고, 지우면 파일에서도 지운다")
    func servesAndRemovesStoredPeers() async throws {
        try await Self.withDirectory { directory in
            var list = PairedPeerList()
            _ = list.insert(Self.peer("nA"))
            _ = list.insert(Self.peer("nB"))
            try PairedPeerFile(directory: directory).save(list)

            let host = try await Self.host(try Self.node(directory), store: directory)
            #expect(await host.pairedPeers == [Self.peer("nA"), Self.peer("nB")])
            #expect(await host.pairedPeer(withStableID: "nB") == Self.peer("nB"))
            #expect(await host.pairedPeer(withStableID: "nC") == nil)

            try await host.removePairedPeer(withStableID: "nA")
            try await host.removePairedPeer(withStableID: "nC")
            #expect(await host.pairedPeers == [Self.peer("nB")])
            #expect(try PairedPeerFile(directory: directory).load().peers == [Self.peer("nB")])
        }
    }

    @Test("openOffer: 수명과 인증 키를 먼저 보고, 노드에 FQDN이 없으면 notRunning이다")
    func validatesOffer() async throws {
        try await Self.withDirectory { directory in
            let host = try await Self.host(try Self.node(directory), store: directory)
            for lifetime in [Duration.zero, .milliseconds(999), .seconds(3601), .seconds(-5)] {
                guard case .invalidConfiguration = await pairingError({ try await host.openOffer(lifetime: lifetime) }) else {
                    Issue.record("invalidConfiguration이어야 한다: \(lifetime)")
                    continue
                }
            }
            for key in ["tskey-client-EXAMPLE", "tskey-auth-EXAMPLE_0", "tskey-auth-EXAMPLE--TLEXAMPLE-EXAMPLE", ""] {
                #expect(await pairingError { try await host.openOffer(authKey: key) } == .invalidAuthKey)
            }
            // 돌지 않는 노드에는 자기 FQDN이 없다.
            #expect(await pairingError { try await host.openOffer() } == .notRunning)
            #expect(await pairingError { try await host.openOffer(lifetime: .seconds(1), authKey: Sample.authKey) } == .notRunning)
            await host.closeOffer()
        }
    }
}
