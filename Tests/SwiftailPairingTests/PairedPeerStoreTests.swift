import Foundation
import Swiftail
import Testing
@testable import SwiftailPairing

/// Tests the paired peer list (contract §6, behaviors S1–S5, §7 test 5).
@Suite("Paired peer list")
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

    /// Creates and passes an empty temporary directory, then removes it when done.
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

    // MARK: List (S1, S4)

    @Test("Pairing again with the same StableID replaces the existing entry in place")
    func replacesSameStableID() {
        var list = PairedPeerList()
        let again = Self.peer("nA", deviceName: "새 이름", pairedAt: 1_900_000_500)
        let inserted = [list.insert(Self.peer("nA")), list.insert(Self.peer("nB")), list.insert(again)]
        #expect(inserted == [true, true, true])
        #expect(list.peers == [again, Self.peer("nB")])
        #expect(list.peer(withStableID: "nA") == again)
        #expect(list.peer(withStableID: "nC") == nil)
        #expect(list.peer(withStableID: "na") == nil, "StableID uses literal character comparison")
    }

    @Test("The list holds up to 256 entries. A full list rejects new paired peers and allows replacement of existing ones")
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

    // MARK: File (S2, S3)

    @Test("Reloading the saved list returns the same list")
    func roundTrips() async throws {
        try await Self.withDirectory { directory in
            let file = PairedPeerFile(directory: directory)
            var list = PairedPeerList()
            _ = list.insert(Self.peer("nA", deviceName: "거실 \"iPad\"", pairedAt: 1_900_000_000.25))
            _ = list.insert(Self.peer("nB"))
            try file.save(list)
            #expect(try file.load() == list)

            let text = try String(contentsOf: directory.appending(path: "paired-peers.json"), encoding: .utf8)
            #expect(text.hasPrefix(#"{"peers":[{"#) && text.hasSuffix(#""version":1}"#), "The version and peers array are present")
        }
    }

    @Test("A missing file gives an empty list, and a missing directory is created on first save")
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

    @Test("The file has mode 0600, and no temporary file remains after replacement")
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

    @Test("Unknown fields are ignored")
    func ignoresUnknownFields() async throws {
        try await Self.withDirectory { directory in
            let record = Self.record("nA").dropLast() + #","future":{"x":[1,2]}}"#
            let contents = #"{"version":1,"note":"x","peers":[\#(record)]}"#
            try Data(contents.utf8).write(to: directory.appending(path: "paired-peers.json"))
            #expect(try PairedPeerFile(directory: directory).load().peers == [Self.peer("nA")])
        }
    }

    private static let unreadable: [(String, Data)] = [
        ("Empty file", Data()),
        ("Non-JSON input", Data("짝 목록".utf8)),
        ("Truncated JSON", file([record("nA")]).dropLast(3)),
        ("Different version", file(version: 2, [record("nA")])),
        ("Missing version", Data(#"{"peers":[]}"#.utf8)),
        ("Missing peers", Data(#"{"version":1}"#.utf8)),
        ("Empty StableID", file([record("nA"), record("")])),
        ("Duplicate StableID", file([record("nA"), record("nB"), record("nA")])),
        ("Entry with missing fields", Data(#"{"version":1,"peers":[{"stableID":"nA"}]}"#.utf8)),
        ("257 entries", file((0..<257).map { record("n\($0)") })),
        ("Over 1MiB", Data((#"{"version":1,"peers":[],"pad":""# + String(repeating: "a", count: 1 << 20) + #""}"#).utf8)),
    ]

    @Test("An unreadable file fails instead of producing an empty list (S3)", arguments: unreadable.map(\.0))
    func refusesUnreadableFile(label: String) async throws {
        let contents = try #require(Self.unreadable.first { $0.0 == label }?.1)
        try await Self.withDirectory { directory in
            let url = directory.appending(path: "paired-peers.json")
            try contents.write(to: url)
            #expect(await pairingError { try PairedPeerFile(directory: directory).load() } == .storeUnreadable)
            // The host is not created either, and the file stays unchanged.
            let node = try Self.node(directory)
            #expect(await pairingError { try await Self.host(node, store: directory) } == .storeUnreadable)
            #expect(try Data(contentsOf: url) == contents)
        }
    }

    @Test("Limits: 256 entries and 1MiB are accepted")
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

    @Test("Symbolic links are not followed")
    func refusesSymbolicLink() async throws {
        try await Self.withDirectory { directory in
            let target = directory.appending(path: "elsewhere.json")
            try Self.file([Self.record("nA")]).write(to: target)
            try FileManager.default.createSymbolicLink(
                at: directory.appending(path: "paired-peers.json"), withDestinationURL: target)
            #expect(await pairingError { try PairedPeerFile(directory: directory).load() } == .storeUnreadable)
        }
    }

    @Test("A write failure returns storeWriteFailed and preserves the old file")
    func reportsWriteFailure() async throws {
        try await Self.withDirectory { directory in
            // A file occupies the directory path.
            let blocked = directory.appending(path: "not-a-directory")
            try Data().write(to: blocked)
            var list = PairedPeerList()
            _ = list.insert(Self.peer("nA"))
            #expect(await pairingError { try PairedPeerFile(directory: blocked).save(list) } == .storeWriteFailed)

            // A directory with no write access.
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

    // MARK: Host (S5, init and openOffer in §5)

    @Test("Each process can have one host per directory. Releasing the host frees the directory")
    func claimsStoreDirectory() async throws {
        try await Self.withDirectory { directory in
            let node = try Self.node(directory)
            let store = directory.appending(path: "store")
            var first: PairingHost? = try await Self.host(node, store: store)
            // Another spelling of the same directory is treated as the same directory.
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

    @Test("A path through a symbolic link refers to the same directory before and after creation")
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

    @Test("Directories writable by the group or others are neither used nor reserved", arguments: [0o777, 0o770, 0o702])
    func refusesWritableStoreDirectory(mode: Int) async throws {
        try await Self.withDirectory { directory in
            let node = try Self.node(directory)
            let store = directory.appending(path: "store")
            try FileManager.default.createDirectory(at: store, withIntermediateDirectories: true)
            try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: store.path)
            #expect(await pairingError { try await Self.host(node, store: store) } == .storeUnreadable)

            try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: store.path)
            _ = try await Self.host(node, store: store)
        }
    }

    @Test("The paired peer list directory must be a directory, owned by the current user, and not writable by the group or others (S2)")
    func judgesStoreDirectory() {
        let directory = mode_t(S_IFDIR)
        #expect(PairedPeerFile.isPrivateDirectory(mode: directory | 0o700, owner: 501, currentUser: 501))
        #expect(PairedPeerFile.isPrivateDirectory(mode: directory | 0o755, owner: 501, currentUser: 501))
        #expect(!PairedPeerFile.isPrivateDirectory(mode: directory | 0o700, owner: 502, currentUser: 501), "Owned by another user")
        #expect(!PairedPeerFile.isPrivateDirectory(mode: directory | 0o700, owner: 0, currentUser: 501))
        #expect(!PairedPeerFile.isPrivateDirectory(mode: directory | 0o720, owner: 501, currentUser: 501), "Group-writable")
        #expect(!PairedPeerFile.isPrivateDirectory(mode: directory | 0o702, owner: 501, currentUser: 501), "Other-writable")
        #expect(!PairedPeerFile.isPrivateDirectory(mode: mode_t(S_IFREG) | 0o600, owner: 501, currentUser: 501))
    }

    @Test("A device other than .inProcess or a port of 0 prevents creation and leaves the directory unreserved")
    func validatesConfiguration() async throws {
        try await Self.withDirectory { directory in
            let store = directory.appending(path: "store")
            for (node, port) in [(try Self.node(directory, device: .memory()), UInt16(4747)), (try Self.node(directory), 0)] {
                guard case .invalidConfiguration = await pairingError({ try await Self.host(node, port: port, store: store) }) else {
                    Issue.record("Expected invalidConfiguration")
                    continue
                }
            }
            _ = try await Self.host(try Self.node(directory), store: store)
        }
    }

    @Test("Reads and returns stored paired peers, and removes deleted peers from the file")
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

    @Test("openOffer checks the lifetime and auth key first, then returns notRunning if the node lacks an FQDN")
    func validatesOffer() async throws {
        try await Self.withDirectory { directory in
            let host = try await Self.host(try Self.node(directory), store: directory)
            for lifetime in [Duration.zero, .milliseconds(999), .seconds(3601), .seconds(-5)] {
                guard case .invalidConfiguration = await pairingError({ try await host.openOffer(lifetime: lifetime) }) else {
                    Issue.record("Expected invalidConfiguration: \(lifetime)")
                    continue
                }
            }
            for key in ["tskey-client-EXAMPLE", "tskey-auth-EXAMPLE_0", "tskey-auth-EXAMPLE--TLEXAMPLE-EXAMPLE", ""] {
                #expect(await pairingError { try await host.openOffer(authKey: key) } == .invalidAuthKey)
            }
            // A node that is not running has no FQDN of its own.
            #expect(await pairingError { try await host.openOffer() } == .notRunning)
            #expect(await pairingError { try await host.openOffer(lifetime: .seconds(1), authKey: Sample.authKey) } == .notRunning)
            await host.closeOffer()
        }
    }
}
