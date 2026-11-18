import Foundation
import Testing
@testable import Swiftail

/// Rejects duplicate state directory claims. Contract `docs/contracts/SwiftailTunnel.md` behaviors P 3·C 4, test list 8.
@Suite("State directory claims table")
struct StateDirectoryClaimsTests {
    @Test("Rejects the second claim for the same path even if spelled differently, and allows it after the first is released. Other paths remain available")
    func sameDirectoryTwice() throws {
        let claims = StateDirectoryClaims()
        let plain = URL(filePath: "/var/empty/swiftail-claims/node", directoryHint: .isDirectory)
        let dotted = try #require(URL(string: "file:///var/empty/swiftail-claims/./other/../node/"))
        let other = URL(filePath: "/var/empty/swiftail-claims/other", directoryHint: .isDirectory)

        let first = try #require(claims.claim(plain))
        #expect(claims.claim(dotted) == nil)
        #expect(claims.claim(plain) == nil)
        #expect(claims.claim(other) != nil)
        claims.release(first)
        #expect(claims.claim(dotted) != nil)
    }

    @Test("Paths through a symbolic link and direct paths match both before and after the directory exists")
    func sameDirectoryThroughSymlink() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let real = directory.appending(path: "real")
            let link = directory.appending(path: "link")
            try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
            let claims = StateDirectoryClaims()

            // Before creation: claiming through the symlink creates the directory and recognizes the direct path as the same.
            let throughLink = link.appending(path: "state")
            let direct = real.appending(path: "state")
            let first = try claims.claimCreating(throughLink)
            #expect(try FileManager.default.attributesOfItem(atPath: direct.path)[.posixPermissions] as? Int == 0o700)
            for same in [direct, throughLink] {
                #expect(throws: NodeError.self) { try claims.claimCreating(same) }
                #expect(claims.claim(same) == nil)
            }

            // After release (the directory now exists): claiming the direct path still recognizes the symlink path as the same.
            claims.release(first)
            let second = try claims.claimCreating(direct)
            #expect(claims.claim(throughLink) == nil)

            // Even if the link points elsewhere after the claim, releasing with the returned key releases the claim held.
            try FileManager.default.removeItem(at: link)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: directory.appending(path: "elsewhere"))
            claims.release(second)
            #expect(claims.claim(direct) != nil)
        }
    }

    @Test("If two nodes receive the same directory, one via a symlink and one directly, the second run() yields stateDirectoryInUse")
    func nodeRejectsDirectoryClaimedThroughSymlink() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let real = directory.appending(path: "real")
            let link = directory.appending(path: "link")
            try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
            // The first node holds a claim to a directory that does not yet exist through a symlink.
            let claim = try StateDirectoryClaims.shared.claimCreating(link.appending(path: "state"))
            defer { StateDirectoryClaims.shared.release(claim) }

            let node = try TailnetNode(
                configuration: try NodeTestSupport.configuration(stateDirectory: real.appending(path: "state")))
            do throws(NodeError) {
                try await node.run()
                Issue.record("run() did not throw")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("Expected stateDirectoryInUse, got \(error)")
                    return
                }
            }
        }
    }

    @Test("If another node is using the directory, run() ends with stateDirectoryInUse before creating files and leaves no claim")
    func nodeRejectsClaimedDirectory() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let claim = try #require(StateDirectoryClaims.shared.claim(directory))
            let node = try TailnetNode(configuration: try NodeTestSupport.configuration(stateDirectory: directory))
            do throws(NodeError) {
                try await node.run()
                Issue.record("run() did not throw")
            } catch {
                guard case .stateDirectoryInUse = error else {
                    Issue.record("Expected stateDirectoryInUse, got \(error)")
                    return
                }
            }
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path).isEmpty)
            #expect(await NodeTestSupport.drain(node.events).isEmpty, "The stream ends when run() ends")
            StateDirectoryClaims.shared.release(claim)
            let again = try #require(StateDirectoryClaims.shared.claim(directory), "The rejected node leaves no claim")
            StateDirectoryClaims.shared.release(again)
        }
    }
}
