// `TailnetNode.hasSavedIdentity(in:)` lets an app check whether an identity is saved before starting a node.

import CryptoKit
import Foundation
import SwiftailControl
import Testing
@testable import Swiftail

@Suite("Checking for a saved identity")
struct SavedIdentityTests {
    private static func save(nodeKey: Bool, in directory: URL) throws {
        var identity = NodeIdentity()
        if nodeKey { identity.nodeKey = Curve25519.KeyAgreement.PrivateKey() }
        try NodeIdentityStore(directory: directory).save(identity)
    }

    /// Returns the `NodeError` thrown by `body`, or nil if it does not throw.
    private static func nodeError(_ body: () throws(NodeError) -> Bool) -> NodeError? {
        do throws(NodeError) {
            _ = try body()
            return nil
        } catch {
            return error
        }
    }

    @Test("A missing identity file returns false. A missing directory also returns false without creating it")
    func noIdentity() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory throws in
            #expect(try TailnetNode.hasSavedIdentity(in: directory) == false)
            let missing = directory.appending(path: "missing")
            #expect(try TailnetNode.hasSavedIdentity(in: missing) == false)
            #expect(!FileManager.default.fileExists(atPath: missing.path))
        }
    }

    @Test("A registered identity (with a node key) returns true. An identity with only a machine key returns false")
    func registeredIdentity() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory throws in
            try Self.save(nodeKey: false, in: directory)
            #expect(try TailnetNode.hasSavedIdentity(in: directory) == false)
            try Self.save(nodeKey: true, in: directory)
            #expect(try TailnetNode.hasSavedIdentity(in: directory) == true)
        }
    }

    @Test("A corrupt identity file throws control(.storage), as run() does", arguments: [
        Data("not json".utf8),
        Data(#"{"MachineKey":"privkey:00"}"#.utf8),
        Data(repeating: 0x20, count: 64 * 1_024 + 1),
    ])
    func corruptIdentity(contents: Data) async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            try contents.write(to: directory.appending(path: "identity.json"))
            let error = Self.nodeError { () throws(NodeError) in try TailnetNode.hasSavedIdentity(in: directory) }
            guard case .control(.storage) = error else {
                Issue.record("Expected control(.storage), got \(String(describing: error))")
                return
            }
        }
    }

    @Test("Throws control(.storage) for an identity file that is a symbolic link without following it")
    func symbolicLink() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            let elsewhere = directory.appending(path: "elsewhere")
            try Self.save(nodeKey: true, in: elsewhere)
            let state = directory.appending(path: "state")
            try FileManager.default.createDirectory(at: state, withIntermediateDirectories: true)
            try FileManager.default.createSymbolicLink(
                at: state.appending(path: "identity.json"), withDestinationURL: elsewhere.appending(path: "identity.json"))

            #expect(try TailnetNode.hasSavedIdentity(in: elsewhere) == true)
            let error = Self.nodeError { () throws(NodeError) in try TailnetNode.hasSavedIdentity(in: state) }
            guard case .control(.storage) = error else {
                Issue.record("Expected control(.storage), got \(String(describing: error))")
                return
            }
        }
    }

    @Test("A non-file URL yields invalidConfiguration")
    func notFileURL() throws {
        let url = try #require(URL(string: "https://example.com/state"))
        let error = Self.nodeError { () throws(NodeError) in try TailnetNode.hasSavedIdentity(in: url) }
        guard case .invalidConfiguration = error else {
            Issue.record("Expected invalidConfiguration, got \(String(describing: error))")
            return
        }
    }
}
