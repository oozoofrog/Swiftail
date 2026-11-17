// `TailnetNode.hasSavedIdentity(in:)`: 앱이 노드를 띄우기 전에 저장된 신원이 있는지 묻는다.

import CryptoKit
import Foundation
import SwiftailControl
import Testing
@testable import Swiftail

@Suite("저장된 신원 묻기")
struct SavedIdentityTests {
    private static func save(nodeKey: Bool, in directory: URL) throws {
        var identity = NodeIdentity()
        if nodeKey { identity.nodeKey = Curve25519.KeyAgreement.PrivateKey() }
        try NodeIdentityStore(directory: directory).save(identity)
    }

    /// `body`가 던진 `NodeError`. 던지지 않으면 nil.
    private static func nodeError(_ body: () throws(NodeError) -> Bool) -> NodeError? {
        do throws(NodeError) {
            _ = try body()
            return nil
        } catch {
            return error
        }
    }

    @Test("신원 파일이 없으면 false다. 디렉터리가 없어도 만들지 않고 false다")
    func noIdentity() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory throws in
            #expect(try TailnetNode.hasSavedIdentity(in: directory) == false)
            let missing = directory.appending(path: "missing")
            #expect(try TailnetNode.hasSavedIdentity(in: missing) == false)
            #expect(!FileManager.default.fileExists(atPath: missing.path))
        }
    }

    @Test("등록을 마친 신원(node 키 있음)이면 true, machine 키만 있으면 false다")
    func registeredIdentity() async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory throws in
            try Self.save(nodeKey: false, in: directory)
            #expect(try TailnetNode.hasSavedIdentity(in: directory) == false)
            try Self.save(nodeKey: true, in: directory)
            #expect(try TailnetNode.hasSavedIdentity(in: directory) == true)
        }
    }

    @Test("깨진 신원 파일은 run()과 같은 control(.storage)로 던진다", arguments: [
        Data("not json".utf8),
        Data(#"{"MachineKey":"privkey:00"}"#.utf8),
        Data(repeating: 0x20, count: 64 * 1_024 + 1),
    ])
    func corruptIdentity(contents: Data) async throws {
        try await NodeTestSupport.withTemporaryDirectory { directory in
            try contents.write(to: directory.appending(path: "identity.json"))
            let error = Self.nodeError { () throws(NodeError) in try TailnetNode.hasSavedIdentity(in: directory) }
            guard case .control(.storage) = error else {
                Issue.record("control(.storage)가 아니다: \(String(describing: error))")
                return
            }
        }
    }

    @Test("심볼릭 링크인 신원 파일은 따라가지 않고 control(.storage)로 던진다")
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
                Issue.record("control(.storage)가 아니다: \(String(describing: error))")
                return
            }
        }
    }

    @Test("파일 URL이 아니면 invalidConfiguration이다")
    func notFileURL() throws {
        let url = try #require(URL(string: "https://example.com/state"))
        let error = Self.nodeError { () throws(NodeError) in try TailnetNode.hasSavedIdentity(in: url) }
        guard case .invalidConfiguration = error else {
            Issue.record("invalidConfiguration이 아니다: \(String(describing: error))")
            return
        }
    }
}
