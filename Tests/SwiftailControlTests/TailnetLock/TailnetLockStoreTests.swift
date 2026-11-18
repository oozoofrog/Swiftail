// `TailnetLockStore`: contract `docs/contracts/SwiftailTailnetLock.md`, behaviors T and M, decisions L6 and L14, unit test 20.

import Foundation
import Testing

import SwiftailCrypto
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("Tailnet lock: State storage")
struct TailnetLockStoreTests {
    private let signer = LockTesting.Signer()

    /// Runs `body` with a store in a temporary directory.
    private func withStore<T>(_ body: (TailnetLockStore, URL) throws -> T) throws -> T {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-lock-store-\(UUID().uuidString)")
        defer {
            // Restore permissions so tests that made the directory read-only can also clean it up.
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            try? FileManager.default.removeItem(at: directory)
        }
        return try body(TailnetLockStore(directory: directory), directory)
    }

    /// A checkpoint followed by one AddKey.
    private func chain() throws -> (authority: Authority, aums: [AUM]) {
        let genesis = try LockTesting.checkpoint(trusting: [signer], signedBy: signer)
        var authority = try Authority(bootstrappingWith: genesis)
        let added = try LockTesting.addKey(LockTesting.Signer(), after: authority.head, signedBy: signer)
        try authority.inform([added])
        return (authority, [genesis, added])
    }

    /// Builds the on-disk bytes directly (the `TailnetLockStore` comment describes the format).
    private func file(version: UInt64 = 1, bootstrap: [UInt8], aums: [[UInt8]], digest: ([UInt8]) -> [UInt8] = { BLAKE2s.hash($0) }) -> Data {
        var writer = CBORWriter()
        writer.mapHeader(count: 3)
        writer.unsigned(1)
        writer.unsigned(version)
        writer.unsigned(2)
        writer.byteString(bootstrap)
        writer.unsigned(3)
        writer.arrayHeader(count: aums.count)
        for aum in aums { writer.byteString(aum) }
        return Data(writer.bytes + digest(writer.bytes))
    }

    private func write(_ data: Data, to store: TailnetLockStore, in directory: URL) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try data.write(to: store.fileURL)
    }

    private func isStorageError(_ error: any Error) -> Bool {
        if case ControlError.storage = error { return true }
        return false
    }

    @Test("A missing file yields nil. Writing then reopening preserves the head, root, and AUMs, the file is 0600, and no temporary file remains")
    func roundTrip() throws {
        try withStore { store, directory in
            #expect(try store.load() == nil)
            let (authority, aums) = try chain()
            try store.save(authority)

            let loaded = try #require(try store.load())
            #expect(loaded.head == authority.head)
            #expect(loaded.bootstrap == authority.bootstrap)
            #expect(loaded.aums == aums)
            #expect(loaded.state == authority.state)

            let attributes = try FileManager.default.attributesOfItem(atPath: store.fileURL.path)
            #expect(attributes[.posixPermissions] as? Int == 0o600)
            #expect(try FileManager.default.contentsOfDirectory(atPath: directory.path) == [TailnetLockStore.fileName])
            // The contents match the documented format: a map and its BLAKE2s-256.
            let expected = file(bootstrap: authority.bootstrap.bytes, aums: aums.map { $0.serialized() })
            #expect(try Data(contentsOf: store.fileURL) == expected)
        }
    }

    @Test("Rewriting replaces the entire file. Removing it makes it disappear, and removing a missing file is allowed")
    func overwriteAndRemove() throws {
        try withStore { store, _ in
            let genesis = try LockTesting.checkpoint(trusting: [signer], signedBy: signer)
            try store.save(try Authority(bootstrappingWith: genesis))
            let (longer, _) = try chain()
            try store.save(longer)
            #expect(try store.load()?.head == longer.head)

            try store.remove()
            #expect(!FileManager.default.fileExists(atPath: store.fileURL.path))
            #expect(try store.load() == nil)
            try store.remove()
        }
    }

    @Test("Corrupt files fail to open and stay intact: trailing hash, truncation, empty file, and format version")
    func corrupted() throws {
        let (authority, aums) = try chain()
        let good = file(bootstrap: authority.bootstrap.bytes, aums: aums.map { $0.serialized() })
        var flipped = good
        flipped[10] ^= 0x01
        var wrongDigest = good
        wrongDigest[good.count - 1] ^= 0x01
        let cases: [(String, Data)] = [
            ("One byte in the body", flipped),
            ("One byte in the hash", wrongDigest),
            ("Truncated tail", good.dropLast(5)),
            ("Shorter than the hash", good.prefix(20)),
            ("Hash only", Data(BLAKE2s.hash([UInt8]()))),
            ("Empty file", Data()),
            ("Unknown format version", file(version: 2, bootstrap: authority.bootstrap.bytes, aums: aums.map { $0.serialized() })),
            ("Correct hash with non-CBOR data", Data([0xff, 0x00] + BLAKE2s.hash([0xff, 0x00]))),
        ]
        for (name, contents) in cases {
            try withStore { store, directory in
                try write(contents, to: store, in: directory)
                #expect("\(name)", performing: { try store.load() }, throws: isStorageError)
                #expect(try Data(contentsOf: store.fileURL) == contents, "\(name): Modified or removed the file")
            }
        }
    }

    @Test("Replaced contents with a recomputed hash also fail to open: signature, root, parent, and limits")
    func tampered() throws {
        let (authority, aums) = try chain()
        let bytes = aums.map { $0.serialized() }
        // AddKey with one signature byte changed (the last 64 bytes are the signature).
        var forged = bytes[1]
        forged[forged.count - 1] ^= 0x01
        // A different signing device's checkpoint. A valid chain on its own.
        let other = LockTesting.Signer()
        let foreign = try LockTesting.checkpoint(trusting: [other], signedBy: other)
        let cases: [(String, Data)] = [
            ("AUM with a changed signature", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[0], forged])),
            ("Recorded root missing from the store", file(bootstrap: foreign.hash.bytes, aums: bytes)),
            ("Two roots", file(bootstrap: authority.bootstrap.bytes, aums: bytes + [foreign.serialized()])),
            ("Missing parent", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[1]])),
            ("Non-AUM element", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[0], [0x00]])),
            ("31-byte root", file(bootstrap: Array(authority.bootstrap.bytes.dropLast()), aums: bytes)),
            ("4,097 AUMs", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[0]] + Array(repeating: bytes[1], count: 4_096))),
        ]
        for (name, contents) in cases {
            try withStore { store, directory in
                try write(contents, to: store, in: directory)
                #expect("\(name)", performing: { try store.load() }, throws: isStorageError)
            }
        }
        // A valid chain substituted in full opens because initial trust is TOFU, so signatures cannot prevent it and file permissions provide protection.
        try withStore { store, directory in
            try write(file(bootstrap: foreign.hash.bytes, aums: [foreign.serialized()]), to: store, in: directory)
            #expect(try store.load()?.head == foreign.hash)
        }
    }

    @Test("Does not read files over 17MiB")
    func tooLarge() throws {
        try withStore { store, directory in
            #expect(TailnetLockStore.maximumFileSize == 17 * 1_024 * 1_024)
            try write(Data(count: TailnetLockStore.maximumFileSize + 1), to: store, in: directory)
            #expect(performing: { try store.load() }, throws: isStorageError)
        }
    }

    @Test("Does not follow a symlink at the state file path")
    func refusesSymbolicLink() throws {
        try withStore { store, directory in
            // A valid state file is located elsewhere, and the file in the state directory is a link to it.
            let elsewhere = TailnetLockStore(directory: directory.appending(path: "elsewhere"))
            try elsewhere.save(try chain().authority)
            try FileManager.default.createSymbolicLink(at: store.fileURL, withDestinationURL: elsewhere.fileURL)
            #expect(performing: { try store.load() }, throws: isStorageError)
            #expect(try elsewhere.load() != nil)
        }
    }

    @Test("A write failure yields a storage error and leaves the previous file intact")
    func saveFailure() throws {
        try withStore { store, directory in
            let genesis = try Authority(bootstrappingWith: LockTesting.checkpoint(trusting: [signer], signedBy: signer))
            try store.save(genesis)
            let before = try Data(contentsOf: store.fileURL)

            try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: directory.path)
            #expect(performing: { try store.save(try chain().authority) }, throws: isStorageError)
            #expect(try Data(contentsOf: store.fileURL) == before)
            #expect(try store.load()?.head == genesis.head)
        }
    }
}
