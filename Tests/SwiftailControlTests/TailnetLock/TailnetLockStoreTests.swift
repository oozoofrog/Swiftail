// `TailnetLockStore`: 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 T·M, 결정 L6·L14, 단위 시험 20.

import Foundation
import Testing

import SwiftailCrypto
@testable import SwiftailControl
@testable import SwiftailTKA

@Suite("tailnet lock: 상태 저장")
struct TailnetLockStoreTests {
    private let signer = LockTesting.Signer()

    /// 임시 디렉터리의 저장소로 `body`를 돌린다.
    private func withStore<T>(_ body: (TailnetLockStore, URL) throws -> T) throws -> T {
        let directory = FileManager.default.temporaryDirectory.appending(path: "swiftail-lock-store-\(UUID().uuidString)")
        defer {
            // 읽기 전용으로 바꾼 시험도 지워지게 권한을 되돌린다.
            try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
            try? FileManager.default.removeItem(at: directory)
        }
        return try body(TailnetLockStore(directory: directory), directory)
    }

    /// 체크포인트와 그 뒤의 AddKey 하나.
    private func chain() throws -> (authority: Authority, aums: [AUM]) {
        let genesis = try LockTesting.checkpoint(trusting: [signer], signedBy: signer)
        var authority = try Authority(bootstrappingWith: genesis)
        let added = try LockTesting.addKey(LockTesting.Signer(), after: authority.head, signedBy: signer)
        try authority.inform([added])
        return (authority, [genesis, added])
    }

    /// 저장 파일의 바이트를 직접 만든다(형식은 `TailnetLockStore`의 주석).
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

    @Test("파일이 없으면 nil. 쓰고 다시 열면 같은 머리·뿌리·AUM이고, 파일은 0600이며 임시 파일이 남지 않는다")
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
            // 내용은 주석의 형식 그대로다: 맵과 그 BLAKE2s-256.
            let expected = file(bootstrap: authority.bootstrap.bytes, aums: aums.map { $0.serialized() })
            #expect(try Data(contentsOf: store.fileURL) == expected)
        }
    }

    @Test("다시 쓰면 통째로 바뀐다. 지우면 없어지고, 없는 것을 지워도 된다")
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

    @Test("깨진 파일은 열리지 않고 그대로 남는다: 끝의 해시, 잘림, 빈 파일, 형식 버전")
    func corrupted() throws {
        let (authority, aums) = try chain()
        let good = file(bootstrap: authority.bootstrap.bytes, aums: aums.map { $0.serialized() })
        var flipped = good
        flipped[10] ^= 0x01
        var wrongDigest = good
        wrongDigest[good.count - 1] ^= 0x01
        let cases: [(String, Data)] = [
            ("본문의 한 바이트", flipped),
            ("해시의 한 바이트", wrongDigest),
            ("끝이 잘림", good.dropLast(5)),
            ("해시보다 짧음", good.prefix(20)),
            ("해시뿐", Data(BLAKE2s.hash([UInt8]()))),
            ("빈 파일", Data()),
            ("모르는 형식 버전", file(version: 2, bootstrap: authority.bootstrap.bytes, aums: aums.map { $0.serialized() })),
            ("해시는 맞지만 CBOR이 아님", Data([0xff, 0x00] + BLAKE2s.hash([0xff, 0x00]))),
        ]
        for (name, contents) in cases {
            try withStore { store, directory in
                try write(contents, to: store, in: directory)
                #expect("\(name)", performing: { try store.load() }, throws: isStorageError)
                #expect(try Data(contentsOf: store.fileURL) == contents, "\(name): 파일을 고치거나 지웠다")
            }
        }
    }

    @Test("해시를 다시 계산해 바꿔 넣은 내용도 열리지 않는다: 서명, 뿌리, 부모, 한도")
    func tampered() throws {
        let (authority, aums) = try chain()
        let bytes = aums.map { $0.serialized() }
        // 서명 한 바이트를 바꾼 AddKey(끝 64바이트가 서명이다).
        var forged = bytes[1]
        forged[forged.count - 1] ^= 0x01
        // 다른 서명 기기의 체크포인트: 그 자체로는 유효한 사슬이다.
        let other = LockTesting.Signer()
        let foreign = try LockTesting.checkpoint(trusting: [other], signedBy: other)
        let cases: [(String, Data)] = [
            ("서명이 바뀐 AUM", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[0], forged])),
            ("기록된 뿌리가 저장소에 없음", file(bootstrap: foreign.hash.bytes, aums: bytes)),
            ("뿌리가 둘", file(bootstrap: authority.bootstrap.bytes, aums: bytes + [foreign.serialized()])),
            ("부모가 빠짐", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[1]])),
            ("AUM이 아닌 원소", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[0], [0x00]])),
            ("31바이트 뿌리", file(bootstrap: Array(authority.bootstrap.bytes.dropLast()), aums: bytes)),
            ("AUM 4,097개", file(bootstrap: authority.bootstrap.bytes, aums: [bytes[0]] + Array(repeating: bytes[1], count: 4_096))),
        ]
        for (name, contents) in cases {
            try withStore { store, directory in
                try write(contents, to: store, in: directory)
                #expect("\(name)", performing: { try store.load() }, throws: isStorageError)
            }
        }
        // 통째로 바꿔 넣은 유효한 사슬은 열린다: 첫 신뢰가 TOFU라 서명으로는 막지 못하고, 파일 권한이 지킨다.
        try withStore { store, directory in
            try write(file(bootstrap: foreign.hash.bytes, aums: [foreign.serialized()]), to: store, in: directory)
            #expect(try store.load()?.head == foreign.hash)
        }
    }

    @Test("17MiB를 넘는 파일은 읽지 않는다")
    func tooLarge() throws {
        try withStore { store, directory in
            #expect(TailnetLockStore.maximumFileSize == 17 * 1_024 * 1_024)
            try write(Data(count: TailnetLockStore.maximumFileSize + 1), to: store, in: directory)
            #expect(performing: { try store.load() }, throws: isStorageError)
        }
    }

    @Test("상태 파일이 심볼릭 링크면 따라가지 않는다")
    func refusesSymbolicLink() throws {
        try withStore { store, directory in
            // 올바른 상태 파일이 다른 곳에 있고, 상태 디렉터리의 파일은 그것을 가리키는 링크다.
            let elsewhere = TailnetLockStore(directory: directory.appending(path: "elsewhere"))
            try elsewhere.save(try chain().authority)
            try FileManager.default.createSymbolicLink(at: store.fileURL, withDestinationURL: elsewhere.fileURL)
            #expect(performing: { try store.load() }, throws: isStorageError)
            #expect(try elsewhere.load() != nil)
        }
    }

    @Test("쓰지 못하면 storage 오류이고 이전 파일이 그대로 남는다")
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
