import CryptoKit
import Foundation
import SwiftailBase

/// 신원을 디렉터리의 파일 하나(`identity.json`)에 둔다. 다시 시작해도 같은 노드로 뜨게 하는 유일한 상태다.
///
/// 파일은 JSON이고 키는 Go와 같은 텍스트다: machine 키와 node 키는 `privkey:` + 16진 64자리, NL 키는 `nlpriv:` + 16진
/// 128자리(Ed25519 시드 32바이트 ‖ 공개 키 32바이트).
///
/// ```json
/// {"MachineKey":"privkey:…","NodeKey":"privkey:…","NLKey":"nlpriv:…"}
/// ```
///
/// `NLKey`가 없는 옛 파일(tailnet lock 전)도 읽는다. 그때는 같은 machine 키·node 키에 새 NL 키를 채운다(`loadOrCreate()`가 첫
/// 요청 전에 저장한다). `NLKey`의 뒤 32바이트가 시드로 만든 공개 키와 다르면 손상으로 본다(Go는 이것을 보지 않는다).
/// `docs/contracts/SwiftailTailnetLock.md` 동작 R1.
///
/// 개인 키를 담으므로 소유자만 읽게(0600) 만들고, 같은 디렉터리의 임시 파일에 다 쓴 뒤 이름을 바꿔 원자적으로
/// 바꾼다. 쓰다가 멈춰도 이전 신원이 남는다. 오류 메시지에는 경로와 키를 넣지 않는다.
/// `docs/contracts/SwiftailControl.md` 단위 4 동작 7.
///
/// iOS에서는 쓰기 전에 임시 파일에 데이터 보호 등급 `completeUntilFirstUserAuthentication`과 백업 제외를 건다. 패킷 터널
/// 확장은 잠긴 화면에서도 뜨므로(`complete`면 시작이 실패한다) 첫 잠금 해제 뒤에 읽을 수 있어야 하고, 개인 키가 다른 기기로
/// 복원되면 같은 머신 키를 가진 기기가 둘이 된다. 두 성질은 파일에 붙어 이름을 바꿔도 따라간다고 보았다(실기기 관문에서
/// 확인한다). `docs/contracts/SwiftailTunnel.md` 동작 P 2.
public struct NodeIdentityStore: Sendable {
    static let fileName = "identity.json"
    private static let keyPrefix = "privkey:"
    private static let lockKeyPrefix = "nlpriv:"

    private let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    var fileURL: URL { directory.appending(path: Self.fileName, directoryHint: .notDirectory) }

    /// 저장된 신원을 읽는다. 파일이 없으면 nil.
    ///
    /// `NLKey`가 없는 옛 파일이면 새 NL 키를 채워 돌려주되 저장하지 않는다. 그 키를 등록에 쓰려면 저장해야 한다(`loadOrCreate()`).
    public func load() throws(ControlError) -> NodeIdentity? {
        try read()?.identity
    }

    /// 제어 클라이언트가 시작할 때 쓴다. 파일이 없으면 새 신원을, `NLKey`가 없는 옛 파일이면 새 NL 키를 만들어 저장한 뒤 돌려준다.
    ///
    /// 첫 요청 전에 저장해야 한다. 저장하지 않은 NL 키로 등록하면 다시 시작할 때 다른 키가 나간다(동작 R1). machine 키도 등록 전에
    /// 저장한다: 다시 시작해도 같은 기기로 보여야 한다.
    func loadOrCreate() throws(ControlError) -> NodeIdentity {
        guard let stored = try read() else {
            let identity = NodeIdentity()
            try save(identity)
            return identity
        }
        if !stored.hasLockKey { try save(stored.identity) }
        return stored.identity
    }

    /// 파일을 읽어 신원과, 파일에 NL 키가 있었는지를 돌려준다. 파일이 없으면 nil.
    private func read() throws(ControlError) -> (identity: NodeIdentity, hasLockKey: Bool)? {
        let data: Data
        do {
            data = try Data(contentsOf: fileURL)
        } catch CocoaError.fileReadNoSuchFile {
            return nil
        } catch {
            throw .storage("신원 파일을 읽지 못했다(코드 \((error as NSError).code))")
        }
        guard let file = try? JSONDecoder().decode(IdentityFile.self, from: data),
              let machineKey = Self.privateKey(file.machineKey)
        else { throw .storage("신원 파일이 손상되었다") }
        var nodeKey: Curve25519.KeyAgreement.PrivateKey?
        if let text = file.nodeKey {
            guard let key = Self.privateKey(text) else { throw .storage("신원 파일이 손상되었다") }
            nodeKey = key
        }
        guard let text = file.lockKey else {
            return (NodeIdentity(machineKey: machineKey, nodeKey: nodeKey), false)
        }
        guard let lockKey = Self.lockKey(text) else { throw .storage("신원 파일의 NL 키가 손상되었다") }
        return (NodeIdentity(machineKey: machineKey, nodeKey: nodeKey, lockKey: lockKey), true)
    }

    /// 신원을 원자적으로 저장한다. 디렉터리가 없으면 소유자 전용(0700)으로 만든다.
    public func save(_ identity: NodeIdentity) throws(ControlError) {
        let file = IdentityFile(
            machineKey: Self.text(identity.machineKey),
            nodeKey: identity.nodeKey.map(Self.text),
            lockKey: Self.text(identity.lockKey)
        )
        let data: Data
        do {
            data = try JSONEncoder().encode(file)
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw .storage("신원 디렉터리를 준비하지 못했다(코드 \((error as NSError).code))")
        }

        let temporary = directory.appending(path: ".\(Self.fileName).\(UUID().uuidString)", directoryHint: .notDirectory)
        // Foundation의 파일 쓰기는 권한을 쓴 뒤에 바꾼다. 개인 키가 잠깐이라도 남에게 읽히지 않도록
        // 처음부터 0600으로 만드는 open(2)과 이름을 원자적으로 바꾸는 rename(2)만 POSIX로 부른다.
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL, 0o600)
        guard descriptor >= 0 else { throw .storage("임시 신원 파일을 만들지 못했다(errno \(errno))") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try Self.protect(temporary)
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("신원 파일을 쓰지 못했다(코드 \((error as NSError).code))")
        }
        guard rename(temporary.path, fileURL.path) == 0 else {
            let code = errno
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("신원 파일을 바꾸지 못했다(errno \(code))")
        }
    }

    /// 신원 파일의 보호 등급과 백업 제외. iOS에서만 뜻이 있다(macOS의 데이터 보호는 다른 체계이고 백업 제외도 앱 몫이다).
    private static func protect(_ file: URL) throws {
        #if os(iOS)
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: file.path
        )
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var file = file
        try file.setResourceValues(values)
        #endif
    }

    private static func text(_ key: Curve25519.KeyAgreement.PrivateKey) -> String {
        keyPrefix + [UInt8](key.rawRepresentation).hex
    }

    private static func privateKey(_ text: String) -> Curve25519.KeyAgreement.PrivateKey? {
        guard text.hasPrefix(keyPrefix),
              let bytes = [UInt8](hex: String(text.dropFirst(keyPrefix.count))),
              bytes.count == 32
        else { return nil }
        return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes)
    }

    /// `nlpriv:` + 시드 ‖ 공개 키의 16진(Go `NLPrivate.MarshalText`).
    static func text(_ key: Curve25519.Signing.PrivateKey) -> String {
        lockKeyPrefix + ([UInt8](key.rawRepresentation) + [UInt8](key.publicKey.rawRepresentation)).hex
    }

    /// `nlpriv:` + 16진 128자리(대소문자 모두)를 읽는다. 뒤 32바이트가 앞 32바이트(시드)로 만든 공개 키와 다르면 nil(동작 R1).
    /// 견주는 것은 공개 값이라 상수 시간 비교가 필요 없다.
    static func lockKey(_ text: String) -> Curve25519.Signing.PrivateKey? {
        guard text.hasPrefix(lockKeyPrefix),
              let bytes = [UInt8](hex: String(text.dropFirst(lockKeyPrefix.count))),
              bytes.count == 64,
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: bytes[..<32]),
              [UInt8](key.publicKey.rawRepresentation) == Array(bytes[32...])
        else { return nil }
        return key
    }
}

/// 신원 파일의 JSON 모양.
private struct IdentityFile: Codable {
    var machineKey: String
    var nodeKey: String?
    /// 옛 파일에는 없다.
    var lockKey: String?

    enum CodingKeys: String, CodingKey {
        case machineKey = "MachineKey"
        case nodeKey = "NodeKey"
        case lockKey = "NLKey"
    }
}
