import CryptoKit
import Foundation
import SwiftailBase

/// 신원을 디렉터리의 파일 하나(`identity.json`)에 둔다. 다시 시작해도 같은 노드로 뜨게 하는 유일한 상태다.
///
/// 파일은 JSON이고 키는 Go와 같은 텍스트(`privkey:` + 16진 64자리)다.
///
/// ```json
/// {"MachineKey":"privkey:…","NodeKey":"privkey:…"}
/// ```
///
/// 개인 키를 담으므로 소유자만 읽게(0600) 만들고, 같은 디렉터리의 임시 파일에 다 쓴 뒤 이름을 바꿔 원자적으로
/// 바꾼다. 쓰다가 멈춰도 이전 신원이 남는다. 오류 메시지에는 경로와 키를 넣지 않는다.
/// `docs/contracts/SwiftailControl.md` 단위 4 동작 7.
public struct NodeIdentityStore: Sendable {
    static let fileName = "identity.json"
    private static let keyPrefix = "privkey:"

    private let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    var fileURL: URL { directory.appending(path: Self.fileName, directoryHint: .notDirectory) }

    /// 저장된 신원을 읽는다. 파일이 없으면 nil.
    public func load() throws(ControlError) -> NodeIdentity? {
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
        return NodeIdentity(machineKey: machineKey, nodeKey: nodeKey)
    }

    /// 신원을 원자적으로 저장한다. 디렉터리가 없으면 소유자 전용(0700)으로 만든다.
    public func save(_ identity: NodeIdentity) throws(ControlError) {
        let file = IdentityFile(
            machineKey: Self.text(identity.machineKey),
            nodeKey: identity.nodeKey.map(Self.text)
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
}

/// 신원 파일의 JSON 모양.
private struct IdentityFile: Codable {
    var machineKey: String
    var nodeKey: String?

    enum CodingKeys: String, CodingKey {
        case machineKey = "MachineKey"
        case nodeKey = "NodeKey"
    }
}
