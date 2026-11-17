import Foundation
import SwiftailCrypto
import SwiftailTKA

/// 서명 권한 상태를 상태 디렉터리의 파일 하나(`tailnet-lock.cbor`)에 둔다. 다시 시작해도 같은 신뢰 상태로 거르게 한다.
///
/// 파일의 내용은 정준 CBOR 맵과 그 바이트의 BLAKE2s-256 32바이트를 이어 붙인 것이다.
///
/// ```
/// {1: 형식 버전(1), 2: 부트스트랩 AUM의 해시(32바이트), 3: [받아들인 AUM의 정준 바이트, 받아들인 순서]} ‖ BLAKE2s-256
/// ```
///
/// 신뢰 상태 자체는 적지 않고 열 때 AUM에서 다시 계산한다. 끝의 해시는 쓰다 만 파일과 깨진 파일을 알아채는 무결성 검사일
/// 뿐 인증이 아니다(파일을 바꿀 수 있는 쪽은 해시도 다시 쓴다). 바꿔 넣은 내용을 막는 것은 열 때 받아들일 때와 같은 규칙으로
/// 정적 검사와 서명을 다시 보는 것이다(`Authority(opening:bootstrap:)`). 그것도 부트스트랩 체크포인트를 통째로 바꾸는 것은
/// 막지 못하므로(첫 신뢰는 TOFU다) 파일을 소유자만 읽고 쓰게(0600) 둔다. 비밀은 들어 있지 않다.
///
/// 쓰기는 `NodeIdentityStore`와 같은 차례다: 같은 디렉터리의 임시 파일을 0600으로 만들어 다 쓰고 디스크에 내린 뒤 이름을
/// 바꾼다. 쓰다가 멈춰도 이전 파일이 남는다. iOS에서는 신원 파일과 같은 보호 등급과 백업 제외를 건다.
///
/// 압축하지 않으므로 변화마다 파일 전체를 다시 쓴다.
/// shortcut: 필요해지는 시점은 사슬이 길어 쓰기가 눈에 띌 때다.
/// shortcut: 한 상태 디렉터리로 다른 tailnet에 다시 로그인하면 옛 tailnet의 상태가 남아 새 tailnet의 피어가 모두 걸러진다
/// (`TailnetLockStatus.issue`가 `.storedStateDiverged`). 스스로 풀지 않고, 사용자가 고르면 앱이
/// `ControlClient.removeTailnetLockState(inDirectory:)`로 이 파일만 지운다. 필요해지는 시점: 상태 디렉터리 하나로 tailnet을
/// 자동으로 바꾸는 사용처.
///
/// 계약 `docs/contracts/SwiftailTailnetLock.md` 동작 T, 결정 L6·L14.
struct TailnetLockStore: Sendable {
    static let fileName = "tailnet-lock.cbor"
    /// 읽는 파일의 크기 한도(동작 M). 쥐는 AUM의 한도(16MiB)에 머리와 길이 표기를 더한 것보다 넉넉하다.
    static let maximumFileSize = 17 * 1_024 * 1_024
    private static let formatVersion: UInt64 = 1
    private static let digestByteCount = 32

    private let directory: URL

    init(directory: URL) {
        self.directory = directory
    }

    var fileURL: URL { directory.appending(path: Self.fileName, directoryHint: .notDirectory) }

    /// 저장된 상태를 열어 다시 계산한다. 파일이 없으면 nil.
    ///
    /// 크기, 끝의 해시, CBOR, 형식 버전, AUM마다의 디코딩, 사슬의 불변 조건과 서명을 차례로 본다. 어느 것이든 어긋나면
    /// 던지고 파일은 건드리지 않는다: 부르는 쪽은 "상태 없음"이 아니라 "확인하지 못함"으로 다뤄야 한다(동작 T4).
    func load() throws(ControlError) -> Authority? {
        // 신원 파일과 같은 규칙으로 읽는다: 심볼릭 링크를 따라가지 않고, 정규 파일만, 한도까지만.
        guard let data = try StateFile.read(fileURL, limit: Self.maximumFileSize, label: "tailnet lock 상태 파일") else {
            return nil
        }
        guard data.count > Self.digestByteCount else {
            throw .storage("tailnet lock 상태 파일의 크기가 맞지 않다")
        }
        let body = [UInt8](data.dropLast(Self.digestByteCount))
        guard BLAKE2s.hash(body) == [UInt8](data.suffix(Self.digestByteCount)) else {
            throw .storage("tailnet lock 상태 파일이 손상되었다(해시)")
        }
        // 우리가 쓰는 모양 그대로만 받는다: 키 1·2·3이 이 순서로 하나씩.
        guard case .map(let pairs)? = try? CBOR.decode(body), pairs.map(\.key) == [.unsigned(1), .unsigned(2), .unsigned(3)],
              pairs[0].value == .unsigned(Self.formatVersion),
              case .bytes(let rootBytes) = pairs[1].value, let root = AUMHash(rootBytes),
              case .array(let items) = pairs[2].value
        else { throw .storage("tailnet lock 상태 파일의 형식을 모른다") }
        do {
            let aums = try items.map { item throws(TKAError) -> AUM in
                guard case .bytes(let bytes) = item else { throw .invalidStructure }
                return try AUM(decoding: bytes)
            }
            return try Authority(opening: aums, bootstrap: root)
        } catch {
            // 까닭은 종류만 남긴다. `TKAError`는 키나 바이트를 담지 않는다.
            throw .storage("tailnet lock 상태 파일의 서명 권한 상태가 검증되지 않는다(\(error))")
        }
    }

    /// 상태를 원자적으로 저장한다. 디렉터리가 없으면 소유자 전용(0700)으로 만든다.
    func save(_ authority: Authority) throws(ControlError) {
        var writer = CBORWriter()
        writer.mapHeader(count: 3)
        writer.unsigned(1)
        writer.unsigned(Self.formatVersion)
        writer.unsigned(2)
        writer.byteString(authority.bootstrap.bytes)
        writer.unsigned(3)
        writer.arrayHeader(count: authority.aums.count)
        for aum in authority.aums {
            writer.byteString(aum.serialized())
        }
        let contents = Data(writer.bytes + BLAKE2s.hash(writer.bytes))

        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw .storage("tailnet lock 상태 디렉터리를 준비하지 못했다(코드 \((error as NSError).code))")
        }
        let temporary = directory.appending(path: ".\(Self.fileName).\(UUID().uuidString)", directoryHint: .notDirectory)
        // 처음부터 0600으로 만드는 open(2)과 이름을 원자적으로 바꾸는 rename(2)만 POSIX로 부른다(`NodeIdentityStore`와 같다).
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw .storage("임시 tailnet lock 상태 파일을 만들지 못했다(errno \(errno))") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try Self.protect(temporary)
            try handle.write(contentsOf: contents)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("tailnet lock 상태 파일을 쓰지 못했다(코드 \((error as NSError).code))")
        }
        guard rename(temporary.path, fileURL.path) == 0 else {
            let code = errno
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("tailnet lock 상태 파일을 바꾸지 못했다(errno \(code))")
        }
    }

    /// 파일을 지운다. 없으면 아무 일도 하지 않는다. 끄기 비밀이 맞았을 때(동작 T5)와 사용자가 고른 지우기
    /// (`ControlClient.removeTailnetLockState(inDirectory:)`)에서만 부른다.
    func remove() throws(ControlError) {
        do {
            try FileManager.default.removeItem(at: fileURL)
        } catch CocoaError.fileNoSuchFile {
            return
        } catch {
            throw .storage("tailnet lock 상태 파일을 지우지 못했다(코드 \((error as NSError).code))")
        }
    }

    /// 신원 파일과 같은 보호 등급과 백업 제외(`docs/contracts/SwiftailTunnel.md` 동작 P 2). iOS에서만 뜻이 있다.
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
}

extension ControlClient {
    /// 상태 디렉터리에서 tailnet lock 상태 파일만 지운다(계약 5절 TL-11b 항목 4). 파일이 없으면 아무 일도 하지 않는다.
    ///
    /// `TailnetLockStatus.issue`가 `.unreadableStoredState`나 `.storedStateDiverged`일 때 푸는 길이다. 둘 다 스스로 풀리지 않는다.
    /// 상태 디렉터리를 통째로 지우면 NL 키도 잃어 서명 기기에서 다시 서명받아야 하므로, 이 파일만 지운다.
    ///
    /// 지우면 다음 시작에 서명 권한 상태를 서버가 주는 체크포인트로 처음부터 새로 믿는다(TOFU). 지금까지 검증해 온 상태가
    /// 서버를 견제하던 것이 사라지므로, 앱이 알아서 부르지 말고 **사용자가 고른 행동**이어야 한다.
    /// 노드가 돌고 있지 않을 때(이 디렉터리를 쓰는 `ControlClient.run()`이 끝난 뒤) 부른다: 돌고 있는 클라이언트는 메모리의
    /// 상태로 계속 거르고 바뀔 때 파일을 다시 쓴다.
    ///
    /// - Parameter directory: `NodeIdentityStore(directory:)`에 준 상태 디렉터리.
    /// - Throws: `ControlError.storage` — 파일을 지우지 못했다.
    public static func removeTailnetLockState(inDirectory directory: URL) throws(ControlError) {
        try TailnetLockStore(directory: directory).remove()
    }
}
