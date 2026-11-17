import Foundation

/// 짝 목록의 파일 `storeDirectory/paired-peers.json`을 읽고 쓰는 가장자리(계약 동작 S2·S3).
///
/// 쓰기는 같은 디렉터리의 임시 파일(0600)에 다 쓰고 디스크에 내린 뒤 이름을 바꾼다. 쓰는 도중에 멈춰도 옛 파일이 남는다.
/// 읽기는 심볼릭 링크를 따라가지 않고 1MiB까지만 읽는다. 오류에는 경로를 싣지 않는다.
struct PairedPeerFile: Sendable {
    static let name = "paired-peers.json"
    /// 파일의 한도(S3).
    static let maximumLength = 1 << 20

    let directory: URL

    private var path: String { directory.appending(path: Self.name).path(percentEncoded: false) }

    /// 저장된 목록. 파일이 없으면 빈 목록이다.
    ///
    /// - Throws: 파일이 있는데 읽지 못하면(열지 못함, 1MiB 초과, 형식이 다름) `storeUnreadable`.
    func load() throws(PairingError) -> PairedPeerList {
        // O_NOFOLLOW: 심볼릭 링크는 따라가지 않는다. O_NONBLOCK: FIFO에서 막히지 않는다(JSON이 아니어서 걸린다).
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ENOENT { return PairedPeerList() }
            throw .storeUnreadable
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        // 한도보다 한 바이트 더 읽어 넘는지 본다.
        guard let contents = try? handle.read(upToCount: Self.maximumLength + 1),
              contents.count <= Self.maximumLength, let list = PairedPeerList(fileContents: contents)
        else { throw .storeUnreadable }
        return list
    }

    /// 목록을 파일에 쓴다. 디렉터리가 없으면 0700으로 만든다.
    ///
    /// - Throws: 쓰지 못하면 `storeWriteFailed`. 옛 파일은 그대로다.
    func save(_ list: PairedPeerList) throws(PairingError) {
        guard let contents = list.fileContents,
              (try? FileManager.default.createDirectory(
                  at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])) != nil
        else { throw .storeWriteFailed }
        let temporary = directory.appending(path: ".\(Self.name).\(UUID().uuidString).tmp").path(percentEncoded: false)
        let descriptor = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw .storeWriteFailed }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            // umask와 무관하게 정확히 0600으로 둔다.
            guard fchmod(descriptor, 0o600) == 0 else { throw PairingError.storeWriteFailed }
            try handle.write(contentsOf: contents)
            try handle.synchronize()
            try handle.close()
            guard rename(temporary, path) == 0 else { throw PairingError.storeWriteFailed }
        } catch {
            try? handle.close()
            unlink(temporary)
            throw .storeWriteFailed
        }
    }
}
