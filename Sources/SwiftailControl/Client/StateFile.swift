import Foundation

/// 상태 디렉터리의 파일 하나를 읽는 규칙. 신원 파일과 tailnet lock 상태 파일이 함께 쓴다.
///
/// 심볼릭 링크를 따라가지 않고, 정규 파일만, 한도까지만 읽는다. 그 자리에 링크나 FIFO, 큰 파일을 놓을 수 있는 쪽이 노드에게
/// 다른 파일을 읽히거나 시작을 붙잡아 두지 못하게 한다. 디렉터리 자체를 다른 사용자가 쓸 수 있으면 막지 못한다
/// (파일을 통째로 바꿔 넣을 수 있다). 그것은 상태 디렉터리를 정하는 앱의 몫이다.
enum StateFile {
    /// 파일의 내용. 파일이 없으면 nil.
    ///
    /// - Parameters:
    ///   - limit: 읽을 바이트의 한도. 넘는 파일은 읽지 않는다.
    ///   - label: 오류 메시지에 적을 파일의 이름("신원 파일"). 경로와 내용은 적지 않는다.
    static func read(_ file: URL, limit: Int, label: String) throws(ControlError) -> Data? {
        // O_NOFOLLOW: 끝 이름이 심볼릭 링크면 실패한다(ELOOP). O_NONBLOCK: FIFO에서 막히지 않는다(아래서 거절한다).
        let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            let code = errno
            if code == ENOENT { return nil }
            throw .storage("\(label)을 열지 못했다(errno \(code))")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw .storage("\(label)이 정규 파일이 아니다")
        }
        guard status.st_size <= limit else { throw .storage("\(label)이 한도보다 크다") }
        // 크기를 본 뒤에 파일이 자랐을 수 있으므로 한도보다 한 바이트 더 읽어 본다.
        guard let data = try? handle.read(upToCount: limit + 1) else { throw .storage("\(label)을 읽지 못했다") }
        guard data.count <= limit else { throw .storage("\(label)이 한도보다 크다") }
        return data
    }
}
