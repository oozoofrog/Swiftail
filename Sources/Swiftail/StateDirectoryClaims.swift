import Foundation
import Synchronization

/// 같은 프로세스에서 돌고 있는 노드의 상태 디렉터리 표. 노드 둘이 한 신원 파일을 함께 쓰지 못하게 한다.
///
/// `run()`이 시작할 때 디렉터리를 올리고(파일·소켓을 열기 전) 끝날 때 내린다. 이미 있으면 `stateDirectoryInUse`다.
/// 다른 프로세스 사이는 막지 않는다. 첫 사용처에는 터널 확장이 둘 있고 한 번에 하나만 켜지므로 잠금 파일을 남기지 않는다.
/// `docs/contracts/SwiftailTunnel.md` 동작 P 3.
final class StateDirectoryClaims: Sendable {
    /// 프로세스 전역 표. 노드가 쓴다.
    static let shared = StateDirectoryClaims()

    private let claimed = Mutex<Set<String>>([])

    /// `directory`를 차지한다. 이미 차지되어 있으면 nil, 아니면 풀 때 쓸 열쇠.
    ///
    /// 디렉터리는 이미 있어야 한다. 없는 경로는 심볼릭 링크가 풀리지 않아, 디렉터리가 생긴 뒤의 같은 자리와 다른 열쇠가
    /// 된다(노드는 `claimCreating(_:)`으로 쥔다).
    func claim(_ directory: URL) -> String? {
        let key = Self.key(for: directory)
        return claimed.withLock { $0.insert(key).inserted } ? key : nil
    }

    /// 노드가 상태 디렉터리를 쥐는 길: 없으면 소유자 전용(0700)으로 만든 뒤 차지한다.
    ///
    /// - Throws: 만들지 못하면 `control(.storage)`, 이미 차지되어 있으면 `stateDirectoryInUse`.
    func claimCreating(_ directory: URL) throws(NodeError) -> String {
        guard (try? FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])) != nil
        else { throw .control(.storage("상태 디렉터리를 만들지 못했다")) }
        guard let key = claim(directory) else { throw .stateDirectoryInUse }
        return key
    }

    /// 차지를 푼다. 차지할 때 받은 열쇠로 푼다: 그 사이 경로의 심볼릭 링크가 바뀌었어도 쥔 것을 그대로 놓는다.
    func release(_ key: String) {
        _ = claimed.withLock { $0.remove(key) }
    }

    /// 표준화한 경로: `.`·`..`을 풀고 심볼릭 링크를 따라가며 끝의 `/`를 뗀다. 같은 디렉터리의 다른 표기가 같은 열쇠가 된다.
    static func key(for directory: URL) -> String {
        let path = directory.standardizedFileURL.resolvingSymlinksInPath().path(percentEncoded: false)
        return path.count > 1 && path.hasSuffix("/") ? String(path.dropLast()) : path
    }
}
