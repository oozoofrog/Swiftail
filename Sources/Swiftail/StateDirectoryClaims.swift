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

    /// `directory`를 차지한다. 이미 차지되어 있으면 false.
    func claim(_ directory: URL) -> Bool {
        let key = Self.key(for: directory)
        return claimed.withLock { $0.insert(key).inserted }
    }

    /// 차지를 푼다.
    func release(_ directory: URL) {
        let key = Self.key(for: directory)
        _ = claimed.withLock { $0.remove(key) }
    }

    /// 표준화한 경로: `.`·`..`을 풀고 심볼릭 링크를 따라가며 끝의 `/`를 뗀다. 같은 디렉터리의 다른 표기가 같은 열쇠가 된다.
    static func key(for directory: URL) -> String {
        let path = directory.standardizedFileURL.resolvingSymlinksInPath().path(percentEncoded: false)
        return path.count > 1 && path.hasSuffix("/") ? String(path.dropLast()) : path
    }
}
