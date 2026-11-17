import Foundation
import Synchronization

/// 같은 프로세스에서 `PairingHost`가 쥐고 있는 짝 목록 디렉터리의 표(계약 동작 S5).
///
/// 호스트 둘이 한 파일을 함께 쓰면 한쪽이 지운 짝을 다른 쪽의 다음 저장이 되살린다. 프로세스 사이는 막지 않는다.
/// 노드의 상태 디렉터리 표(`Swiftail`의 `StateDirectoryClaims`)와 같은 방식이다.
final class StoreDirectoryClaims: Sendable {
    /// 프로세스 전역 표.
    static let shared = StoreDirectoryClaims()

    private let claimed = Mutex<Set<String>>([])

    /// `directory`를 차지한다. 이미 차지되어 있으면 nil, 아니면 풀 때 쓸 열쇠. 디렉터리는 이미 있어야 한다(없는 경로는
    /// 심볼릭 링크가 풀리지 않는다).
    func claim(_ directory: URL) -> String? {
        // `.`·`..`을 풀고 심볼릭 링크를 따라가며 끝의 `/`를 뗀다. 같은 디렉터리의 다른 표기가 같은 열쇠가 된다.
        let path = directory.standardizedFileURL.resolvingSymlinksInPath().path(percentEncoded: false)
        let key = path.count > 1 && path.hasSuffix("/") ? String(path.dropLast()) : path
        return claimed.withLock { $0.insert(key).inserted } ? key : nil
    }

    /// 차지를 푼다.
    func release(_ key: String) {
        _ = claimed.withLock { $0.remove(key) }
    }
}
