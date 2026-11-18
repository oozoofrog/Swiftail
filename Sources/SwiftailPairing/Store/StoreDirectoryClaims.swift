import Foundation
import Synchronization

/// A registry of paired peer list directories held by `PairingHost` instances in this process (contract behavior S5).
///
/// If two hosts share a file, the next save by one can restore peers removed by the other. The registry does not prevent this across processes.
/// It works like the node state directory registry (`StateDirectoryClaims` in `Swiftail`).
final class StoreDirectoryClaims: Sendable {
    /// The process-wide registry.
    static let shared = StoreDirectoryClaims()

    private let claimed = Mutex<Set<String>>([])

    /// Claims `directory`. Returns nil if already claimed or a key to release the claim otherwise. The directory must already exist
    /// because symlinks are not resolved for a nonexistent path.
    func claim(_ directory: URL) -> String? {
        // Resolve `.` and `..`, follow symlinks, and remove the trailing `/`. Different spellings of the same directory produce the same key.
        let path = directory.standardizedFileURL.resolvingSymlinksInPath().path(percentEncoded: false)
        let key = path.count > 1 && path.hasSuffix("/") ? String(path.dropLast()) : path
        return claimed.withLock { $0.insert(key).inserted } ? key : nil
    }

    /// Releases the claim.
    func release(_ key: String) {
        _ = claimed.withLock { $0.remove(key) }
    }
}
