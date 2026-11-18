import Foundation
import Synchronization

/// A table of state directories for nodes running in the same process. Prevents two nodes from sharing an identity file.
///
/// Claims the directory at the start of `run()`, before opening files or sockets, and releases it at the end. An
/// existing claim yields `stateDirectoryInUse`. Does not exclude other processes. The first adopter has two tunnel
/// extensions and runs only one at a time, so no lock file is left. `docs/contracts/SwiftailTunnel.md` behavior P 3.
final class StateDirectoryClaims: Sendable {
    /// The process-wide table used by nodes.
    static let shared = StateDirectoryClaims()

    private let claimed = Mutex<Set<String>>([])

    /// Claims `directory`. Returns nil if already claimed or a key for releasing it otherwise.
    ///
    /// The directory must already exist. Symlinks in a missing path do not resolve, resulting in a different key from
    /// the same location after directory creation. The node uses `claimCreating(_:)`.
    func claim(_ directory: URL) -> String? {
        let key = Self.key(for: directory)
        return claimed.withLock { $0.insert(key).inserted } ? key : nil
    }

    /// Claims the node's state directory, first creating it with owner-only mode (0700) if missing.
    ///
    /// - Throws: `control(.storage)` if creation fails, or `stateDirectoryInUse` if already claimed.
    func claimCreating(_ directory: URL) throws(NodeError) -> String {
        guard (try? FileManager.default.createDirectory(
            at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])) != nil
        else { throw .control(.storage("Could not create the state directory")) }
        guard let key = claim(directory) else { throw .stateDirectoryInUse }
        return key
    }

    /// Releases a claim by the key received when claiming it. Releases the original claim even if symlinks in the path
    /// changed in the meantime.
    func release(_ key: String) {
        _ = claimed.withLock { $0.remove(key) }
    }

    /// A standardized path. Resolves `.` and `..`, follows symlinks, and strips the trailing `/`. Different spellings
    /// of the same directory yield one key.
    static func key(for directory: URL) -> String {
        let path = directory.standardizedFileURL.resolvingSymlinksInPath().path(percentEncoded: false)
        return path.count > 1 && path.hasSuffix("/") ? String(path.dropLast()) : path
    }
}
