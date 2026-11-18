import Foundation
import SwiftailControl

extension TailnetNode {
    /// Checks whether `stateDirectory` contains a registered identity. Before starting the node, the app uses this to
    /// decide whether to connect automatically with the saved identity or obtain an auth key or login. Reads only the
    /// identity file and creates no files or sockets.
    ///
    /// Reads and validates the file's format using the same rules as `run()`, rather than checking only for existence.
    /// Follows no symlinks, accepts only regular files, and limits size to 64KiB. An existing but unreadable file also
    /// ends `run()` with `control(.storage)`. Reporting that failure first keeps the app from obtaining an auth key and
    /// then failing to start. Returns true only when there is a node key. A file with only a machine key means
    /// registration stopped before completion (`run()` saves the machine key before registration), and an auth key or
    /// login is needed again.
    ///
    /// Even if true, `run()` reports `.needsLogin` or a `control(_:)` failure if the control server removed the node or
    /// the node key expired. Only the server can answer that. Does not expose the identity contents (keys).
    ///
    /// - Parameter stateDirectory: The directory to pass to `NodeConfiguration.stateDirectory`.
    /// - Returns: True if a registered identity exists. False if the identity file is absent or is from before registration.
    /// - Throws: `invalidConfiguration` for a URL other than a file URL. Throws `control(.storage)` if the identity
    ///   file is a symlink, is not a regular file, exceeds the limit, cannot be read, or has an invalid format.
    public static func hasSavedIdentity(in stateDirectory: URL) throws(NodeError) -> Bool {
        guard stateDirectory.isFileURL else { throw .invalidConfiguration("State directory must be a file URL") }
        do throws(ControlError) {
            return try NodeIdentityStore(directory: stateDirectory).load()?.nodeKey != nil
        } catch {
            throw NodeError(error)
        }
    }
}
