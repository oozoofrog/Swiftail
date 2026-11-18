import Foundation

/// Rules for reading a file from the state directory. Shared by the identity file and the tailnet lock state file.
///
/// Reads only regular files up to the limit, without following symbolic links. This keeps anyone who can put a link, FIFO, or large file there
/// from making the node read another file or stalling startup. These checks cannot protect against another user with write access to the directory itself
/// (that user can replace the entire file). The app that chooses the state directory is responsible for this.
enum StateFile {
    /// The file's contents, or nil if the file is absent.
    ///
    /// - Parameters:
    ///   - limit: The maximum bytes to read. Rejects larger files.
    ///   - label: The file name to use in error messages ("identity file"). Omits the path and contents.
    static func read(_ file: URL, limit: Int, label: String) throws(ControlError) -> Data? {
        // O_NOFOLLOW fails if the final path component is a symlink (ELOOP). O_NONBLOCK avoids blocking on a FIFO (rejected below).
        let descriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            let code = errno
            if code == ENOENT { return nil }
            throw .storage("Could not open \(label) (errno \(code))")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var status = stat()
        guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFREG else {
            throw .storage("\(label) is not a regular file")
        }
        guard status.st_size <= limit else { throw .storage("\(label) exceeds the size limit") }
        // The file may have grown since checking its size, so try reading one byte beyond the limit.
        guard let data = try? handle.read(upToCount: limit + 1) else { throw .storage("Could not read \(label)") }
        guard data.count <= limit else { throw .storage("\(label) exceeds the size limit") }
        return data
    }
}
