import Foundation

/// The edge that reads and writes the paired peer list file, `storeDirectory/paired-peers.json` (contract behaviors S2 and S3).
///
/// Writes to a temporary file (0600) in the same directory, flushes it to disk, then renames it. Stopping during the write leaves the old file.
/// Reads do not follow symlinks and read up to 1MiB. Errors omit paths. The directory must belong to the current user and be unwritable by
/// the group or others (`hasPrivateDirectory`).
struct PairedPeerFile: Sendable {
    static let name = "paired-peers.json"
    /// The file size limit (S3).
    static let maximumLength = 1 << 20

    let directory: URL

    private var path: String { directory.appending(path: Self.name).path(percentEncoded: false) }

    /// Checks whether the ownership and permissions allow storing the paired peer list (S2). It must be a directory owned by the current user and unwritable by the group or others.
    ///
    /// Anyone able to write to the directory can replace the list file and add paired peers. The file's permissions alone (0600) cannot prevent that.
    /// `SwiftailCertificates` applies the same rule to `certs/`.
    static func isPrivateDirectory(mode: mode_t, owner: uid_t, currentUser: uid_t) -> Bool {
        mode & S_IFMT == S_IFDIR && owner == currentUser && mode & (S_IWGRP | S_IWOTH) == 0
    }

    /// Checks whether the directory exists and satisfies `isPrivateDirectory`. Follows symlinks in the path and checks the target directory.
    var hasPrivateDirectory: Bool {
        var status = stat()
        return stat(directory.path(percentEncoded: false), &status) == 0
            && Self.isPrivateDirectory(mode: status.st_mode, owner: status.st_uid, currentUser: geteuid())
    }

    /// The stored list, or an empty list if the file is missing.
    ///
    /// - Throws: `storeUnreadable` if an existing file cannot be read (cannot open, over 1MiB, or wrong format).
    func load() throws(PairingError) -> PairedPeerList {
        // O_NOFOLLOW prevents following symlinks. O_NONBLOCK prevents blocking on a FIFO (it fails the JSON check).
        let descriptor = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            if errno == ENOENT { return PairedPeerList() }
            throw .storeUnreadable
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        // Read one byte past the limit to detect oversized files.
        guard let contents = try? handle.read(upToCount: Self.maximumLength + 1),
              contents.count <= Self.maximumLength, let list = PairedPeerList(fileContents: contents)
        else { throw .storeUnreadable }
        return list
    }

    /// Writes the list to the file. Creates the directory with mode 0700 if absent.
    ///
    /// - Throws: `storeWriteFailed` if writing fails. The old file stays as it was.
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
            // Set exactly 0600 regardless of umask.
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
