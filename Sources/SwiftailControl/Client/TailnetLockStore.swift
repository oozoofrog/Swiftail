import Foundation
import SwiftailCrypto
import SwiftailTKA

/// Keeps signing authority state in one file (`tailnet-lock.cbor`) in the state directory, so filtering uses the same trust state after restart.
///
/// The file concatenates a canonical CBOR map and the 32-byte BLAKE2s-256 digest of that map's bytes.
///
/// ```
/// {1: format version(1), 2: bootstrap AUM hash(32 bytes), 3: [canonical bytes of accepted AUMs, in acceptance order]} ‖ BLAKE2s-256
/// ```
///
/// Recomputes trust state from AUMs on open and omits the state itself from the file. The trailing hash is only an integrity check for
/// partial writes and corruption. It provides no authentication (anyone who can replace the file can rewrite the hash). To reject tampered contents,
/// opening repeats static and signature checks under the same rules used at acceptance (`Authority(opening:bootstrap:)`). Even this cannot prevent wholesale
/// replacement of the bootstrap checkpoint (initial trust is TOFU), so allow only the owner to read and write the file (0600). It contains no secrets.
///
/// Uses the `NodeIdentityStore` write sequence. Creates a 0600 temporary file in the same directory, writes it fully, flushes it to disk, and renames
/// it. An interrupted write leaves the previous file intact. On iOS, uses the same protection class and backup exclusion as the identity file.
///
/// Uses no compression, so every change rewrites the entire file.
/// shortcut: revisit when writing a long chain takes a noticeable amount of time.
/// shortcut: logging in to another tailnet with the same state directory leaves the old tailnet's state behind and can filter out peers on the new tailnet, potentially all of them.
/// When synchronization finds no common ancestor, `TailnetLockStatus.issue` is `.storedStateDiverged` and requires manual recovery. If the user chooses to, the app deletes only this file with
/// `ControlClient.removeTailnetLockState(inDirectory:)`. Revisit when an adopter automatically switches tailnets using
/// one state directory.
///
/// Contract `docs/contracts/SwiftailTailnetLock.md` behavior T, decisions L6 and L14.
struct TailnetLockStore: Sendable {
    static let fileName = "tailnet-lock.cbor"
    /// The input file size limit (behavior M). Allows more than the retained AUM limit (16MiB) plus the head and length encodings.
    static let maximumFileSize = 17 * 1_024 * 1_024
    private static let formatVersion: UInt64 = 1
    private static let digestByteCount = 32

    private let directory: URL

    init(directory: URL) {
        self.directory = directory
    }

    var fileURL: URL { directory.appending(path: Self.fileName, directoryHint: .notDirectory) }

    /// Opens stored state and recomputes it. Returns nil if the file is absent.
    ///
    /// Checks size, the trailing hash, CBOR, the format version, decoding of each AUM, chain invariants, and signatures in order. Any violation
    /// throws and leaves the file untouched. The caller must treat the state as unverified even though it could not be loaded (behavior T4).
    func load() throws(ControlError) -> Authority? {
        // Read by the same rules as the identity file: no symlink following, regular files only, and at most the limit.
        guard let data = try StateFile.read(fileURL, limit: Self.maximumFileSize, label: "tailnet lock state file") else {
            return nil
        }
        guard data.count > Self.digestByteCount else {
            throw .storage("Tailnet lock state file has an invalid size")
        }
        let body = [UInt8](data.dropLast(Self.digestByteCount))
        guard BLAKE2s.hash(body) == [UInt8](data.suffix(Self.digestByteCount)) else {
            throw .storage("Tailnet lock state file is corrupted (hash)")
        }
        // Accept only the exact shape we write, with keys 1, 2, and 3 once each in that order.
        guard case .map(let pairs)? = try? CBOR.decode(body), pairs.map(\.key) == [.unsigned(1), .unsigned(2), .unsigned(3)],
              pairs[0].value == .unsigned(Self.formatVersion),
              case .bytes(let rootBytes) = pairs[1].value, let root = AUMHash(rootBytes),
              case .array(let items) = pairs[2].value
        else { throw .storage("Unknown tailnet lock state file format") }
        do {
            let aums = try items.map { item throws(TKAError) -> AUM in
                guard case .bytes(let bytes) = item else { throw .invalidStructure }
                return try AUM(decoding: bytes)
            }
            return try Authority(opening: aums, bootstrap: root)
        } catch {
            // Report only the reason's kind. `TKAError` contains no keys or bytes.
            throw .storage("Could not verify the signing authority state in the tailnet lock state file (\(error))")
        }
    }

    /// Stores state atomically. Creates the directory as owner-only (0700) if absent.
    func save(_ authority: Authority) throws(ControlError) {
        var writer = CBORWriter()
        writer.mapHeader(count: 3)
        writer.unsigned(1)
        writer.unsigned(Self.formatVersion)
        writer.unsigned(2)
        writer.byteString(authority.bootstrap.bytes)
        writer.unsigned(3)
        writer.arrayHeader(count: authority.aums.count)
        for aum in authority.aums {
            writer.byteString(aum.serialized())
        }
        let contents = Data(writer.bytes + BLAKE2s.hash(writer.bytes))

        do {
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw .storage("Could not prepare the tailnet lock state directory (code \((error as NSError).code))")
        }
        let temporary = directory.appending(path: ".\(Self.fileName).\(UUID().uuidString)", directoryHint: .notDirectory)
        // Use POSIX only for open(2), which creates the file as 0600 from the start, and rename(2), which renames it atomically (as in `NodeIdentityStore`).
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw .storage("Could not create a temporary tailnet lock state file (errno \(errno))") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try Self.protect(temporary)
            try handle.write(contentsOf: contents)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("Could not write the tailnet lock state file (code \((error as NSError).code))")
        }
        guard rename(temporary.path, fileURL.path) == 0 else {
            let code = errno
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("Could not replace the tailnet lock state file (errno \(code))")
        }
    }

    /// Deletes the file. Does nothing if absent. Called only for a matching disablement secret (behavior T5) or for user-selected deletion
    /// (`ControlClient.removeTailnetLockState(inDirectory:)`).
    func remove() throws(ControlError) {
        do {
            try FileManager.default.removeItem(at: fileURL)
        } catch CocoaError.fileNoSuchFile {
            return
        } catch {
            throw .storage("Could not delete the tailnet lock state file (code \((error as NSError).code))")
        }
    }

    /// The same protection class and backup exclusion as the identity file (`docs/contracts/SwiftailTunnel.md` behavior P §2). Meaningful only on iOS.
    private static func protect(_ file: URL) throws {
        #if os(iOS)
        try FileManager.default.setAttributes(
            [.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: file.path
        )
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        var file = file
        try file.setResourceValues(values)
        #endif
    }
}

extension ControlClient {
    /// Deletes only the tailnet lock state file from the state directory (contract §5 TL-11b item 4). Does nothing if the file is absent.
    ///
    /// Resolves `TailnetLockStatus.issue` when it is `.unreadableStoredState` or `.storedStateDiverged`. Both require manual resolution.
    /// Deletes only this file because removing the entire state directory also loses the NL key and requires a new signature from the signing device.
    ///
    /// After deletion, the next startup establishes trust in signing authority state from scratch using the server's checkpoint (TOFU). The previously verified state
    /// previously constrained what the server could change. The app may call this method only as an explicit user decision.
    /// Call while the node is stopped, after `ControlClient.run()` using this directory has ended. A running client continues filtering with in-memory
    /// state and rewrites the file when that state changes.
    ///
    /// - Parameter directory: The state directory passed to `NodeIdentityStore(directory:)`.
    /// - Throws: `ControlError.storage` if the file could not be deleted.
    public static func removeTailnetLockState(inDirectory directory: URL) throws(ControlError) {
        try TailnetLockStore(directory: directory).remove()
    }
}
