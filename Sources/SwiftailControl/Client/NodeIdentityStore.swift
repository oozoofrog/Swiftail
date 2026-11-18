import CryptoKit
import Foundation
import SwiftailBase

/// Stores the identity in one file (`identity.json`) in the directory. This is the only state needed to restart as the same node.
///
/// The file is JSON, and its keys use the same text format as Go. The machine and node keys are `privkey:` + 64 hexadecimal digits. The NL key is `nlpriv:` +
/// 128 hexadecimal digits (32-byte Ed25519 seed ‖ 32-byte public key).
///
/// ```json
/// {"MachineKey":"privkey:…","NodeKey":"privkey:…","NLKey":"nlpriv:…"}
/// ```
///
/// Also reads legacy files without `NLKey` (before tailnet lock). In that case, adds a fresh NL key to the same machine and node keys (`loadOrCreate()` saves it before the first
/// request). Treats a mismatch between the last 32 bytes of `NLKey` and the public key derived from the seed as corruption (Go does not check this).
/// `docs/contracts/SwiftailTailnetLock.md` behavior R1.
///
/// The file contains private keys, so create it readable only by the owner (0600). Write it fully to a temporary file in the same directory and rename it to replace the file
/// atomically. An interrupted write leaves the previous identity intact. Error messages omit paths and keys.
/// `docs/contracts/SwiftailControl.md` unit 4 behavior 7.
///
/// Reads only regular files up to 64KiB and does not follow symbolic links (`StateFile`). Skips checking directory ownership and
/// permissions. The app must supply a directory other users cannot write to (`NodeConfiguration.stateDirectory`).
///
/// On iOS, applies the `completeUntilFirstUserAuthentication` data protection class and backup exclusion to the temporary file before writing. The packet tunnel
/// extension starts even with the screen locked (`complete` makes startup fail), so it must be able to read after the first unlock. Restoring a private key on another device would
/// create two devices with the same machine key. Assumes both attributes stay on the file across a rename (to be verified at the
/// real device gate). `docs/contracts/SwiftailTunnel.md` behavior P §2.
public struct NodeIdentityStore: Sendable {
    static let fileName = "identity.json"
    /// The input file size limit. The identity file is about 300 bytes.
    static let maximumFileSize = 64 * 1_024
    private static let keyPrefix = "privkey:"
    private static let lockKeyPrefix = "nlpriv:"

    private let directory: URL

    public init(directory: URL) {
        self.directory = directory
    }

    var fileURL: URL { directory.appending(path: Self.fileName, directoryHint: .notDirectory) }

    /// Reads the stored identity. Returns nil if the file is absent.
    ///
    /// For a legacy file without `NLKey`, adds a fresh NL key to the returned identity without saving it. Save that key before registration (`loadOrCreate()`).
    public func load() throws(ControlError) -> NodeIdentity? {
        try read()?.identity
    }

    /// Used when the control client starts. If the file is absent, creates, stores, and returns a fresh identity. For a legacy file without `NLKey`, creates, stores, and returns a fresh NL key in the identity.
    ///
    /// Save before the first request. Registering with an unsaved NL key would send a different key after restart (behavior R1). Save the machine key before registration too
    /// so the node appears as the same device after restart.
    func loadOrCreate() throws(ControlError) -> NodeIdentity {
        guard let stored = try read() else {
            let identity = NodeIdentity()
            try save(identity)
            return identity
        }
        if !stored.hasLockKey { try save(stored.identity) }
        return stored.identity
    }

    /// Reads the file and returns the identity and whether the file had an NL key. Returns nil if the file is absent.
    private func read() throws(ControlError) -> (identity: NodeIdentity, hasLockKey: Bool)? {
        guard let data = try StateFile.read(fileURL, limit: Self.maximumFileSize, label: "identity file") else { return nil }
        guard let file = try? JSONDecoder().decode(IdentityFile.self, from: data),
              let machineKey = Self.privateKey(file.machineKey)
        else { throw .storage("Identity file is corrupted") }
        var nodeKey: Curve25519.KeyAgreement.PrivateKey?
        if let text = file.nodeKey {
            guard let key = Self.privateKey(text) else { throw .storage("Identity file is corrupted") }
            nodeKey = key
        }
        guard let text = file.lockKey else {
            return (NodeIdentity(machineKey: machineKey, nodeKey: nodeKey), false)
        }
        guard let lockKey = Self.lockKey(text) else { throw .storage("NL key in the identity file is corrupted") }
        return (NodeIdentity(machineKey: machineKey, nodeKey: nodeKey, lockKey: lockKey), true)
    }

    /// Stores the identity atomically. Creates the directory as owner-only (0700) if absent.
    public func save(_ identity: NodeIdentity) throws(ControlError) {
        let file = IdentityFile(
            machineKey: Self.text(identity.machineKey),
            nodeKey: identity.nodeKey.map(Self.text),
            lockKey: Self.text(identity.lockKey)
        )
        let data: Data
        do {
            data = try JSONEncoder().encode(file)
            try FileManager.default.createDirectory(
                at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]
            )
        } catch {
            throw .storage("Could not prepare the identity directory (code \((error as NSError).code))")
        }

        let temporary = directory.appending(path: ".\(Self.fileName).\(UUID().uuidString)", directoryHint: .notDirectory)
        // Foundation file writing changes permissions after writing. To keep private keys unreadable by others even briefly,
        // use POSIX only for open(2), which creates the file as 0600 from the start, and rename(2), which renames it atomically.
        let descriptor = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw .storage("Could not create a temporary identity file (errno \(errno))") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        do {
            try Self.protect(temporary)
            try handle.write(contentsOf: data)
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("Could not write the identity file (code \((error as NSError).code))")
        }
        guard rename(temporary.path, fileURL.path) == 0 else {
            let code = errno
            try? FileManager.default.removeItem(at: temporary)
            throw .storage("Could not replace the identity file (errno \(code))")
        }
    }

    /// The protection class and backup exclusion for the identity file. Meaningful only on iOS (macOS uses a different data protection system, and the app handles backup exclusion).
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

    private static func text(_ key: Curve25519.KeyAgreement.PrivateKey) -> String {
        keyPrefix + [UInt8](key.rawRepresentation).hex
    }

    private static func privateKey(_ text: String) -> Curve25519.KeyAgreement.PrivateKey? {
        guard text.hasPrefix(keyPrefix),
              let bytes = [UInt8](hex: String(text.dropFirst(keyPrefix.count))),
              bytes.count == 32
        else { return nil }
        return try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes)
    }

    /// `nlpriv:` + hexadecimal seed ‖ public key (Go `NLPrivate.MarshalText`).
    static func text(_ key: Curve25519.Signing.PrivateKey) -> String {
        lockKeyPrefix + ([UInt8](key.rawRepresentation) + [UInt8](key.publicKey.rawRepresentation)).hex
    }

    /// Reads `nlpriv:` + 128 hexadecimal digits (uppercase or lowercase). Returns nil if the last 32 bytes differ from the public key derived from the first 32 bytes (the seed) (behavior R1).
    /// Compares public values, so constant-time comparison is unnecessary.
    static func lockKey(_ text: String) -> Curve25519.Signing.PrivateKey? {
        guard text.hasPrefix(lockKeyPrefix),
              let bytes = [UInt8](hex: String(text.dropFirst(lockKeyPrefix.count))),
              bytes.count == 64,
              let key = try? Curve25519.Signing.PrivateKey(rawRepresentation: bytes[..<32]),
              [UInt8](key.publicKey.rawRepresentation) == Array(bytes[32...])
        else { return nil }
        return key
    }
}

/// The JSON shape of the identity file.
private struct IdentityFile: Codable {
    var machineKey: String
    var nodeKey: String?
    /// Absent from legacy files.
    var lockKey: String?

    enum CodingKeys: String, CodingKey {
        case machineKey = "MachineKey"
        case nodeKey = "NodeKey"
        case lockKey = "NLKey"
    }
}
