// The location, names, and write order follow Go's `feature/acme/certstore.go` (certDir, ACMEKey, Read, WriteTLSCertAndKey, keyFile, certFile) and
// `atomicfile/atomicfile.go` (tailscale.com v1.104.6, BSD-3-Clause, Copyright (c) Tailscale Inc & contributors).
// No code was ported.

import CryptoKit
import Foundation

/// A storage failure. `CertificateManager` maps it to the same-named `CertificateError` case.
enum CertificateStoreError: Error, Sendable, Equatable {
    /// Failed to create, open, write, or read `certs/`. Also covers an existing certs/ owned by another user or writable by the group or others
    /// (behavior S1, H20). The message includes the reason and, when available, an error code. It omits paths, names, and keys (behavior K3).
    case storage(String)
    /// `acme-account.key.pem` exists but could not be read as a P-256 key (RSA, corrupt, or over 64KiB). It is kept as is (behavior C4, H16).
    case accountKeyUnreadable
}

/// Files in `certs/` under the node's state directory: the certificate chain, certificate key, and ACME account key (contract behaviors S1–S3 and C4, H7 and H20).
///
/// Locations and names match Go: `certs/<name>.crt` (chain, `CERTIFICATE` PEM with leaf first), `certs/<name>.key` (private key PEM),
/// and `certs/acme-account.key.pem`. Go files work after copying alone (behavior G6), and Go can read Swiftail's files.
///
/// New `certs/` directories have mode 0700. Existing permissions are kept. If the path is not a directory (including symlinks), is owned
/// by someone other than the current user, or is writable by the group or others, reading and writing fail with `storage`. This keeps
/// a key that someone else could substitute from being served as the TLS identity (H20).
///
/// All newly written files have mode 0600 (Go writes certificates with 0644, behavior S2). Write everything to a temporary file in the same
/// directory, set permissions, flush it to disk, and rename it. Reads never follow symlinks and accept only regular files up to 64KiB.
///
/// Two managers or processes can still share one `certs/` (Go also lacks cross-process locking, behavior C9).
///
/// Value functions make decisions about format, key matching, verification, and permissions (`decodeAccountKey`, `decodeCertificate`, `directoryProblem`).
/// File I/O lives only in this type's `private` edge functions. It uses only POSIX calls bound to the directory descriptor, such as `openat` and
/// `renameatx_np`. Foundation file APIs cannot confine paths to the verified `certs/`, create files with mode 0600 from the outset, or avoid
/// overwriting the account key (`RENAME_EXCL`).
struct CertificateStore: Sendable {
    /// The certificate directory name under the state directory (`certDir` in `feature/acme/certstore.go`).
    static let directoryName = "certs"
    /// The ACME account key file name (`acmePEMName` in `certstore.go`).
    static let accountKeyFileName = "acme-account.key.pem"
    /// The size limit for one certificate or key file on disk (behavior M).
    static let maximumFileByteCount = 64 * 1024

    /// The node's state directory. It must already exist as the place where the node stored its identity. If absent, writes fail with `storage` and reads report absence.
    let stateDirectory: URL

    init(stateDirectory: URL) {
        self.stateDirectory = stateDirectory
    }

    // MARK: - Account Key (behavior C4)

    /// The stored ACME account key. Returns nil only when the file is absent.
    ///
    /// - Throws: `accountKeyUnreadable` if the file exists but cannot be read as a P-256 key, or `storage` for other read errors.
    func accountKey() throws(CertificateStoreError) -> P256.Signing.PrivateKey? {
        guard let directory = try openDirectory(creating: false) else { return nil }
        defer { close(directory) }
        return try Self.decodeAccountKey(Self.read(Self.accountKeyFileName, in: directory))
    }

    /// Stores a new account key. Fails with `storage` if the file already exists, preserving the account that Go used.
    func saveAccountKey(_ key: P256.Signing.PrivateKey) throws(CertificateStoreError) {
        guard let directory = try openDirectory(creating: true) else { throw .storage("The state directory is missing") }
        defer { close(directory) }
        try Self.write(Array(key.pemRepresentation.utf8), as: Self.accountKeyFileName, in: directory, replacing: false)
    }

    // MARK: - Certificates (behaviors S2 and S3)

    /// Reads and verifies a stored certificate (behavior S3). Returns nil for a missing file, more than 64KiB, invalid encoding, a key mismatch,
    /// or verification failure. The files stay in place for new issuance to overwrite.
    ///
    /// - Throws: `storage` for directory permission failures (H20) or read errors other than absence, including symlinks and non-regular files.
    func certificate(
        for domain: CertificateDomain, at now: Date, anchors: CertificateTrustAnchors
    ) throws(CertificateStoreError) -> VerifiedCertificate? {
        guard let directory = try openDirectory(creating: false) else { return nil }
        defer { close(directory) }
        let chain = try Self.read(Self.certificateFileName(domain), in: directory)
        let key = try Self.read(Self.keyFileName(domain), in: directory)
        return Self.decodeCertificate(key: key, chain: chain, domain: domain, at: now, anchors: anchors)
    }

    /// Writes a verified certificate. Writes the key file first, then the certificate file (same order as Go, behavior S2).
    ///
    /// The two writes occur outside a single transaction. Stopping between them leaves the new key and old certificate. The next read's key-match check
    /// treats the pair as absent.
    func save(_ certificate: VerifiedCertificate) throws(CertificateStoreError) {
        guard let directory = try openDirectory(creating: true) else { throw .storage("The state directory is missing") }
        defer { close(directory) }
        let files = Self.encode(certificate)
        let domain = certificate.lifetime.domain
        try Self.write(files.key, as: Self.keyFileName(domain), in: directory, replacing: true)
        try Self.write(files.chain, as: Self.certificateFileName(domain), in: directory, replacing: true)
    }

    // MARK: - File Names and Formats (Value Functions)

    /// `<name>.crt`. The name passed validation (behavior C2), so it contains no path characters. Go's `wildcard_` substitution is unnecessary
    /// because wildcards are not accepted.
    static func certificateFileName(_ domain: CertificateDomain) -> String { domain.name + ".crt" }

    /// `<name>.key`.
    static func keyFileName(_ domain: CertificateDomain) -> String { domain.name + ".key" }

    /// The result of reading one file.
    enum StoredFile: Sendable, Equatable {
        case missing
        /// The file exceeds the limit (64KiB). Its contents were not read.
        case tooLarge
        case contents([UInt8])
    }

    /// Parses an account key file. Returns nil only for absence and reports `accountKeyUnreadable` if unreadable, including oversized files.
    static func decodeAccountKey(_ file: StoredFile) throws(CertificateStoreError) -> P256.Signing.PrivateKey? {
        switch file {
        case .missing:
            return nil
        case .tooLarge:
            throw .accountKeyUnreadable
        case .contents(let bytes):
            do {
                return try P256.Signing.PrivateKey(pemFile: bytes, maximumByteCount: maximumFileByteCount)
            } catch {
                throw .accountKeyUnreadable
            }
        }
    }

    /// Parses and verifies the certificate and key files (behavior S3 ①–⑤). Returns nil if any check fails (treats the files as absent).
    static func decodeCertificate(
        key: StoredFile, chain: StoredFile, domain: CertificateDomain, at now: Date, anchors: CertificateTrustAnchors
    ) -> VerifiedCertificate? {
        guard case .contents(let keyBytes) = key, case .contents(let chainBytes) = chain,
              let privateKey = try? P256.Signing.PrivateKey(pemFile: keyBytes, maximumByteCount: maximumFileByteCount)
        else { return nil }
        return try? VerifiedCertificate(
            pemChain: chainBytes, maximumByteCount: maximumFileByteCount,
            privateKey: privateKey, domain: domain, at: now, anchors: anchors
        )
    }

    /// The bytes for the two files. The key is CryptoKit's PKCS#8 PEM (Go can read it, notes §4.6). The chain is the original chain reencoded
    /// block by block as PEM (same as Go `feature/acme/cert.go:600-609`, behavior S6).
    static func encode(_ certificate: VerifiedCertificate) -> (key: [UInt8], chain: [UInt8]) {
        let chain = certificate.receivedChain.map { PEM.encode(PEMBlock(label: .certificate, der: $0)) }.joined()
        return (Array(certificate.privateKey.pemRepresentation.utf8), Array(chain.utf8))
    }

    /// The reason an existing `certs/` is unusable, or nil if usable (behavior S1, H20).
    static func directoryProblem(mode: mode_t, owner: uid_t, currentUser: uid_t) -> String? {
        if mode & S_IFMT != S_IFDIR { return "The certificate path is not a directory" }
        if owner != currentUser { return "The certificate directory belongs to another user" }
        if mode & (S_IWGRP | S_IWOTH) != 0 { return "The certificate directory is writable by the group or others" }
        return nil
    }

    // MARK: - Edge File I/O

    /// Opens `certs/`, checks it, and returns its directory descriptor. The caller closes it.
    ///
    /// - Parameter creating: Creates a missing directory with mode 0700 (umask can only restrict permissions).
    /// - Returns: nil if `creating` is false and the state directory or `certs/` is missing. If creating is true, returns nil only when the state
    ///   directory is missing.
    private func openDirectory(creating: Bool) throws(CertificateStoreError) -> Int32? {
        let state = open(stateDirectory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard state >= 0 else {
            let code = errno
            if code == ENOENT { return nil }
            throw .storage("Could not open the state directory (errno \(code))")
        }
        defer { close(state) }
        if creating, mkdirat(state, Self.directoryName, 0o700) != 0, errno != EEXIST {
            throw .storage("Could not create the certificate directory (errno \(errno))")
        }
        // O_NOFOLLOW: Fail with ELOOP if `certs` is a symlink, without following it.
        let directory = openat(state, Self.directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else {
            let code = errno
            if code == ENOENT, !creating { return nil }
            throw .storage("Could not open the certificate directory (errno \(code))")
        }
        var status = stat()
        guard fstat(directory, &status) == 0 else {
            let code = errno
            close(directory)
            throw .storage("Could not inspect the certificate directory (errno \(code))")
        }
        if let problem = Self.directoryProblem(mode: status.st_mode, owner: status.st_uid, currentUser: geteuid()) {
            close(directory)
            throw .storage(problem)
        }
        return directory
    }

    /// Reads one file in `certs/`. Returns `missing` if absent or `tooLarge` without reading contents if it exceeds the limit.
    private static func read(_ name: String, in directory: Int32) throws(CertificateStoreError) -> StoredFile {
        // O_NOFOLLOW prevents following symlinks. O_NONBLOCK prevents blocking on a FIFO (non-regular files are rejected below).
        let descriptor = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            let code = errno
            if code == ENOENT { return .missing }
            throw .storage("Could not open the certificate file (errno \(code))")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var status = stat()
        guard fstat(descriptor, &status) == 0 else { throw .storage("Could not inspect the certificate file (errno \(errno))") }
        guard status.st_mode & S_IFMT == S_IFREG else { throw .storage("The certificate file is not a regular file") }
        guard status.st_size <= maximumFileByteCount else { return .tooLarge }
        do {
            // Read one byte beyond the limit in case the file grew after checking its size.
            let data = try handle.read(upToCount: maximumFileByteCount + 1) ?? Data()
            return data.count <= maximumFileByteCount ? .contents(Array(data)) : .tooLarge
        } catch {
            throw .storage("Could not read the certificate file (code \((error as NSError).code))")
        }
    }

    /// Writes one file atomically in `certs/`. Create a temporary file (0600) → write → `fsync` → close → rename
    /// (same order as Go's `atomicfile.WriteFile`).
    ///
    /// - Parameter replacing: If false, preserves any existing file (`RENAME_EXCL`, `storage` on failure).
    ///   If true, replaces the entry with the same name. If the entry is a symlink, replaces the link itself without touching its target.
    private static func write(
        _ bytes: [UInt8], as name: String, in directory: Int32, replacing: Bool
    ) throws(CertificateStoreError) {
        let temporary = ".\(name).\(UUID().uuidString).tmp"
        let descriptor = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw .storage("Could not create the temporary file (errno \(errno))") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        // Set exactly 0600 regardless of umask (Go uses `Chmod(perm)`).
        guard fchmod(descriptor, 0o600) == 0 else {
            let code = errno
            try? handle.close()
            unlinkat(directory, temporary, 0)
            throw .storage("Could not set the temporary file permissions (errno \(code))")
        }
        do {
            try handle.write(contentsOf: Data(bytes))
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            unlinkat(directory, temporary, 0)
            throw .storage("Could not write the file (code \((error as NSError).code))")
        }
        guard renameatx_np(directory, temporary, directory, name, replacing ? 0 : UInt32(RENAME_EXCL)) == 0 else {
            let code = errno
            unlinkat(directory, temporary, 0)
            throw .storage("Could not rename the file (errno \(code))")
        }
    }
}
