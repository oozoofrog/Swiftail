// 자리·이름·쓰는 차례는 Go `feature/acme/certstore.go`(certDir, ACMEKey, Read, WriteTLSCertAndKey, keyFile, certFile)와
// `atomicfile/atomicfile.go`(tailscale.com v1.104.6, BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를 따랐다.
// 코드는 옮기지 않았다.

import CryptoKit
import Foundation

/// 저장소가 일을 하지 못한 까닭. `CertificateManager`는 `CertificateError`의 같은 이름 case로 옮긴다.
enum CertificateStoreError: Error, Sendable, Equatable {
    /// `certs/`를 만들거나 열거나 쓰거나 읽지 못했다. 이미 있는 `certs/`가 다른 사용자의 것이거나 그룹·기타가 쓸 수
    /// 있는 것도 여기다(동작 S1, H20). 메시지에는 까닭과 오류 코드만 담는다(경로·이름·키를 넣지 않는다. 동작 K3).
    case storage(String)
    /// `acme-account.key.pem`이 있지만 P-256 키로 읽지 못했다(RSA, 깨짐, 64KiB 초과). 덮어쓰지 않는다(동작 C4, H16).
    case accountKeyUnreadable
}

/// 노드 상태 디렉터리 아래 `certs/`의 파일: 인증서 사슬, 인증서 키, ACME 계정 키(계약 동작 S1~S3·C4, H7·H20).
///
/// 자리와 이름은 Go와 같다: `certs/<이름>.crt`(사슬, `CERTIFICATE` PEM을 leaf부터), `certs/<이름>.key`(개인 키 PEM),
/// `certs/acme-account.key.pem`. Go가 받아 둔 파일을 복사만으로 쓰고(동작 G6), Go도 Swiftail이 쓴 파일을 읽는다.
///
/// 디렉터리: 새 `certs/`는 0700이다. 이미 있으면 권한을 고치지 않지만, 디렉터리가 아니거나(심볼릭 링크 포함), 지금
/// 사용자의 것이 아니거나, 그룹·기타가 쓸 수 있으면 읽지도 쓰지도 않고 `storage`로 실패한다. 남이 바꿔 넣을 수 있는
/// 키를 TLS 신원으로 내지 않기 위해서다(H20).
///
/// 파일: 새로 쓰는 파일은 모두 0600이다(Go는 인증서를 0644로 쓴다. 동작 S2). 같은 디렉터리의 임시 파일에 다 쓰고
/// 권한을 정하고 디스크에 내린 뒤 이름을 바꾼다. 읽을 때는 심볼릭 링크를 따라가지 않고 정규 파일만 64KiB까지 읽는다.
///
/// 한 `certs/`를 두 관리자나 두 프로세스가 함께 쓰는 것은 막지 못한다(Go도 프로세스 사이 잠금이 없다. 동작 C9).
///
/// 판단(형식, 키 짝, 검증, 권한)은 값 함수(`decodeAccountKey`, `decodeCertificate`, `directoryProblem`)가 하고,
/// 파일 입출력은 이 타입의 `private` 가장자리 함수에만 있다. POSIX 호출은 디렉터리 기술자에 묶은 `openat`·
/// `renameatx_np` 같은 것만 쓴다: 확인한 `certs/` 밖으로 경로가 새지 않게 하고, 처음부터 0600으로 만들고, 계정 키를
/// 덮어쓰지 않는 것(`RENAME_EXCL`)을 Foundation의 파일 API로는 할 수 없기 때문이다.
struct CertificateStore: Sendable {
    /// 상태 디렉터리 아래의 인증서 디렉터리 이름(`feature/acme/certstore.go` `certDir`).
    static let directoryName = "certs"
    /// ACME 계정 키 파일의 이름(`certstore.go` `acmePEMName`).
    static let accountKeyFileName = "acme-account.key.pem"
    /// 디스크의 인증서·키 파일 하나의 한도(동작 M).
    static let maximumFileByteCount = 64 * 1024

    /// 노드의 상태 디렉터리. 이미 있어야 한다(노드가 신원을 저장한 자리다). 없으면 쓰기는 `storage`, 읽기는 "없음"이다.
    let stateDirectory: URL

    init(stateDirectory: URL) {
        self.stateDirectory = stateDirectory
    }

    // MARK: - 계정 키(동작 C4)

    /// 저장된 ACME 계정 키. 파일이 없을 때만 nil이다.
    ///
    /// - Throws: 파일이 있는데 P-256 키로 읽지 못하면 `accountKeyUnreadable`, 그 밖의 읽기 오류는 `storage`.
    func accountKey() throws(CertificateStoreError) -> P256.Signing.PrivateKey? {
        guard let directory = try openDirectory(creating: false) else { return nil }
        defer { close(directory) }
        return try Self.decodeAccountKey(Self.read(Self.accountKeyFileName, in: directory))
    }

    /// 새 계정 키를 저장한다. 이미 파일이 있으면 덮어쓰지 않고 `storage`로 실패한다(Go가 쓰던 계정을 잃지 않게).
    func saveAccountKey(_ key: P256.Signing.PrivateKey) throws(CertificateStoreError) {
        guard let directory = try openDirectory(creating: true) else { throw .storage("상태 디렉터리가 없다") }
        defer { close(directory) }
        try Self.write(Array(key.pemRepresentation.utf8), as: Self.accountKeyFileName, in: directory, replacing: false)
    }

    // MARK: - 인증서(동작 S2·S3)

    /// 저장된 인증서를 읽어 검증한다(동작 S3). 파일이 없거나, 64KiB를 넘거나, 해석되지 않거나, 키와 짝이 맞지 않거나,
    /// 검증을 통과하지 못하면 nil이다(지우지 않는다. 새 발급이 덮어쓴다).
    ///
    /// - Throws: 디렉터리의 권한(H20)이나 없음 밖의 읽기 오류(심볼릭 링크, 정규 파일이 아님 포함)는 `storage`.
    func certificate(
        for domain: CertificateDomain, at now: Date, anchors: CertificateTrustAnchors
    ) throws(CertificateStoreError) -> VerifiedCertificate? {
        guard let directory = try openDirectory(creating: false) else { return nil }
        defer { close(directory) }
        let chain = try Self.read(Self.certificateFileName(domain), in: directory)
        let key = try Self.read(Self.keyFileName(domain), in: directory)
        return Self.decodeCertificate(key: key, chain: chain, domain: domain, at: now, anchors: anchors)
    }

    /// 검증을 통과한 인증서를 쓴다: 키 파일, 그다음 인증서 파일(Go와 같은 차례. 동작 S2).
    ///
    /// 두 파일의 쓰기는 한 트랜잭션이 아니다. 둘 사이에 멈추면 새 키와 옛 인증서가 남고, 다음 읽기의 키 짝 확인이
    /// 그것을 "없음"으로 본다.
    func save(_ certificate: VerifiedCertificate) throws(CertificateStoreError) {
        guard let directory = try openDirectory(creating: true) else { throw .storage("상태 디렉터리가 없다") }
        defer { close(directory) }
        let files = Self.encode(certificate)
        let domain = certificate.lifetime.domain
        try Self.write(files.key, as: Self.keyFileName(domain), in: directory, replacing: true)
        try Self.write(files.chain, as: Self.certificateFileName(domain), in: directory, replacing: true)
    }

    // MARK: - 파일 이름과 형식(값 함수)

    /// `<이름>.crt`. 이름 검사(동작 C2)를 통과한 이름이라 경로 문자가 없다. Go의 `wildcard_` 치환은 와일드카드를
    /// 받지 않으므로 필요 없다.
    static func certificateFileName(_ domain: CertificateDomain) -> String { domain.name + ".crt" }

    /// `<이름>.key`.
    static func keyFileName(_ domain: CertificateDomain) -> String { domain.name + ".key" }

    /// 파일 하나를 읽은 결과.
    enum StoredFile: Sendable, Equatable {
        case missing
        /// 한도(64KiB)를 넘는다. 내용은 읽지 않았다.
        case tooLarge
        case contents([UInt8])
    }

    /// 계정 키 파일을 해석한다. 없을 때만 nil이고, 있는데 읽지 못하면(크기 초과 포함) `accountKeyUnreadable`.
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

    /// 인증서 파일과 키 파일을 해석하고 검증한다(동작 S3 ①~⑤). 어느 하나라도 어긋나면 nil(없는 것으로 본다).
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

    /// 쓸 두 파일의 바이트: 키는 CryptoKit의 PKCS#8 PEM(Go가 읽는다. 노트 4.6), 사슬은 받은 그대로를 블록마다 PEM으로
    /// 다시 적은 것(Go `feature/acme/cert.go:600-609`와 같다. 동작 S6).
    static func encode(_ certificate: VerifiedCertificate) -> (key: [UInt8], chain: [UInt8]) {
        let chain = certificate.receivedChain.map { PEM.encode(PEMBlock(label: .certificate, der: $0)) }.joined()
        return (Array(certificate.privateKey.pemRepresentation.utf8), Array(chain.utf8))
    }

    /// 이미 있는 `certs/`를 쓰면 안 되는 까닭. 써도 되면 nil(동작 S1, H20).
    static func directoryProblem(mode: mode_t, owner: uid_t, currentUser: uid_t) -> String? {
        if mode & S_IFMT != S_IFDIR { return "인증서 자리가 디렉터리가 아니다" }
        if owner != currentUser { return "인증서 디렉터리가 다른 사용자의 것이다" }
        if mode & (S_IWGRP | S_IWOTH) != 0 { return "인증서 디렉터리를 그룹이나 기타가 쓸 수 있다" }
        return nil
    }

    // MARK: - 가장자리: 파일 입출력

    /// `certs/`를 열어 검사한 디렉터리 기술자. 부르는 쪽이 닫는다.
    ///
    /// - Parameter creating: 없으면 0700으로 만든다(umask는 권한을 줄이기만 한다).
    /// - Returns: `creating`이 거짓인데 상태 디렉터리나 `certs/`가 없으면 nil. `creating`이 참이면 상태 디렉터리가
    ///   없을 때만 nil.
    private func openDirectory(creating: Bool) throws(CertificateStoreError) -> Int32? {
        let state = open(stateDirectory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard state >= 0 else {
            let code = errno
            if code == ENOENT { return nil }
            throw .storage("상태 디렉터리를 열지 못했다(errno \(code))")
        }
        defer { close(state) }
        if creating, mkdirat(state, Self.directoryName, 0o700) != 0, errno != EEXIST {
            throw .storage("인증서 디렉터리를 만들지 못했다(errno \(errno))")
        }
        // O_NOFOLLOW: `certs`가 심볼릭 링크면 따라가지 않고 실패한다(ELOOP).
        let directory = openat(state, Self.directoryName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard directory >= 0 else {
            let code = errno
            if code == ENOENT, !creating { return nil }
            throw .storage("인증서 디렉터리를 열지 못했다(errno \(code))")
        }
        var status = stat()
        guard fstat(directory, &status) == 0 else {
            let code = errno
            close(directory)
            throw .storage("인증서 디렉터리를 보지 못했다(errno \(code))")
        }
        if let problem = Self.directoryProblem(mode: status.st_mode, owner: status.st_uid, currentUser: geteuid()) {
            close(directory)
            throw .storage(problem)
        }
        return directory
    }

    /// `certs/` 안의 파일 하나를 읽는다. 없으면 `missing`, 한도를 넘으면 내용을 읽지 않고 `tooLarge`.
    private static func read(_ name: String, in directory: Int32) throws(CertificateStoreError) -> StoredFile {
        // O_NOFOLLOW: 심볼릭 링크는 따라가지 않는다. O_NONBLOCK: FIFO에서 막히지 않는다(정규 파일이 아니면 아래서 거절).
        let descriptor = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard descriptor >= 0 else {
            let code = errno
            if code == ENOENT { return .missing }
            throw .storage("인증서 파일을 열지 못했다(errno \(code))")
        }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        var status = stat()
        guard fstat(descriptor, &status) == 0 else { throw .storage("인증서 파일을 보지 못했다(errno \(errno))") }
        guard status.st_mode & S_IFMT == S_IFREG else { throw .storage("인증서 파일이 정규 파일이 아니다") }
        guard status.st_size <= maximumFileByteCount else { return .tooLarge }
        do {
            // 크기를 본 뒤에 파일이 자랐을 수도 있으므로 한도보다 한 바이트 더 읽어 본다.
            let data = try handle.read(upToCount: maximumFileByteCount + 1) ?? Data()
            return data.count <= maximumFileByteCount ? .contents(Array(data)) : .tooLarge
        } catch {
            throw .storage("인증서 파일을 읽지 못했다(코드 \((error as NSError).code))")
        }
    }

    /// `certs/` 안에 파일 하나를 원자적으로 쓴다: 임시 파일(0600) → 쓰기 → `fsync` → 닫기 → 이름 바꾸기
    /// (Go `atomicfile.WriteFile`과 같은 차례).
    ///
    /// - Parameter replacing: 거짓이면 이미 있는 파일을 덮어쓰지 않는다(`RENAME_EXCL`, 실패하면 `storage`).
    ///   참이면 같은 이름의 항목을 바꾼다. 그 항목이 심볼릭 링크면 링크 자체가 바뀌고 가리키던 곳은 건드리지 않는다.
    private static func write(
        _ bytes: [UInt8], as name: String, in directory: Int32, replacing: Bool
    ) throws(CertificateStoreError) {
        let temporary = ".\(name).\(UUID().uuidString).tmp"
        let descriptor = openat(directory, temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw .storage("임시 파일을 만들지 못했다(errno \(errno))") }
        let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
        // umask와 무관하게 정확히 0600으로 둔다(Go는 `Chmod(perm)`).
        guard fchmod(descriptor, 0o600) == 0 else {
            let code = errno
            try? handle.close()
            unlinkat(directory, temporary, 0)
            throw .storage("임시 파일의 권한을 정하지 못했다(errno \(code))")
        }
        do {
            try handle.write(contentsOf: Data(bytes))
            try handle.synchronize()
            try handle.close()
        } catch {
            try? handle.close()
            unlinkat(directory, temporary, 0)
            throw .storage("파일을 쓰지 못했다(코드 \((error as NSError).code))")
        }
        guard renameatx_np(directory, temporary, directory, name, replacing ? 0 : UInt32(RENAME_EXCL)) == 0 else {
            let code = errno
            unlinkat(directory, temporary, 0)
            throw .storage("파일 이름을 바꾸지 못했다(errno \(code))")
        }
    }
}
