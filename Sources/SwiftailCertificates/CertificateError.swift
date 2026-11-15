/// `CertificateManager`가 더 돌 수 없는 실패. 다시 돌려도 소용없으므로 `run()`이 던진다(동작 R4).
///
/// 발급의 실패(ACME 서버의 거절, 연결 끊김, 조건)는 여기가 아니라 `CertificateStatus.lastFailure`에 적힌다.
public enum CertificateError: Error, Sendable, Equatable {
    /// 디렉터리 URL이 잘못되었다. `run()`을 두 번 부른 것도 여기다.
    case invalidConfiguration(String)
    /// `certs/`를 만들거나 쓰거나 읽지 못했다. 이미 있는 `certs/`를 그룹이나 기타가 쓸 수 있는 것도 여기다(동작 S1).
    /// 메시지에는 오류 코드만 담는다.
    case storage(String)
    /// `certs/acme-account.key.pem`이 있지만 P-256 계정 키로 읽지 못했다(Go가 남긴 RSA 키, 깨진 파일, 크기 초과).
    /// 덮어쓰지 않는다: 새 계정을 만들면 그 파일이 가리키던 계정을 잃는다(동작 C4).
    case accountKeyUnreadable
}

extension CertificateError {
    /// 저장소의 실패를 같은 이름의 case로 옮긴다.
    init(_ error: CertificateStoreError) {
        switch error {
        case .storage(let message): self = .storage(message)
        case .accountKeyUnreadable: self = .accountKeyUnreadable
        }
    }
}
