import CryptoKit

extension P256.Signing.PrivateKey {
    /// 키 파일(계정 키 `acme-account.key.pem`, 인증서 키 `<이름>.key`)의 PEM을 P-256 개인 키로 읽는다.
    ///
    /// 파일 전체가 `PRIVATE KEY`(PKCS#8, Swiftail과 CryptoKit이 쓴다) 또는 `EC PRIVATE KEY`(SEC1, Go가 쓴다.
    /// 노트 3.7) 블록 **하나**여야 한다. 블록 밖의 글, 블록 둘 이상, 다른 라벨, P-256이 아닌 키는 모두 거절한다.
    /// 거절된 계정 키를 "없음"으로 보지 않는 것은 부르는 쪽의 몫이다(계약 동작 C4).
    ///
    /// - Parameter maximumByteCount: 파일의 최대 바이트 수(계약 동작 M의 64KiB).
    init(pemFile input: [UInt8], maximumByteCount: Int) throws(PEMError) {
        let blocks = try PEM.decode(input, maximumByteCount: maximumByteCount)
        guard blocks.count == 1, let block = blocks.first else { throw .wrongBlockCount }
        guard block.label == .privateKey || block.label == .ecPrivateKey else { throw .unexpectedLabel }
        do {
            // CryptoKit의 DER 읽기는 PKCS#8과 SEC1을 모두 받는다(시험 `PrivateKeyPEMTests`가 둘을 고정한다).
            try self.init(derRepresentation: block.der)
        } catch {
            throw .malformed
        }
    }
}
