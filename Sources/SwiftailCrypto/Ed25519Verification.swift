// Ed25519 서명 검증을 Go의 두 구현과 같은 판정으로 한다.
//
// 출처: 검증 절차는 `github.com/hdevalence/ed25519consensus` v0.2.0 `ed25519.go`의 `Verify`와
// Go 1.27.3 `crypto/internal/fips140/ed25519/ed25519.go`의 `verifyWithDom`을 따랐다.
// Copyright 2016 The Go Authors, Copyright 2016 Henry de Valence. BSD-3-Clause(전문은
// `Edwards25519/FieldElement.swift` 머리. ed25519consensus의 LICENSE는 3항의 이름(Google Inc.)과 저작권 줄만 다르다).

import CryptoKit

/// Ed25519 서명 검증. 서명을 만들지 않는다(비밀 값을 다루지 않는다).
///
/// Tailnet Lock은 서명마다 검증 규칙이 다르다. AUM 서명과 direct·credential `NodeKeySignature`는
/// ZIP-215 규칙으로, rotation `NodeKeySignature`의 바깥 서명은 Go 표준 규칙으로 검증한다
/// (`docs/protocol-notes/tailnet-lock.md` 3.7·6.1). 두 규칙 모두 Ed25519 순수 변형(문맥 없음)이다.
///
/// 두 규칙의 공통 부분:
/// - 서명은 64바이트(R ‖ S), 공개 키 A는 32바이트다. 아니면 거짓이다.
/// - `sig[63]`의 위 세 비트가 0이어야 한다.
/// - A와 R의 비정준 인코딩(y ≥ p, x = 0에 부호 비트)을 받아들인다. 곡선 위가 아닌 인코딩은 거절한다.
/// - S는 정준(S < L)이어야 한다.
/// - k = SHA-512(R ‖ A ‖ M) mod L. R과 A는 받은 바이트 그대로 해시한다.
///
/// 정직하게 만든 서명은 두 규칙에서 모두 참이다. 판정이 갈리는 것은 작은 위수 성분이나 비정준 인코딩이 든,
/// 일부러 만든 서명뿐이다.
public enum Ed25519Verification {
    /// ZIP-215 규칙(Go `github.com/hdevalence/ed25519consensus`의 `Verify`와 같은 판정).
    ///
    /// cofactor를 곱한 식 [8]([S]B − [k]A − R) = 0을 검사한다. 그래서 A나 R에 작은 위수 성분이 있어도
    /// 그 성분은 판정에 영향을 주지 않는다.
    public static func isValidZIP215(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard let input = Input(signature: signature, message: message, publicKey: publicKey),
              let r = EdwardsPoint(encoding: Array(signature[0..<32]))
        else { return false }
        return (input.computedR - r).multipliedByCofactor().isIdentity
    }

    /// Go 표준 라이브러리 `crypto/ed25519`의 `Verify`와 같은 판정.
    ///
    /// cofactor 없이 계산한 [S]B − [k]A의 정준 인코딩이 서명의 R 바이트와 같아야 한다. 그래서 R이 비정준
    /// 인코딩이거나 R에 작은 위수 성분이 더해진 서명은 거절한다. Go는 공개 키 길이가 틀리면 panic하지만
    /// 여기서는 거짓을 돌려준다.
    public static func isValidStandard(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) -> Bool {
        guard let input = Input(signature: signature, message: message, publicKey: publicKey) else { return false }
        return input.computedR.encoding == Array(signature[0..<32])
    }

    /// 두 규칙이 같이 쓰는 검사와 계산. 검사를 통과한 입력만 만들어진다.
    private struct Input {
        /// [S]B − [k]A. 올바른 서명이면 R(ZIP-215에서는 작은 위수 성분을 뺀 R)과 같다.
        let computedR: EdwardsPoint

        init?(signature: [UInt8], message: [UInt8], publicKey: [UInt8]) {
            guard signature.count == 64, publicKey.count == 32, signature[63] & 0b1110_0000 == 0,
                  let a = EdwardsPoint(encoding: publicKey),
                  let s = Scalar(canonicalBytes: Array(signature[32..<64]))
            else { return nil }
            var hash = SHA512()
            hash.update(data: signature[0..<32])
            hash.update(data: publicKey)
            hash.update(data: message)
            let k = Scalar(reducing: Array(hash.finalize()))
            computedR = EdwardsPoint.varTimeDoubleScalarBaseMultiply(k, -a, s)
        }
    }
}
