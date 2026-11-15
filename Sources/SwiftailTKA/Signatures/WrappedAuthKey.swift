// 서명된 인증 키(`<인증 키>--TL<A>-<B>`)의 해석과, 그것으로 새 node 키에 서명하기. 노트 3.8·4.6 2, 계약 동작 R3·R5②·K, 결정 L12·L13.
// 자르는 자리와 서명의 모양은 Go `tailscale.com` v1.104.7 `tka/sig.go:439-498`(`SignByCredential`·`DecodeWrappedAuthkey`)을 따른다.
//   Copyright (c) Tailscale Inc & contributors, SPDX-License-Identifier: BSD-3-Clause.

import CryptoKit
import SwiftailBase

/// `--TL`이 붙은 인증 키를 해석한 것. 감싼 개인 키를 쥐는 비밀이다.
///
/// 인증 키와 감싼 개인 키는 `description`·`dump`·`String(reflecting:)`에 나오지 않는다(동작 K2). 서버에는 `controlValue`만 보낸다.
package struct WrappedAuthKey: Sendable {
    /// 서버에 보낼 부분(첫 `--TL` 앞). 이것도 인증 키라 비밀이다.
    package let controlValue: String
    /// 서명 권한을 위임한 credential NKS(A). 신뢰 키인지는 여기서 보지 않는다(받는 쪽의 `authorize`가 본다).
    let credential: NodeKeySignature
    /// 위임받은 Ed25519 키(B의 앞 32바이트 시드).
    private let wrappingKey: Curve25519.Signing.PrivateKey

    /// 인증 키 문자열 전체의 한도와 감싼 개인 키의 길이(동작 M, R3).
    static let maximumByteCount = 16 * 1_024
    static let wrappedPrivateKeyByteCount = 64

    /// 인증 키를 해석한다(동작 R3). 첫 `--TL`에서 자르고, 그 뒤를 첫 `-`에서 잘라 A(credential)와 B(64바이트 개인 키)를 얻는다.
    ///
    /// Go는 디코딩이 실패하면 원문 전체(개인 키 포함)를 인증 키로 돌려주고, B가 64바이트가 아니면 서명할 때 panic하며, B의 뒤 32바이트를
    /// 확인하지 않는다(노트 3.8). Swiftail은 그 모두를 서버로 아무것도 보내기 전에 거절한다(결정 L12·L13).
    ///
    /// - Returns: `--TL`이 없으면 nil(평범한 인증 키).
    /// - Throws: `invalidAuthKey` — 문자열이 16KiB를 넘음, `-` 없음, A·B가 패딩 없는 표준 base64의 정규형이 아님, A가 8KiB를 넘거나
    ///   NKS로 읽히지 않거나 credential이 아니거나 `WrappingPubkey`가 32바이트가 아님, B가 64바이트가 아님, B의 시드로 만든 공개 키가
    ///   B의 뒤 32바이트나 A의 `WrappingPubkey`와 다름. 오류에 키 내용은 담지 않는다.
    package init?(parsing authKey: String) throws(TKAError) {
        let text = Array(authKey.utf8)
        guard let marker = text.firstRange(of: Array("--TL".utf8)) else { return nil }
        let suffix = text[marker.upperBound...]
        guard text.count <= Self.maximumByteCount,
            let dash = suffix.firstIndex(of: UInt8(ascii: "-")),
            let credentialBytes = Self.decodeRawBase64(suffix[..<dash]),
            let privateKey = Self.decodeRawBase64(suffix[(dash + 1)...]),
            let credential = try? NodeKeySignature(decoding: credentialBytes),
            credential.kind == NodeKeySignature.Kind.credential,
            credential.wrappingPublicKey.count == 32,
            privateKey.count == Self.wrappedPrivateKeyByteCount,
            let wrappingKey = try? Curve25519.Signing.PrivateKey(rawRepresentation: privateKey[..<32])
        else { throw .invalidAuthKey }
        let publicKey = Array(wrappingKey.publicKey.rawRepresentation)
        guard publicKey == Array(privateKey[32...]), publicKey == credential.wrappingPublicKey else { throw .invalidAuthKey }
        controlValue = String(decoding: text[..<marker.lowerBound], as: UTF8.self)
        self.credential = credential
        self.wrappingKey = wrappingKey
    }

    /// 새 node 키에 대한 서명(Go `SignByCredential`): rotation NKS{`Pubkey`: np ‖ node 키, `Nested`: credential}의 `SigHash`에
    /// 감싼 키로 서명한 정준 바이트. 등록 요청의 `NodeKeySignature`에 싣는다(동작 R5②).
    ///
    /// CryptoKit의 Ed25519 서명은 결정적이지 않아 부를 때마다 바이트가 다르다. 받는 쪽은 Go 표준 규칙으로 검증한다(노트 3.7).
    /// - Throws: `signingFailed` — CryptoKit이 서명하지 못했다.
    package func keySignature(for nodeKey: NodePublicKey) throws(TKAError) -> [UInt8] {
        var signature = NodeKeySignature(kind: NodeKeySignature.Kind.rotation, publicKey: nodeKey.binaryForm, nested: credential)
        try signature.sign(with: wrappingKey)
        return signature.serialized()
    }

    /// 패딩 없는 표준 base64(RFC 4648 4절, `+/`)의 정규형만 읽는다: 다른 글자·`=`·줄바꿈, 남는 6비트, 0이 아닌 남는 비트는 nil.
    /// Go `base64.RawStdEncoding`은 줄바꿈을 건너뛰고 남는 비트를 보지 않는다(동작 R3이 정규형만 받기로 했다).
    private static func decodeRawBase64(_ text: ArraySlice<UInt8>) -> [UInt8]? {
        var bytes: [UInt8] = []
        var buffer: UInt32 = 0
        var bitCount: UInt32 = 0
        for character in text {
            let value: UInt8
            switch character {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"): value = character - UInt8(ascii: "A")
            case UInt8(ascii: "a")...UInt8(ascii: "z"): value = character - UInt8(ascii: "a") + 26
            case UInt8(ascii: "0")...UInt8(ascii: "9"): value = character - UInt8(ascii: "0") + 52
            case UInt8(ascii: "+"): value = 62
            case UInt8(ascii: "/"): value = 63
            default: return nil
            }
            buffer = buffer << 6 | UInt32(value)
            bitCount += 6
            if bitCount >= 8 {
                bitCount -= 8
                bytes.append(UInt8(truncatingIfNeeded: buffer >> bitCount))
                buffer &= (1 << bitCount) - 1
            }
        }
        guard bitCount < 6, buffer == 0 else { return nil }
        return bytes
    }
}

extension WrappedAuthKey: CustomStringConvertible, CustomReflectable {
    /// 인증 키와 감싼 키를 가린다.
    package var description: String { "WrappedAuthKey(<가림>)" }

    /// `dump`는 `description`을 거치지 않으므로 자식을 비운다.
    package var customMirror: Mirror { Mirror(self, children: []) }
}

extension NodeKeySignature {
    /// `signatureHash`에 Ed25519로 서명해 `signature`를 채운다(Go `NLPrivate.SignNKS`, `ed25519.Sign`).
    ///
    /// - Throws: `signingFailed` — CryptoKit이 서명하지 못했다.
    mutating func sign(with key: Curve25519.Signing.PrivateKey) throws(TKAError) {
        do {
            signature = Array(try key.signature(for: signatureHash))
        } catch {
            throw .signingFailed
        }
    }
}
