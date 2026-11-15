import CryptoKit
import SwiftailBase

/// tailnet lock 키(NL 키)의 공개 키. 와이어(JSON)의 텍스트는 `"nlpub:" + 16진 64자리`다.
///
/// 노드는 자기 NL 키의 공개 키를 등록 요청의 `NLKey`에 늘 싣는다. 서명 기기는 이 키를 신뢰 키로 더하거나, 이 노드의 node 키
/// 서명에 `WrappingPubkey`로 넣어 이 노드가 키를 바꿀 때 스스로 다시 서명하게 한다.
/// `docs/protocol-notes/tailnet-lock.md` 3.8·3.9·4.6 1 (출처: tailscale.com `types/key/nl.go`, BSD-3-Clause).
public enum NLKeyKind: KeyKind { public static let prefix = "nlpub:" }

public typealias NLPublicKey = PrefixedKey<NLKeyKind>

extension PrefixedKey where Kind == NLKeyKind {
    /// CryptoKit의 Ed25519 공개 키를 NL 공개 키로 바꾼다.
    public init(_ key: Curve25519.Signing.PublicKey) {
        // Ed25519 공개 키의 원시 표현은 늘 32바이트다. 실패하면 CryptoKit의 계약이 깨진 것이다.
        guard let value = Self(rawValue: key.rawRepresentation) else {
            preconditionFailure("Ed25519 공개 키는 32바이트다")
        }
        self = value
    }

    /// 명령줄에 쓰는 텍스트 `"tlpub:" + 16진 64자리`(Go `NLPublic.CLIString`). 서명 기기의 `tailscale lock sign`이 받는다.
    ///
    /// Go는 두 접두사를 모두 읽지만, Swiftail은 NL 공개 키를 밖에서 읽는 곳이 없어 와이어의 `nlpub:`만 읽는다(`init?(_:)`).
    public var commandLineDescription: String { "tlpub:" + rawValue.hex }
}
