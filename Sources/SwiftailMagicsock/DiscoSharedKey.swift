import CryptoKit
import SwiftailBase
import SwiftailCrypto

/// 자기 disco 개인 키와 상대 disco 공개 키로 계산한 NaCl box 공유 키.
///
/// 비밀이다. 키 바이트는 이 타입 안에만 두고 `customMirror`가 감추므로 `print`·`dump`·디버거 요약에 나오지 않는다.
/// 계산은 X25519와 HSalsa20으로 비싸므로 상대 키마다 한 번만 만들어 두고 쓴다(`docs/protocol-notes/disco-magicsock.md` 3.2 5).
///
/// 같은 키로 봉하고 여는 `box.Seal`과 `box.Open`은 이 키 위의 `secretbox`다(노트 3.2 2·3).
struct DiscoSharedKey: Sendable, CustomReflectable {
    private let key: [UInt8]

    /// - Throws: `invalidKey` — 상대의 공개 키가 저차수라 공유 키가 0이 된다(Go는 0을 그대로 쓰지만 M4는 버린다. 노트 3.2).
    init(privateKey: Curve25519.KeyAgreement.PrivateKey, peerPublicKey: DiscoPublicKey) throws(DiscoError) {
        do {
            key = try NaClBox.sharedKey(privateKey: Array(privateKey.rawRepresentation), peerPublicKey: peerPublicKey.rawValue)
        } catch {
            throw .invalidKey
        }
    }

    var customMirror: Mirror {
        Mirror(self, children: [])
    }

    /// `nonce`(24바이트)로 `plaintext`를 봉한다. 출력 배치는 tag(16) ‖ 암호문이다.
    ///
    /// nonce 길이는 부르는 쪽이 지킬 약속이다. 어긋나면 프로그래밍 오류로 멈춘다(상대 입력이 아니다).
    func seal(_ plaintext: [UInt8], nonce: [UInt8]) -> [UInt8] {
        guard let sealed = try? NaClSecretBox.seal(plaintext, nonce: nonce, key: key) else {
            preconditionFailure("disco nonce는 \(NaClSecretBox.nonceByteCount)바이트여야 한다")
        }
        return sealed
    }

    /// tag ‖ 암호문을 열어 평문을 돌려준다.
    ///
    /// - Throws: `authenticationFailed` — 키·nonce·tag·암호문이 맞지 않는다. `malformed` — nonce나 box 길이가 규격보다 짧다.
    func open(_ box: ArraySlice<UInt8>, nonce: [UInt8]) throws(DiscoError) -> [UInt8] {
        do {
            return try NaClSecretBox.open(box, nonce: nonce, key: key)
        } catch {
            switch error {
            case .invalidLength: throw .malformed
            case .authenticationFailed, .invalidKey: throw .authenticationFailed
            }
        }
    }
}
