import SwiftailBase
import SwiftailCrypto

/// disco 메시지의 겉 형식: 알아보기, 보낸 쪽 키 읽기, 봉하기, 열기.
///
/// 겉 형식은 `magic(6) ‖ 보낸 쪽 disco 공개 키(32) ‖ nonce(24) ‖ secretbox(평문)`이다(노트 3.1). magic과 보낸 쪽 키는
/// 암호로 묶이지 않는다. 보낸 쪽 키는 어느 공유 키로 열지를 고르는 데만 쓰고, 열린 뒤에야 믿는다.
/// 난수(nonce)는 인자로 받는다. 시스템 난수는 바깥 층에서만 뽑는다.
///
/// `docs/protocol-notes/disco-magicsock.md` 3.1·3.2절, 4.1 3
/// (출처: tailscale.com `disco/disco.go`·`types/key/disco.go`, BSD-3-Clause).
enum DiscoPacket {
    /// `"TS💬"`.
    static let magic: [UInt8] = [0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC]
    /// disco로 알아보는 최소 길이: magic과 보낸 쪽 키(노트 4.1 3). 62바이트 기준의 Go `LooksLikeDiscoWrapper`와 다르다.
    static let classificationLength = 38

    private static let senderKeyRange = 6..<38
    private static let nonceRange = 38..<62
    private static let sealedStart = 62
    /// 열 수 있는 최소 길이: 머리 62바이트와 tag 16바이트.
    private static let minimumOpenableLength = sealedStart + NaClSecretBox.overhead

    /// 길이 ≥ 38이고 magic으로 시작한다. 열어 보지 않는다.
    static func isDisco(_ bytes: [UInt8]) -> Bool {
        bytes.count >= classificationLength && bytes.starts(with: magic)
    }

    /// 보낸 쪽 disco 공개 키(오프셋 6..<38). `isDisco`가 참일 때만 값이 있다.
    static func senderKey(of bytes: [UInt8]) -> DiscoPublicKey? {
        guard isDisco(bytes) else { return nil }
        return DiscoPublicKey(rawValue: bytes[senderKeyRange])
    }

    /// `magic ‖ sender ‖ nonce ‖ secretbox(평문)`을 만든다. nonce는 24바이트여야 한다(어긋나면 프로그래밍 오류로 멈춘다).
    static func seal(_ message: DiscoMessage, sender: DiscoPublicKey, sharedKey: DiscoSharedKey, nonce: [UInt8]) -> [UInt8] {
        magic + sender.rawValue + nonce + sharedKey.seal(message.plaintext, nonce: nonce)
    }

    /// 겉 형식을 열어 메시지로 해석한다. 열린 평문만 해석한다.
    ///
    /// - Throws: `malformed` — disco로 알아볼 수 없거나(38바이트 미만, magic 불일치) nonce와 tag를 담기에 짧거나(78바이트 미만)
    ///   열린 평문의 형식이 틀리다. `authenticationFailed` — 열리지 않는다. `unknownType` — 처리하지 않는 종류.
    static func open(_ bytes: [UInt8], sharedKey: DiscoSharedKey) throws(DiscoError) -> DiscoMessage {
        guard isDisco(bytes), bytes.count >= minimumOpenableLength else { throw .malformed }
        let plaintext = try sharedKey.open(bytes[sealedStart...], nonce: Array(bytes[nonceRange]))
        return try DiscoMessage(parsing: plaintext)
    }
}
