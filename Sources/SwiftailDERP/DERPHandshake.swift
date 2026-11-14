import CryptoKit
import Foundation
import SwiftailCrypto

/// DERP 핸드셰이크의 순수한 단계들: 업그레이드 요청, ServerKey 검증, ClientInfo 봉하기, ServerInfo 열기.
///
/// 소켓·시계·난수를 갖지 않는다. nonce는 인자로 받고, 시스템 난수는 가장자리(`DERPClient`)에서만 뽑는다.
///
/// `docs/protocol-notes/derp-stun.md` 3.3~3.5절, 3.7절, 4.3절
/// (출처: tailscale.com `derp/derp_client.go`·`types/key/node.go`, BSD-3-Clause).
enum DERPHandshake {
    /// ServerKey 본문의 앞 8바이트: `"DERP🔑"`.
    static let serverKeyMagic: [UInt8] = [0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91]
    /// ServerKey 본문의 한도(Go 클라이언트와 같다). 40바이트 뒤는 향후 확장이므로 버린다.
    static let maximumServerKeyBody = 1024
    static let nonceSize = 24
    /// 클라이언트가 알리는 것: 프로토콜 버전 2, Ping에 답할 수 있음.
    private static let clientInfoJSON = Array(#"{"version":2,"CanAckPings":true}"#.utf8)

    /// `GET /derp` 업그레이드 요청. `User-Agent`·`Ideal-Node`·fast-start는 보내지 않는다.
    ///
    /// `host`는 헤더 값 하나여야 한다. 공백·제어 문자(CR·LF 포함)가 있으면 요청 머리를 오염시키므로 거절한다.
    static func upgradeRequest(host: String) throws(DERPError) -> [UInt8] {
        let bytes = Array(host.utf8)
        guard !bytes.isEmpty, !bytes.contains(where: { $0 <= 0x20 || $0 == 0x7F }) else { throw .malformed }
        return Array("GET /derp HTTP/1.1\r\nHost: \(host)\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n".utf8)
    }

    /// ServerKey 프레임에서 서버의 공개 키를 꺼낸다. 타입·길이(40 이상)·magic이 맞아야 한다.
    static func serverPublicKey(from frame: DERPFrame) throws(DERPError) -> [UInt8] {
        guard frame.kind == .serverKey, frame.body.count >= 40, frame.body.starts(with: serverKeyMagic) else {
            throw .handshakeFailed
        }
        return Array(frame.body[8..<40])
    }

    /// ClientInfo 프레임 본문과 이후 ServerInfo를 여는 데 쓸 공유 키.
    ///
    /// 본문은 `클라이언트 공개 키(32) ‖ nonce(24) ‖ tag(16) ‖ 암호문`이다. `box.Seal`은 두 단계로 나뉜다:
    /// X25519와 HSalsa20으로 공유 키를 만들고(`NaClBox.sharedKey`), 그 키로 XSalsa20-Poly1305를 봉한다
    /// (`NaClSecretBox.seal`).
    static func clientInfo(
        privateKey: Curve25519.KeyAgreement.PrivateKey, serverKey: [UInt8], nonce: [UInt8]
    ) throws(DERPError) -> (body: [UInt8], sharedKey: [UInt8]) {
        do {
            let sharedKey = try NaClBox.sharedKey(privateKey: Array(privateKey.rawRepresentation), peerPublicKey: serverKey)
            let sealed = try NaClSecretBox.seal(clientInfoJSON, nonce: nonce, key: sharedKey)
            return (Array(privateKey.publicKey.rawRepresentation) + nonce + sealed, sharedKey)
        } catch {
            throw .handshakeFailed
        }
    }

    /// ServerInfo 본문(`nonce(24) ‖ box`)을 열어 JSON까지 확인한다.
    ///
    /// 열리지 않으면 `handshakeFailed`, 열렸지만 JSON 객체가 아니면 `malformed`.
    /// shortcut: 속도 제한(`TokenBucketBytesPerSecond`·`TokenBucketBytesBurst`)은 읽지 않는다. 이 버전의 서버는
    /// `{"version":2}`만 보낸다.
    static func openServerInfo(_ body: [UInt8], sharedKey: [UInt8]) throws(DERPError) {
        guard body.count >= nonceSize else { throw .handshakeFailed }
        let plaintext: [UInt8]
        do {
            plaintext = try NaClSecretBox.open(body[nonceSize...], nonce: Array(body[..<nonceSize]), key: sharedKey)
        } catch {
            throw .handshakeFailed
        }
        struct ServerInfo: Decodable { var version: Int? }
        guard (try? JSONDecoder().decode(ServerInfo.self, from: Data(plaintext))) != nil else { throw .malformed }
    }
}
