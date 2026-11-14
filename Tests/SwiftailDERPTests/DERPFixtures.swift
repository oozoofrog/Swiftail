import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import SwiftailDERP
import Testing

/// 시험에 쓰는 고정 값과, 서버 쪽 바이트를 만드는 도우미.
///
/// 키는 공개된 시험용 값이다: 개인 키 입력은 `SHA-256("swiftail-fixtures/derp/<번호>")`(클라이언트 1, 서버 2).
/// 운영 키가 아니다. nonce는 `00 01 … 17`이다.
///
/// ClientInfo·ServerInfo 본문의 고정 벡터는 Go의 `box.Seal`(`golang.org/x/crypto/nacl/box`, tailscale.com v1.104.6의
/// `NodePrivate.SealTo`와 같은 호출)로 같은 키·같은 nonce를 넣어 뽑았다. 다시 뽑으려면
/// `Tools/interop`에서 `go run ./cmd/derpvectors`(환경 변수는 `Tools/interop/README.md`)를 실행한다.
enum DERPFixtures {
    static let clientSeed = "b7f801a79c5f48484f7c5bdf69b48d042fa0cc965db569b5df72e3893fe2e5b7"
    static let serverSeed = "ac720aec903565f3baa1fdc3f652959183cf04cb4d79b8b5e59d0c7234ab2bc3"
    static let clientPublic = "01b5e48ad0a98cecf0af5e20b9f7c1018d05eb3907f602a42ff64b872c54537f"
    static let serverPublic = "eec4e62b771c47da8fb0eb2c95f6fe3dd4290559303249239be2e077a54e0d67"
    static let nonce = "000102030405060708090a0b0c0d0e0f1011121314151617"
    /// Go가 봉한 ClientInfo 평문: `{"version":2,"CanAckPings":true}`.
    static let clientInfoBody = "01b5e48ad0a98cecf0af5e20b9f7c1018d05eb3907f602a42ff64b872c54537f000102030405060708090a0b0c0d0e0f10111213141516174cd54de08147b1a40033c0a0e8a25de77ceff26dd8baa3416c70d17e0f231e85c823f65cbc2f1c2bdf0f8f129c77d92b"
    /// Go가 봉한 ServerInfo 평문: `{"version":2}`.
    static let serverInfoBody = "000102030405060708090a0b0c0d0e0f1011121314151617adc070ff55d0e4d3be5ea1766a88021e7ceff26dd8baa3416c70d17e5e"

    static func bytes(_ hex: String) throws -> [UInt8] {
        try #require([UInt8](hex: hex), "16진 문자열이 아니다")
    }

    static func privateKey(seed: String) throws -> Curve25519.KeyAgreement.PrivateKey {
        try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: bytes(seed))
    }

    static func nodeKey(_ fill: UInt8) throws -> NodePublicKey {
        try #require(NodePublicKey(rawValue: [UInt8](repeating: fill, count: 32)))
    }

    /// 클라이언트 쪽 상태 기계. 고정 키와 고정 nonce를 쓴다.
    static func connection(isPreferred: Bool = true, host: String = "127.0.0.1:3340") throws -> DERPConnection {
        try DERPConnection(
            privateKey: privateKey(seed: clientSeed), host: host, isPreferred: isPreferred, clientInfoNonce: bytes(nonce)
        )
    }

    /// 업그레이드 요청을 꺼내고 101과 ServerKey를 넣어 준비된 상태 기계. 내보낸 핸드셰이크 바이트는 버린다.
    static func readyConnection(isPreferred: Bool = true) throws -> DERPConnection {
        var connection = try connection(isPreferred: isPreferred)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(Server.upgradeResponse + Server.serverKeyFrame())
        #expect(events == [.ready])
        _ = connection.takeOutboundBytes()
        return connection
    }

    /// DERP 서버가 보내는 바이트.
    enum Server {
        static let upgradeResponse = Array(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: 2\r\nDerp-Public-Key: \(serverPublic)\r\n\r\n".utf8
        )
        static let magic: [UInt8] = [0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91]

        /// 5바이트 머리와 본문.
        static func frame(_ type: UInt8, _ body: [UInt8]) -> [UInt8] {
            let length = UInt32(body.count)
            return [type, UInt8(length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                    UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)] + body
        }

        /// 서버는 magic과 공개 키 40바이트만 보낸다. `trailing`은 "향후 확장" 자리다.
        static func serverKeyFrame(trailing: [UInt8] = []) throws -> [UInt8] {
            try frame(0x01, magic + bytes(serverPublic) + trailing)
        }

        static func recvPacket(from peer: NodePublicKey, _ packet: [UInt8]) -> [UInt8] {
            frame(0x05, peer.rawValue + packet)
        }

        /// 서버 개인 키·클라이언트 공개 키로 봉한 ServerInfo 프레임. `plaintext`가 JSON이 아니어도 봉할 수 있다.
        static func serverInfoFrame(_ plaintext: [UInt8] = Array(#"{"version":2}"#.utf8)) throws -> [UInt8] {
            let shared = try NaClBox.sharedKey(
                privateKey: Array(privateKey(seed: serverSeed).rawRepresentation), peerPublicKey: bytes(clientPublic)
            )
            let nonce = try bytes(nonce)
            return try frame(0x03, nonce + NaClSecretBox.seal(plaintext, nonce: nonce, key: shared))
        }
    }
}

/// 재현되는 가짜 난수. 임의 입력 시험이 실패하면 같은 입력으로 다시 돌릴 수 있게 한다.
struct SplitMix64: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}
