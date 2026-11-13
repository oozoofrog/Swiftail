import SwiftailBase

/// 복호화한 transport 평문을 IP 패킷으로 해석한 결과.
///
/// 평문은 인증되었어도 상대 피어가 만든 것이므로 신뢰하지 않는다. 여기서 한 번 길이를 검사하고,
/// IP 머리의 길이 필드로 패딩을 떼고, AllowedIPs 검사에 쓸 출발 주소를 꺼낸다.
///
/// 백서 §5.4.6(cryptokey routing), `docs/protocol-notes/wireguard.md` "전송 데이터: 받기" 8
/// (출처: wireguard-go `device/receive.go`).
struct InboundIPPacket {
    /// 패딩을 뗀 IP 패킷.
    let bytes: [UInt8]
    let source: IPAddress

    /// 버전이 4·6이 아니거나 머리보다 짧거나 길이 필드가 평문 밖을 가리키면 `nil`.
    init?(plaintext: [UInt8]) {
        guard let first = plaintext.first else { return nil }
        let length: Int
        let sourceRange: Range<Int>
        switch first >> 4 {
        case 4:
            let headerLength = 20
            guard plaintext.count >= headerLength else { return nil }
            length = Self.bigEndianLength(plaintext, at: 2)
            guard (headerLength...plaintext.count).contains(length) else { return nil }
            sourceRange = 12..<16
        case 6:
            let headerLength = 40
            guard plaintext.count >= headerLength else { return nil }
            // payload length + 40. Go는 이 덧셈을 UInt16에서 해 wrap하지만 여기서는 Int로 더해 그대로 비교한다.
            length = Self.bigEndianLength(plaintext, at: 4) + headerLength
            guard length <= plaintext.count else { return nil }
            sourceRange = 8..<24
        default:
            return nil
        }
        guard let source = IPAddress(bytes: plaintext[sourceRange]) else { return nil }
        self.bytes = Array(plaintext[..<length])
        self.source = source
    }

    /// 머리 길이를 확인한 뒤에만 부른다.
    private static func bigEndianLength(_ bytes: [UInt8], at offset: Int) -> Int {
        Int(bytes[offset]) << 8 | Int(bytes[offset + 1])
    }
}
