// STUN 바인딩 요청의 형식은 Tailscale의 `net/stun/stun.go`(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를
// 따른다. 바이트 배치와 상수만 옮겼고 코드는 Swift로 새로 썼다.

import SwiftailBase

/// STUN 바인딩 메시지의 부호화와 판정. 자기 바깥 주소(엔드포인트)를 알아내는 데 쓴다.
///
/// 이 타입은 입출력이 없다. 요청 바이트를 만들고, 받은 바이트가 STUN인지 가리고, 응답에서 TxID와 바깥 주소를 꺼낸다.
/// 요청이 어떤 TxID로 나갔는지 기억하는 일은 `Netcheck`가 한다.
///
/// 형식: `docs/protocol-notes/derp-stun.md` 3.8(요청)·3.9(응답), 4.10 3(해석), `disco-magicsock.md` 4.1 1(판정).
/// - 요청은 40바이트다. Go STUN 서버는 SOFTWARE가 정확히 `tailnode`이고 마지막 속성이 맞는 FINGERPRINT인 요청에만
///   답하므로 이 바이트를 그대로 만들어야 한다.
/// - 응답은 신뢰할 수 없는 입력이다. 해석은 `parseBindingResponse`에서 한 번 하고, 실패하면 `nil`이다.
enum STUNMessage {
    /// 헤더 길이. 메시지 종류(2), 본문 길이(2), cookie(4), TxID(12).
    static let headerLength = 20
    /// RFC 5389의 magic cookie. 주소 XOR와 STUN 판정에 쓴다.
    static let magicCookie: [UInt8] = [0x21, 0x12, 0xa4, 0x42]

    /// SOFTWARE 속성의 값. Go STUN 서버가 요청의 출처를 가리는 표지다(8바이트라 패딩이 없다).
    private static let software = Array("tailnode".utf8)
    private static let softwareAttribute: UInt16 = 0x8022
    private static let fingerprintAttribute: UInt16 = 0x8028
    /// FINGERPRINT는 CRC-32에 이 값을 XOR한다(RFC 5389 15.5. ASCII `STUN`).
    private static let fingerprintXOR: UInt32 = 0x5354_554e

    /// DERP 노트 3.8의 40바이트 요청.
    static func bindingRequest(_ txID: TransactionID) -> [UInt8] {
        var bytes: [UInt8] = [0x00, 0x01]  // binding request
        // 헤더 뒤 길이: SOFTWARE(4 + 8)와 FINGERPRINT(4 + 4).
        bytes += bigEndian(UInt16(4 + software.count + 8))
        bytes += magicCookie
        bytes += txID.bytes
        bytes += bigEndian(softwareAttribute)
        bytes += bigEndian(UInt16(software.count))
        bytes += software
        // 길이 필드는 FINGERPRINT까지 센 값이고, CRC는 FINGERPRINT 앞의 32바이트에 건다.
        let fingerprint = CRC32.checksum(bytes) ^ fingerprintXOR
        bytes += bigEndian(fingerprintAttribute)
        bytes += bigEndian(UInt16(4))
        bytes += bigEndian(fingerprint)
        return bytes
    }

    /// 노트 4.1 1의 STUN 판정: 길이 ≥ 20, 상위 2비트 0, cookie, 바이트 1이 0x01(binding 방식).
    ///
    /// 형식 검사만 한다. 이것이 참인 데이터그램은 WireGuard로 넘기지 않고 `Netcheck`가 맞춰 본다.
    static func looksLikeSTUN(_ bytes: [UInt8]) -> Bool {
        hasSTUNHeader(bytes) && bytes[1] == 0x01
    }

    /// 길이 ≥ 20, 첫 바이트 상위 2비트 0, cookie 일치. Go `stun.Is`와 같다.
    static func hasSTUNHeader(_ bytes: [UInt8]) -> Bool {
        bytes.count >= headerLength && bytes[0] & 0b1100_0000 == 0 && bytes[4..<8].elementsEqual(magicCookie)
    }

    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    private static func bigEndian(_ value: UInt32) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: value >> UInt32(24 - 8 * $0)) }
    }
}

/// CRC-32/IEEE(다항식 0xEDB88320, 반사형). Go `crc32.ChecksumIEEE`와 같다. FINGERPRINT를 계산하는 데만 쓴다.
private enum CRC32 {
    private static let table: [UInt32] = (0..<256).map { index in
        (0..<8).reduce(UInt32(index)) { value, _ in
            value & 1 == 1 ? (value >> 1) ^ 0xEDB8_8320 : value >> 1
        }
    }

    static func checksum(_ bytes: [UInt8]) -> UInt32 {
        ~bytes.reduce(UInt32.max) { crc, byte in
            table[Int(UInt8(truncatingIfNeeded: crc) ^ byte)] ^ (crc >> 8)
        }
    }
}
