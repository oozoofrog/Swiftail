// AUM의 해시와 그 텍스트 표기. 노트 `docs/protocol-notes/tailnet-lock.md` 3.7·3.8, Go `tailscale.com/tka/aum.go:21-51`.
// Copyright (c) Tailscale Inc & contributors. BSD-3-Clause.

import SwiftailCrypto

/// AUM의 해시 32바이트(Go `tka.AUMHash`): 정준 AUM 바이트의 BLAKE2s-256이다(동작 E5).
///
/// 비교는 바이트로 한다. 텍스트는 끝 글자의 남는 4비트를 보지 않아서 글자가 달라도 같은 해시일 수 있다(노트 3.8).
package struct AUMHash: Sendable, Hashable {
    /// 해시 32바이트. 생성자가 길이를 검사하므로 늘 32바이트다.
    package let bytes: [UInt8]

    /// 32바이트가 아니면 nil.
    package init?(_ bytes: [UInt8]) {
        guard bytes.count == 32 else { return nil }
        self.bytes = bytes
    }

    /// `content`의 BLAKE2s-256. 출력은 늘 32바이트다.
    init(hashing content: [UInt8]) {
        bytes = BLAKE2s.hash(content)
    }

    /// RFC 4648 base32 표준 알파벳(대문자), 패딩 없음, 52자(Go `UnmarshalText`). 소문자·패딩·다른 길이는 nil.
    ///
    /// 마지막 글자의 아래 4비트는 버린다(Go와 같다). Go의 `base32.Encoding.Decode`는 `\r`·`\n`을 지우고 읽지만
    /// 여기서는 알파벳 밖의 글자로 거절한다(계약 2절의 선언대로 52자의 알파벳만 받는다).
    package init?(text: String) {
        let characters = Array(text.utf8)
        guard characters.count == Self.textLength else { return nil }
        var result: [UInt8] = []
        result.reserveCapacity(32)
        var buffer: UInt32 = 0
        var bitCount = 0
        for character in characters {
            guard let value = Self.alphabetValue(character) else { return nil }
            buffer = buffer << 5 | UInt32(value)
            bitCount += 5
            if bitCount >= 8 {
                bitCount -= 8
                result.append(UInt8(truncatingIfNeeded: buffer >> UInt32(bitCount)))
            }
        }
        // 52 × 5 = 260비트에서 32바이트를 채우고 남은 4비트는 버린다.
        bytes = result
    }

    /// base32 표준 알파벳(대문자), 패딩 없음, 52자(Go `String`·`MarshalText`).
    package var text: String {
        var characters: [UInt8] = []
        characters.reserveCapacity(Self.textLength)
        var buffer: UInt32 = 0
        var bitCount = 0
        for byte in bytes {
            buffer = buffer << 8 | UInt32(byte)
            bitCount += 8
            while bitCount >= 5 {
                bitCount -= 5
                characters.append(Self.alphabet[Int(buffer >> UInt32(bitCount) & 0x1f)])
            }
        }
        // 남은 1비트를 위로 붙이고 아래를 0으로 채운다.
        characters.append(Self.alphabet[Int(buffer << UInt32(5 - bitCount) & 0x1f)])
        return String(decoding: characters, as: UTF8.self)
    }

    private static let textLength = 52
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    private static func alphabetValue(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "A")...UInt8(ascii: "Z"): character - UInt8(ascii: "A")
        case UInt8(ascii: "2")...UInt8(ascii: "7"): character - UInt8(ascii: "2") + 26
        default: nil
        }
    }
}
