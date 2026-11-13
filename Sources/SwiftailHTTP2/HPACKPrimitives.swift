/// HPACK의 정수와 문자열 표현.
///
/// 헤더 필드 표현은 모두 "prefix 정수"와 "문자열 리터럴"로 만들어진다. prefix 정수는 첫 바이트의
/// 아래쪽 n비트에 값을 넣고, 담지 못하면 7비트씩 뒤따르는 바이트로 잇는다(RFC 7541 §5.1). 문자열은
/// 허프만 flag 1비트와 7비트 prefix 길이, 그 뒤의 바이트로 이루어진다(§5.2).

extension ByteReader {
    /// 정수를 읽는다. `prefixBits`는 첫 바이트에서 값에 쓰이는 아래쪽 비트 수(1~8)다.
    /// 첫 바이트의 윗부분(표현 형식 비트)은 부르는 쪽이 이미 `peek()`으로 읽었으므로 무시한다.
    mutating func hpackInteger(prefixBits: Int) throws(HPACKError) -> Int {
        guard let first = uint8() else { throw .truncated }
        let prefixMax = (1 << prefixBits) - 1
        var value = Int(first) & prefixMax
        guard value == prefixMax else { return value }
        var shift = 0
        while true {
            guard let byte = uint8() else { throw .truncated }
            // 5바이트(35비트)면 헤더 블록 한도(64KiB)를 한참 넘는 값이다. 그 뒤는 넘침 없이 거절한다.
            guard shift <= 28 else { throw .integerOverflow }
            value += Int(byte & 0x7f) << shift
            guard byte & 0x80 != 0 else { return value }
            shift += 7
        }
    }

    /// 문자열 리터럴을 읽는다. 허프만 부호면 풀어서 돌려준다.
    mutating func hpackString() throws(HPACKError) -> String {
        guard let first = peek() else { throw .truncated }
        let isHuffman = first & 0x80 != 0
        let length = try hpackInteger(prefixBits: 7)
        guard let raw = take(length) else { throw .truncated }
        let bytes: [UInt8]
        if isHuffman {
            bytes = try HPACKHuffman.decode(raw)
        } else {
            bytes = Array(raw)
        }
        guard let string = String(validating: bytes, as: UTF8.self) else { throw .invalidUTF8 }
        return string
    }
}

/// HPACK 표현을 만드는 쪽.
enum HPACKEncoding {
    /// 정수를 `prefixBits`비트 prefix로 덧붙인다. `flags`는 첫 바이트의 윗부분(표현 형식 비트)이다.
    static func appendInteger(_ value: Int, prefixBits: Int, flags: UInt8, to output: inout [UInt8]) {
        let prefixMax = (1 << prefixBits) - 1
        guard value >= prefixMax else {
            output.append(flags | UInt8(truncatingIfNeeded: value))
            return
        }
        output.append(flags | UInt8(truncatingIfNeeded: prefixMax))
        var rest = value - prefixMax
        while rest >= 0x80 {
            output.append(UInt8(truncatingIfNeeded: rest & 0x7f) | 0x80)
            rest >>= 7
        }
        output.append(UInt8(truncatingIfNeeded: rest))
    }

    /// 허프만 없이 문자열 리터럴을 덧붙인다.
    static func appendString(_ string: String, to output: inout [UInt8]) {
        appendInteger(string.utf8.count, prefixBits: 7, flags: 0, to: &output)
        output.append(contentsOf: string.utf8)
    }
}
