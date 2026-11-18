/// HPACK integer and string representations.
///
/// All header field representations are built from prefix integers and string literals. A prefix integer stores its value in the low
/// n bits of the first byte. If it cannot fit there, it continues in subsequent bytes with 7 bits each (RFC 7541 §5.1). A string has
/// a 1-bit Huffman flag, a 7-bit prefix length, and the bytes that follow (§5.2).

extension ByteReader {
    /// Reads an integer. `prefixBits` is the number of low bits (1~8) used for the value in the first byte.
    /// Ignores the high bits of the first byte (representation type bits), which the caller has already read with `peek()`.
    mutating func hpackInteger(prefixBits: Int) throws(HPACKError) -> Int {
        guard let first = uint8() else { throw .truncated }
        let prefixMax = (1 << prefixBits) - 1
        var value = Int(first) & prefixMax
        guard value == prefixMax else { return value }
        var shift = 0
        while true {
            guard let byte = uint8() else { throw .truncated }
            // 5 bytes (35 bits) can represent a value far over the header block limit (64KiB). Reject anything beyond that without overflow.
            guard shift <= 28 else { throw .integerOverflow }
            value += Int(byte & 0x7f) << shift
            guard byte & 0x80 != 0 else { return value }
            shift += 7
        }
    }

    /// Reads a string literal. Decodes it before returning if it uses Huffman coding.
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

/// Encodes HPACK representations.
enum HPACKEncoding {
    /// Appends an integer with a `prefixBits`-bit prefix. `flags` occupies the high bits of the first byte (representation type bits).
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

    /// Appends a string literal without Huffman coding.
    static func appendString(_ string: String, to output: inout [UInt8]) {
        appendInteger(string.utf8.count, prefixBits: 7, flags: 0, to: &output)
        output.append(contentsOf: string.utf8)
    }
}
