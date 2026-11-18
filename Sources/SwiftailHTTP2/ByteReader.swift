/// Reads a byte sequence from the start. Returns `nil` without reading when too few bytes remain.
///
/// Lengths supplied by the peer in frame payloads and HPACK blocks are untrusted, so centralize bounds checking in the reader
/// to prevent out-of-bounds reads on any input. All integers are big-endian.
struct ByteReader {
    private let bytes: ArraySlice<UInt8>
    private var offset: Int

    init(_ bytes: ArraySlice<UInt8>) {
        self.bytes = bytes
        offset = bytes.startIndex
    }

    init(_ bytes: [UInt8]) {
        self.init(bytes[...])
    }

    var remainingCount: Int { bytes.endIndex - offset }
    var isAtEnd: Bool { remainingCount == 0 }

    /// Peeks at the next byte without consuming it.
    func peek() -> UInt8? {
        isAtEnd ? nil : bytes[offset]
    }

    mutating func uint8() -> UInt8? {
        guard let byte = peek() else { return nil }
        offset += 1
        return byte
    }

    mutating func uint16() -> UInt16? {
        guard let high = uint8(), let low = uint8() else { return nil }
        return UInt16(high) << 8 | UInt16(low)
    }

    mutating func uint32() -> UInt32? {
        guard let high = uint16(), let low = uint16() else { return nil }
        return UInt32(high) << 16 | UInt32(low)
    }

    mutating func take(_ count: Int) -> ArraySlice<UInt8>? {
        guard count >= 0, count <= remainingCount else { return nil }
        defer { offset += count }
        return bytes[offset..<offset + count]
    }

    /// All remaining bytes.
    mutating func rest() -> ArraySlice<UInt8> {
        defer { offset = bytes.endIndex }
        return bytes[offset...]
    }
}
