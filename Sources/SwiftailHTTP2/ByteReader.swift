/// 바이트열을 앞에서부터 읽는다. 남은 바이트가 모자라면 읽지 않고 `nil`을 돌려준다.
///
/// 프레임 payload와 HPACK 블록은 상대가 보낸 길이를 믿을 수 없으므로, 범위 확인을 읽는 쪽 한 곳에
/// 모아 어떤 입력으로도 범위 밖을 읽지 않게 한다. 정수는 모두 big-endian이다.
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

    /// 읽지 않고 다음 바이트를 본다.
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

    /// 남은 바이트 전부.
    mutating func rest() -> ArraySlice<UInt8> {
        defer { offset = bytes.endIndex }
        return bytes[offset...]
    }
}
