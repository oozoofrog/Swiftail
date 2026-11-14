/// 고정 용량의 원형 바이트 저장소. 보내는 버퍼와 받는 버퍼가 함께 쓴다.
///
/// 연결의 수명 동안 저장소 하나를 되풀이해 쓰므로 세그먼트·읽기마다 버퍼를 새로 할당하지 않는다.
/// 위치는 모두 "맨 앞(`head`)에서의 오프셋"이다. 오프셋이 `capacity`를 넘는 일은 호출하는 쪽의 몫이다.
///
/// 저장소는 쓰는 만큼만 자란다(계약 동작 M: 유휴 연결은 버퍼를 쥐지 않는다). 아직 쓰지 않은 자리는 읽히지 않는다.
struct ByteRing: Sendable {
    /// 처음 잡는 크기의 하한. 작은 연결이 늘 4KiB쯤에서 시작하게 한다.
    private static let minimumAllocation = 4096

    let capacity: Int
    private var storage: [UInt8] = []
    private var head = 0

    /// 지금 실제로 잡힌 바이트 수. `capacity` 이하다.
    var allocatedByteCount: Int { storage.count }

    init(capacity: Int) {
        precondition(capacity > 0, "저장소 용량은 양수여야 한다")
        self.capacity = capacity
    }

    /// `offset` 자리부터 `bytes`를 쓴다. 맨 앞에서 `capacity`를 넘어서는 쪽은 저장소의 처음으로 되감긴다.
    mutating func write(_ bytes: ArraySlice<UInt8>, at offset: Int) {
        precondition(offset >= 0 && bytes.count <= capacity - offset, "쓰기가 용량을 넘는다")
        guard !bytes.isEmpty else { return }
        let start = (head + offset) % capacity
        let firstCount = min(bytes.count, capacity - start)
        grow(toCover: start + firstCount)
        storage.replaceSubrange(start..<start + firstCount, with: bytes.prefix(firstCount))
        let restCount = bytes.count - firstCount
        if restCount > 0 {
            grow(toCover: restCount)
            storage.replaceSubrange(0..<restCount, with: bytes.suffix(restCount))
        }
    }

    /// `offset` 자리부터 `count`바이트를 복사해 낸다. 앞서 쓴 자리여야 한다.
    func copy(from offset: Int, count: Int) -> [UInt8] {
        precondition(offset >= 0 && count >= 0 && count <= capacity - offset, "읽기가 용량을 넘는다")
        guard count > 0 else { return [] }
        let start = (head + offset) % capacity
        let firstCount = min(count, capacity - start)
        var bytes = Array(storage[start..<start + firstCount])
        if firstCount < count {
            bytes.append(contentsOf: storage[0..<count - firstCount])
        }
        return bytes
    }

    /// 맨 앞의 `count`바이트를 버린다(맨 앞이 그만큼 나아간다).
    mutating func discard(_ count: Int) {
        precondition(count >= 0 && count <= capacity, "버리는 양이 용량을 넘는다")
        head = (head + count) % capacity
    }

    /// 쓴 바이트가 하나도 없을 때 맨 앞을 처음으로 되돌린다. 가끔 쓰는 연결의 저장소가 용량까지 자라지 않게 한다.
    mutating func rewind() {
        head = 0
    }

    /// 저장소가 물리 위치 `end`(배타)까지 닿도록 키운다. 두 배씩, 용량까지.
    ///
    /// shortcut: 한 번 자란 저장소는 연결이 끝날 때까지 줄이지 않는다. 큰 전송 뒤에 유휴가 된 연결이 최대 256KiB를 쥔다.
    /// 줄이면 전송이 잦게 비는 연결에서 할당이 되풀이된다. 유휴 연결의 메모리가 문제로 재어지면 그때 정책을 정한다.
    private mutating func grow(toCover end: Int) {
        guard end > storage.count else { return }
        let target = min(capacity, max(end, storage.count * 2, Self.minimumAllocation))
        storage.append(contentsOf: repeatElement(0, count: target - storage.count))
    }
}
