/// Fixed-capacity circular byte storage shared by the send and receive buffers.
///
/// Reuses the same storage throughout the connection, avoiding a new allocation per segment or read. All positions are
/// offsets from the front (`head`). The caller is responsible for keeping offsets within `capacity`.
///
/// Storage grows only as it is written (contract behavior M: idle connections do not hold buffers). Unwritten slots are never read.
struct ByteRing: Sendable {
    /// The minimum initial allocation, so small connections always start at about 4KiB.
    private static let minimumAllocation = 4096

    let capacity: Int
    private var storage: [UInt8] = []
    private var head = 0

    /// The number of bytes actually allocated, at most `capacity`.
    var allocatedByteCount: Int { storage.count }

    init(capacity: Int) {
        precondition(capacity > 0, "Storage capacity must be positive")
        self.capacity = capacity
    }

    /// Writes `bytes` starting at `offset`. Writes that reach `capacity` measured from the front wrap to the start of storage.
    mutating func write(_ bytes: ArraySlice<UInt8>, at offset: Int) {
        precondition(offset >= 0 && bytes.count <= capacity - offset, "Write exceeds capacity")
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

    /// Copies `count` bytes starting at `offset`. The range must have been written before.
    func copy(from offset: Int, count: Int) -> [UInt8] {
        precondition(offset >= 0 && count >= 0 && count <= capacity - offset, "Read exceeds capacity")
        guard count > 0 else { return [] }
        let start = (head + offset) % capacity
        let firstCount = min(count, capacity - start)
        var bytes = Array(storage[start..<start + firstCount])
        if firstCount < count {
            bytes.append(contentsOf: storage[0..<count - firstCount])
        }
        return bytes
    }

    /// Discards the first `count` bytes by advancing the front by that amount.
    mutating func discard(_ count: Int) {
        precondition(count >= 0 && count <= capacity, "Discard count exceeds capacity")
        head = (head + count) % capacity
    }

    /// Resets the front to the start when no written bytes remain. Keeps storage for connections with occasional writes
    /// from growing to capacity.
    mutating func rewind() {
        head = 0
    }

    /// Grows the storage to cover physical position `end` (exclusive), doubling up to capacity.
    ///
    /// shortcut: Once grown, storage never shrinks until the connection ends. A connection that goes idle after a large
    /// transfer holds up to 256KiB. Shrinking causes repeated allocations on connections with frequent gaps in
    /// transmission. Decide on a policy if measurements show that idle connection memory is a problem.
    private mutating func grow(toCover end: Int) {
        guard end > storage.count else { return }
        let target = min(capacity, max(end, storage.count * 2, Self.minimumAllocation))
        storage.append(contentsOf: repeatElement(0, count: target - storage.count))
    }
}
