/// The HPACK dynamic table.
///
/// Stores header fields the decoder has seen so later blocks can refer to them by short indices. New entries
/// go at the front (index 62), and older entries' indices shift by one. When the table exceeds its size limit, it evicts
/// the oldest entries first. Entry size is the byte count of the name and value plus 32 (RFC 7541 §4.1, §4.4).
struct HPACKDynamicTable {
    /// The fixed overhead per entry (§4.1).
    private static let entryOverhead = 32

    /// The newest entry is first.
    private var entries: [HeaderField] = []
    private var size = 0
    private(set) var maximumSize: Int

    init(maximumSize: Int) {
        self.maximumSize = maximumSize
    }

    /// Looks up an entry by its position in the dynamic table (0 is the newest entry).
    func field(at position: Int) -> HeaderField? {
        entries.indices.contains(position) ? entries[position] : nil
    }

    mutating func insert(_ field: HeaderField) {
        let entrySize = Self.size(of: field)
        // An entry larger than the entire table only clears the table (§4.4).
        evict(toFit: maximumSize - entrySize)
        guard entrySize <= maximumSize else { return }
        entries.insert(field, at: 0)
        size += entrySize
    }

    /// Changes the limit and evicts excess entries (§4.3).
    mutating func resize(to newMaximumSize: Int) {
        maximumSize = newMaximumSize
        evict(toFit: newMaximumSize)
    }

    /// Removes the oldest entries until the sum of entry sizes is at most `limit`.
    private mutating func evict(toFit limit: Int) {
        while size > limit, let oldest = entries.popLast() {
            size -= Self.size(of: oldest)
        }
    }

    private static func size(of field: HeaderField) -> Int {
        field.name.utf8.count + field.value.utf8.count + entryOverhead
    }
}
