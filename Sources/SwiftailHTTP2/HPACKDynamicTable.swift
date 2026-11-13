/// HPACK 동적 표.
///
/// 해제기가 본 헤더 필드를 기억해 두었다가 뒤의 블록이 짧은 색인으로 부르게 하는 표다. 새 항목은
/// 맨 앞(색인 62)에 들어가고 기존 항목의 색인은 하나씩 밀린다. 표가 정해진 크기를 넘으면 가장 오래된
/// 항목부터 밀려난다. 항목 크기는 이름과 값의 바이트 수에 32를 더한 값이다(RFC 7541 §4.1, §4.4).
struct HPACKDynamicTable {
    /// 항목마다 붙는 고정 비용(§4.1).
    private static let entryOverhead = 32

    /// 가장 새 항목이 앞에 있다.
    private var entries: [HeaderField] = []
    private var size = 0
    private(set) var maximumSize: Int

    init(maximumSize: Int) {
        self.maximumSize = maximumSize
    }

    /// 동적 표 안의 위치(0이 가장 새 항목)로 항목을 찾는다.
    func field(at position: Int) -> HeaderField? {
        entries.indices.contains(position) ? entries[position] : nil
    }

    mutating func insert(_ field: HeaderField) {
        let entrySize = Self.size(of: field)
        // 항목이 표 전체보다 크면 표를 비우기만 한다(§4.4).
        evict(toFit: maximumSize - entrySize)
        guard entrySize <= maximumSize else { return }
        entries.insert(field, at: 0)
        size += entrySize
    }

    /// 상한을 바꾸고 넘치는 항목을 민다(§4.3).
    mutating func resize(to newMaximumSize: Int) {
        maximumSize = newMaximumSize
        evict(toFit: newMaximumSize)
    }

    /// 항목 크기의 합이 `limit` 이하가 될 때까지 오래된 항목부터 지운다.
    private mutating func evict(toFit limit: Int) {
        while size > limit, let oldest = entries.popLast() {
            size -= Self.size(of: oldest)
        }
    }

    private static func size(of field: HeaderField) -> Int {
        field.name.utf8.count + field.value.utf8.count + entryOverhead
    }
}
