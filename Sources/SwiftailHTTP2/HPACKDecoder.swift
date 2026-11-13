/// HPACK 해제기: 헤더 블록 바이트를 헤더 필드 목록으로 되돌린다.
///
/// 연결 하나에 해제기 하나가 있고, 상대가 보낸 모든 헤더 블록을 도착한 순서대로 넣어야 한다. 동적
/// 표가 블록을 넘어 이어지기 때문이다. 블록 하나는 필드 표현의 나열이며 첫 바이트의 윗비트로
/// 종류가 갈린다(RFC 7541 §6):
///
/// - `1`: 색인된 필드(§6.1). 정적·동적 표의 항목을 그대로 쓴다.
/// - `01`: 리터럴 필드, 동적 표에 넣는다(§6.2.1).
/// - `001`: 동적 표 크기 갱신(§6.3). 블록의 맨 앞에서만 올 수 있다(§4.2).
/// - `0000`, `0001`: 리터럴 필드, 표에 넣지 않는다(§6.2.2). `0001`은 중간 장치도 넣지 말라는 뜻(§6.2.3)이지만
///   이 모듈은 중계하지 않으므로 둘을 구분하지 않는다.
struct HPACKDecoder {
    /// 알린 SETTINGS_HEADER_TABLE_SIZE의 초깃값(RFC 9113 §6.5.2). 상대는 이보다 큰 표를 요구할 수 없다.
    static let defaultTableSize = 4_096
    /// 해제한 헤더 목록의 한도. 항목마다 이름·값 바이트 수에 32를 더해 센다(RFC 9113 §6.5.2의
    /// SETTINGS_MAX_HEADER_LIST_SIZE와 같은 방식). 압축된 블록이 작아도 동적 표 항목을 반복해 부르면
    /// 훨씬 큰 목록이 되므로 해제 결과에도 한도가 필요하다.
    static let defaultHeaderListSize = 65_536

    private var table: HPACKDynamicTable
    private let tableSizeLimit: Int
    private let headerListSizeLimit: Int

    init(tableSizeLimit: Int = defaultTableSize, headerListSizeLimit: Int = defaultHeaderListSize) {
        table = HPACKDynamicTable(maximumSize: tableSizeLimit)
        self.tableSizeLimit = tableSizeLimit
        self.headerListSizeLimit = headerListSizeLimit
    }

    /// 완성된 헤더 블록 하나를 해제한다. 오류가 나면 해제기는 더 쓸 수 없다.
    mutating func decode(_ block: [UInt8]) throws(HPACKError) -> [HeaderField] {
        var reader = ByteReader(block)
        var fields: [HeaderField] = []
        var listSize = 0
        while let first = reader.peek() {
            let field: HeaderField
            if first & 0x80 != 0 {
                field = try indexedField(try reader.hpackInteger(prefixBits: 7))
            } else if first & 0x40 != 0 {
                field = try literalField(from: &reader, prefixBits: 6)
                table.insert(field)
            } else if first & 0x20 != 0 {
                // 크기 갱신은 필드 표현보다 앞에 와야 한다.
                guard fields.isEmpty else { throw .invalidTableSizeUpdate }
                let newSize = try reader.hpackInteger(prefixBits: 5)
                guard newSize <= tableSizeLimit else { throw .invalidTableSizeUpdate }
                table.resize(to: newSize)
                continue
            } else {
                field = try literalField(from: &reader, prefixBits: 4)
            }
            listSize += field.name.utf8.count + field.value.utf8.count + 32
            guard listSize <= headerListSizeLimit else { throw .headerListTooLarge }
            fields.append(field)
        }
        return fields
    }

    /// 색인 1~61은 정적 표, 62부터는 동적 표다(§2.3.3).
    private func indexedField(_ index: Int) throws(HPACKError) -> HeaderField {
        let staticCount = HPACKStaticTable.fields.count
        if index >= 1 && index <= staticCount { return HPACKStaticTable.fields[index - 1] }
        guard index > staticCount, let field = table.field(at: index - staticCount - 1) else { throw .invalidIndex }
        return field
    }

    /// 리터럴 표현: 이름 색인(0이면 이름이 문자열로 이어진다)과 값 문자열.
    private func literalField(from reader: inout ByteReader, prefixBits: Int) throws(HPACKError) -> HeaderField {
        let nameIndex = try reader.hpackInteger(prefixBits: prefixBits)
        let name: String
        if nameIndex == 0 {
            name = try reader.hpackString()
        } else {
            name = try indexedField(nameIndex).name
        }
        return HeaderField(name, try reader.hpackString())
    }
}
