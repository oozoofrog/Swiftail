/// An HPACK decoder that turns header block bytes back into a list of header fields.
///
/// A connection has one decoder and must feed it every header block from the peer in arrival order because the dynamic
/// table carries across blocks. Each block is a sequence of field representations. The high bits of the first byte
/// indicate the type (RFC 7541 §6).
///
/// - `1`: Indexed field (§6.1). Uses an entry from the static or dynamic table as is.
/// - `01`: Literal field added to the dynamic table (§6.2.1).
/// - `001`: Dynamic table size update (§6.3). May appear only at the start of the block (§4.2).
/// - `0000`: Literal without indexing (§6.2.2). `0001`: Literal never indexed (§6.2.3), which also forbids intermediaries from indexing the field.
///   This module does not proxy and treats both the same.
struct HPACKDecoder {
    /// The initial advertised SETTINGS_HEADER_TABLE_SIZE (RFC 9113 §6.5.2). The peer cannot request a larger table.
    static let defaultTableSize = 4_096
    /// The limit on the decoded header list. Counts the bytes of each entry's name and value plus 32 (the same method as
    /// SETTINGS_MAX_HEADER_LIST_SIZE in RFC 9113 §6.5.2). Even a small compressed block can expand to a much larger
    /// list by repeatedly indexing dynamic table entries, so the decoded result also needs a limit.
    static let defaultHeaderListSize = 65_536

    private var table: HPACKDynamicTable
    private let tableSizeLimit: Int
    private let headerListSizeLimit: Int

    init(tableSizeLimit: Int = defaultTableSize, headerListSizeLimit: Int = defaultHeaderListSize) {
        table = HPACKDynamicTable(maximumSize: tableSizeLimit)
        self.tableSizeLimit = tableSizeLimit
        self.headerListSizeLimit = headerListSizeLimit
    }

    /// Decodes one complete header block. An error leaves the decoder unusable.
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
                // Size updates must precede field representations.
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

    /// Indices 1~61 refer to the static table and indices from 62 refer to the dynamic table (§2.3.3).
    private func indexedField(_ index: Int) throws(HPACKError) -> HeaderField {
        let staticCount = HPACKStaticTable.fields.count
        if index >= 1 && index <= staticCount { return HPACKStaticTable.fields[index - 1] }
        guard index > staticCount, let field = table.field(at: index - staticCount - 1) else { throw .invalidIndex }
        return field
    }

    /// A literal representation carries a name index (0 means the name follows as a string) and a value string.
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
