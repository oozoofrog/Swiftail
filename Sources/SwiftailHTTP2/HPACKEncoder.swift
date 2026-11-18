/// An HPACK encoder that turns header fields into header block bytes.
///
/// Uses only the simplest valid representation. Encodes every field as "literal without indexing, new name" (RFC 7541 §6.2.2,
/// first byte `0x00`) and sends strings without Huffman coding. Omitting the dynamic table keeps the encoder stateless
/// and independent of the peer's SETTINGS_HEADER_TABLE_SIZE.
///
/// shortcut: omits static table indices and the dynamic table (slightly larger headers per request), add support if request volume makes header size a problem.
enum HPACKEncoder {
    static func encode(_ fields: [HeaderField]) -> [UInt8] {
        var block: [UInt8] = []
        for field in fields {
            block.append(0x00)
            HPACKEncoding.appendString(field.name, to: &block)
            HPACKEncoding.appendString(field.value, to: &block)
        }
        return block
    }
}
