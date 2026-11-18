/// The reason an HPACK header block could not be decoded.
///
/// Failing to decode even one header block leaves the compression state out of sync with the peer, so the connection ends
/// with COMPRESSION_ERROR (RFC 9113 §4.3). Only `headerListTooLarge` maps to ENHANCE_YOUR_CALM.
enum HPACKError: Error, Equatable {
    /// An integer or string was cut off at the end of the block.
    case truncated
    /// An integer exceeds the limit (RFC 7541 §5.1 requires implementations to set a limit).
    case integerOverflow
    /// An index is 0 or outside the static and dynamic tables.
    case invalidIndex
    /// The Huffman code is invalid, contains EOS, or has invalid padding (§5.2).
    case invalidHuffman
    /// The string is invalid UTF-8. Headers in this module use `String`.
    case invalidUTF8
    /// A dynamic table size update followed a field representation or exceeded the advertised limit (SETTINGS_HEADER_TABLE_SIZE) (§4.2).
    case invalidTableSizeUpdate
    /// The decoded header list exceeds the limit.
    case headerListTooLarge
}
