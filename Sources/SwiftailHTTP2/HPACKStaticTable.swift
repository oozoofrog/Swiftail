/// The HPACK static table.
///
/// The encoder and decoder agree in advance on these 61 header fields. Indices 1~61 refer to this table, and indices from 62 refer to the dynamic table.
/// Frequently used fields can be sent as single-byte indices.
///
/// RFC 7541 Appendix A (https://www.rfc-editor.org/rfc/rfc7541#appendix-A). The values were copied mechanically from the original table
/// and checked entry by entry against `static_table.go` in Go's `golang.org/x/net/http2/hpack`.
enum HPACKStaticTable {
    /// The field at index `i` is `fields[i - 1]`.
    static let fields: [HeaderField] = [
        HeaderField(":authority", ""),  // 1
        HeaderField(":method", "GET"),  // 2
        HeaderField(":method", "POST"),  // 3
        HeaderField(":path", "/"),  // 4
        HeaderField(":path", "/index.html"),  // 5
        HeaderField(":scheme", "http"),  // 6
        HeaderField(":scheme", "https"),  // 7
        HeaderField(":status", "200"),  // 8
        HeaderField(":status", "204"),  // 9
        HeaderField(":status", "206"),  // 10
        HeaderField(":status", "304"),  // 11
        HeaderField(":status", "400"),  // 12
        HeaderField(":status", "404"),  // 13
        HeaderField(":status", "500"),  // 14
        HeaderField("accept-charset", ""),  // 15
        HeaderField("accept-encoding", "gzip, deflate"),  // 16
        HeaderField("accept-language", ""),  // 17
        HeaderField("accept-ranges", ""),  // 18
        HeaderField("accept", ""),  // 19
        HeaderField("access-control-allow-origin", ""),  // 20
        HeaderField("age", ""),  // 21
        HeaderField("allow", ""),  // 22
        HeaderField("authorization", ""),  // 23
        HeaderField("cache-control", ""),  // 24
        HeaderField("content-disposition", ""),  // 25
        HeaderField("content-encoding", ""),  // 26
        HeaderField("content-language", ""),  // 27
        HeaderField("content-length", ""),  // 28
        HeaderField("content-location", ""),  // 29
        HeaderField("content-range", ""),  // 30
        HeaderField("content-type", ""),  // 31
        HeaderField("cookie", ""),  // 32
        HeaderField("date", ""),  // 33
        HeaderField("etag", ""),  // 34
        HeaderField("expect", ""),  // 35
        HeaderField("expires", ""),  // 36
        HeaderField("from", ""),  // 37
        HeaderField("host", ""),  // 38
        HeaderField("if-match", ""),  // 39
        HeaderField("if-modified-since", ""),  // 40
        HeaderField("if-none-match", ""),  // 41
        HeaderField("if-range", ""),  // 42
        HeaderField("if-unmodified-since", ""),  // 43
        HeaderField("last-modified", ""),  // 44
        HeaderField("link", ""),  // 45
        HeaderField("location", ""),  // 46
        HeaderField("max-forwards", ""),  // 47
        HeaderField("proxy-authenticate", ""),  // 48
        HeaderField("proxy-authorization", ""),  // 49
        HeaderField("range", ""),  // 50
        HeaderField("referer", ""),  // 51
        HeaderField("refresh", ""),  // 52
        HeaderField("retry-after", ""),  // 53
        HeaderField("server", ""),  // 54
        HeaderField("set-cookie", ""),  // 55
        HeaderField("strict-transport-security", ""),  // 56
        HeaderField("transfer-encoding", ""),  // 57
        HeaderField("user-agent", ""),  // 58
        HeaderField("vary", ""),  // 59
        HeaderField("via", ""),  // 60
        HeaderField("www-authenticate", ""),  // 61
    ]
}
