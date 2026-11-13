/// HPACK 정적 표.
///
/// 압축기와 해제기가 미리 합의한 61개 헤더 필드다. 색인 1~61이 이 표를 가리키고, 62부터는 동적 표다.
/// 자주 쓰는 필드는 한 바이트 색인으로 줄여 보낼 수 있다.
///
/// RFC 7541 부록 A (https://www.rfc-editor.org/rfc/rfc7541#appendix-A). 값은 원문 표에서 기계적으로
/// 옮겼고, Go `golang.org/x/net/http2/hpack`의 `static_table.go`와 항목별로 대조했다.
enum HPACKStaticTable {
    /// 색인 `i`의 필드는 `fields[i - 1]`이다.
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
