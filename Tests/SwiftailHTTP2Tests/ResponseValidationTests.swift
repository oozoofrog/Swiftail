// 검토 발견 반영: 응답 헤더·트레일러 검증(RFC 9113 §8.2, §8.3), 본문 길이와 content-length(§8.1.1), 101(§8.6).

import Testing

@testable import SwiftailHTTP2

/// 서버(상대) 역할로 응답 머리 뒤 DATA·트레일러까지 보내는 시험 도구.
private struct Exchange {
    var connection: HTTP2ClientConnection
    let id: HTTP2StreamID

    init(method: String = "GET") throws {
        connection = try HTTP2ClientConnection.established()
        id = try connection.startRequest(
            HTTP2ClientConnection.Request(method: method, path: "/", authority: "tail0001"), body: nil)
        _ = connection.takeOutboundBytes()
    }

    mutating func receive(_ bytes: [UInt8]) throws -> [HTTP2ClientConnection.Event] {
        try connection.receive(bytes)
    }

    /// 헤더 블록(필드 목록)을 그대로 HEADERS(END_HEADERS)로 보낸다.
    static func headers(_ fields: [HeaderField], endStream: Bool = false) -> [UInt8] {
        frameBytes(1, flags: 0x4 | (endStream ? 0x1 : 0), stream: 1, payload: HPACKEncoder.encode(fields))
    }
}

@Suite("응답 헤더 검증")
struct ResponseHeaderValidationTests {
    @Test("잘못된 이름·값·연결 전용 필드가 든 응답은 그 스트림의 PROTOCOL_ERROR")
    func invalidFields() throws {
        let bad: [HeaderField] = [
            HeaderField("", "x"),                       // 빈 이름
            HeaderField("a:b", "x"),                    // 이름 중간의 ':'
            HeaderField("a b", "x"),                    // 공백이 든 이름
            HeaderField("X-Upper", "x"),                // 대문자
            HeaderField("x", "a\r\nb: c"),              // CR·LF가 든 값
            HeaderField("x", "a\nb"),
            HeaderField("x", "a\rb"),
            HeaderField("x", "a\u{0}b"),                // NUL
            HeaderField("connection", "close"),         // 연결 전용 필드
            HeaderField("keep-alive", "timeout=5"),
            HeaderField("proxy-connection", "keep-alive"),
            HeaderField("transfer-encoding", "chunked"),
            HeaderField("upgrade", "h2c"),
            HeaderField("te", "gzip"),                  // trailers 외의 te
        ]
        for field in bad {
            var exchange = try Exchange()
            let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200"), field]))
            #expect(events == [.streamClosed(exchange.id, resetCode: 1)], "\(field)")
            #expect(try exchange.connection.takeOutboundFrames() == [.rstStream(exchange.id, code: 1)], "\(field)")
        }
    }

    @Test("te: trailers와 token 기호가 든 이름은 받아들인다")
    func validFields() throws {
        var exchange = try Exchange()
        let fields = [HeaderField("te", "trailers"), HeaderField("x-a.b_c~d", "a b\tc"), HeaderField("grpc-status", "0")]
        let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200")] + fields))
        #expect(events == [.responseHead(exchange.id, status: 200, headers: fields)])
    }

    @Test("트레일러에 의사 헤더나 잘못된 필드가 있으면 스트림 오류")
    func invalidTrailers() throws {
        let bad: [HeaderField] = [
            HeaderField(":status", "200"), HeaderField(":path", "/"), HeaderField("X-Upper", "1"), HeaderField("a:b", "1"),
            HeaderField("x", "a\r\nb"), HeaderField("connection", "close"), HeaderField("", "1"),
        ]
        for field in bad {
            var exchange = try Exchange()
            let events = try exchange.receive(
                responseHeadBytes(stream: 1) + dataBytes(stream: 1, [1]) + Exchange.headers([field], endStream: true))
            #expect(events.suffix(2) == [.responseData(exchange.id, [1]), .streamClosed(exchange.id, resetCode: 1)], "\(field)")
            #expect(try exchange.connection.takeOutboundFrames().contains(.rstStream(exchange.id, code: 1)), "\(field)")
        }
    }

    @Test("요청 헤더도 같은 규칙: 이름 중간의 ':'와 연결 전용 필드는 invalidRequest")
    func invalidRequestHeaders() throws {
        var connection = try HTTP2ClientConnection.established()
        let bad: [HeaderField] = [
            HeaderField("a:b", "x"), HeaderField("connection", "close"), HeaderField("keep-alive", "1"),
            HeaderField("proxy-connection", "x"), HeaderField("transfer-encoding", "chunked"), HeaderField("upgrade", "h2c"),
            HeaderField("te", "gzip"), HeaderField("x", "a\u{0}b"),
        ]
        for field in bad {
            let request = HTTP2ClientConnection.Request(method: "GET", path: "/", authority: "tail0001", headers: [field])
            #expect(throws: HTTP2Error.invalidRequest, "\(field)") { try connection.startRequest(request, body: nil) }
        }
        let allowed = HTTP2ClientConnection.Request(
            method: "GET", path: "/", authority: "tail0001", headers: [HeaderField("te", "trailers")])
        #expect(try connection.startRequest(allowed, body: nil).rawValue == 1)
    }
}

@Suite("본문 길이와 상태")
struct BodyLengthTests {
    private let length2 = HeaderField("content-length", "2")

    @Test("content-length보다 짧게 끝나면 스트림 오류")
    func shortBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1], endStream: true))
        #expect(events == [
            .responseHead(exchange.id, status: 200, headers: [length2]), .responseData(exchange.id, [1]),
            .streamClosed(exchange.id, resetCode: 1),
        ])
        #expect(try exchange.connection.takeOutboundFrames().contains(.rstStream(exchange.id, code: 1)))
    }

    @Test("content-length보다 길면 넘는 DATA를 내지 않고 스트림 오류")
    func longBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1]) + dataBytes(stream: 1, [2, 3]))
        #expect(events == [
            .responseHead(exchange.id, status: 200, headers: [length2]), .responseData(exchange.id, [1]),
            .streamClosed(exchange.id, resetCode: 1),
        ])
    }

    @Test("content-length와 같은 합계면 여러 DATA로 나뉘어도 정상 종료")
    func exactBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1]) + dataBytes(stream: 1, [2], endStream: true))
        #expect(events.last == .streamClosed(exchange.id, resetCode: nil))
        #expect(events.count == 4)
    }

    @Test("본문 없이 END_STREAM으로 끝나는데 content-length가 0이 아니면 스트림 오류")
    func missingBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200"), length2], endStream: true))
        #expect(events == [.responseHead(exchange.id, status: 200, headers: [length2]), .streamClosed(exchange.id, resetCode: 1)])
    }

    @Test("트레일러로 끝나도 본문 합계를 맞춰 본다")
    func trailerAfterShortBody() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(
            Exchange.headers([HeaderField(":status", "200"), length2]) + dataBytes(stream: 1, [1])
                + Exchange.headers([HeaderField("grpc-status", "0")], endStream: true))
        #expect(events.last == .streamClosed(exchange.id, resetCode: 1))
    }

    @Test("content-length가 여러 개이거나 숫자가 아니면 스트림 오류")
    func invalidContentLength() throws {
        let bad: [[HeaderField]] = [
            [HeaderField("content-length", "1"), HeaderField("content-length", "1")],
            [HeaderField("content-length", "abc")], [HeaderField("content-length", "-1")], [HeaderField("content-length", "+1")],
            [HeaderField("content-length", "")], [HeaderField("content-length", "1 ")],
            [HeaderField("content-length", "99999999999999999999999")],
        ]
        for fields in bad {
            var exchange = try Exchange()
            let events = try exchange.receive(Exchange.headers([HeaderField(":status", "200")] + fields))
            #expect(events == [.streamClosed(exchange.id, resetCode: 1)], "\(fields)")
        }
    }

    @Test("HEAD 응답과 204·304는 content-length가 있어도 본문 없이 정상 종료")
    func noBodyResponses() throws {
        let length = HeaderField("content-length", "5")
        for (method, status) in [("HEAD", "200"), ("GET", "204"), ("GET", "304")] {
            var exchange = try Exchange(method: method)
            let events = try exchange.receive(Exchange.headers([HeaderField(":status", status), length], endStream: true))
            #expect(events == [
                .responseHead(exchange.id, status: Int(status) ?? 0, headers: [length]), .streamClosed(exchange.id, resetCode: nil),
            ], "\(method) \(status)")
        }
    }

    @Test("101은 HTTP/2에서 쓰지 않으므로 임시 응답으로 넘기지 않고 스트림 오류")
    func switchingProtocols() throws {
        var exchange = try Exchange()
        let events = try exchange.receive(responseHeadBytes(stream: 1, status: "101"))
        #expect(events == [.streamClosed(exchange.id, resetCode: 1)])
        #expect(try exchange.connection.takeOutboundFrames() == [.rstStream(exchange.id, code: 1)])
    }
}
