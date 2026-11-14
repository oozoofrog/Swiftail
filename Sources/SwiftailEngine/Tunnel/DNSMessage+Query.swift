// 질의 해석의 순서와 범위는 Tailscale의 `net/dns/resolver/tsdns.go` `parseQuery`(BSD-3-Clause,
// Copyright (c) Tailscale Inc & contributors)와 golang.org/x/net `dns/dnsmessage`의 `Parser.Start`·`Parser.Question`
// (BSD-3-Clause, Copyright 2009 The Go Authors)을 따른다. 코드는 Swift로 새로 썼다.

extension DNSMessage {
    /// 질문 하나: 이름, QTYPE, QCLASS.
    struct Question: Equatable, Sendable {
        /// 질의에 온 대소문자 그대로의 이름.
        var name: Name
        var type: RecordType
        /// 응답에도 질의 값을 그대로 쓴다.
        var recordClass: UInt16
    }

    /// 검증된 DNS 질의: 머리와 첫 질문.
    ///
    /// Go 응답기처럼 머리와 첫 질문만 읽는다(노트 3.1). 질문이 둘 이상이어도 나머지와 답변·권한·추가 구역은 읽지 않으며,
    /// 응답에는 첫 질문만 싣는다. Opcode는 보지 않는다.
    struct Query: Equatable, Sendable {
        let header: Header
        let question: Question

        /// 질의를 읽지 못한 이유. 모두 FORMERR(질문 없음)로 이어진다(노트 3.1 RCODE 표 1행).
        enum ParseError: Error, Equatable, Sendable {
            /// 머리 12바이트가 다 없다.
            case truncatedHeader
            /// QR 비트가 켜진 응답 메시지다.
            case notAQuery
            /// QDCOUNT가 0이다.
            case noQuestion
            /// 질문 이름을 읽지 못했다.
            case malformedName(Name.ParseError)
            /// 이름 뒤에 QTYPE·QCLASS 4바이트가 다 없다.
            case truncatedQuestion
        }

        /// 바이트열을 질의로 해석한다. 어떤 입력에서도 트랩 없이 값이나 오류를 낸다.
        init(parsing message: [UInt8]) throws(ParseError) {
            guard let header = Header(parsing: message) else { throw .truncatedHeader }
            guard !header.flags.contains(.response) else { throw .notAQuery }
            guard DNSMessage.readUInt16(message, at: 4) > 0 else { throw .noQuestion }
            let name: Name
            let end: Int
            do {
                (name, end) = try Name.read(from: message, at: DNSMessage.headerLength)
            } catch {
                throw .malformedName(error)
            }
            guard end + 4 <= message.count else { throw .truncatedQuestion }
            self.header = header
            question = Question(
                name: name,
                type: RecordType(rawValue: DNSMessage.readUInt16(message, at: end)),
                recordClass: DNSMessage.readUInt16(message, at: end + 2)
            )
        }
    }
}
