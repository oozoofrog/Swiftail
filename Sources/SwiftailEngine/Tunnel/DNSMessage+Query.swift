// Query parsing order and scope follow `parseQuery` in Tailscale's `net/dns/resolver/tsdns.go` (BSD-3-Clause,
// Copyright (c) Tailscale Inc & contributors), and `Parser.Start` and `Parser.Question` in golang.org/x/net `dns/dnsmessage`
// (BSD-3-Clause, Copyright 2009 The Go Authors). The code was written from scratch in Swift.

extension DNSMessage {
    /// One question, consisting of name, QTYPE, and QCLASS.
    struct Question: Equatable, Sendable {
        /// The name with its original query casing.
        var name: Name
        var type: RecordType
        /// The response reuses the query values verbatim.
        var recordClass: UInt16
    }

    /// A validated DNS query containing the header and the first question.
    ///
    /// Reads only the header and first question, as the Go responder does (notes §3.1). Even when there are multiple questions, the remaining questions and the answer, authority,
    /// and additional sections are left unread. The response includes only the first question. Ignores Opcode.
    struct Query: Equatable, Sendable {
        let header: Header
        let question: Question

        /// A reason the query could not be read. All reasons yield FORMERR without a question (notes 3.1, row 1 of the RCODE table).
        enum ParseError: Error, Equatable, Sendable {
            /// Fewer than the 12 header bytes are present.
            case truncatedHeader
            /// The QR bit is set, marking a response message.
            case notAQuery
            /// QDCOUNT is 0.
            case noQuestion
            /// The question name could not be read.
            case malformedName(Name.ParseError)
            /// Fewer than all 4 QTYPE and QCLASS bytes are present after the name.
            case truncatedQuestion
        }

        /// Parses a byte sequence as a query. Returns a value or an error for any input without trapping.
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
