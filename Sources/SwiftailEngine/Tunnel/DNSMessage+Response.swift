// The response layout and TTL and SOA values follow `marshalResponse` and `marshalSOA` in Tailscale's `net/dns/resolver/tsdns.go` and
// `checkResponseSizeAndSetTC` in `forwarder.go` (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors).
// Only the constants and layout were ported. The code was written from scratch in Swift.

import SwiftailBase

extension DNSMessage {
    /// One response from the responder, with 0 or 1 questions, 0 or 1 answers, and 0 or 1 SOA records in the authority section. Omits the additional section, including EDNS OPT.
    ///
    /// Does not compress names (notes 3.1 "Writing"). The caller (the responder) chooses the header flags.
    struct Response: Sendable {
        var header: Header
        /// The question to echo in the response. Nil for FORMERR when the question could not be read.
        var question: Question?
        /// The answer record. Its owner name is the question name, so it is written only when `question` is present.
        var answer: Answer?
        /// The SOA to include in the authority section of a negative response (NXDOMAIN or NOERROR with no record of that type).
        var authority: StartOfAuthority?

        /// RDATA for the answer record.
        enum Answer: Equatable, Sendable {
            /// A for IPv4, AAAA for IPv6.
            case address(IPAddress)
            /// PTR with a target name (FQDN with trailing dot).
            case pointer(Name)
        }

        /// The authority section's SOA. Its purpose is to limit negative caching by the recipient to 10 seconds. The remaining fields are placeholders (RFC 2308).
        struct StartOfAuthority: Equatable, Sendable {
            /// The responder zone containing the name. Used for the owner, MNAME, and RNAME.
            var zone: Name
            /// SERIAL. Go uses the current time in Unix seconds.
            var serial: UInt32
        }

        /// The TTL for A, AAAA, and PTR answers (seconds). The source is the in-memory netmap, so querying again has almost no cost. Go `defaultTTL`.
        static let answerTTL: UInt32 = 5
        /// The SOA TTL and REFRESH, RETRY, EXPIRE, and MINIMUM (seconds). Go `negativeTTL`.
        static let negativeTTL: UInt32 = 10

        /// Writes the response as bytes.
        ///
        /// - Parameter limit: The maximum UDP response size (`DNSMessage.udpPayloadLimit(ofQuery:)`). If the response is larger, sets only the TC bit
        ///   without truncating it (notes 4.2.4, as in Go). Nil skips the size check.
        func encoded(udpPayloadLimit limit: Int? = nil) -> [UInt8] {
            var questionSection: [UInt8] = []
            var answerSection: [UInt8] = []
            if let question {
                questionSection = question.name.wireFormat
                    + DNSMessage.bigEndian(question.type.rawValue)
                    + DNSMessage.bigEndian(question.recordClass)
                if let answer {
                    answerSection = record(owner: question.name, answer)
                }
            }
            let authoritySection = authority.map(soaRecord) ?? []

            var bytes = DNSMessage.bigEndian(header.id) + DNSMessage.bigEndian(header.flags.rawValue)
            for section in [questionSection, answerSection, authoritySection] {
                bytes += DNSMessage.bigEndian(UInt16(section.isEmpty ? 0 : 1))
            }
            bytes += DNSMessage.bigEndian(UInt16(0))
            bytes += questionSection + answerSection + authoritySection
            if let limit, bytes.count > limit {
                bytes[2] |= UInt8(Header.Flags.truncated.rawValue >> 8)
            }
            return bytes
        }

        private func record(owner: Name, _ answer: Answer) -> [UInt8] {
            switch answer {
            case .address(let address):
                record(owner: owner, type: address.isIPv4 ? .a : .aaaa, ttl: Self.answerTTL, data: address.bytes)
            case .pointer(let target):
                record(owner: owner, type: .ptr, ttl: Self.answerTTL, data: target.wireFormat)
            }
        }

        private func soaRecord(_ authority: StartOfAuthority) -> [UInt8] {
            let zone = authority.zone.wireFormat
            var data = zone + zone + DNSMessage.bigEndian(authority.serial)
            for _ in 0..<4 {
                data += DNSMessage.bigEndian(Self.negativeTTL)
            }
            return record(owner: authority.zone, type: .soa, ttl: Self.negativeTTL, data: data)
        }

        /// A resource record contains NAME, TYPE, CLASS IN, TTL, RDLENGTH, and RDATA. RDATA is at most the combined size of two names (≤ 255 bytes each) plus 20 bytes.
        private func record(owner: Name, type: RecordType, ttl: UInt32, data: [UInt8]) -> [UInt8] {
            owner.wireFormat
                + DNSMessage.bigEndian(type.rawValue)
                + DNSMessage.bigEndian(DNSMessage.internetClass)
                + DNSMessage.bigEndian(ttl)
                + DNSMessage.bigEndian(UInt16(data.count))
                + data
        }
    }
}
