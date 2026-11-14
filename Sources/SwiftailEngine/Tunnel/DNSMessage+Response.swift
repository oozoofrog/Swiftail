// 응답의 배치와 TTL·SOA 값은 Tailscale의 `net/dns/resolver/tsdns.go` `marshalResponse`·`marshalSOA`와
// `forwarder.go` `checkResponseSizeAndSetTC`(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를 따른다.
// 상수와 배치만 옮겼고 코드는 Swift로 새로 썼다.

import SwiftailBase

extension DNSMessage {
    /// 응답기가 내는 응답 하나: 질문 0·1개, 답변 0·1개, 권한 구역의 SOA 0·1개. 추가 구역(EDNS OPT 포함)은 싣지 않는다.
    ///
    /// 이름은 압축하지 않는다(노트 3.1 "쓰기"). 머리 플래그를 어떻게 정할지는 부르는 쪽(응답기)의 몫이다.
    struct Response: Sendable {
        var header: Header
        /// 응답에 되돌릴 질문. FORMERR 가운데 질문을 읽지 못한 것은 nil이다.
        var question: Question?
        /// 답변 레코드. 소유자 이름은 질문 이름이므로 `question`이 있을 때만 쓴다.
        var answer: Answer?
        /// 부정 응답(NXDOMAIN, 그 타입의 레코드가 없는 NOERROR)의 권한 구역에 실을 SOA.
        var authority: StartOfAuthority?

        /// 답변 레코드의 RDATA.
        enum Answer: Equatable, Sendable {
            /// IPv4면 A, IPv6면 AAAA.
            case address(IPAddress)
            /// PTR. 대상 이름(끝 점 포함 FQDN).
            case pointer(Name)
        }

        /// 권한 구역의 SOA. 받은 쪽 캐시가 부정 응답을 10초만 두게 하는 것이 목적이고 나머지 필드는 자리 채움이다(RFC 2308).
        struct StartOfAuthority: Equatable, Sendable {
            /// 이름을 포함하는 응답기의 영역. 소유자, MNAME, RNAME에 모두 쓴다.
            var zone: Name
            /// SERIAL. Go는 지금 시각의 유닉스 초를 쓴다.
            var serial: UInt32
        }

        /// A·AAAA·PTR 답변의 TTL(초). 원본이 메모리의 netmap이라 다시 묻는 비용이 거의 없다. Go `defaultTTL`.
        static let answerTTL: UInt32 = 5
        /// SOA의 TTL과 REFRESH·RETRY·EXPIRE·MINIMUM(초). Go `negativeTTL`.
        static let negativeTTL: UInt32 = 10

        /// 응답을 바이트로 쓴다.
        ///
        /// - Parameter limit: UDP 응답의 최대 크기(`DNSMessage.udpPayloadLimit(ofQuery:)`). 응답이 이보다 길면 TC 비트만 켜고
        ///   자르지는 않는다(노트 4.2.4, Go와 같다). nil이면 크기를 보지 않는다.
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

        /// 자원 레코드: NAME, TYPE, CLASS IN, TTL, RDLENGTH, RDATA. RDATA는 이름 둘(≤ 255바이트씩)과 20바이트를 넘지 않는다.
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
