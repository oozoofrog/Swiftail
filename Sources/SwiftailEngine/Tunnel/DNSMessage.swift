// DNS 메시지의 바이트 배치와 해석 규칙은 golang.org/x/net의 `dns/dnsmessage/message.go`(BSD-3-Clause,
// Copyright 2009 The Go Authors)를 따르고, 응답 크기 규칙은 Tailscale의 `net/dns/resolver/forwarder.go`
// (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를 따른다. 규칙과 상수만 옮겼고 코드는 Swift로 새로 썼다.

/// MagicDNS 응답기가 다루는 만큼의 DNS 메시지 코덱(RFC 1035 4.1).
///
/// 질의는 터널 안의 어떤 앱이든 보낼 수 있는 신뢰할 수 없는 입력이다. 경계에서 한 번 머리와 첫 질문만 읽어
/// 검증된 값(`Query`)으로 바꾸고, 응답(`Response`)은 이름 압축 없이 쓴다. Go 로컬 응답도 압축을 쓰지 않으므로
/// 바이트가 같다. 입출력은 없다.
///
/// `docs/protocol-notes/dns-state-node.md` 3.1·4.2.4, `docs/contracts/SwiftailTunnel.md` 동작 D1·D6.
enum DNSMessage {
    /// 머리의 길이: ID, 플래그, 네 구역의 개수(각 2바이트, 빅엔디언).
    static let headerLength = 12
    /// 질의에 EDNS가 없을 때 UDP 응답의 최대 크기(RFC 1035 4.2.1).
    static let defaultUDPPayloadLimit = 512
    /// CLASS IN. 응답의 레코드는 모두 이 class다.
    static let internetClass: UInt16 = 1

    /// 질의에 맞춘 UDP 응답의 최대 크기. 노트 4.2.4, Go `findOPTRecord`·`checkResponseSizeAndSetTC`.
    ///
    /// ARCOUNT가 0이 아니고 메시지의 마지막 11바이트가 옵션 없는 EDNS 0 OPT 레코드(NAME 0, TYPE 41, 버전 0,
    /// RDLEN 0)면 그 광고 크기다. 옵션이 붙었거나 끝에 있지 않은 OPT는 보지 않고 512를 쓴다.
    /// 질문을 읽지 못한 질의에도 적용한다(Go는 원래 바이트에서 찾는다).
    static func udpPayloadLimit(ofQuery message: [UInt8]) -> Int {
        let optLength = 11
        guard message.count >= headerLength + optLength, readUInt16(message, at: 10) != 0 else {
            return defaultUDPPayloadLimit
        }
        let opt = message.count - optLength
        guard message[opt] == 0,
              readUInt16(message, at: opt + 1) == RecordType.opt.rawValue,
              message[opt + 6] == 0,
              readUInt16(message, at: opt + 9) == 0
        else { return defaultUDPPayloadLimit }
        return Int(readUInt16(message, at: opt + 3))
    }

    /// `offset`부터 2바이트를 빅엔디언으로 읽는다. 범위는 부르는 쪽이 확인한다.
    static func readUInt16(_ bytes: [UInt8], at offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    static func bigEndian(_ value: UInt16) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }

    static func bigEndian(_ value: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value >> 24), UInt8(truncatingIfNeeded: value >> 16),
         UInt8(truncatingIfNeeded: value >> 8), UInt8(truncatingIfNeeded: value)]
    }
}

// MARK: - 머리

extension DNSMessage {
    /// 머리의 ID와 플래그. 구역의 개수는 메시지를 읽고 쓸 때만 다룬다.
    struct Header: Equatable, Sendable {
        /// 질의와 응답을 짝짓는 ID. 응답은 질의 값을 그대로 쓴다.
        var id: UInt16
        var flags: Flags

        /// 플래그 16비트: QR·Opcode(4)·AA·TC·RD·RA·Z·AD·CD·RCODE(4). RFC 1035 4.1.1, AD·CD는 RFC 4035 3.2.
        struct Flags: OptionSet, Sendable {
            let rawValue: UInt16

            static let response = Flags(rawValue: 1 << 15)
            static let authoritative = Flags(rawValue: 1 << 10)
            static let truncated = Flags(rawValue: 1 << 9)
            static let recursionDesired = Flags(rawValue: 1 << 8)
            static let recursionAvailable = Flags(rawValue: 1 << 7)
            /// Z(예약) 비트. Go `dnsmessage.Header`에는 이 필드가 없어 Go 응답에서는 늘 0이다.
            static let reserved = Flags(rawValue: 1 << 6)
            /// RCODE 4비트의 자리.
            static let responseCodeBits = Flags(rawValue: 0x000F)
        }

        /// 메시지의 앞 4바이트(ID, 플래그)를 읽는다. 머리 12바이트가 다 없으면 nil.
        init?(parsing message: [UInt8]) {
            guard message.count >= DNSMessage.headerLength else { return nil }
            id = DNSMessage.readUInt16(message, at: 0)
            flags = Flags(rawValue: DNSMessage.readUInt16(message, at: 2))
        }

        init(id: UInt16, flags: Flags) {
            self.id = id
            self.flags = flags
        }

        /// RCODE 자리를 바꾼다.
        mutating func setResponseCode(_ code: ResponseCode) {
            flags.subtract(.responseCodeBits)
            flags.insert(Flags(rawValue: code.rawValue))
        }
    }

    /// 응답기가 쓰는 RCODE. RFC 1035 4.1.1.
    enum ResponseCode: UInt16, Sendable {
        case noError = 0
        case formatError = 1
        case serverFailure = 2
        case nameError = 3
        case notImplemented = 4
    }

    /// 레코드 TYPE(QTYPE 포함). 정의되지 않은 값도 담는다.
    struct RecordType: Hashable, Sendable {
        let rawValue: UInt16

        static let a = RecordType(rawValue: 1)
        static let ns = RecordType(rawValue: 2)
        static let soa = RecordType(rawValue: 6)
        static let ptr = RecordType(rawValue: 12)
        static let hinfo = RecordType(rawValue: 13)
        static let aaaa = RecordType(rawValue: 28)
        static let opt = RecordType(rawValue: 41)
        static let axfr = RecordType(rawValue: 252)
        /// QTYPE `*`(ANY). Go `dnsmessage.TypeALL`.
        static let any = RecordType(rawValue: 255)
    }
}
