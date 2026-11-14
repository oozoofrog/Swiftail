import Testing

import SwiftailBase

@testable import SwiftailNetstack

/// 세그먼트 해석(동작 W 1·2·4, X1). 입력 바이트는 `RawPacket`이 구현과 따로 짠다.
@Suite("TCP 세그먼트 해석")
struct TCPSegmentParsingTests {
    private func parse(_ bytes: [UInt8]) throws(TCPSegment.ParseError) -> TCPSegment {
        try TCPSegment(parsingIPPacket: bytes)
    }

    private func parseError(_ bytes: [UInt8]) -> TCPSegment.ParseError? {
        do {
            _ = try TCPSegment(parsingIPPacket: bytes)
            return nil
        } catch {
            return error
        }
    }

    // MARK: - 정상 입력

    @Test("IPv4 SYN: 주소·포트·번호·플래그·창·MSS·Window Scale")
    func ipv4SYN() throws {
        let segment = RawPacket.segment(
            sourcePort: 51_000, destinationPort: 443, sequence: 0xFFFF_FFF0, acknowledgment: 0,
            flags: 0x02, window: 65_535, options: [2, 4, 0x04, 0xD8, 1, 3, 3, 7])
        let parsed = try parse(RawPacket.ipv4(segment: segment))
        #expect(parsed.source == WireHosts.endpoint(WireHosts.v4a, 51_000))
        #expect(parsed.destination == WireHosts.endpoint(WireHosts.v4b, 443))
        #expect(parsed.sequenceNumber == SequenceNumber(0xFFFF_FFF0))
        #expect(parsed.acknowledgmentNumber == SequenceNumber(0))
        #expect(parsed.flags == [.syn])
        #expect(parsed.window == 65_535)
        #expect(parsed.maximumSegmentSize == 1240)
        #expect(parsed.windowScale == 7)
        #expect(parsed.payload.isEmpty)
        #expect(parsed.sequenceLength == 1)
    }

    @Test("IPv6 데이터 세그먼트")
    func ipv6Data() throws {
        let payload = Array("hello".utf8)
        let segment = RawPacket.segment(
            sequence: 100, acknowledgment: 200, flags: 0x18, window: 512, payload: payload)
        let parsed = try parse(RawPacket.ipv6(segment: segment))
        #expect(parsed.source == WireHosts.endpoint(WireHosts.v6a, 40_000))
        #expect(parsed.destination == WireHosts.endpoint(WireHosts.v6b, 443))
        #expect(parsed.sequenceNumber == SequenceNumber(100))
        #expect(parsed.acknowledgmentNumber == SequenceNumber(200))
        #expect(parsed.flags == [.ack, .psh])
        #expect(parsed.window == 512)
        #expect(parsed.maximumSegmentSize == nil)
        #expect(parsed.windowScale == nil)
        #expect(parsed.payload == payload)
        #expect(parsed.sequenceLength == 5)
    }

    @Test("IPv4 옵션이 있는 패킷(IHL 6, 8)")
    func ipv4Options() throws {
        let segment = RawPacket.segment(flags: 0x10, payload: [1, 2, 3])
        for ipOptions in [[UInt8](repeating: 1, count: 4), [UInt8](repeating: 1, count: 12)] {
            let parsed = try parse(RawPacket.ipv4(segment: segment, ipOptions: ipOptions))
            #expect(parsed.payload == [1, 2, 3], "IP 옵션 \(ipOptions.count)바이트")
            #expect(parsed.source.port == 40_000)
        }
        // IHL이 15(60바이트)인 최대 머리.
        let maximum = try parse(RawPacket.ipv4(segment: segment, ipOptions: [UInt8](repeating: 0, count: 40)))
        #expect(maximum.payload == [1, 2, 3])
    }

    @Test("선언된 길이 뒤의 바이트(링크 계층 패딩)는 버린다")
    func trailingPaddingIgnored() throws {
        let segment = RawPacket.segment(payload: [9, 8, 7])
        for packet in [RawPacket.ipv4(segment: segment), RawPacket.ipv6(segment: segment)] {
            let exact = try parse(packet)
            let padded = try parse(packet + [0xAA, 0xBB, 0xCC])
            #expect(padded == exact)
            #expect(padded.payload == [9, 8, 7])
        }
    }

    @Test("홀수 길이 데이터의 체크섬")
    func oddLengthPayload() throws {
        for count in [1, 3, 1239] {
            let payload = [UInt8](repeating: 0xA5, count: count)
            let segment = RawPacket.segment(payload: payload)
            #expect(try parse(RawPacket.ipv4(segment: segment)).payload == payload)
            #expect(try parse(RawPacket.ipv6(segment: segment)).payload == payload)
        }
    }

    @Test("확인 번호·시퀀스 번호는 2³² 경계의 값도 그대로")
    func sequenceNumbersAtTheEdge() throws {
        let segment = RawPacket.segment(sequence: 0xFFFF_FFFF, acknowledgment: 0x8000_0000, flags: 0x11)
        let parsed = try parse(RawPacket.ipv4(segment: segment))
        #expect(parsed.sequenceNumber == SequenceNumber(0xFFFF_FFFF))
        #expect(parsed.acknowledgmentNumber == SequenceNumber(0x8000_0000))
        #expect(parsed.flags == [.fin, .ack])
        #expect(parsed.sequenceLength == 1)
    }

    @Test("URG·CWR·ECE와 urgent pointer는 무시한다")
    func ignoredFields() throws {
        let segment = RawPacket.segment(flags: 0xF0 | 0x08, urgent: 0xBEEF)
        let parsed = try parse(RawPacket.ipv4(segment: segment))
        #expect(parsed.flags == [.ack, .psh])
    }

    // MARK: - 잘림과 머리 길이

    @Test("어디서 잘려도 해석하지 못한다", arguments: [4, 6])
    func truncated(version: Int) throws {
        let segment = RawPacket.segment(flags: 0x02, options: [2, 4, 0x04, 0xD8], payload: [1, 2, 3, 4, 5])
        let packet = version == 4 ? RawPacket.ipv4(segment: segment) : RawPacket.ipv6(segment: segment)
        _ = try parse(packet)
        for length in 0..<packet.count {
            let error = parseError(Array(packet[..<length]))
            #expect(error == .malformed, "길이 \(length)")
        }
    }

    @Test("IP 머리가 틀린 것: 버전, IHL 4, IHL이 선언 길이 밖, 선언 길이가 버퍼 밖")
    func badIPHeader() {
        let segment = RawPacket.segment()
        let good = RawPacket.ipv4(segment: segment)
        #expect(parseError([]) == .malformed)
        #expect(parseError([UInt8](repeating: 0, count: 40)) == .malformed)  // 버전 0
        var version5 = good
        version5[0] = 0x55
        #expect(parseError(version5) == .malformed)
        var ihl4 = good
        ihl4[0] = 0x44
        #expect(parseError(ihl4) == .malformed)
        var ihlBeyond = good
        ihlBeyond[0] = 0x4F  // 60바이트 머리인데 선언 길이는 40
        ihlBeyond[2] = 0
        ihlBeyond[3] = 40
        #expect(parseError(ihlBeyond) == .malformed)
        var tooLong = good
        tooLong[3] &+= 1  // 선언 길이가 실제보다 1 길다
        #expect(parseError(tooLong) == .malformed)
        // IPv6: payload length가 버퍼 밖.
        var v6 = RawPacket.ipv6(segment: segment)
        v6[5] &+= 1
        #expect(parseError(v6) == .malformed)
    }

    @Test("IPv4 조각(MF, 조각 오프셋)은 해석하지 않는다")
    func fragments() {
        let segment = RawPacket.segment()
        for flagsAndOffset: UInt16 in [0x2000, 0x0001, 0x2001, 0x1FFF] {
            let packet = RawPacket.ipv4(segment: segment, flagsAndOffset: flagsAndOffset)
            #expect(parseError(packet) == .malformed, "플래그·오프셋 \(flagsAndOffset)")
        }
        // DF와 예약 비트는 조각이 아니다.
        #expect(parseError(RawPacket.ipv4(segment: segment, flagsAndOffset: 0x4000)) == nil)
    }

    @Test("TCP 머리가 20바이트보다 짧다")
    func shortTCPHeader() {
        for length in [0, 1, 12, 19] {
            let segment = Array(RawPacket.segment()[..<length])
            // IPv4 머리 체크섬은 맞춰 둔다(TCP 머리 검사보다 먼저 보기 때문이다). 20바이트 미만 세그먼트의 TCP 체크섬은 채워지지 않는다.
            #expect(parseError(RawPacket.ipv4(segment: segment)) == .malformed, "길이 \(length)")
            #expect(parseError(RawPacket.ipv6(segment: segment)) == .malformed, "길이 \(length)")
        }
    }

    @Test("data offset: 5가 최소, 15가 최대, 세그먼트 밖을 가리키면 버린다")
    func dataOffsetBoundaries() throws {
        // 4는 머리 최소 길이(20)보다 작다.
        let offset4 = RawPacket.segment(dataOffset: 4, payload: [1, 2, 3, 4])
        #expect(parseError(RawPacket.ipv4(segment: offset4)) == .malformed)
        // 5: 옵션 없음.
        #expect(try parse(RawPacket.ipv4(segment: RawPacket.segment(dataOffset: 5, payload: [1]))).payload == [1])
        // 15: 옵션 40바이트가 꽉 찬다. 데이터는 그 뒤다.
        let options = [UInt8](repeating: 1, count: 40)  // NOP 40개
        let offset15 = RawPacket.segment(options: options, payload: [7, 7])
        #expect(try parse(RawPacket.ipv4(segment: offset15)).payload == [7, 7])
        // 머리 밖: 세그먼트가 23바이트인데 data offset이 15(60바이트). 4비트라 16은 적을 수 없다.
        let beyond = RawPacket.segment(dataOffset: 15, payload: [1, 2, 3])
        #expect(parseError(RawPacket.ipv4(segment: beyond)) == .malformed)
        // 머리 끝이 세그먼트 끝과 정확히 같은 경우(데이터 0)는 정상이다.
        let exact = RawPacket.segment(options: [UInt8](repeating: 1, count: 8))
        #expect(try parse(RawPacket.ipv6(segment: exact)).payload.isEmpty)
        // 하나 모자란다.
        let short = Array(RawPacket.segment(options: [UInt8](repeating: 1, count: 8)).dropLast(4))
        #expect(parseError(RawPacket.ipv6(segment: short)) == .malformed)
    }

    // MARK: - 프로토콜

    @Test("TCP가 아니면 notTCP: UDP, ICMP, IPv6 확장 헤더·조각 헤더, 알 수 없는 번호")
    func notTCP() {
        let segment = RawPacket.segment()
        for number: UInt8 in [1, 17, 58, 99, 132, 255] {
            #expect(parseError(RawPacket.ipv4(segment: segment, protocolNumber: number)) == .notTCP, "IPv4 \(number)")
            #expect(parseError(RawPacket.ipv6(segment: segment, nextHeader: number)) == .notTCP, "IPv6 \(number)")
        }
        // 확장 헤더(0 hop-by-hop, 43 routing, 44 fragment, 60 destination options)는 체인을 따라가지 않는다.
        for number: UInt8 in [0, 43, 44, 60] {
            #expect(parseError(RawPacket.ipv6(segment: segment, nextHeader: number)) == .notTCP, "IPv6 \(number)")
        }
        // TCP 머리가 없어도 프로토콜이 먼저다(체크섬을 채우지 않은 UDP 패킷).
        #expect(parseError(RawPacket.ipv4(segment: [1, 2, 3], protocolNumber: 17, fixChecksums: false)) == .notTCP)
    }

    // MARK: - 체크섬

    @Test("TCP 체크섬이 틀리면 badChecksum: 데이터, 머리, 체크섬 필드, 의사 머리의 주소")
    func badTCPChecksum() {
        for version in [4, 6] {
            let packet = version == 4
                ? RawPacket.ipv4(segment: RawPacket.segment(payload: [1, 2, 3]))
                : RawPacket.ipv6(segment: RawPacket.segment(payload: [1, 2, 3]))
            let ipLength = version == 4 ? 20 : 40
            #expect(parseError(packet) == nil)
            for (name, index) in [("데이터", packet.count - 1), ("시퀀스", ipLength + 4), ("체크섬", ipLength + 17), ("창", ipLength + 14)] {
                var changed = packet
                changed[index] ^= 0x01
                #expect(parseError(changed) == .badChecksum, "IPv\(version) \(name)")
            }
            // 주소가 바뀌면 의사 머리 때문에 틀린다(IPv4는 머리 체크섬도 틀리므로 둘 다 badChecksum).
            var address = packet
            address[version == 4 ? 15 : 23] ^= 0x01
            #expect(parseError(address) == .badChecksum, "IPv\(version) 주소")
        }
    }

    @Test("IPv4: 머리 체크섬이 맞아도 TCP 체크섬이 다른 주소로 계산됐으면 badChecksum(의사 머리)")
    func pseudoHeaderCoversTheAddresses() {
        var packet = RawPacket.ipv4(segment: RawPacket.segment(payload: [1, 2, 3]))
        #expect(parseError(packet) == nil)
        // 목적 주소를 바꾸고 IPv4 머리 체크섬만 다시 맞춘다.
        packet.replaceSubrange(16..<20, with: [100, 64, 0, 3])
        packet.replaceSubrange(10..<12, with: [0, 0])
        packet.replaceSubrange(10..<12, with: RawPacket.be16(Int(RawPacket.checksum(Array(packet[..<20])))))
        #expect(parseError(packet) == .badChecksum)
    }

    @Test("IPv4 머리 체크섬이 틀리면 badChecksum")
    func badIPv4HeaderChecksum() {
        var packet = RawPacket.ipv4(segment: RawPacket.segment())
        packet[10] ^= 0x80
        #expect(parseError(packet) == .badChecksum)
        // TTL이 바뀌어도 머리 체크섬이 틀린다. TCP 체크섬은 TTL을 보지 않는다.
        var ttl = RawPacket.ipv4(segment: RawPacket.segment())
        ttl[8] &-= 1
        #expect(parseError(ttl) == .badChecksum)
    }

    @Test("체크섬 필드가 0인 TCP 세그먼트는 받지 않는다")
    func zeroChecksumRejected() {
        let segment = RawPacket.segment(payload: [1, 2, 3])
        // IPv4 머리 20바이트 + TCP 체크섬 필드(16)의 자리.
        #expect(parseError(RawPacket.ipv4(segment: segment).zeroing(at: 36, count: 2)) == .badChecksum)
    }

    // MARK: - 옵션

    private func synPacket(options: [UInt8], flags: UInt8 = 0x02, ipv6: Bool = false) -> [UInt8] {
        let segment = RawPacket.segment(flags: flags, options: options)
        return ipv6 ? RawPacket.ipv6(segment: segment) : RawPacket.ipv4(segment: segment)
    }

    @Test("MSS와 Window Scale, NOP로 어긋난 정렬")
    func mssAndWindowScaleWithNOPs() throws {
        let layouts: [[UInt8]] = [
            [2, 4, 0x05, 0xB4, 1, 3, 3, 8],  // MSS, NOP, WS
            [1, 3, 3, 2, 2, 4, 0x02, 0x18],  // NOP, WS, MSS
            [1, 1, 1, 2, 4, 0x05, 0xB4, 1, 1, 3, 3, 5],  // NOP이 어긋나게 여럿
            [3, 3, 9, 2, 4, 0x05, 0xB4],  // WS 먼저, 정렬 없음(뒤는 EOL 채움)
        ]
        let expected: [(UInt16, UInt8)] = [(1460, 8), (536, 2), (1460, 5), (1460, 9)]
        for (options, (mss, shift)) in zip(layouts, expected) {
            let parsed = try parse(synPacket(options: options))
            #expect(parsed.maximumSegmentSize == mss, "\(options)")
            #expect(parsed.windowScale == shift, "\(options)")
        }
    }

    @Test("EOL에서 멈춘다: 그 뒤의 바이트는 틀린 옵션이어도 읽지 않는다")
    func endOfOptionList() throws {
        // MSS, EOL, 그리고 길이 0인 "옵션"과 Window Scale.
        let parsed = try parse(synPacket(options: [2, 4, 0x05, 0xB4, 0, 9, 0, 3, 3, 7]))
        #expect(parsed.maximumSegmentSize == 1460)
        #expect(parsed.windowScale == nil)
        // 옵션 영역이 EOL로 시작.
        let first = try parse(synPacket(options: [0, 2, 4, 0x05, 0xB4]))
        #expect(first.maximumSegmentSize == nil)
    }

    @Test("모르는 옵션은 길이로 건너뛴다")
    func unknownOptionsSkipped() throws {
        // SACK-permitted(4, 2), 타임스탬프(8, 10), 모르는 kind 77(길이 5), 그 뒤의 MSS.
        let options: [UInt8] = [4, 2, 8, 10, 0, 0, 0, 1, 0, 0, 0, 2, 77, 5, 9, 9, 9, 2, 4, 0x05, 0x00]
        let parsed = try parse(synPacket(options: options))
        #expect(parsed.maximumSegmentSize == 1280)
        #expect(parsed.windowScale == nil)
    }

    @Test("옵션의 길이가 잘못되면 malformed: 0, 1, 머리 밖, 길이 바이트 없음")
    func malformedOptions() {
        let cases: [(name: String, options: [UInt8])] = [
            ("길이 0", [77, 0, 1, 1]),
            ("길이 1", [77, 1, 1, 1]),
            ("MSS인데 길이 0", [2, 0, 0, 0]),
            ("길이가 머리 밖", [77, 8, 0, 0]),
            ("MSS가 머리 끝에 걸림", [1, 1, 2, 4]),
            ("Window Scale이 머리 끝에 걸림", [1, 1, 1, 1, 1, 1, 3, 3]),
            ("마지막 바이트가 kind라 길이 바이트가 없음", [1, 1, 1, 77]),
        ]
        for (name, options) in cases {
            #expect(parseError(synPacket(options: options)) == .malformed, "\(name)")
            #expect(parseError(synPacket(options: options, ipv6: true)) == .malformed, "IPv6 \(name)")
        }
    }

    @Test("SYN이 아닌 세그먼트의 MSS·Window Scale은 무시하되 길이는 여전히 본다")
    func optionsIgnoredWithoutSYN() throws {
        for flags: UInt8 in [0x10, 0x18, 0x01, 0x04, 0x14, 0x11] {
            let parsed = try parse(synPacket(options: [2, 4, 0x05, 0xB4, 1, 3, 3, 7], flags: flags))
            #expect(parsed.maximumSegmentSize == nil, "플래그 \(flags)")
            #expect(parsed.windowScale == nil, "플래그 \(flags)")
        }
        #expect(parseError(synPacket(options: [77, 1, 0, 0], flags: 0x10)) == .malformed)
        // SYN-ACK는 SYN이다.
        let synAck = try parse(synPacket(options: [2, 4, 0x05, 0xB4, 1, 3, 3, 7], flags: 0x12))
        #expect(synAck.maximumSegmentSize == 1460)
        #expect(synAck.windowScale == 7)
    }

    @Test("MSS 0은 기본값(IPv4 536, IPv6 1220)이고 그 밖의 값은 그대로(1, 65535도)")
    func mssZeroAndExtremes() throws {
        #expect(try parse(synPacket(options: [2, 4, 0, 0])).maximumSegmentSize == 536)
        #expect(try parse(synPacket(options: [2, 4, 0, 0], ipv6: true)).maximumSegmentSize == 1220)
        #expect(try parse(synPacket(options: [2, 4, 0, 1])).maximumSegmentSize == 1)
        #expect(try parse(synPacket(options: [2, 4, 0xFF, 0xFF], ipv6: true)).maximumSegmentSize == 65_535)
    }

    @Test("Window Scale shift는 14까지, 넘으면 14")
    func windowScaleClamped() throws {
        let expected: [(UInt8, UInt8)] = [(0, 0), (1, 1), (14, 14), (15, 14), (255, 14)]
        for (given, shift) in expected {
            #expect(try parse(synPacket(options: [3, 3, given])).windowScale == shift, "shift \(given)")
        }
    }

    @Test("길이가 규격과 다른 MSS·Window Scale은 값을 읽지 않고 길이로 건너뛴다")
    func wrongSizedKnownOptions() throws {
        // MSS 길이 3(값 한 바이트), 그 뒤 Window Scale 길이 4.
        let parsed = try parse(synPacket(options: [2, 3, 0x05, 3, 4, 7, 7, 1]))
        #expect(parsed.maximumSegmentSize == nil)
        #expect(parsed.windowScale == nil)
    }

    @Test("같은 옵션이 여럿이면 뒤의 것")
    func duplicateOptions() throws {
        let parsed = try parse(synPacket(options: [2, 4, 0x02, 0x00, 2, 4, 0x04, 0x00, 3, 3, 2, 3, 3, 6, 1, 1]))
        #expect(parsed.maximumSegmentSize == 1024)
        #expect(parsed.windowScale == 6)
    }

    @Test("옵션 40바이트가 꽉 차도, 길이 2의 옵션이 끝없이 이어져도 끝난다")
    func maximumOptionRegion() throws {
        // kind 77 길이 2가 20번(40바이트).
        let options = [UInt8](Array(repeating: [77, 2], count: 20).joined())
        let parsed = try parse(synPacket(options: options))
        #expect(parsed.maximumSegmentSize == nil)
        // NOP 40개.
        let nops = try parse(synPacket(options: [UInt8](repeating: 1, count: 40)))
        #expect(nops.windowScale == nil)
    }
}

extension [UInt8] {
    /// `index`부터 `count`바이트를 0으로 만든 복사본.
    fileprivate func zeroing(at index: Int, count: Int) -> [UInt8] {
        var copy = self
        for offset in index..<index + count { copy[offset] = 0 }
        return copy
    }
}
