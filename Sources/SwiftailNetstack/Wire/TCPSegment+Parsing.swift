import SwiftailBase

extension TCPSegment {
    /// IP 패킷 바이트를 검증해 세그먼트로 바꾼다. 신뢰할 수 없는 입력의 경계다.
    ///
    /// IPv4(옵션 포함)와 IPv6(확장 헤더 없음)의 머리에서 주소와 길이를 읽는다. 선언된 길이 뒤의 바이트(링크 계층 패딩 등)는
    /// 버린다. 검사 순서는 다음과 같다. 앞의 것이 걸리면 뒤의 것은 보지 않는다.
    ///
    /// 1. IP 머리의 길이·버전·머리 길이가 맞지 않으면 `malformed`.
    /// 2. 프로토콜(IPv4 protocol, IPv6 next header)이 6이 아니면 `notTCP`.
    /// 3. IPv4 조각(MF나 조각 오프셋)이면 `malformed`. 재조립하지 않으므로 조각의 TCP 머리는 믿을 수 없다.
    /// 4. IPv4 머리 체크섬이 틀리면 `badChecksum`.
    /// 5. TCP 머리가 20바이트보다 짧거나 data offset이 5 미만이거나 세그먼트 밖을 가리키면 `malformed`.
    /// 6. TCP 체크섬(의사 머리 포함)이 틀리면 `badChecksum`.
    /// 7. 옵션의 길이가 잘못됐으면 `malformed`.
    ///
    /// 옵션은 EOL에서 멈추고 NOP는 건너뛴다. MSS(kind 2, 길이 4)와 Window Scale(kind 3, 길이 3)만 읽고 SYN이 켜진
    /// 세그먼트에서만 담는다. 모르는 옵션과, 길이가 다른 MSS·Window Scale은 길이로 건너뛴다. 길이가 2보다 작거나 머리
    /// 밖으로 나가는 옵션은 `malformed`다(RFC 9293 3.2 MUST-7의 대비로, 연결을 끊지 않는다). MSS 0은 IPv4 536·IPv6 1220으로
    /// 읽는다: RFC에 정해진 값이 없어(RFC 9293 3.7.1의 536·1220은 옵션이 **없을** 때의 값이다) 계약 동작 W2가 그 값을 쓰기로
    /// 정했다. shift 14 초과는 14로 읽는다(RFC 7323 2.3). 같은 옵션이 여럿이면 뒤의 것이 남는다.
    ///
    /// 받을 때 urgent pointer와 CWR·ECE·URG는 무시한다.
    package init(parsingIPPacket bytes: [UInt8]) throws(ParseError) {
        guard let first = bytes.first else { throw .malformed }
        let ip: IPHeader
        switch first >> 4 {
        case 4: ip = try IPHeader(ipv4: bytes)
        case 6: ip = try IPHeader(ipv6: bytes)
        default: throw .malformed
        }
        guard ip.protocolNumber == 6 else { throw .notTCP }
        if ip.isIPv4 {
            // 조각이면 TCP 머리가 첫 조각에만 있고 체크섬이 전체를 덮으므로 쓸 수 없다.
            guard bytes.uint16(at: 6) & 0x3FFF == 0 else { throw .malformed }
            var headerChecksum = InternetChecksum()
            headerChecksum.add(bytes[..<ip.headerLength])
            // 체크섬 필드를 포함해 더하면 0이어야 한다(RFC 1071 1절).
            guard headerChecksum.value == 0 else { throw .badChecksum }
        }

        let segment = bytes[ip.headerLength..<ip.totalLength]
        guard segment.count >= 20 else { throw .malformed }
        let headerLength = Int(segment.byte(at: 12) >> 4) * 4
        guard headerLength >= 20, headerLength <= segment.count else { throw .malformed }

        let sourceAddress = ip.sourceAddress
        let destinationAddress = ip.destinationAddress
        var checksum = InternetChecksum()
        checksum.addPseudoHeader(
            source: sourceAddress.bytes, destination: destinationAddress.bytes, protocolNumber: 6, length: segment.count)
        checksum.add(segment)
        guard checksum.value == 0 else { throw .badChecksum }

        let flags = Flags(rawValue: segment.byte(at: 13) & 0x1F)
        var maximumSegmentSize: UInt16?
        var windowScale: UInt8?
        let options = try Options(
            parsing: segment[(segment.startIndex + 20)..<(segment.startIndex + headerLength)])
        if flags.contains(.syn) {
            let defaultMSS: UInt16 = ip.isIPv4 ? 536 : 1220
            maximumSegmentSize = options.maximumSegmentSize.map { $0 == 0 ? defaultMSS : $0 }
            windowScale = options.windowScale.map { min($0, 14) }
        }

        self.init(
            source: IPEndpoint(address: sourceAddress, port: segment.uint16(at: 0)),
            destination: IPEndpoint(address: destinationAddress, port: segment.uint16(at: 2)),
            sequenceNumber: SequenceNumber(segment.uint32(at: 4)),
            acknowledgmentNumber: SequenceNumber(segment.uint32(at: 8)),
            flags: flags,
            window: segment.uint16(at: 14),
            maximumSegmentSize: maximumSegmentSize,
            windowScale: windowScale,
            payload: Array(segment[(segment.startIndex + headerLength)...])
        )
    }

    /// 해석한 IP 머리. 만들 때 모든 범위가 버퍼 안에 있음을 확인한다.
    private struct IPHeader {
        let isIPv4: Bool
        /// IP 머리의 길이(IPv4 옵션 포함). TCP 세그먼트가 시작하는 위치다.
        let headerLength: Int
        /// 선언된 패킷 전체 길이. `headerLength` 이상이고 버퍼 길이 이하다.
        let totalLength: Int
        let protocolNumber: UInt8
        let sourceAddress: IPAddress
        let destinationAddress: IPAddress

        /// IPv4: 20바이트 이상, IHL 5 이상, IHL ≤ 선언 길이 ≤ 버퍼.
        init(ipv4 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 20 else { throw .malformed }
            let headerLength = Int(bytes[0] & 0x0F) * 4
            let totalLength = Int(bytes.uint16(at: 2))
            guard headerLength >= 20, headerLength <= totalLength, totalLength <= bytes.count,
                  let source = IPAddress(bytes: bytes[12..<16]),
                  let destination = IPAddress(bytes: bytes[16..<20])
            else { throw .malformed }
            isIPv4 = true
            self.headerLength = headerLength
            self.totalLength = totalLength
            protocolNumber = bytes[9]
            sourceAddress = source
            destinationAddress = destination
        }

        /// IPv6: 40바이트 이상, 40 + payload length ≤ 버퍼. 확장 헤더는 따라가지 않으므로 next header가 6이 아니면 TCP가 아니다.
        init(ipv6 bytes: [UInt8]) throws(ParseError) {
            guard bytes.count >= 40 else { throw .malformed }
            let totalLength = 40 + Int(bytes.uint16(at: 4))
            guard totalLength <= bytes.count,
                  let source = IPAddress(bytes: bytes[8..<24]),
                  let destination = IPAddress(bytes: bytes[24..<40])
            else { throw .malformed }
            isIPv4 = false
            headerLength = 40
            self.totalLength = totalLength
            protocolNumber = bytes[6]
            sourceAddress = source
            destinationAddress = destination
        }
    }

    /// TCP 머리의 옵션 영역에서 읽은 값(RFC 9293 3.2).
    private struct Options {
        var maximumSegmentSize: UInt16?
        var windowScale: UInt8?

        /// 옵션 영역을 한 번 훑는다. 매 걸음이 한 바이트 이상 나아가므로 영역 길이를 넘어 돌지 않는다.
        init(parsing region: ArraySlice<UInt8>) throws(ParseError) {
            var index = region.startIndex
            walk: while index < region.endIndex {
                switch region[index] {
                case 0:
                    break walk
                case 1:
                    index += 1
                case let kind:
                    // EOL·NOP 밖의 옵션은 kind, 길이(머리 두 바이트 포함), 값이다.
                    guard index + 1 < region.endIndex else { throw .malformed }
                    let length = Int(region[index + 1])
                    guard length >= 2, length <= region.endIndex - index else { throw .malformed }
                    if kind == 2, length == 4 {
                        maximumSegmentSize = UInt16(region[index + 2]) << 8 | UInt16(region[index + 3])
                    } else if kind == 3, length == 3 {
                        windowScale = region[index + 2]
                    }
                    index += length
                }
            }
        }
    }
}

extension ArraySlice<UInt8> {
    /// 슬라이스의 처음에서 `offset`만큼 떨어진 바이트. 길이를 확인한 뒤에만 부른다.
    fileprivate func byte(at offset: Int) -> UInt8 {
        self[startIndex + offset]
    }

    fileprivate func uint16(at offset: Int) -> UInt16 {
        UInt16(byte(at: offset)) << 8 | UInt16(byte(at: offset + 1))
    }

    fileprivate func uint32(at offset: Int) -> UInt32 {
        UInt32(uint16(at: offset)) << 16 | UInt32(uint16(at: offset + 2))
    }
}

extension [UInt8] {
    /// 길이를 확인한 뒤에만 부른다.
    fileprivate func uint16(at offset: Int) -> UInt16 {
        UInt16(self[offset]) << 8 | UInt16(self[offset + 1])
    }
}
