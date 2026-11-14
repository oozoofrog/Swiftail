/// 인터넷 체크섬(RFC 1071): 16비트 빅엔디언 낱말의 1의 보수 합을 다시 보수로 만든 값.
///
/// IPv4 머리, TCP·UDP(IP 의사 머리 포함), ICMP가 같은 합을 쓴다. 엔진의 서비스 IP 응답과 netstack의 세그먼트 코덱이
/// 이 계산을 함께 쓴다(`docs/contracts/SwiftailNetstack.md` 결정 D10).
///
/// 바이트를 여러 번에 나눠 `add`해도 이어 붙여 한 번에 더한 것과 같다. 그래서 의사 머리와 세그먼트를 한 배열로
/// 복사하지 않고 차례로 더한다. 만드는 쪽은 체크섬 필드를 0으로 두고 계산하고, 검사하는 쪽은 필드를 포함해 더한
/// 값이 `0`이면(합이 `0xFFFF`) 맞다.
///
/// 합은 `UInt64`에 모으므로 2⁴⁸바이트를 넘기 전에는 넘치지 않는다.
package struct InternetChecksum: Sendable {
    private var sum: UInt64 = 0
    /// 다음 바이트가 낱말의 위쪽 바이트인지. 홀수 길이로 끝난 조각 다음의 첫 바이트는 아래쪽이다.
    private var nextIsHighByte = true

    /// 아무것도 더하지 않은 상태.
    package init() {}

    /// 바이트를 합에 더한다. 앞서 더한 전체 길이가 홀수였으면 첫 바이트가 앞 낱말의 아래쪽을 채운다.
    package mutating func add(_ bytes: ArraySlice<UInt8>) {
        var index = bytes.startIndex
        if !nextIsHighByte, index < bytes.endIndex {
            sum += UInt64(bytes[index])
            nextIsHighByte = true
            index += 1
        }
        while bytes.endIndex - index >= 2 {
            sum += UInt64(bytes[index]) << 8 | UInt64(bytes[index + 1])
            index += 2
        }
        // 홀수 바이트는 0을 덧붙여 센다(RFC 1071 1절). 뒤에 더하는 바이트가 있으면 그 0 자리를 채운다.
        if index < bytes.endIndex {
            sum += UInt64(bytes[index]) << 8
            nextIsHighByte = false
        }
    }

    /// 바이트를 합에 더한다.
    package mutating func add(_ bytes: [UInt8]) {
        add(bytes[...])
    }

    /// TCP·UDP·ICMPv6의 IP 의사 머리를 합에 더한다. 전송 계층 조각보다 먼저, 합의 처음에 부른다.
    ///
    /// IPv4(주소가 4바이트)는 출발 주소, 목적 주소, 0, 프로토콜, 전송 계층 길이(16비트). 그 밖에는 IPv6로 본다:
    /// 출발 주소, 목적 주소, 전송 계층 길이(32비트), 0 셋, next header(RFC 9293 3.1, RFC 8200 8.1).
    ///
    /// - Parameters:
    ///   - source: 출발 주소(4 또는 16바이트).
    ///   - destination: 목적 주소. `source`와 같은 길이다.
    ///   - protocolNumber: IPv4 protocol 또는 IPv6 next header.
    ///   - length: 전송 계층 조각 전체의 길이(IP 머리·확장 헤더는 빼고, TCP는 옵션과 데이터를 더한다).
    package mutating func addPseudoHeader(source: [UInt8], destination: [UInt8], protocolNumber: UInt8, length: Int) {
        let length = UInt32(truncatingIfNeeded: length)
        add(source)
        add(destination)
        if source.count == 4 {
            add([0, protocolNumber, UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length)])
        } else {
            add([
                UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
                UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length),
                0, 0, 0, protocolNumber,
            ])
        }
    }

    /// 지금까지 더한 것의 체크섬. 올림을 16비트에 들어올 때까지 되돌려 더하고 보수를 취한다. 더한 것이 없으면 `0xFFFF`.
    package var value: UInt16 {
        var folded = sum
        while folded > 0xFFFF {
            folded = (folded & 0xFFFF) + (folded >> 16)
        }
        return ~UInt16(truncatingIfNeeded: folded)
    }

    /// `bytes` 하나의 체크섬.
    package static func checksum(of bytes: [UInt8]) -> UInt16 {
        var checksum = InternetChecksum()
        checksum.add(bytes)
        return checksum.value
    }
}
