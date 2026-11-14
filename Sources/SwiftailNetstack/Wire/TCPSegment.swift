import SwiftailBase

/// 검증을 마친 TCP 세그먼트 하나. IP 패킷 바이트와 서로 바뀐다.
///
/// 연결 상태 기계는 바이트가 아니라 이 값을 본다. 바이트열을 해석하는 일은 경계에서 한 번만 하고(`init(parsingIPPacket:)`),
/// 그 뒤의 코드는 머리 길이·옵션·체크섬을 다시 따지지 않는다. 만드는 쪽도 이 값에서 한 번에 패킷 바이트를 낸다
/// (`ipPacket(hopLimit:)`).
///
/// 담는 것은 상태 기계가 쓰는 필드뿐이다. urgent pointer와 CWR·ECE는 받을 때 버리고 보낼 때 0으로 둔다.
/// 시퀀스·확인 번호는 `SequenceNumber`로만 다룬다.
///
/// 규격: RFC 9293 3.1(머리, 체크섬), 3.2(옵션), RFC 7323 2.2(Window Scale), `docs/protocol-notes/tcp-netstack.md` 3절,
/// `docs/contracts/SwiftailNetstack.md` 동작 W.
package struct TCPSegment: Sendable, Equatable {
    /// 제어 비트. 상태 기계가 쓰는 다섯 개만 둔다.
    package struct Flags: OptionSet, Sendable {
        /// TCP 머리의 플래그 바이트(오프셋 13)에서 쓰는 비트. 그 밖의 비트(URG, ECE, CWR)는 해석할 때 버린다.
        package let rawValue: UInt8

        /// 비트 값으로 만든다. 위의 다섯 비트만 뜻이 있다.
        package init(rawValue: UInt8) {
            self.rawValue = rawValue
        }

        /// 보내는 쪽이 더 보낼 것이 없다.
        package static let fin = Flags(rawValue: 0x01)
        /// 시퀀스 번호를 맞춘다(연결을 연다).
        package static let syn = Flags(rawValue: 0x02)
        /// 연결을 끊는다.
        package static let rst = Flags(rawValue: 0x04)
        /// 받는 쪽이 곧바로 응용에 넘긴다. 상태 기계는 쓰지 않는다.
        package static let psh = Flags(rawValue: 0x08)
        /// `acknowledgmentNumber`가 뜻을 가진다.
        package static let ack = Flags(rawValue: 0x10)
    }

    /// IP 패킷 바이트를 세그먼트로 해석하지 못한 까닭. 어느 쪽이든 연결을 끊지 않고 그 패킷만 버린다.
    package enum ParseError: Error, Sendable, Equatable {
        /// TCP(프로토콜 6)가 아니다. IPv6 확장 헤더가 앞에 붙은 패킷도 여기다(체인을 따라가지 않는다).
        case notTCP
        /// 길이·버전·머리 길이가 맞지 않거나, 조각이거나, 옵션의 길이가 잘못됐다.
        case malformed
        /// IPv4 머리나 TCP 세그먼트의 체크섬이 틀리다.
        case badChecksum
    }

    /// 출발 주소와 포트.
    package var source: IPEndpoint
    /// 목적 주소와 포트.
    package var destination: IPEndpoint
    /// SEG.SEQ. SYN이 켜져 있으면 ISS(SYN 자신이 쓰는 번호)다.
    package var sequenceNumber: SequenceNumber
    /// SEG.ACK. `.ack`가 꺼져 있으면 뜻이 없다(받은 값을 그대로 둔다).
    package var acknowledgmentNumber: SequenceNumber
    /// 제어 비트.
    package var flags: Flags
    /// SEG.WND. 머리에 실린 16비트 값 그대로다. 창 확장은 곱하지 않았다(SYN이 아닌 세그먼트는 상태 기계가 협상한 shift로 읽는다).
    package var window: UInt16
    /// MSS 옵션. SYN이 켜진 세그먼트에만 있다. 해석할 때 0은 기본값(IPv4 536, IPv6 1220)으로 바뀐다. 광고하지 않으면 `nil`.
    package var maximumSegmentSize: UInt16?
    /// Window Scale 옵션의 shift. SYN이 켜진 세그먼트에만 있다. 해석할 때 14를 넘는 값은 14가 된다(RFC 7323 2.3). 광고하지 않으면 `nil`.
    package var windowScale: UInt8?
    /// 데이터.
    package var payload: [UInt8]

    /// 필드로 세그먼트를 만든다. 값을 검사하지 않는다(상태 기계와 시험이 만드는 값이다. 받은 바이트는 `init(parsingIPPacket:)`
    /// 으로만 들인다). `maximumSegmentSize`·`windowScale`은 SYN이 켜진 세그먼트에서만 `ipPacket(hopLimit:)`이 싣는다.
    package init(
        source: IPEndpoint,
        destination: IPEndpoint,
        sequenceNumber: SequenceNumber,
        acknowledgmentNumber: SequenceNumber = SequenceNumber(0),
        flags: Flags,
        window: UInt16 = 0,
        maximumSegmentSize: UInt16? = nil,
        windowScale: UInt8? = nil,
        payload: [UInt8] = []
    ) {
        self.source = source
        self.destination = destination
        self.sequenceNumber = sequenceNumber
        self.acknowledgmentNumber = acknowledgmentNumber
        self.flags = flags
        self.window = window
        self.maximumSegmentSize = maximumSegmentSize
        self.windowScale = windowScale
        self.payload = payload
    }

    /// SEG.LEN: 데이터 바이트 수에 SYN과 FIN을 1씩 더한 값(RFC 9293 3.4). 시퀀스 번호 공간에서 이 세그먼트가 차지하는 길이다.
    package var sequenceLength: UInt32 {
        UInt32(clamping: payload.count) + (flags.contains(.syn) ? 1 : 0) + (flags.contains(.fin) ? 1 : 0)
    }
}
