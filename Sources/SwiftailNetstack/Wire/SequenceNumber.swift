/// TCP 시퀀스 번호(RFC 9293 3.4).
///
/// 2³²을 법으로 하는 수다. 4GiB를 넘게 보내면 한 바퀴 돌아 0으로 돌아오므로 `UInt32`의 크기 비교를 쓰면 안 된다.
/// 두 번호의 앞뒤는 차이를 부호 있는 32비트로 읽어 정한다. 이 비교는 두 번호가 2³¹보다 가까울 때만 뜻이 있고,
/// TCP의 창(창 확장을 써도 2³⁰ 미만)이 그것을 보장한다. 전순서가 아니므로 `Comparable`을 채택하지 않는다.
package struct SequenceNumber: Sendable, Hashable {
    /// 세그먼트 머리에 실리는 값.
    package var rawValue: UInt32

    /// 세그먼트 머리의 32비트 값 그대로인 번호.
    package init(_ rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// `count`만큼 뒤의 번호. 2³²에서 돈다.
    package func advanced(by count: UInt32) -> SequenceNumber {
        SequenceNumber(rawValue &+ count)
    }

    /// `other`에서 이 번호까지의 거리. 이 번호가 뒤면 양수, 앞이면 음수다.
    package func distance(from other: SequenceNumber) -> Int32 {
        Int32(bitPattern: rawValue &- other.rawValue)
    }

    /// 이 번호가 `other`보다 앞이다(RFC의 `<`).
    package func precedes(_ other: SequenceNumber) -> Bool {
        distance(from: other) < 0
    }

    /// 이 번호가 `other`와 같거나 앞이다(RFC의 `=<`).
    package func precedesOrEquals(_ other: SequenceNumber) -> Bool {
        distance(from: other) <= 0
    }
}
