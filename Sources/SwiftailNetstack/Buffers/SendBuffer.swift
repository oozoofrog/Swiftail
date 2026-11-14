/// 연결 하나의 보내는 버퍼(계약 `docs/contracts/SwiftailNetstack.md` 동작 F6).
///
/// 아직 확인받지 못한(`SND.UNA` 이후 보낸) 바이트와 아직 보내지 않은 바이트를 순서대로 쥔다. 앱이 쓴 바이트는
/// `append`로 뒤에 붙고, ACK가 오면 `acknowledge`가 앞에서부터 버리며, 재전송은 `SND.UNA`에서의 오프셋으로 구간을
/// 복사해 간다. 저장소는 연결의 수명 동안 되풀이해 쓰는 원형 구조라 보내고 확인받는 동안 새로 할당하지 않는다.
///
/// SYN과 FIN은 시퀀스 번호를 하나씩 쓰지만 데이터가 아니므로 이 버퍼에 없다. `startSequence`는 **데이터** 쪽의
/// `SND.UNA`다. SYN이 확인받기 전에는 첫 데이터 번호(`ISS + 1`)이고, 데이터를 다 확인받은 뒤에는 FIN의 번호이며,
/// FIN의 ACK(`endSequence + 1`)는 연결이 직접 본다.
package struct SendBuffer: Sendable {
    /// 계약 동작 F6: 연결마다 256KiB.
    package static let defaultCapacity = 256 * 1024

    private var ring: ByteRing

    /// 가장 오래된 미확인 바이트의 번호(데이터 쪽 `SND.UNA`).
    package private(set) var startSequence: SequenceNumber
    /// 쥐고 있는 바이트 수(확인받지 못한 것 + 아직 보내지 않은 것).
    package private(set) var count = 0

    /// 첫 바이트의 번호가 `firstSequence`이고 용량이 `capacity`인 빈 버퍼. 용량은 2³⁰ 이하여야 한다.
    package init(firstSequence: SequenceNumber, capacity: Int = SendBuffer.defaultCapacity) {
        precondition(capacity <= 1 << 30, "용량이 시퀀스 번호의 비교 범위를 넘는다")
        ring = ByteRing(capacity: capacity)
        startSequence = firstSequence
    }

    /// 저장소의 용량(바이트). 쥐는 바이트는 이것을 넘지 않는다.
    package var capacity: Int { ring.capacity }

    /// 더 받아들일 수 있는 바이트 수.
    package var freeSpace: Int { capacity - count }

    /// 쥔 바이트 바로 뒤의 번호. 다음에 붙는 바이트가 얻을 번호다.
    package var endSequence: SequenceNumber { startSequence.advanced(by: UInt32(count)) }

    /// 저장소로 실제 잡힌 바이트 수(시험·측정용). 용량을 넘지 않는다.
    package var allocatedByteCount: Int { ring.allocatedByteCount }

    /// 받아들일 수 있는 만큼만 뒤에 붙이고, 받아들인 바이트 수를 돌려준다(남은 것은 호출한 쪽이 쥔다).
    package mutating func append(_ bytes: ArraySlice<UInt8>) -> Int {
        let accepted = min(bytes.count, freeSpace)
        guard accepted > 0 else { return 0 }
        ring.write(bytes.prefix(accepted), at: count)
        count += accepted
        return accepted
    }

    /// `startSequence`에서 `offset`만큼 뒤의 바이트부터 `maximumLength`바이트까지 복사해 낸다.
    /// 보내는 세그먼트(`offset = SND.NXT − SND.UNA`)와 재전송(`offset = 0`)이 모두 이것을 쓴다.
    /// 쥔 바이트를 넘는 부분은 없다: 범위 밖 `offset`이거나 `maximumLength`가 0 이하면 빈 배열이다.
    ///
    /// shortcut: 호출마다 새 배열 하나에 복사한다. 세그먼트의 페이로드가 `[UInt8]`이라 어차피 한 번의 복사가 들고,
    /// 저장소를 빌려 주려면 안전하지 않은 포인터나 `Span`(이 플랫폼 하한에는 없다)이 필요하다.
    package func bytes(from offset: Int, upTo maximumLength: Int) -> [UInt8] {
        guard offset >= 0, offset < count, maximumLength > 0 else { return [] }
        return ring.copy(from: offset, count: min(maximumLength, count - offset))
    }

    /// 누적 ACK `ack`까지 확인받은 바이트를 앞에서부터 버리고, 버린 바이트 수를 돌려준다.
    ///
    /// `ack`가 `startSequence`보다 앞이거나 같으면(오래된·중복 ACK) 0이다. `endSequence`보다 뒤면(보내지 않은 것을
    /// 확인한다는 뜻) 아무것도 바꾸지 않고 0이다. 그런 ACK를 어떻게 다룰지(ACK로 답하고 버린다, 동작 X3)는 연결이 정한다.
    package mutating func acknowledge(upTo ack: SequenceNumber) -> Int {
        let released = Int(ack.distance(from: startSequence))
        guard released > 0, released <= count else { return 0 }
        ring.discard(released)
        count -= released
        startSequence = ack
        if count == 0 {
            ring.rewind()
        }
        return released
    }
}
