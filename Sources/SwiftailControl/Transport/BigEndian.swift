/// 제어 전송 계층의 고정 폭 정수는 모두 빅엔디언이다: 메시지 길이(uint16), 레코드 nonce의
/// 카운터(uint64), early payload 길이(uint32).
///
/// `docs/protocol-notes/control-transport.md` 3장 머리말.
extension FixedWidthInteger {
    /// 빅엔디언 바이트열. 길이는 `bitWidth / 8`이다.
    var bigEndianBytes: [UInt8] {
        (0..<(Self.bitWidth / 8)).reversed().map { UInt8(truncatingIfNeeded: self >> ($0 * 8)) }
    }

    /// 빅엔디언 바이트열을 읽는다. 호출하는 쪽이 길이를 `bitWidth / 8`로 맞춰 넘긴다.
    init(bigEndianBytes bytes: some Collection<UInt8>) {
        self = bytes.reduce(0) { $0 << 8 | Self($1) }
    }
}
