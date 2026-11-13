/// 전송 counter의 재전송 방지 창(RFC 6479).
///
/// UDP는 순서를 지키지 않으므로 counter가 늘 증가하리라 기대할 수 없다. 가장 큰 counter에서
/// 8128개 뒤까지는 순서가 바뀐 패킷으로 받아들이되, 같은 counter는 한 번만 받는다.
/// 64비트 블록 128개를 고리로 쓰고, 창이 앞으로 움직이면 지나간 블록만 비운다.
///
/// AEAD로 인증된 패킷에만 적용해야 한다. 위조한 counter로 창을 밀어 정상 패킷을 막지 못하게 하기 위해서다.
///
/// 백서 §5.4.6, `docs/protocol-notes/wireguard.md` "전송 데이터: 받기" 4
/// (출처: wireguard-go `replay/replay.go`, MIT 라이선스, Copyright (C) 2017-2023 WireGuard LLC).
struct ReplayFilter {
    private static let blockBitLog: UInt64 = 6
    private static let blockBits: UInt64 = 1 << blockBitLog
    private static let ringBlocks: UInt64 = 1 << 7
    /// 받아들이는 최대 뒤처짐. (128 − 1) × 64 = 8128.
    static let windowSize: UInt64 = (ringBlocks - 1) * blockBits

    private var last: UInt64 = 0
    private var ring = [UInt64](repeating: 0, count: Int(ringBlocks))

    /// counter를 받아들일지 정하고, 받아들이면 기록한다. limit 이상은 늘 거절한다.
    /// 거절할 때는 상태를 바꾸지 않는다.
    mutating func accept(_ counter: UInt64, limit: UInt64 = Constants.rejectAfterMessages) -> Bool {
        guard counter < limit else { return false }
        let block = counter >> Self.blockBitLog
        if counter > last {
            // 창을 앞으로 민다. 지나간 블록을 비우되 고리 한 바퀴를 넘게 돌 필요는 없다.
            let current = last >> Self.blockBitLog
            let advance = min(block - current, Self.ringBlocks)
            for offset in stride(from: 1, through: advance, by: 1) {
                ring[Self.ringIndex(current &+ offset)] = 0
            }
            last = counter
        } else if last - counter > Self.windowSize {
            return false
        }
        let index = Self.ringIndex(block)
        let bit: UInt64 = 1 << (counter & (Self.blockBits - 1))
        guard ring[index] & bit == 0 else { return false }
        ring[index] |= bit
        return true
    }

    private static func ringIndex(_ block: UInt64) -> Int {
        Int(block & (ringBlocks - 1))
    }
}
