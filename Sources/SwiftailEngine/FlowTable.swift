import SwiftailBase

/// 먼저 내보낸 UDP·SCTP의 응답을 알아보기 위한 흐름 기록. 512개 LRU이고 시간 제한은 없다.
///
/// 내보낸 패킷의 역방향 튜플을 넣고, 받은 패킷의 튜플로 찾는다. 찾기도 최근 사용 순서를 갱신한다.
/// 받은 패킷은 기록을 만들지 않는다. Go `flowtrack.Cache`와 같은 규칙이다.
///
/// `docs/protocol-notes/netmap-engine.md` 4.5, 5장(상수).
struct FlowTable: Sendable {
    /// 받은 쪽에서 본 흐름: 프로토콜, 출발 주소·포트 → 목적 주소·포트.
    struct Flow: Hashable, Sendable {
        let protocolNumber: UInt8
        let source: IPAddress
        let sourcePort: UInt16
        let destination: IPAddress
        let destinationPort: UInt16
    }

    /// 기록의 최대 수.
    static let capacity = 512

    /// 흐름 → 마지막으로 쓴 순번. 가장 작은 순번이 가장 오래 쓰지 않은 것이다.
    private var lastUse: [Flow: UInt64] = [:]
    private var clock: UInt64 = 0

    /// 내보낸 패킷의 응답이 될 흐름(주소·포트를 맞바꾼 것)을 기록한다.
    mutating func recordReply(to outbound: IPPacket) {
        let reply = Flow(
            protocolNumber: outbound.protocolNumber,
            source: outbound.destination,
            sourcePort: outbound.destinationPort,
            destination: outbound.source,
            destinationPort: outbound.sourcePort
        )
        if lastUse[reply] == nil, lastUse.count >= Self.capacity,
           let oldest = lastUse.min(by: { $0.value < $1.value })?.key {
            // 가득 찼을 때만 512개를 훑는다. 한 번에 하나를 내보내므로 크기는 한도를 넘지 않는다.
            lastUse[oldest] = nil
        }
        touch(reply)
    }

    /// 받은 패킷이 기록된 흐름이면 `true`. 찾으면 그 흐름을 가장 최근에 쓴 것으로 올린다.
    mutating func containsFlow(of inbound: IPPacket) -> Bool {
        let flow = Flow(
            protocolNumber: inbound.protocolNumber,
            source: inbound.source,
            sourcePort: inbound.sourcePort,
            destination: inbound.destination,
            destinationPort: inbound.destinationPort
        )
        guard lastUse[flow] != nil else { return false }
        touch(flow)
        return true
    }

    private mutating func touch(_ flow: Flow) {
        // 패킷 하나에 1씩 는다. 2^64개의 패킷은 오지 않는다.
        clock += 1
        lastUse[flow] = clock
    }
}
