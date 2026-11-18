import SwiftailBase

/// Flow records for identifying replies to previously sent UDP and SCTP packets. A 512-entry LRU with no time limit.
///
/// Stores the reverse tuple of an outgoing packet and looks up the tuple of an incoming packet. Lookups also update recency.
/// Incoming packets do not create records. This follows the same rule as Go's `flowtrack.Cache`.
///
/// `docs/protocol-notes/netmap-engine.md` 4.5 and §5 (constants).
struct FlowTable: Sendable {
    /// A flow as seen by the receiver, with protocol, source address and port → destination address and port.
    struct Flow: Hashable, Sendable {
        let protocolNumber: UInt8
        let source: IPAddress
        let sourcePort: UInt16
        let destination: IPAddress
        let destinationPort: UInt16
    }

    /// The maximum number of records.
    static let capacity = 512

    /// Maps each flow to its last-use sequence number. The smallest value is the least recently used.
    private var lastUse: [Flow: UInt64] = [:]
    private var clock: UInt64 = 0

    /// Records the reply flow for an outgoing packet (with addresses and ports reversed).
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
            // Scan 512 entries only when full. Evict one at a time, so the size never exceeds the limit.
            lastUse[oldest] = nil
        }
        touch(reply)
    }

    /// Returns `true` for an incoming packet from a recorded flow and marks the flow as most recently used.
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
        // Increases by 1 per packet. 2^64 packets will not arrive.
        clock += 1
        lastUse[flow] = clock
    }
}
