import Foundation
import SwiftailNetstack
import Testing
@testable import Swiftail

/// The format of a single `Connection ended` log line (contract `docs/contracts/SwiftailNetstack.md`, "Connection Close Statistics Log").
@Suite("Node TCP connection close log")
struct NetstackCloseLogTests {
    private static func statistics(openedAt: ContinuousClock.Instant) -> TCPConnection.Statistics {
        var statistics = TCPConnection.Statistics(openedAt: openedAt)
        statistics.sackPermitted = true
        statistics.sentBytes = 262_144
        statistics.retransmittedBytes = 1_200
        statistics.retransmissionTimeouts = 1
        statistics.maximumCongestionWindow = 143_840
        return statistics
    }

    @Test("The line for an application-held connection has no suffix. The line for a connection that ended after release ends with `, ended after release`")
    func releasedSuffix() {
        let openedAt = ContinuousClock.now
        let statistics = Self.statistics(openedAt: openedAt)
        let held = statistics.closeLogLine(
            reason: .aborted, closedAt: openedAt + .milliseconds(240), afterRelease: false)
        #expect(
            held
                == "Connection ended: aborted, lifetime 240ms, sent 262144B, retransmitted 1200B, RTO 1, fast retransmits 0, "
                + "partial ACK retransmits 0, duplicate ACKs 0, ACKs with SACK 0, SACK negotiated true, peak cwnd 143840B, ssthresh reductions 0")
        let released = statistics.closeLogLine(
            reason: .finished, closedAt: openedAt + .milliseconds(240), afterRelease: true)
        #expect(released == held.replacingOccurrences(of: "aborted", with: "finished") + ", ended after release")
    }
}
