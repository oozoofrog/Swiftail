import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// Zero-window edge cases (M6 review A): the zero-window probe limit for a connection released by the application with `close`, the retransmission limit when the window shrinks with data in flight,
/// and a data-free FIN when the receive window is zero. Contract behavior F8 and the material below it, T6.
@Suite("Zero-window edge cases")
struct ConnectionZeroWindowTests {
    /// Runs timers in order and uses `answer` to feed the peer's replies. Stops and returns the output when an event occurs or `limit` is reached.
    private func runTimers(
        _ peer: inout ManualPeer, until limit: Duration,
        answer: (inout ManualPeer, [TCPConnection.Output]) -> Void
    ) -> [TCPConnection.Output] {
        let start = peer.now
        while let deadline = peer.connection.nextDeadline, deadline - start <= limit {
            peer.now = deadline
            let outputs = peer.connection.advance(to: deadline)
            if !outputs.events.isEmpty { return outputs }
            answer(&peer, outputs)
        }
        return []
    }

    // MARK: Zero-window probes on released connections (behavior F8)

    @Test("A connection released with close sends RST and ends with .timedOut after 15 probes even if the peer replies with a zero window. It releases the send buffer")
    func releasedConnectionProbeLimit() throws {
        var peer = try ManualPeer.established(ackWindow: 0)
        let (accepted, _) = peer.connection.write(patternBytes(count: 200_000)[...], at: peer.now)
        #expect(accepted == 200_000)
        _ = peer.connection.close(at: peer.now)
        var probes = 0
        let final = runTimers(&peer, until: .seconds(30_000)) { peer, outputs in
            guard outputs.segments.contains(where: { $0.payload == [0] }) else { return }
            probes += 1
            // The connection stays through the 15th probe.
            #expect(peer.connection.state == .established)
            _ = peer.receive(peer.segment(flags: [.ack], window: 0))
        }
        #expect(probes == 15)
        #expect(final.segments.map(\.flags) == [[.rst]])
        #expect(final.segments.first?.sequenceNumber == peer.connection.sendNext)
        #expect(final.events == [.closed(.timedOut)])
        #expect(peer.connection.unacknowledgedSendByteCount == 0)
    }

    @Test("An application-held connection stays open beyond 15 probes as long as the peer replies (MUST-37)")
    func heldConnectionKeepsProbing() throws {
        var peer = try ManualPeer.established(ackWindow: 0)
        _ = peer.connection.write(patternBytes(count: 200_000)[...], at: peer.now)
        var probes = 0
        let final = runTimers(&peer, until: .seconds(3_000)) { peer, outputs in
            guard outputs.segments.contains(where: { $0.payload == [0] }) else { return }
            probes += 1
            _ = peer.receive(peer.segment(flags: [.ack], window: 0))
        }
        #expect(final.isEmpty)
        #expect(probes > 40)
        #expect(peer.connection.state == .established)
    }

    @Test("A released connection resets its probe count after the peer opens the window and acknowledges data")
    func releasedConnectionProbeCountResetsOnProgress() throws {
        var peer = try ManualPeer.established(ackWindow: 0)
        _ = peer.connection.write(patternBytes(count: 200_000)[...], at: peer.now)
        _ = peer.connection.close(at: peer.now)
        var probes = 0
        var opened = false
        let final = runTimers(&peer, until: .seconds(30_000)) { peer, outputs in
            guard outputs.segments.contains(where: { $0.payload == [0] }) else { return }
            probes += 1
            guard probes == 10, !opened else {
                _ = peer.receive(peer.segment(flags: [.ack], window: 0))
                return
            }
            // Open the window on the 10th probe, receive data, then acknowledge it while closing the window back to 0.
            opened = true
            let sent = peer.receive(peer.segment(flags: [.ack], window: 4_960))
            #expect(sent.segments.map(\.payload.count).reduce(0, +) == 4_960)
            _ = peer.receive(peer.segment(flags: [.ack], window: 0))
        }
        #expect(probes == 25)
        #expect(final.events == [.closed(.timedOut)])
    }

    // MARK: Retransmission in a shrunk window (below behavior F8, RFC 9293 3.8.6 SHLD-17·MUST-35)

    /// A connection whose peer responded to 3,000 bytes sent with `ACK=SND.UNA` and a zero window.
    private func shrunkWindowPeer() throws -> ManualPeer {
        var peer = try ManualPeer.established()
        let (_, sent) = peer.connection.write(patternBytes(count: 3_000)[...], at: peer.now)
        #expect(sent.segments.map(\.payload.count).reduce(0, +) == 3_000)
        _ = peer.receive(peer.segment(acknowledgment: peer.connection.sendUnacknowledged, flags: [.ack], window: 0))
        #expect(peer.connection.sendWindow == 0)
        return peer
    }

    @Test("If the window shrinks to 0 with data in flight and the peer ACKs each retransmission, the retransmission limit does not abort the connection")
    func shrunkWindowAnswered() throws {
        var peer = try shrunkWindowPeer()
        var retransmissions = 0
        let final = runTimers(&peer, until: .seconds(3_000)) { peer, outputs in
            guard outputs.segments.contains(where: { !$0.payload.isEmpty }) else { return }
            retransmissions += 1
            _ = peer.receive(
                peer.segment(acknowledgment: peer.connection.sendUnacknowledged, flags: [.ack], window: 0))
        }
        #expect(final.isEmpty)
        #expect(retransmissions > 15)
        #expect(peer.connection.state == .established)
    }

    @Test("If the peer does not respond after the window shrinks, the limit ends the connection. Only the first expiration after the zero-window ACK is skipped, so .timedOut follows 16 retransmissions")
    func shrunkWindowSilentPeer() throws {
        var peer = try shrunkWindowPeer()
        var retransmissions = 0
        let final = runTimers(&peer, until: .seconds(5_000)) { _, outputs in
            if outputs.segments.contains(where: { !$0.payload.isEmpty }) { retransmissions += 1 }
        }
        #expect(retransmissions == 16)
        #expect(final.segments.isEmpty)
        #expect(final.events == [.closed(.timedOut)])
    }

    @Test("A connection released with close sends RST and ends with .timedOut after 15 retransmissions even if the peer responds in the shrunk window")
    func shrunkWindowReleased() throws {
        var peer = try shrunkWindowPeer()
        _ = peer.connection.close(at: peer.now)
        var retransmissions = 0
        let final = runTimers(&peer, until: .seconds(5_000)) { peer, outputs in
            guard outputs.segments.contains(where: { !$0.payload.isEmpty }) else { return }
            retransmissions += 1
            _ = peer.receive(
                peer.segment(acknowledgment: peer.connection.sendUnacknowledged, flags: [.ack], window: 0))
        }
        #expect(retransmissions == 15)
        #expect(final.segments.map(\.flags) == [[.rst]])
        #expect(final.events == [.closed(.timedOut)])
    }

    // MARK: FIN with a zero window (behavior T6)

    /// Fill a connection that advertised 256KiB because of Window Scale in the peer's SYN with 256KiB to close its receive window. Returns the bytes sent.
    private func fillReceiveWindow(_ peer: inout ManualPeer) -> [UInt8] {
        var sent: [UInt8] = []
        for index in 0..<(256 * 1024 / 1_024) {
            let chunk = patternBytes(count: 1_024, seed: UInt8(truncatingIfNeeded: index))
            sent += chunk
            peer.send(flags: [.ack], payload: chunk)
        }
        _ = peer.advance(by: .milliseconds(40))
        return sent
    }

    @Test("Consumes a data-free FIN at RCV.NXT even with a zero receive window. The application sees EOF after reading all remaining data")
    func bareFinOnZeroWindow() throws {
        var peer = try ManualPeer.established(windowScale: 7)
        let sent = fillReceiveWindow(&peer)
        #expect(peer.connection.readableByteCount == 256 * 1024)
        let outputs = peer.send(flags: [.fin, .ack])
        #expect(outputs.events == [.endOfStream])
        #expect(outputs.segments.map(\.acknowledgmentNumber) == [peer.peerNext])
        #expect(outputs.segments.first?.window == 0)
        #expect(peer.connection.state == .closeWait)

        var received: [UInt8] = []
        while true {
            let bytes = peer.connection.read(upTo: 10_000, at: peer.now).bytes
            if bytes.isEmpty { break }
            received += bytes
        }
        #expect(received == sent)
        #expect(peer.connection.readableByteCount == 0)
        #expect(peer.connection.hasReceivedEndOfStream)
    }

    @Test("A FIN carrying data is still not consumed with a zero receive window under the current rule (all the data must fit in the window)")
    func finWithDataOnZeroWindow() throws {
        var peer = try ManualPeer.established(windowScale: 7)
        _ = fillReceiveWindow(&peer)
        let outputs = peer.receive(peer.segment(flags: [.fin, .ack], payload: [1]))
        #expect(outputs.events.isEmpty)
        #expect(outputs.segments.map(\.acknowledgmentNumber) == [peer.peerNext])
        #expect(outputs.segments.first?.window == 0)
        #expect(peer.connection.state == .established)
        #expect(!peer.connection.hasReceivedEndOfStream)
        // A FIN at a position other than RCV.NXT is also rejected.
        let ahead = peer.receive(peer.segment(sequence: peer.peerNext.advanced(by: 1), flags: [.fin, .ack]))
        #expect(ahead.events.isEmpty)
        #expect(!peer.connection.hasReceivedEndOfStream)
    }
}
