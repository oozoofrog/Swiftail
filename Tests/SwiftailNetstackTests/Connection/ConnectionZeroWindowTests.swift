import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 창 0의 경계(M6 검토 A): 응용이 `close`로 놓은 연결의 0 창 탐침 한도, 데이터가 날아가는 중에 줄어든 창의 재전송 한도,
/// 받는 창이 0일 때의 데이터 없는 FIN. 계약 동작 F8과 그 아래, T6.
@Suite("창 0의 경계")
struct ConnectionZeroWindowTests {
    /// 타이머를 차례로 돌리며 `answer`로 상대의 답을 넣는다. 사건이 나오거나 `limit`에 닿으면 멈추고 그 출력을 돌려준다.
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

    // MARK: 놓은 연결의 0 창 탐침 (동작 F8)

    @Test("close로 놓은 연결은 상대가 탐침에 창 0으로 답해도 15번 뒤 RST를 보내고 .timedOut으로 끝난다. 보내는 버퍼를 놓는다")
    func releasedConnectionProbeLimit() throws {
        var peer = try ManualPeer.established(ackWindow: 0)
        let (accepted, _) = peer.connection.write(patternBytes(count: 200_000)[...], at: peer.now)
        #expect(accepted == 200_000)
        _ = peer.connection.close(at: peer.now)
        var probes = 0
        let final = runTimers(&peer, until: .seconds(30_000)) { peer, outputs in
            guard outputs.segments.contains(where: { $0.payload == [0] }) else { return }
            probes += 1
            // 15번째 탐침까지는 연결이 남는다.
            #expect(peer.connection.state == .established)
            _ = peer.receive(peer.segment(flags: [.ack], window: 0))
        }
        #expect(probes == 15)
        #expect(final.segments.map(\.flags) == [[.rst]])
        #expect(final.segments.first?.sequenceNumber == peer.connection.sendNext)
        #expect(final.events == [.closed(.timedOut)])
        #expect(peer.connection.unacknowledgedSendByteCount == 0)
    }

    @Test("응용이 쥐고 있는 연결은 상대가 탐침에 답하는 한 15번을 넘어도 끊지 않는다(MUST-37)")
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

    @Test("놓은 연결의 탐침 수는 상대가 창을 열어 데이터를 확인받으면 다시 센다")
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
            // 10번째 탐침에 창을 열어 데이터를 받고, 받은 것을 확인하며 다시 창을 0으로 닫는다.
            opened = true
            let sent = peer.receive(peer.segment(flags: [.ack], window: 4_960))
            #expect(sent.segments.map(\.payload.count).reduce(0, +) == 4_960)
            _ = peer.receive(peer.segment(flags: [.ack], window: 0))
        }
        #expect(probes == 25)
        #expect(final.events == [.closed(.timedOut)])
    }

    // MARK: 줄어든 창의 재전송 (동작 F8 아래, RFC 9293 3.8.6 SHLD-17·MUST-35)

    /// 3,000바이트를 보낸 뒤 상대가 `ACK=SND.UNA`, 창 0으로 답한 연결.
    private func shrunkWindowPeer() throws -> ManualPeer {
        var peer = try ManualPeer.established()
        let (_, sent) = peer.connection.write(patternBytes(count: 3_000)[...], at: peer.now)
        #expect(sent.segments.map(\.payload.count).reduce(0, +) == 3_000)
        _ = peer.receive(peer.segment(acknowledgment: peer.connection.sendUnacknowledged, flags: [.ack], window: 0))
        #expect(peer.connection.sendWindow == 0)
        return peer
    }

    @Test("데이터가 날아가는 중에 창이 0으로 줄고 상대가 재전송마다 ACK하면 재전송 한도로 끊지 않는다")
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

    @Test("줄어든 창에서 상대가 답하지 않으면 한도로 끝난다: 창 0의 ACK 뒤 첫 만료만 세지 않아 16번 다시 보낸 뒤 .timedOut")
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

    @Test("close로 놓은 연결은 줄어든 창에서 상대가 답해도 재전송 15번 뒤 RST를 보내고 .timedOut으로 끝난다")
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

    // MARK: 창 0의 FIN (동작 T6)

    /// 상대 SYN에 Window Scale이 있어 256KiB를 광고한 연결에 256KiB를 채워 받는 창을 0으로 만든다. 보낸 바이트를 돌려준다.
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

    @Test("받는 창이 0이어도 RCV.NXT의 데이터 없는 FIN은 소비한다. 응용은 남은 데이터를 다 읽은 뒤 EOF를 본다")
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

    @Test("받는 창이 0일 때 데이터가 든 FIN은 지금 규칙 그대로 소비하지 않는다(데이터가 창에 다 들어와야 한다)")
    func finWithDataOnZeroWindow() throws {
        var peer = try ManualPeer.established(windowScale: 7)
        _ = fillReceiveWindow(&peer)
        let outputs = peer.receive(peer.segment(flags: [.fin, .ack], payload: [1]))
        #expect(outputs.events.isEmpty)
        #expect(outputs.segments.map(\.acknowledgmentNumber) == [peer.peerNext])
        #expect(outputs.segments.first?.window == 0)
        #expect(peer.connection.state == .established)
        #expect(!peer.connection.hasReceivedEndOfStream)
        // RCV.NXT가 아닌 곳의 FIN도 받지 않는다.
        let ahead = peer.receive(peer.segment(sequence: peer.peerNext.advanced(by: 1), flags: [.fin, .ack]))
        #expect(ahead.events.isEmpty)
        #expect(!peer.connection.hasReceivedEndOfStream)
    }
}
