import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// 응용이 `close`·`abort`로 놓은 연결의 끝: TCP의 일이 끝날 때(CLOSED, TIME-WAIT) `.releasedConnectionClosed`가 한 번
/// 나오고, 응용에 가는 사건은 그대로다. 계약 `docs/contracts/SwiftailNetstack.md` "연결 종료 통계 로그"의 "응용이 놓은 연결".
@Suite("스택: 놓은 연결의 끝")
struct StackReleasedCloseTests {
    @Test("상대가 먼저 FIN을 보낸 뒤 close로 놓은 연결은 마지막 ACK에서 한 번 알린다")
    func lastAcknowledgmentAfterPeerFinish() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        _ = pair.write(Array(repeating: 7, count: 3_000), to: ids.server, from: .server)
        try pair.deliver()
        pair.collect(pair.client.finishWriting(ids.client, at: pair.now), from: .client)
        try pair.deliver()
        #expect(pair.serverEvents.last == .endOfStream(ids.server))
        let eventsBefore = pair.serverEvents

        // 서버가 LAST-ACK에 들고, 클라이언트의 ACK로 CLOSED가 된다.
        pair.collect(pair.server.close(ids.server, at: pair.now), from: .server)
        #expect(pair.serverReleasedCloses.isEmpty)
        try pair.deliver()
        #expect(pair.serverReleasedCloses.map(\.reason) == [.finished])
        #expect(pair.serverReleasedCloses.first?.statistics.sentBytes == 3_000)
        #expect(pair.serverEvents == eventsBefore)
        #expect(pair.server.connections.isEmpty)

        try pair.run(for: .seconds(300))
        #expect(pair.serverReleasedCloses.count == 1)
        #expect(pair.clientReleasedCloses.isEmpty)
        expectStackInvariants(pair.server)
    }

    @Test("응용이 먼저 close로 놓은 연결은 FIN을 주고받아 TIME-WAIT에 들 때 한 번 알린다")
    func timeWaitAfterRelease() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        _ = pair.write(Array(repeating: 1, count: 2_000), to: ids.client, from: .client)
        try pair.deliver()
        #expect(pair.read(ids.server, from: .server).count == 2_000)
        let clientEventsBefore = pair.clientEvents

        try pair.closeFromClient(ids)
        #expect(pair.client.timeWaitRecords.count == 1)
        #expect(pair.clientReleasedCloses.map(\.reason) == [.finished])
        #expect(pair.clientReleasedCloses.first?.statistics.sentBytes == 2_000)
        #expect(pair.serverReleasedCloses.map(\.reason) == [.finished])
        #expect(pair.clientEvents == clientEventsBefore)

        // TIME-WAIT 기록이 기한에 사라져도 다시 알리지 않는다.
        try pair.run(for: .seconds(300))
        #expect(pair.client.timeWaitRecords.isEmpty)
        #expect(pair.clientReleasedCloses.count == 1)
        #expect(pair.serverReleasedCloses.count == 1)
        expectStackInvariants(pair.client)
    }

    @Test("쥔 채 .closed를 받은 연결은 놓아도 다시 알리지 않는다")
    func heldCloseIsNotRepeated() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        // 서버는 받은 데이터를 읽지 않은 채 쓰기를 끝낸다. LAST-ACK에서 끝나 `.closed(.finished)`를 받고, 읽지 않은 데이터
        // 때문에 항목이 남는다.
        _ = pair.write([1, 2, 3], to: ids.client, from: .client)
        pair.collect(pair.client.finishWriting(ids.client, at: pair.now), from: .client)
        try pair.deliver()
        pair.collect(pair.server.finishWriting(ids.server, at: pair.now), from: .server)
        try pair.deliver()
        #expect(pair.serverEvents.map(\.withoutStatistics).last == .closed(ids.server, .finished, .unchecked))
        #expect(pair.clientEvents.map(\.withoutStatistics).last == .closed(ids.client, .finished, .unchecked))
        #expect(pair.server.connections[ids.server]?.isDetached == true)

        pair.collect(pair.server.close(ids.server, at: pair.now), from: .server)
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        try pair.run(for: .seconds(300))
        #expect(pair.serverReleasedCloses.isEmpty)
        #expect(pair.clientReleasedCloses.isEmpty)
        #expect(pair.server.connections.isEmpty)
        #expect(pair.client.connections.isEmpty)
    }

    @Test("놓은 뒤의 재전송도 통계에 든다")
    func retransmissionAfterRelease() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        _ = pair.write(Array(repeating: 2, count: 1_000), to: ids.client, from: .client)
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        // 데이터와 FIN을 잃는다. RTO 뒤 클라이언트가 다시 보낸다.
        pair.toServer = []
        try pair.run(for: .seconds(3))
        #expect(pair.read(ids.server, from: .server).count == 1_000)
        pair.collect(pair.server.close(ids.server, at: pair.now), from: .server)
        try pair.deliver()

        #expect(pair.clientReleasedCloses.map(\.reason) == [.finished])
        let statistics = try #require(pair.clientReleasedCloses.first?.statistics)
        #expect(statistics.sentBytes == 1_000)
        #expect(statistics.retransmittedBytes == 1_000)
        #expect(statistics.retransmissionTimeouts >= 1)
    }

    @Test("놓은 뒤 상대의 RST로 끝나면 reset으로 알린다")
    func resetAfterRelease() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        let clientEventsBefore = pair.clientEvents
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        pair.collect(pair.server.abort(ids.server, at: pair.now), from: .server)
        try pair.deliver()

        #expect(pair.clientReleasedCloses.map(\.reason) == [.reset])
        #expect(pair.clientEvents == clientEventsBefore)
        #expect(pair.client.connections.isEmpty)
        // 쥔 채 끊은 서버는 사건 하나이고 놓은 연결의 끝은 없다.
        #expect(pair.serverEvents.map(\.withoutStatistics).last == .closed(ids.server, .aborted, .unchecked))
        #expect(pair.serverReleasedCloses.isEmpty)
    }

    @Test("놓은 연결도 주소가 바뀌어 끝나면 peerRemoved로 알린다")
    func peerRemovedAfterRelease() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        let outputs = pair.client.setLocalAddresses([WireHosts.v6a])
        #expect(outputs.events.isEmpty)
        #expect(outputs.releasedCloses.map(\.reason) == [.peerRemoved])
    }

    @Test("abort와 곧바로 끝나는 close는 .closed 하나만 내고, 노드가 멈추며 버리는 연결은 알리지 않는다")
    func immediateEndsAreReportedOnce() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let aborted = try pair.open(listener: listener)
        let unread = try pair.open(listener: listener)
        let closing = try pair.open(listener: listener)

        let abortOutputs = pair.client.abort(aborted.client, at: pair.now)
        #expect(abortOutputs.events.map(\.withoutStatistics) == [.closed(aborted.client, .aborted, .unchecked)])
        #expect(abortOutputs.releasedCloses.isEmpty)

        // 읽지 않은 데이터가 있는 close는 RST로 곧바로 끝난다.
        _ = pair.write([1, 2, 3], to: unread.server, from: .server)
        try pair.deliver()
        let closeOutputs = pair.client.close(unread.client, at: pair.now)
        #expect(closeOutputs.events.map(\.withoutStatistics) == [.closed(unread.client, .aborted, .unchecked)])
        #expect(closeOutputs.releasedCloses.isEmpty)

        pair.collect(abortOutputs, from: .client)
        pair.collect(closeOutputs, from: .client)
        pair.collect(pair.client.close(closing.client, at: pair.now), from: .client)
        let stopOutputs = pair.client.abortAll()
        #expect(stopOutputs.releasedCloses.isEmpty)
        #expect(stopOutputs.events.isEmpty)
        try pair.run(for: .seconds(300))
        #expect(pair.clientReleasedCloses.isEmpty)
    }
}
