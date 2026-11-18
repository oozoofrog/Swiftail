import SwiftailBase
import Testing

@testable import SwiftailNetstack

/// For a connection the application releases with `close` or `abort`, `.releasedConnectionClosed` is emitted once when TCP finishes (CLOSED, TIME-WAIT),
/// and the events sent to the application stay the same. Contract `docs/contracts/SwiftailNetstack.md`, "Connections Released by the Application" in "Connection Close Statistics Log."
@Suite("Stack completion of released connections")
struct StackReleasedCloseTests {
    @Test("A connection released with close after the peer sends FIN is reported once on the final ACK")
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

        // The server enters LAST-ACK and the client's ACK puts it in CLOSED.
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

    @Test("A connection the application releases first with close is reported once when it enters TIME-WAIT after exchanging FINs")
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

        // Expiration of the TIME-WAIT record does not send another notification.
        try pair.run(for: .seconds(300))
        #expect(pair.client.timeWaitRecords.isEmpty)
        #expect(pair.clientReleasedCloses.count == 1)
        #expect(pair.serverReleasedCloses.count == 1)
        expectStackInvariants(pair.client)
    }

    @Test("Releasing a connection that received .closed while held does not notify again")
    func heldCloseIsNotRepeated() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        // The server finishes writing without reading the data received. It ends in LAST-ACK and receives `.closed(.finished)`, but the unread data
        // keeps the entry around.
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

    @Test("Statistics include retransmissions after release")
    func retransmissionAfterRelease() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        _ = pair.write(Array(repeating: 2, count: 1_000), to: ids.client, from: .client)
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        // Data and FIN are lost. The client retransmits after RTO.
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

    @Test("If the peer ends the connection with RST after release, reports reset")
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
        // Aborting the server connection while held yields one event and no released-connection completion.
        #expect(pair.serverEvents.map(\.withoutStatistics).last == .closed(ids.server, .aborted, .unchecked))
        #expect(pair.serverReleasedCloses.isEmpty)
    }

    @Test("Reports peerRemoved even for a released connection if an address change ends it")
    func peerRemovedAfterRelease() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let ids = try pair.open(listener: listener)
        pair.collect(pair.client.close(ids.client, at: pair.now), from: .client)
        let outputs = pair.client.setLocalAddresses([WireHosts.v6a])
        #expect(outputs.events.isEmpty)
        #expect(outputs.releasedCloses.map(\.reason) == [.peerRemoved])
    }

    @Test("abort and a close that ends immediately emit only one .closed, and connections discarded on node shutdown are not reported")
    func immediateEndsAreReportedOnce() throws {
        var pair = StackPair()
        let listener = try pair.server.listen(on: 443)
        let aborted = try pair.open(listener: listener)
        let unread = try pair.open(listener: listener)
        let closing = try pair.open(listener: listener)

        let abortOutputs = pair.client.abort(aborted.client, at: pair.now)
        #expect(abortOutputs.events.map(\.withoutStatistics) == [.closed(aborted.client, .aborted, .unchecked)])
        #expect(abortOutputs.releasedCloses.isEmpty)

        // A close with unread data ends immediately with RST.
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
