import Foundation
import Testing

import SwiftailBase

@testable import SwiftailIO

/// Tests the UDP socket wrapper (`DatagramSocket` in the contract's "Internal API"). Two sockets exchange datagrams over loopback.
@Suite("UDP sockets")
struct DatagramSocketTests {
    private static let loopback = IPAddress("127.0.0.1")!

    private static func destination(_ socket: DatagramSocket) -> IPEndpoint {
        IPEndpoint(address: loopback, port: socket.localPort)
    }

    /// Waits for one datagram from the stream. Returns nil if none arrives by the deadline.
    private static func next(
        from socket: DatagramSocket,
        within duration: Duration = .seconds(5)
    ) async -> (bytes: [UInt8], source: IPEndpoint)? {
        let stream = socket.datagrams
        return try? await withTimeout(duration) {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next()
        }
    }

    @Test("Binds to an OS-assigned port, and different sockets get different ports")
    func bindsToOSChosenPort() throws {
        let first = try DatagramSocket()
        let second = try DatagramSocket()
        #expect(first.localPort != 0)
        #expect(second.localPort != 0)
        #expect(first.localPort != second.localPort)
    }

    @Test("Binding to a port already in use yields bindFailed(EADDRINUSE)")
    func bindFailsWhenPortInUse() throws {
        let first = try DatagramSocket()
        #expect(throws: SocketError.bindFailed("EADDRINUSE")) {
            _ = try DatagramSocket(port: first.localPort)
        }
    }

    @Test("Exchanges datagrams over loopback and reports the correct source address", arguments: [0, 1, 512, 1400, 9000])
    func exchangesDatagrams(_ size: Int) async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        let payload = (0..<size).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) }
        try sender.send(payload, to: Self.destination(receiver))
        let received = try #require(await Self.next(from: receiver))
        #expect(received.bytes == payload)
        #expect(received.source == IPEndpoint(address: Self.loopback, port: sender.localPort))
    }

    /// The macOS UDP send limit (`net.inet.udp.maxdgram` 9216) is the socket send buffer size. Larger datagrams yield
    /// `EMSGSIZE`. Verify that the receive buffer (65,535 bytes) does not truncate data using a test socket with a larger send buffer.
    @Test("Receives the largest IPv4 datagram (65,507 bytes) without truncation")
    func receivesLargestDatagram() async throws {
        let receiver = try DatagramSocket()
        let payload = (0..<65_507).map { UInt8(truncatingIfNeeded: $0 &* 13) }
        try TestUDPSender.send(payload, toLoopbackPort: receiver.localPort)
        let received = try #require(await Self.next(from: receiver))
        #expect(received.bytes == payload)
    }

    @Test("Reads all datagrams even when several arrive at once")
    func readsUntilNothingLeft() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        for number in 0..<50 {
            try sender.send([UInt8(number)], to: Self.destination(receiver))
        }
        var numbers: [UInt8] = []
        while numbers.count < 50, let datagram = await Self.next(from: receiver) {
            numbers += datagram.bytes
        }
        #expect(numbers == (0..<50).map(UInt8.init))
    }

    @Test("An IPv6 destination yields sendFailed(EAFNOSUPPORT)")
    func ipv6DestinationFails() throws {
        let socket = try DatagramSocket()
        let destination = try #require(IPEndpoint("[2001:db8::1]:9"))
        #expect(throws: SocketError.sendFailed("EAFNOSUPPORT")) {
            try socket.send([1], to: destination)
        }
    }

    @Test("An oversized datagram yields sendFailed(EMSGSIZE), and the socket remains usable")
    func oversizedDatagramFails() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        #expect(throws: SocketError.sendFailed("EMSGSIZE")) {
            try sender.send([UInt8](repeating: 0, count: 70_000), to: Self.destination(receiver))
        }
        try sender.send([9], to: Self.destination(receiver))
        let received = try #require(await Self.next(from: receiver))
        #expect(received.bytes == [9])
    }

    // MARK: Closing

    @Test("Closing ends the stream, and sending afterward yields sendFailed(EBADF)")
    func closeEndsStream() async throws {
        let socket = try DatagramSocket()
        let stream = socket.datagrams
        socket.close()
        socket.close()  // Calling it more than once is allowed
        let ended = try await withTimeout(.seconds(5)) {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        #expect(ended)
        #expect(throws: SocketError.sendFailed("EBADF")) {
            try socket.send([1], to: IPEndpoint(address: Self.loopback, port: 9))
        }
    }

    @Test("Closing while waiting also ends the stream")
    func closeWhileWaiting() async throws {
        let socket = try DatagramSocket()
        let stream = socket.datagrams
        let waiter = Task { () -> Bool in
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        try await Task.sleep(for: .milliseconds(50))
        socket.close()
        let ended = try await withTimeout(.seconds(5)) { await waiter.value }
        #expect(ended)
    }

    @Test("A closed socket leaves another socket alone if it gets the same descriptor number")
    func closedSocketDoesNotTouchReusedDescriptor() async throws {
        // Another socket immediately gets the file descriptor number released by the closed socket. If `send` or `close` after closure reaches it,
        // the new socket breaks. Repeat the closure and verify that the new socket remains usable.
        let peer = try DatagramSocket()
        for round in 0..<20 {
            let old = try DatagramSocket()
            old.close()
            let fresh = try DatagramSocket()
            #expect(throws: SocketError.sendFailed("EBADF")) { try old.send([1], to: Self.destination(peer)) }
            old.close()
            try fresh.send([UInt8(round)], to: Self.destination(peer))
            let received = try #require(await Self.next(from: peer))
            #expect(received.bytes == [UInt8(round)])
            fresh.close()
        }
    }

    @Test("Dropping the socket releases the port and ends the stream")
    func deinitClosesSocket() async throws {
        var port: UInt16 = 0
        var stream: AsyncStream<(bytes: [UInt8], source: IPEndpoint)>?
        do {
            let socket = try DatagramSocket()
            port = socket.localPort
            stream = socket.datagrams
        }
        // The read source's cancellation handler finishes closing. Wait until the port can be bound again.
        var rebound: DatagramSocket?
        for _ in 0..<100 where rebound == nil {
            rebound = try? DatagramSocket(port: port)
            if rebound == nil { try await Task.sleep(for: .milliseconds(20)) }
        }
        #expect(rebound != nil)
        let ended = try await withTimeout(.seconds(5)) { [stream] in
            guard let stream else { return false }
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        #expect(ended)
    }

    // MARK: Cancellation and slow consumers

    @Test("Canceling the waiting Task ends the read")
    func cancellationEndsWaitingRead() async throws {
        let socket = try DatagramSocket()
        let stream = socket.datagrams
        let waiter = Task { () -> Bool in
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        try await Task.sleep(for: .milliseconds(50))
        waiter.cancel()
        let ended = try await withTimeout(.seconds(5)) { await waiter.value }
        #expect(ended)
        // The socket stays open and can send.
        try socket.send([1], to: IPEndpoint(address: Self.loopback, port: 9))
    }

    @Test("Reading from an already canceled Task ends immediately")
    func readInCancelledTask() async throws {
        let socket = try DatagramSocket()
        let stream = socket.datagrams
        let task = Task { () -> Bool in
            while !Task.isCancelled { await Task.yield() }
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        task.cancel()
        let ended = try await withTimeout(.seconds(5)) { await task.value }
        #expect(ended)
    }

    @Test("Without a consumer, queues at most 256 datagrams and drops the oldest first")
    func slowConsumerKeepsNewest256() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        let total = 1000
        for number in 0..<total {
            // Encodes the number in 2 bytes. If the send buffer fills, waits briefly and retries.
            let payload = [UInt8(number >> 8), UInt8(number & 0xff)]
            while true {
                do {
                    try sender.send(payload, to: Self.destination(receiver))
                    break
                } catch SocketError.sendFailed("EAGAIN"), SocketError.sendFailed("ENOBUFS") {
                    try await Task.sleep(for: .milliseconds(1))
                }
            }
        }
        // Start consuming only after the last datagram enters the stream.
        try await Task.sleep(for: .milliseconds(500))
        let marker: [UInt8] = [0xff, 0xff]
        try sender.send(marker, to: Self.destination(receiver))
        try await Task.sleep(for: .milliseconds(200))

        var numbers: [Int] = []
        while let datagram = await Self.next(from: receiver, within: .seconds(2)) {
            if datagram.bytes == marker { break }
            numbers.append(Int(datagram.bytes[0]) << 8 | Int(datagram.bytes[1]))
        }
        // The marker displaced one more oldest datagram, leaving at most 255. The kernel may also have dropped some.
        #expect(numbers.count <= 255)
        #expect(!numbers.isEmpty)
        // The remaining datagrams are the most recent arrivals and stay in order.
        #expect(numbers == numbers.sorted())
        #expect(numbers.last == total - 1)
        #expect(try #require(numbers.first) >= total - 256)
    }

    @Test("When more than 1MiB accumulates without reads, only the newest datagrams remain, with a byte total within the limit")
    func slowConsumerKeepsNewestWithinByteLimit() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        // 8,000 bytes × 400 datagrams = 3.2MB. The count limit (256) alone would hold 2MB, so the byte limit (1MiB) applies first.
        let size = 8000
        let total = 400
        for number in 0..<total {
            var payload = [UInt8](repeating: 0xab, count: size)
            payload[0] = UInt8(number >> 8)
            payload[1] = UInt8(number & 0xff)
            // Give the receiver time to drain the kernel buffer. Sending everything at once under load caused the kernel to drop the last datagrams,
            // making "the last one remains" flaky. Send the last datagram after all earlier ones have entered the stream.
            if number % 16 == 15 { try await Task.sleep(for: .milliseconds(1)) }
            if number == total - 1 { try await Task.sleep(for: .milliseconds(200)) }
            while true {
                do {
                    try sender.send(payload, to: Self.destination(receiver))
                    break
                } catch SocketError.sendFailed("EAGAIN"), SocketError.sendFailed("ENOBUFS") {
                    try await Task.sleep(for: .milliseconds(1))
                }
            }
        }
        // Start consuming only after the last datagram enters the stream.
        try await Task.sleep(for: .milliseconds(500))

        var numbers: [Int] = []
        var byteTotal = 0
        while let datagram = await Self.next(from: receiver, within: .seconds(1)) {
            byteTotal += datagram.bytes.count
            numbers.append(Int(datagram.bytes[0]) << 8 | Int(datagram.bytes[1]))
        }
        #expect(byteTotal <= 1 << 20)
        // Keeps data up to near the limit (it may fall short by the space needed for one datagram, and the kernel may have dropped some).
        #expect(byteTotal > (1 << 20) / 2)
        #expect(numbers == numbers.sorted())
        #expect(numbers.last == total - 1)
        #expect(try #require(numbers.first) > total - 256)
    }

    // MARK: Send queue

    @Test("Sends enqueued datagrams in insertion order")
    func enqueueSendsInOrder() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        for start in stride(from: 0, to: 60, by: 20) {
            sender.enqueue((start..<start + 20).map { ([UInt8($0)], Self.destination(receiver)) })
        }
        var numbers: [UInt8] = []
        while numbers.count < 60, let datagram = await Self.next(from: receiver) {
            numbers += datagram.bytes
        }
        #expect(numbers == (0..<60).map(UInt8.init))
    }

    @Test("The send queue drops the oldest datagrams first above 256")
    func sendQueueKeepsNewest256() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        let total = 1000
        // Enqueue in one batch so the limit applies before the sender dequeues anything.
        sender.enqueue((0..<total).map { ([UInt8($0 >> 8), UInt8($0 & 0xff)], Self.destination(receiver)) })
        var numbers: [Int] = []
        while let datagram = await Self.next(from: receiver, within: .seconds(1)) {
            numbers.append(Int(datagram.bytes[0]) << 8 | Int(datagram.bytes[1]))
        }
        #expect(!numbers.isEmpty)
        #expect(numbers.count <= 256)
        #expect(numbers == numbers.sorted())
        #expect(try #require(numbers.first) >= total - 256)
    }

    @Test("The send queue drops the oldest datagrams first when the byte total exceeds 1MiB")
    func sendQueueKeepsNewestWithinByteLimit() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        // 8,000 bytes × 200 datagrams = 1.6MB. This is within the count limit (256), so the byte limit drops earlier datagrams. 1MiB holds 131.
        let total = 200
        sender.enqueue((0..<total).map { number in
            var payload = [UInt8](repeating: 0xab, count: 8000)
            payload[0] = UInt8(number)
            return (payload, Self.destination(receiver))
        })
        var numbers: [Int] = []
        while let datagram = await Self.next(from: receiver, within: .seconds(1)) {
            numbers.append(Int(datagram.bytes[0]))
        }
        // The kernel may have dropped some datagrams, so only check that those that should have been dropped did not arrive.
        #expect(!numbers.isEmpty)
        #expect(numbers == numbers.sorted())
        #expect(try #require(numbers.first) >= total - (1 << 20) / 8000)
    }

    @Test("Datagrams too large for UDP stay out of the send queue, and later datagrams are sent normally")
    func enqueueDropsOversizedDatagram() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        // A single 2MiB datagram exceeds the byte limit (1MiB) and would leave the queue over the limit if enqueued.
        sender.enqueue([([UInt8](repeating: 0, count: 2 << 20), Self.destination(receiver)), ([7], Self.destination(receiver))])
        #expect(await Self.next(from: receiver)?.bytes == [7])
    }

    @Test("Enqueueing after closing sends nothing")
    func enqueueAfterCloseSendsNothing() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        sender.close()
        sender.enqueue([([1], Self.destination(receiver))])
        #expect(await Self.next(from: receiver, within: .milliseconds(300)) == nil)
    }

    @Test("The send queue of a closed socket does not drain through a new socket that gets the same descriptor number")
    func closedSendQueueDoesNotUseReusedDescriptor() async throws {
        // Fill a socket's send queue, close it immediately, and open a new socket (likely to get the closed descriptor number). Any datagram from the old socket
        // must come from the old socket's port. A datagram from the new socket's port means a write used the closed descriptor number.
        let peer = try DatagramSocket()
        for round in 0..<20 {
            let old = try DatagramSocket()
            let oldPort = old.localPort
            old.enqueue((0..<200).map { _ in ([0xee, UInt8(round)], Self.destination(peer)) })
            old.close()
            let fresh = try DatagramSocket()
            try fresh.send([0x55, UInt8(round)], to: Self.destination(peer))
            while let datagram = await Self.next(from: peer, within: .seconds(2)) {
                if datagram.bytes == [0x55, UInt8(round)] {
                    #expect(datagram.source.port == fresh.localPort)
                    break
                }
                #expect(datagram.bytes.first == 0xee)
                #expect(datagram.source.port == oldPort)
            }
            fresh.close()
            // Drain late arrivals from the previous round.
            while await Self.next(from: peer, within: .milliseconds(50)) != nil {}
        }
    }

    @Test("closeAfterSending sends the queued datagrams, then closes the socket and releases the port")
    func closeAfterSendingFlushesQueue() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        let port = sender.localPort
        sender.enqueue((0..<10).map { ([UInt8($0)], Self.destination(receiver)) })
        sender.closeAfterSending()
        var numbers: [UInt8] = []
        while numbers.count < 10, let datagram = await Self.next(from: receiver) {
            numbers += datagram.bytes
        }
        #expect(numbers == (0..<10).map(UInt8.init))
        var rebound: DatagramSocket?
        for _ in 0..<100 where rebound == nil {
            rebound = try? DatagramSocket(port: port)
            if rebound == nil { try await Task.sleep(for: .milliseconds(20)) }
        }
        #expect(rebound != nil)
    }

    @Test("takeQueuedDatagrams dequeues all pending datagrams at once in order")
    func takeQueuedDatagramsDrainsInOrder() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        for number in 0..<30 {
            try sender.send([UInt8(number)], to: Self.destination(receiver))
        }
        // After receiving one datagram from the stream, wait for the rest to build up in the queue before dequeuing them.
        let first = try #require(await Self.next(from: receiver))
        try await Task.sleep(for: .milliseconds(200))
        let rest = receiver.takeQueuedDatagrams()
        #expect(first.bytes + rest.flatMap(\.bytes) == (0..<30).map(UInt8.init))
        #expect(receiver.takeQueuedDatagrams().isEmpty)
    }

    // MARK: Interface binding

    @Test("Two sockets bound to the loopback interface exchange datagrams over loopback")
    func boundToLoopbackInterfaceExchangesDatagrams() async throws {
        let index = if_nametoindex("lo0")
        try #require(index != 0)
        let receiver = try DatagramSocket(interfaceIndex: index)
        let sender = try DatagramSocket(interfaceIndex: index)
        try sender.send([1, 2, 3], to: Self.destination(receiver))
        let received = try #require(await Self.next(from: receiver))
        #expect(received.bytes == [1, 2, 3])
        #expect(received.source == IPEndpoint(address: Self.loopback, port: sender.localPort))
    }

    @Test("A socket bound to the loopback interface can also exchange datagrams with an unbound socket")
    func boundSocketExchangesWithUnboundSocket() async throws {
        let index = if_nametoindex("lo0")
        try #require(index != 0)
        let bound = try DatagramSocket(interfaceIndex: index)
        let plain = try DatagramSocket()
        try plain.send([7], to: Self.destination(bound))
        #expect(try #require(await Self.next(from: bound)).bytes == [7])
        try bound.send([8], to: Self.destination(plain))
        #expect(try #require(await Self.next(from: plain)).bytes == [8])
    }

    @Test("An interface index that does not exist throws bindFailed and leaves the port free")
    func unknownInterfaceIndexFails() async throws {
        // No device has the large index. The socket must be gone after the throw, so binding the same port again must succeed.
        let holder = try DatagramSocket()
        let port = holder.localPort
        holder.close()
        var failure: SocketError?
        do {
            _ = try DatagramSocket(port: port, interfaceIndex: 0x7fff_fff0)
        } catch {
            failure = error
        }
        guard case .bindFailed? = failure else {
            Issue.record("Expected bindFailed, got \(String(describing: failure))")
            return
        }
        var rebound: DatagramSocket?
        for _ in 0..<100 where rebound == nil {
            rebound = try? DatagramSocket(port: port)
            if rebound == nil { try await Task.sleep(for: .milliseconds(20)) }
        }
        #expect(rebound != nil)
    }

    /// An observation that node integration relies on is that a socket bound to a physical interface can also exchange datagrams with a loopback destination (`IP_BOUND_IF` allows it).
    /// The contract still specifies leaving sockets for loopback destinations unbound (the same rule as Go `isLocalhost`).
    @Test("A socket bound to en0 can also send to a loopback destination and receive from loopback", .enabled(if: if_nametoindex("en0") != 0))
    func physicalInterfaceBoundSocketExchangesOnLoopback() async throws {
        let bound = try DatagramSocket(interfaceIndex: if_nametoindex("en0"))
        let plain = try DatagramSocket()
        try bound.send([1], to: Self.destination(plain))
        #expect(try #require(await Self.next(from: plain)).bytes == [1])
        try plain.send([2], to: Self.destination(bound))
        #expect(try #require(await Self.next(from: bound)).bytes == [2])
    }

    @Test("Sending from a socket bound to lo0 to a non-loopback destination yields sendFailed(ENETUNREACH)")
    func loopbackBoundSocketCannotReachNonLoopback() throws {
        let socket = try DatagramSocket(interfaceIndex: if_nametoindex("lo0"))
        // 192.0.2.1 is a documentation address (TEST-NET-1). It goes nowhere.
        let destination = IPEndpoint(address: try #require(IPAddress("192.0.2.1")), port: 9)
        #expect(throws: SocketError.sendFailed("ENETUNREACH")) {
            try socket.send([1], to: destination)
        }
    }
}

/// A test UDP sender with a larger send buffer. `DatagramSocket` leaves the send buffer alone, so use this sender for
/// datagrams above the default limit (9216 bytes). Keep POSIX pointers in this test function only.
private enum TestUDPSender {
    struct Failure: Error { var step: String }

    static func send(_ payload: [UInt8], toLoopbackPort port: UInt16) throws {
        let descriptor = socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { throw Failure(step: "socket") }
        defer { close(descriptor) }
        var bufferSize: Int32 = 1 << 20
        guard setsockopt(descriptor, SOL_SOCKET, SO_SNDBUF, &bufferSize, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw Failure(step: "setsockopt")
        }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr.s_addr = UInt32(0x7f00_0001).bigEndian
        let sent = payload.withUnsafeBytes { bytes in
            withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(descriptor, bytes.baseAddress, bytes.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard sent == payload.count else { throw Failure(step: "sendto errno=\(errno)") }
    }
}
