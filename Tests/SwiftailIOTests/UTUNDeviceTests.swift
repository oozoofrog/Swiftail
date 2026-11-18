import Darwin
import Foundation
import Synchronization
import Testing

@testable import SwiftailIO

/// Tests the utun device wrapper (contract "Tests" 9). Opening a real utun requires privileges, so leave that to the real-device gate. Instead, bypass the utun check
/// and use one end of a `socketpair` in its place. An `AF_UNIX`·`SOCK_DGRAM` pair preserves datagram boundaries and behaves like utun's
/// "one packet per read."
@Suite("utun device")
struct UTUNDeviceTests {
    private static let ipv4Packet: [UInt8] = [0x45, 0, 0, 20] + [UInt8](repeating: 7, count: 16)
    private static let ipv6Packet: [UInt8] = [0x60, 0, 0, 0] + [UInt8](repeating: 9, count: 36)

    /// Bypasses only the utun check. Duplication, `O_NONBLOCK`, and reads still use the production code.
    private static func device(on descriptor: Int32, mtu: Int = 1280) throws -> UTUNDevice {
        try UTUNDevice(duplicating: descriptor, mtu: mtu, verifying: { _ in })
    }

    private enum Outcome: Sendable, Equatable {
        case packet([UInt8])
        case ended
        case failed(SocketError)
        case timeout
    }

    /// Waits for one item from the stream.
    private static func next(from device: UTUNDevice, within duration: Duration = .seconds(5)) async -> Outcome {
        let stream = device.packets
        do {
            return try await withTimeout(duration) {
                var iterator = stream.makeAsyncIterator()
                if let packet = await iterator.next() { return .packet(packet) }
                if let failure = device.readFailure { return .failed(failure) }
                return .ended
            }
        } catch {
            return .timeout
        }
    }

    // MARK: Header insertion, removal, and version detection (pure functions)

    @Test("IP version 4 gets an AF_INET (2) header and version 6 gets an AF_INET6 (30) header")
    func framesByVersion() {
        #expect(UTUNDevice.frame(Self.ipv4Packet) == [0, 0, 0, 2] + Self.ipv4Packet)
        #expect(UTUNDevice.frame(Self.ipv6Packet) == [0, 0, 0, 30] + Self.ipv6Packet)
    }

    @Test("Packets with a version other than 4 or 6 and empty packets get no header", arguments: [0x00, 0x10, 0x30, 0x50, 0x70, 0xf0, 0x04, 0x06] as [UInt8])
    func rejectsOtherVersions(_ first: UInt8) {
        // Only the upper nibble encodes the version. A 4 or 6 in the lower nibble does not specify a version.
        #expect(UTUNDevice.frame([first, 1, 2, 3]) == nil)
    }

    @Test("The upper nibble of the first byte encodes the version")
    func versionIsHighNibble() {
        #expect(UTUNDevice.frame([0x4f, 0]) == [0, 0, 0, 2, 0x4f, 0])
        #expect(UTUNDevice.frame([0x6f, 0]) == [0, 0, 0, 30, 0x6f, 0])
        #expect(UTUNDevice.frame([]) == nil)
    }

    @Test("Removes the header without inspecting its value")
    func stripsHeaderWithoutLookingAtIt() {
        #expect(UTUNDevice.ipPacket(inFrame: [0, 0, 0, 2] + Self.ipv4Packet) == Self.ipv4Packet)
        #expect(UTUNDevice.ipPacket(inFrame: [0xff, 0xff, 0xff, 0xff, 0x45]) == [0x45])
        // Also works when the slice starts at a nonzero index.
        let frame: [UInt8] = [9, 9, 0, 0, 0, 2, 0x45, 1]
        #expect(UTUNDevice.ipPacket(inFrame: frame[2...]) == [0x45, 1])
    }

    @Test("Discards frames shorter than the header or containing only the header", arguments: 0...4)
    func dropsShortFrames(_ length: Int) {
        #expect(UTUNDevice.ipPacket(inFrame: [UInt8](repeating: 1, count: length)[...]) == nil)
    }

    // MARK: Reading

    @Test("Strips the frame header and yields only the IP packet")
    func readsPacketWithoutHeader() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        try pair.send([0, 0, 0, 2] + Self.ipv4Packet)
        try pair.send([0, 0, 0, 30] + Self.ipv6Packet)
        #expect(await Self.next(from: device) == .packet(Self.ipv4Packet))
        #expect(await Self.next(from: device) == .packet(Self.ipv6Packet))
    }

    @Test("Reads all packets in order even when several arrive at once")
    func readsUntilNothingLeft() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        for number in 0..<50 { try pair.send([0, 0, 0, 2, 0x45, UInt8(number)]) }
        var numbers: [UInt8] = []
        while numbers.count < 50, case .packet(let packet) = await Self.next(from: device) {
            numbers.append(packet[1])
        }
        #expect(numbers == (0..<50).map(UInt8.init))
    }

    @Test("Discards shorter-than-header and header-only reads, then keeps reading")
    func dropsShortReadsAndContinues() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        try pair.send([0, 0, 0])
        try pair.send([0, 0, 0, 2])
        try pair.send([0, 0, 0, 2, 0x45])
        #expect(await Self.next(from: device) == .packet([0x45]))
        #expect(await Self.next(from: device, within: .milliseconds(200)) == .timeout)
    }

    @Test("Yields packets as long as the MTU and drops packets that exceed it", arguments: [1280, 1420])
    func dropsPacketsOverMTU(_ mtu: Int) async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller, mtu: mtu)
        let atLimit = [0x45] + [UInt8](repeating: 1, count: mtu - 1)
        let overLimit = [0x45] + [UInt8](repeating: 2, count: mtu)
        try pair.send([0, 0, 0, 2] + overLimit)
        try pair.send([0, 0, 0, 2] + atLimit)
        #expect(await Self.next(from: device) == .packet(atLimit))
    }

    // MARK: Writing

    @Test("Writes IPv4 with header 2 and IPv6 with header 30")
    func writesHeaders() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        try device.write(Self.ipv4Packet)
        try device.write(Self.ipv6Packet)
        #expect(pair.receive() == [0, 0, 0, 2] + Self.ipv4Packet)
        #expect(pair.receive() == [0, 0, 0, 30] + Self.ipv6Packet)
    }

    @Test("Skips writes for other versions and empty packets and reports EAFNOSUPPORT")
    func writeRejectsOtherVersions() throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        #expect(throws: SocketError.sendFailed("EAFNOSUPPORT")) { try device.write([0x50, 1, 2]) }
        #expect(throws: SocketError.sendFailed("EAFNOSUPPORT")) { try device.write([]) }
        #expect(pair.receive(within: .milliseconds(100)) == nil)
        // The next packet can still be written after a failure.
        try device.write(Self.ipv4Packet)
        #expect(pair.receive() == [0, 0, 0, 2] + Self.ipv4Packet)
    }

    @Test("A packet the kernel could not accept yields sendFailed, and the device remains usable")
    func writeFailureKeepsDevice() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        // Exceeding the maximum `AF_UNIX` datagram size (2,048 bytes by default) yields EMSGSIZE.
        let oversized = [0x45] + [UInt8](repeating: 0, count: 8_000)
        #expect(throws: SocketError.sendFailed("EMSGSIZE")) { try device.write(oversized) }
        try device.write(Self.ipv4Packet)
        #expect(pair.receive() == [0, 0, 0, 2] + Self.ipv4Packet)
    }

    /// Before the fix, writing to a disconnected stream socket killed the test process with SIGPIPE (signal 13).
    @Test("Writing to a socket whose peer closed yields sendFailed(EPIPE) without a fatal signal")
    func writeToClosedPeerDoesNotRaiseSIGPIPE() throws {
        let pair = try SocketPair(type: SOCK_STREAM)
        defer { close(pair.caller) }  // The peer is already closed below. Closing the same descriptor number twice would close a descriptor from another test running in parallel.
        let device = try Self.device(on: pair.caller)
        pair.closePeer()
        #expect(throws: SocketError.sendFailed("EPIPE")) { try device.write(Self.ipv4Packet) }
    }

    // MARK: File descriptor ownership

    @Test("The duplicate has a different descriptor number from the caller's and has FD_CLOEXEC and O_NONBLOCK")
    func duplicateHasCloexecAndNonblocking() throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let copy = try #require(device.duplicateDescriptor)
        #expect(copy != pair.caller)
        #expect(fcntl(copy, F_GETFD) & FD_CLOEXEC != 0)
        #expect(fcntl(copy, F_GETFL) & O_NONBLOCK != 0)
    }

    @Test("Closing the device leaves the caller's descriptor open")
    func closeLeavesCallerDescriptorOpen() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let copy = try #require(device.duplicateDescriptor)
        device.close()
        try await Self.waitUntilClosed(copy, duplicateOf: pair.caller)
        #expect(fcntl(pair.caller, F_GETFD) >= 0)
        // The caller's descriptor can still read and write.
        try pair.send([1, 2, 3])
        #expect(pair.receiveOnCaller() == [1, 2, 3])
    }

    @Test("Dropping the device closes only the duplicate and leaves the caller's descriptor open")
    func deinitClosesOnlyDuplicate() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        var copy: Int32?
        var stream: AsyncStream<[UInt8]>?
        do {
            let device = try Self.device(on: pair.caller)
            copy = device.duplicateDescriptor
            stream = device.packets
        }
        try await Self.waitUntilClosed(try #require(copy), duplicateOf: pair.caller)
        #expect(fcntl(pair.caller, F_GETFD) >= 0)
        let outcome = try await withTimeout(.seconds(5)) { [stream] in
            guard let stream else { return Outcome.timeout }
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil ? .ended : .timeout
        }
        #expect(outcome == .ended)
    }

    // MARK: Closing

    @Test("Closing ends the stream without an error, and writing afterward yields EBADF")
    func closeEndsStream() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        device.close()
        device.close()  // Calling it more than once is allowed
        #expect(await Self.next(from: device) == .ended)
        #expect(throws: SocketError.sendFailed("EBADF")) { try device.write(Self.ipv4Packet) }
        #expect(pair.receive(within: .milliseconds(100)) == nil)
    }

    @Test("Closing while waiting also ends the stream")
    func closeWhileWaiting() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let waiter = Task { await Self.next(from: device) }
        try await Task.sleep(for: .milliseconds(50))
        device.close()
        #expect(await waiter.value == .ended)
    }

    @Test("The closed device leaves another device alone if it gets the same duplicate descriptor number")
    func closedDeviceDoesNotTouchReusedDescriptor() async throws {
        // Another owner immediately gets the descriptor number released by the closed device. If `write` or `close` after closure reaches it, the new device breaks.
        for round in 0..<20 {
            let oldPair = try SocketPair()
            let old = try Self.device(on: oldPair.caller)
            let oldCopy = try #require(old.duplicateDescriptor)
            old.close()
            try await Self.waitUntilClosed(oldCopy, duplicateOf: oldPair.caller)
            oldPair.closeAll()

            let freshPair = try SocketPair()
            defer { freshPair.closeAll() }
            let fresh = try Self.device(on: freshPair.caller)
            #expect(throws: SocketError.sendFailed("EBADF")) { try old.write(Self.ipv4Packet) }
            old.close()
            try fresh.write([0x45, UInt8(round)])
            #expect(freshPair.receive() == [0, 0, 0, 2, 0x45, UInt8(round)])
            fresh.close()
        }
    }

    @Test("When the peer closes, signals EOF and closes the read handler and the duplicate")
    func peerCloseStopsReaderAndClosesDuplicate() async throws {
        // Reads on a datagram socket pair do not end when the peer closes, so this test alone uses a stream socket pair.
        let pair = try SocketPair(type: SOCK_STREAM)
        defer { close(pair.caller) }  // The peer is already closed below. Do not close the same descriptor number twice.
        let readEvents = Mutex(0)
        let device = try UTUNDevice(duplicating: pair.caller, mtu: 1280, onReadEvent: {
            readEvents.withLock { $0 += 1 }
        }, verifying: { _ in })
        let copy = try #require(device.duplicateDescriptor)
        pair.closePeer()
        #expect(await Self.next(from: device) == .failed(.readFailed("EOF")))
        #expect(device.readFailure == .readFailed("EOF"))
        #expect(device.duplicateDescriptor == nil)
        try await Self.waitUntilClosed(copy, duplicateOf: pair.caller)
        #expect(throws: SocketError.sendFailed("EBADF")) { try device.write(Self.ipv4Packet) }
        // The first handler invocation reads EOF, so there is no reason to call it again.
        #expect(readEvents.withLock { $0 } == 1)
        try await Task.sleep(for: .milliseconds(50))
        #expect(readEvents.withLock { $0 } == 1)
        device.close()
        #expect(device.readFailure == .readFailed("EOF"))
    }

    // MARK: Cancellation and slow consumers

    @Test("Canceling the waiting Task ends the read and leaves the device open")
    func cancellationEndsWaitingRead() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let stream = device.packets
        let waiter = Task { () -> Bool in
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        try await Task.sleep(for: .milliseconds(50))
        waiter.cancel()
        let ended = try await withTimeout(.seconds(5)) { await waiter.value }
        #expect(ended)
        try device.write(Self.ipv4Packet)
        #expect(pair.receive() == [0, 0, 0, 2] + Self.ipv4Packet)
    }

    @Test("Reading from an already canceled Task ends immediately")
    func readInCancelledTask() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let stream = device.packets
        let task = Task { () -> Bool in
            while !Task.isCancelled { await Task.yield() }
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        task.cancel()
        let ended = try await withTimeout(.seconds(5)) { await task.value }
        #expect(ended)
    }

    @Test("Without a consumer, queues at most 256 packets and drops the oldest first")
    func slowConsumerKeepsNewest256() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let total = 1000
        for number in 0..<total {
            // Encodes the number in 2 bytes. If the receive queue fills, `send` waits briefly and retries.
            try pair.send([0, 0, 0, 2, UInt8(number >> 8) | 0x40, UInt8(number & 0xff)])
        }
        // Start consuming only after the last packet enters the stream.
        try await Task.sleep(for: .milliseconds(500))
        let marker: [UInt8] = [0x4f, 0xff]
        try pair.send([0, 0, 0, 2] + marker)
        try await Task.sleep(for: .milliseconds(200))

        var numbers: [Int] = []
        while case .packet(let packet) = await Self.next(from: device, within: .seconds(2)) {
            if packet == marker { break }
            numbers.append(Int(packet[0] & 0x3f) << 8 | Int(packet[1]))
        }
        // The marker displaced one more oldest packet, leaving at most 255.
        #expect(numbers.count <= 255)
        #expect(!numbers.isEmpty)
        // The remaining packets are the most recent arrivals and stay in order.
        #expect(numbers == numbers.sorted())
        #expect(numbers.last == total - 1)
        #expect(try #require(numbers.first) >= total - 256)
    }

    // MARK: Public initializer rejection

    /// The rejected descriptor must remain owned by the caller.
    private static func expectRejected(
        _ descriptor: Int32,
        mtu: Int = 1280,
        _ reason: String? = nil,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            _ = try UTUNDevice(duplicating: descriptor, mtu: mtu)
            Issue.record("The descriptor was accepted", sourceLocation: sourceLocation)
        } catch {
            guard case .invalidDevice(let message) = error else {
                Issue.record("Expected invalidDevice, got \(error)", sourceLocation: sourceLocation)
                return
            }
            if let reason { #expect(message == reason, sourceLocation: sourceLocation) }
        }
    }

    @Test("Rejects non-utun descriptors (datagram and stream sockets) and leaves the caller's descriptor open", arguments: [SOCK_DGRAM, SOCK_STREAM])
    func rejectsUnixSockets(_ type: Int32) throws {
        let pair = try SocketPair(type: type)
        defer { pair.closeAll() }
        Self.expectRejected(pair.caller, "notUTUN")
        #expect(fcntl(pair.caller, F_GETFD) >= 0)
        // Rejection does not make the caller's descriptor nonblocking.
        #expect(fcntl(pair.caller, F_GETFL) & O_NONBLOCK == 0)
        try pair.send([1])
        #expect(pair.receiveOnCaller() == [1])
    }

    @Test("Rejects non-utun descriptors (UDP sockets and pipes)")
    func rejectsOtherDescriptors() throws {
        let udp = socket(AF_INET, SOCK_DGRAM, 0)
        try #require(udp >= 0)
        defer { close(udp) }
        Self.expectRejected(udp, "notUTUN")

        var ends: [Int32] = [-1, -1]
        try #require(pipe(&ends) == 0)
        defer { ends.forEach { close($0) } }
        Self.expectRejected(ends[0], "notUTUN")
        Self.expectRejected(ends[1], "notUTUN")
        #expect(fcntl(ends[0], F_GETFD) >= 0)
    }

    @Test("Rejects closed descriptor numbers and negative descriptors")
    func rejectsClosedAndNegative() throws {
        let pair = try SocketPair()
        let closed = pair.caller
        pair.closeAll()
        // Another test may have immediately acquired the same descriptor number, so do not assert the reason. Both cases are rejections.
        Self.expectRejected(closed)
        Self.expectRejected(-1, "fileDescriptor")
        Self.expectRejected(Int32.min, "fileDescriptor")
    }

    @Test("Rejects an MTU outside 1280…1420", arguments: [1, 1000, 1279, 1421, 1500, 9000, 0, -1280])
    func rejectsOutOfRangeMTU(_ mtu: Int) throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        Self.expectRejected(pair.caller, mtu: mtu, "mtu")
        #expect(throws: SocketError.invalidDevice("mtu")) {
            _ = try UTUNDevice(duplicating: pair.caller, mtu: mtu, verifying: { _ in })
        }
    }

    @Test("Accepts the MTU limits 1280 and 1420 and retains each value unchanged", arguments: [1280, 1420])
    func acceptsMTUBoundaries(_ mtu: Int) throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        #expect(try Self.device(on: pair.caller, mtu: mtu).mtu == mtu)
    }

    // MARK: Helpers

    /// Waits for the duplicate to close. Closure is asynchronous because the read source's cancellation handler calls `close(2)`.
    ///
    /// Checking only for `EBADF` is insufficient. Another test running in parallel can immediately take the closed descriptor number, so `EBADF` might never occur.
    /// Instead, check if the number still identifies the same socket as `original` (the inode from `fstat`). If closed or reassigned, the duplicate has closed.
    private static func waitUntilClosed(_ descriptor: Int32, duplicateOf original: Int32) async throws {
        var identity = stat()
        guard fstat(original, &identity) == 0 else {
            Issue.record("fstat failed on the original descriptor")
            return
        }
        for _ in 0..<200 {
            var current = stat()
            if fstat(descriptor, &current) != 0 || current.st_ino != identity.st_ino { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("The duplicate did not close")
    }
}

/// A test `socketpair`. Keep the test code's POSIX pointers in this type only.
///
/// `caller` stands in for utun (the descriptor the app passes to the node), and `peer` stands in for the kernel. The peer writes in nonblocking mode and retries after a brief wait if the queue fills.
private struct SocketPair {
    struct Failure: Error { var step: String }

    let caller: Int32
    let peer: Int32

    init(type: Int32 = SOCK_DGRAM) throws {
        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, type, 0, &pair) == 0 else { throw Failure(step: "socketpair") }
        caller = pair[0]
        peer = pair[1]
        guard fcntl(peer, F_SETFL, fcntl(peer, F_GETFL) | O_NONBLOCK) >= 0 else { throw Failure(step: "fcntl") }
    }

    func closePeer() { close(peer) }

    /// Closes both descriptors. Ignores `EBADF` if already closed.
    func closeAll() {
        close(caller)
        close(peer)
    }

    /// Sends once from the peer to `caller`.
    func send(_ bytes: [UInt8]) throws {
        while true {
            let sent = bytes.withUnsafeBytes { write(peer, $0.baseAddress, $0.count) }
            if sent == bytes.count { return }
            guard sent < 0, errno == EAGAIN || errno == ENOBUFS else { throw Failure(step: "write errno=\(errno)") }
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    /// Returns one datagram received by `peer` (written by the device), or nil if none arrives by the deadline.
    func receive(within duration: Duration = .seconds(5)) -> [UInt8]? {
        read(from: peer, within: duration)
    }

    /// Reads directly from the caller's descriptor (to check that the device left it alone).
    func receiveOnCaller() -> [UInt8]? {
        read(from: caller, within: .seconds(5))
    }

    private func read(from descriptor: Int32, within duration: Duration) -> [UInt8]? {
        var descriptors = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
        let milliseconds = Int32(duration.components.seconds * 1000 + duration.components.attoseconds / 1_000_000_000_000_000)
        guard poll(&descriptors, 1, milliseconds) > 0 else { return nil }
        var buffer = [UInt8](repeating: 0, count: 70_000)
        let count = buffer.withUnsafeMutableBytes { recv(descriptor, $0.baseAddress, $0.count, MSG_DONTWAIT) }
        return count >= 0 ? Array(buffer[..<count]) : nil
    }
}
