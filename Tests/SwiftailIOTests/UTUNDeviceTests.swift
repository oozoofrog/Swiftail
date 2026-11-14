import Darwin
import Foundation
import Testing

@testable import SwiftailIO

/// utun 장치 감싸개(계약 "시험" 9). 실제 utun은 열 때 권한이 필요하므로 시험하지 않는다(실기기 관문). 대신 utun 확인을 건너뛰고
/// `socketpair`의 한쪽을 utun 자리에 붙인다. 데이터그램 경계가 있는 `AF_UNIX`·`SOCK_DGRAM` 쌍은 utun의 "읽기 한 번이 패킷 하나"와
/// 같은 모양이다.
@Suite("utun 장치")
struct UTUNDeviceTests {
    private static let ipv4Packet: [UInt8] = [0x45, 0, 0, 20] + [UInt8](repeating: 7, count: 16)
    private static let ipv6Packet: [UInt8] = [0x60, 0, 0, 0] + [UInt8](repeating: 9, count: 36)

    /// utun 확인만 건너뛴다. 복제·`O_NONBLOCK`·읽기는 실제 코드가 그대로 돈다.
    private static func device(on descriptor: Int32, mtu: Int = 1280) throws -> UTUNDevice {
        try UTUNDevice(duplicating: descriptor, mtu: mtu, verifying: { _ in })
    }

    private enum Outcome: Sendable, Equatable {
        case packet([UInt8])
        case ended
        case failed(SocketError)
        case timeout
    }

    /// 흐름에서 하나를 기다린다.
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

    // MARK: 머리 붙이기·떼기와 버전 판정 (순수 함수)

    @Test("IP 버전 4는 AF_INET(2), 6은 AF_INET6(30) 머리를 붙인다")
    func framesByVersion() {
        #expect(UTUNDevice.frame(Self.ipv4Packet) == [0, 0, 0, 2] + Self.ipv4Packet)
        #expect(UTUNDevice.frame(Self.ipv6Packet) == [0, 0, 0, 30] + Self.ipv6Packet)
    }

    @Test("4도 6도 아닌 버전과 빈 패킷은 머리를 붙이지 않는다", arguments: [0x00, 0x10, 0x30, 0x50, 0x70, 0xf0, 0x04, 0x06] as [UInt8])
    func rejectsOtherVersions(_ first: UInt8) {
        // 윗 니블만 버전이다: 아래 니블이 4나 6이어도 버전은 아니다.
        #expect(UTUNDevice.frame([first, 1, 2, 3]) == nil)
    }

    @Test("버전은 첫 바이트의 윗 니블이다")
    func versionIsHighNibble() {
        #expect(UTUNDevice.frame([0x4f, 0]) == [0, 0, 0, 2, 0x4f, 0])
        #expect(UTUNDevice.frame([0x6f, 0]) == [0, 0, 0, 30, 0x6f, 0])
        #expect(UTUNDevice.frame([]) == nil)
    }

    @Test("머리를 떼고 머리 값은 보지 않는다")
    func stripsHeaderWithoutLookingAtIt() {
        #expect(UTUNDevice.ipPacket(inFrame: [0, 0, 0, 2] + Self.ipv4Packet) == Self.ipv4Packet)
        #expect(UTUNDevice.ipPacket(inFrame: [0xff, 0xff, 0xff, 0xff, 0x45]) == [0x45])
        // 슬라이스의 시작 위치가 0이 아니어도 된다.
        let frame: [UInt8] = [9, 9, 0, 0, 0, 2, 0x45, 1]
        #expect(UTUNDevice.ipPacket(inFrame: frame[2...]) == [0x45, 1])
    }

    @Test("머리보다 짧거나 머리뿐인 프레임은 버린다", arguments: 0...4)
    func dropsShortFrames(_ length: Int) {
        #expect(UTUNDevice.ipPacket(inFrame: [UInt8](repeating: 1, count: length)[...]) == nil)
    }

    // MARK: 읽기

    @Test("프레임에서 머리를 떼고 IP 패킷만 올린다")
    func readsPacketWithoutHeader() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        try pair.send([0, 0, 0, 2] + Self.ipv4Packet)
        try pair.send([0, 0, 0, 30] + Self.ipv6Packet)
        #expect(await Self.next(from: device) == .packet(Self.ipv4Packet))
        #expect(await Self.next(from: device) == .packet(Self.ipv6Packet))
    }

    @Test("한 번에 여러 개가 도착해도 모두 순서대로 읽는다")
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

    @Test("머리보다 짧은 읽기와 머리뿐인 읽기는 버리고 계속 읽는다")
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

    @Test("MTU와 같은 길이는 올리고 MTU를 넘는 패킷은 버린다", arguments: [1280, 1420])
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

    // MARK: 쓰기

    @Test("쓸 때 IPv4는 머리 2, IPv6는 머리 30을 붙인다")
    func writesHeaders() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        try device.write(Self.ipv4Packet)
        try device.write(Self.ipv6Packet)
        #expect(pair.receive() == [0, 0, 0, 2] + Self.ipv4Packet)
        #expect(pair.receive() == [0, 0, 0, 30] + Self.ipv6Packet)
    }

    @Test("다른 버전과 빈 패킷은 쓰지 않고 EAFNOSUPPORT로 알린다")
    func writeRejectsOtherVersions() throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        #expect(throws: SocketError.sendFailed("EAFNOSUPPORT")) { try device.write([0x50, 1, 2]) }
        #expect(throws: SocketError.sendFailed("EAFNOSUPPORT")) { try device.write([]) }
        #expect(pair.receive(within: .milliseconds(100)) == nil)
        // 실패한 뒤에도 다음 패킷을 쓸 수 있다.
        try device.write(Self.ipv4Packet)
        #expect(pair.receive() == [0, 0, 0, 2] + Self.ipv4Packet)
    }

    @Test("커널이 받지 못한 패킷은 sendFailed이고 장치는 계속 쓸 수 있다")
    func writeFailureKeepsDevice() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        // `AF_UNIX` 데이터그램의 최대 크기(기본 2,048바이트)를 넘으면 EMSGSIZE다.
        let oversized = [0x45] + [UInt8](repeating: 0, count: 8_000)
        #expect(throws: SocketError.sendFailed("EMSGSIZE")) { try device.write(oversized) }
        try device.write(Self.ipv4Packet)
        #expect(pair.receive() == [0, 0, 0, 2] + Self.ipv4Packet)
    }

    /// 고치기 전에는 끊긴 스트림 소켓에 쓰면 SIGPIPE로 시험 프로세스가 죽었다(신호 13).
    @Test("상대가 닫힌 소켓에 써도 신호로 죽지 않고 sendFailed(EPIPE)다")
    func writeToClosedPeerDoesNotRaiseSIGPIPE() throws {
        let pair = try SocketPair(type: SOCK_STREAM)
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        pair.closePeer()
        #expect(throws: SocketError.sendFailed("EPIPE")) { try device.write(Self.ipv4Packet) }
    }

    // MARK: 파일 기술자의 소유

    @Test("복제본은 호출자의 기술자와 다른 번호이고 FD_CLOEXEC·O_NONBLOCK이 있다")
    func duplicateHasCloexecAndNonblocking() throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let copy = try #require(device.duplicateDescriptor)
        #expect(copy != pair.caller)
        #expect(fcntl(copy, F_GETFD) & FD_CLOEXEC != 0)
        #expect(fcntl(copy, F_GETFL) & O_NONBLOCK != 0)
    }

    @Test("장치를 닫아도 호출자의 기술자는 열려 있다")
    func closeLeavesCallerDescriptorOpen() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let copy = try #require(device.duplicateDescriptor)
        device.close()
        try await Self.waitUntilClosed(copy)
        #expect(fcntl(pair.caller, F_GETFD) >= 0)
        // 호출자의 기술자는 여전히 읽고 쓸 수 있다.
        try pair.send([1, 2, 3])
        #expect(pair.receiveOnCaller() == [1, 2, 3])
    }

    @Test("장치를 버리면 복제본만 닫히고 호출자의 기술자는 열려 있다")
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
        try await Self.waitUntilClosed(try #require(copy))
        #expect(fcntl(pair.caller, F_GETFD) >= 0)
        let outcome = try await withTimeout(.seconds(5)) { [stream] in
            guard let stream else { return Outcome.timeout }
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil ? .ended : .timeout
        }
        #expect(outcome == .ended)
    }

    // MARK: 닫기

    @Test("닫으면 흐름이 오류 없이 끝나고, 닫은 뒤의 쓰기는 EBADF다")
    func closeEndsStream() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        device.close()
        device.close()  // 여러 번 불러도 된다
        #expect(await Self.next(from: device) == .ended)
        #expect(throws: SocketError.sendFailed("EBADF")) { try device.write(Self.ipv4Packet) }
        #expect(pair.receive(within: .milliseconds(100)) == nil)
    }

    @Test("기다리는 동안 닫아도 흐름이 끝난다")
    func closeWhileWaiting() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let waiter = Task { await Self.next(from: device) }
        try await Task.sleep(for: .milliseconds(50))
        device.close()
        #expect(await waiter.value == .ended)
    }

    @Test("닫은 장치의 복제본 번호를 다른 장치가 받아도 건드리지 않는다")
    func closedDeviceDoesNotTouchReusedDescriptor() async throws {
        // 닫은 장치가 놓은 번호는 곧바로 다른 곳이 받는다. 닫은 뒤의 `write`·`close`가 그 기술자에 닿으면 새 장치가 깨진다.
        for round in 0..<20 {
            let oldPair = try SocketPair()
            let old = try Self.device(on: oldPair.caller)
            let oldCopy = try #require(old.duplicateDescriptor)
            old.close()
            try await Self.waitUntilClosed(oldCopy)
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

    @Test("상대가 닫히면 흐름이 readFailed(EOF)로 끝난다")
    func peerCloseEndsStreamWithError() async throws {
        // 데이터그램 소켓 쌍은 상대가 닫혀도 읽기가 끝나지 않으므로 이 시험만 스트림 소켓 쌍을 쓴다.
        let pair = try SocketPair(type: SOCK_STREAM)
        defer { close(pair.caller) }  // 상대는 아래에서 이미 닫았다. 같은 번호를 두 번 닫지 않는다.
        let device = try Self.device(on: pair.caller)
        pair.closePeer()
        #expect(await Self.next(from: device) == .failed(.readFailed("EOF")))
        // 흐름이 오류로 끝난 뒤에도 닫기는 안전하다.
        device.close()
        #expect(throws: SocketError.sendFailed("EBADF")) { try device.write(Self.ipv4Packet) }
    }

    // MARK: 취소와 느린 소비자

    @Test("기다리던 Task를 취소하면 읽기가 끝나고 장치는 열려 있다")
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

    @Test("이미 취소된 Task에서 읽으면 곧바로 끝난다")
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

    @Test("소비하지 않으면 256개까지만 쌓고 오래된 것부터 버린다")
    func slowConsumerKeepsNewest256() async throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        let device = try Self.device(on: pair.caller)
        let total = 1000
        for number in 0..<total {
            // 번호를 2바이트로 싣는다. 받는 쪽 큐가 차면 `send`가 잠깐 쉬고 다시 보낸다.
            try pair.send([0, 0, 0, 2, UInt8(number >> 8) | 0x40, UInt8(number & 0xff)])
        }
        // 마지막 패킷이 흐름에 들어갈 때까지 기다린 뒤에야 소비를 시작한다.
        try await Task.sleep(for: .milliseconds(500))
        let marker: [UInt8] = [0x4f, 0xff]
        try pair.send([0, 0, 0, 2] + marker)
        try await Task.sleep(for: .milliseconds(200))

        var numbers: [Int] = []
        while case .packet(let packet) = await Self.next(from: device, within: .seconds(2)) {
            if packet == marker { break }
            numbers.append(Int(packet[0] & 0x3f) << 8 | Int(packet[1]))
        }
        // 표지가 들어오며 가장 오래된 하나가 더 밀려났으므로 255개 이하다.
        #expect(numbers.count <= 255)
        #expect(!numbers.isEmpty)
        // 남은 것은 가장 나중에 온 것들이고 순서가 지켜진다.
        #expect(numbers == numbers.sorted())
        #expect(numbers.last == total - 1)
        #expect(try #require(numbers.first) >= total - 256)
    }

    // MARK: 공개 생성자의 거절

    /// 거절된 기술자는 호출자의 것으로 남아 있어야 한다.
    private static func expectRejected(
        _ descriptor: Int32,
        mtu: Int = 1280,
        _ reason: String? = nil,
        sourceLocation: SourceLocation = #_sourceLocation
    ) {
        do {
            _ = try UTUNDevice(duplicating: descriptor, mtu: mtu)
            Issue.record("거절되지 않았다", sourceLocation: sourceLocation)
        } catch {
            guard case .invalidDevice(let message) = error else {
                Issue.record("invalidDevice가 아닌 오류: \(error)", sourceLocation: sourceLocation)
                return
            }
            if let reason { #expect(message == reason, sourceLocation: sourceLocation) }
        }
    }

    @Test("utun이 아닌 기술자(데이터그램·스트림 소켓)를 거절하고 호출자의 기술자는 열려 있다", arguments: [SOCK_DGRAM, SOCK_STREAM])
    func rejectsUnixSockets(_ type: Int32) throws {
        let pair = try SocketPair(type: type)
        defer { pair.closeAll() }
        Self.expectRejected(pair.caller, "notUTUN")
        #expect(fcntl(pair.caller, F_GETFD) >= 0)
        // 거절하면서 호출자의 기술자를 비차단으로 바꾸지 않는다.
        #expect(fcntl(pair.caller, F_GETFL) & O_NONBLOCK == 0)
        try pair.send([1])
        #expect(pair.receiveOnCaller() == [1])
    }

    @Test("utun이 아닌 기술자(UDP 소켓, 파이프)를 거절한다")
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

    @Test("닫힌 번호와 음수 기술자를 거절한다")
    func rejectsClosedAndNegative() throws {
        let pair = try SocketPair()
        let closed = pair.caller
        pair.closeAll()
        // 다른 시험이 같은 번호를 곧바로 받았을 수도 있으므로 이유까지 고정하지 않는다. 어느 쪽이든 거절이다.
        Self.expectRejected(closed)
        Self.expectRejected(-1, "fileDescriptor")
        Self.expectRejected(Int32.min, "fileDescriptor")
    }

    @Test("MTU가 1280…1420 밖이면 거절한다", arguments: [1, 1000, 1279, 1421, 1500, 9000, 0, -1280])
    func rejectsOutOfRangeMTU(_ mtu: Int) throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        Self.expectRejected(pair.caller, mtu: mtu, "mtu")
        #expect(throws: SocketError.invalidDevice("mtu")) {
            _ = try UTUNDevice(duplicating: pair.caller, mtu: mtu, verifying: { _ in })
        }
    }

    @Test("MTU 경계 1280과 1420은 받아들이고 그 값을 그대로 보관한다", arguments: [1280, 1420])
    func acceptsMTUBoundaries(_ mtu: Int) throws {
        let pair = try SocketPair()
        defer { pair.closeAll() }
        #expect(try Self.device(on: pair.caller, mtu: mtu).mtu == mtu)
    }

    // MARK: 도우미

    /// 복제본이 닫혔는지 기다린다. `close(2)`는 읽기 원천의 취소 처리기가 하므로 곧바로는 아니다.
    private static func waitUntilClosed(_ descriptor: Int32) async throws {
        for _ in 0..<200 {
            if fcntl(descriptor, F_GETFD) < 0 && errno == EBADF { return }
            try await Task.sleep(for: .milliseconds(10))
        }
        Issue.record("복제본이 닫히지 않았다")
    }
}

/// 시험용 `socketpair`. 시험 코드의 POSIX 포인터는 이 타입에만 둔다.
///
/// `caller`가 utun 자리(앱이 노드에 넘기는 기술자)이고 `peer`가 커널 자리다. 상대는 비차단으로 써서, 큐가 차면 잠깐 쉬고 다시 보낸다.
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

    /// 두 기술자를 닫는다. 이미 닫았으면 `EBADF`를 무시한다.
    func closeAll() {
        close(caller)
        close(peer)
    }

    /// 상대 쪽에서 `caller`로 한 번 보낸다.
    func send(_ bytes: [UInt8]) throws {
        while true {
            let sent = bytes.withUnsafeBytes { write(peer, $0.baseAddress, $0.count) }
            if sent == bytes.count { return }
            guard sent < 0, errno == EAGAIN || errno == ENOBUFS else { throw Failure(step: "write errno=\(errno)") }
            Thread.sleep(forTimeInterval: 0.001)
        }
    }

    /// `peer`가 받은 데이터그램 하나(장치가 쓴 것). 기한 안에 없으면 nil.
    func receive(within duration: Duration = .seconds(5)) -> [UInt8]? {
        read(from: peer, within: duration)
    }

    /// 호출자의 기술자로 직접 읽는다(장치가 이 기술자를 건드리지 않았는지 볼 때).
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
