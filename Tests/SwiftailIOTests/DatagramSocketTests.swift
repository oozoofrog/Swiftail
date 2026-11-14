import Foundation
import Testing

import SwiftailBase

@testable import SwiftailIO

/// UDP 소켓 감싸개(계약 "내부 API"의 `DatagramSocket`). 루프백에서 소켓 둘이 주고받는다.
@Suite("UDP 소켓")
struct DatagramSocketTests {
    private static let loopback = IPAddress("127.0.0.1")!

    private static func destination(_ socket: DatagramSocket) -> IPEndpoint {
        IPEndpoint(address: loopback, port: socket.localPort)
    }

    /// 흐름에서 데이터그램 하나를 기다린다. 기한 안에 오지 않으면 nil.
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

    @Test("OS가 고른 포트에 묶이고 서로 다른 소켓은 다른 포트를 갖는다")
    func bindsToOSChosenPort() throws {
        let first = try DatagramSocket()
        let second = try DatagramSocket()
        #expect(first.localPort != 0)
        #expect(second.localPort != 0)
        #expect(first.localPort != second.localPort)
    }

    @Test("이미 쓰는 포트에 묶으면 bindFailed(EADDRINUSE)다")
    func bindFailsWhenPortInUse() throws {
        let first = try DatagramSocket()
        #expect(throws: SocketError.bindFailed("EADDRINUSE")) {
            _ = try DatagramSocket(port: first.localPort)
        }
    }

    @Test("루프백에서 데이터그램을 주고받고 출처 주소가 맞다", arguments: [0, 1, 512, 1400, 9000])
    func exchangesDatagrams(_ size: Int) async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        let payload = (0..<size).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) }
        try sender.send(payload, to: Self.destination(receiver))
        let received = try #require(await Self.next(from: receiver))
        #expect(received.bytes == payload)
        #expect(received.source == IPEndpoint(address: Self.loopback, port: sender.localPort))
    }

    /// macOS의 UDP 보내기 한도(`net.inet.udp.maxdgram` 9216)는 소켓의 보내기 버퍼 크기이고, 그보다 큰 데이터그램은
    /// `EMSGSIZE`다. 받는 쪽 버퍼(65,535바이트)가 잘리지 않는지는 보내기 버퍼를 키운 시험용 소켓으로 확인한다.
    @Test("IPv4 데이터그램의 최대(65,507바이트)를 잘리지 않고 받는다")
    func receivesLargestDatagram() async throws {
        let receiver = try DatagramSocket()
        let payload = (0..<65_507).map { UInt8(truncatingIfNeeded: $0 &* 13) }
        try TestUDPSender.send(payload, toLoopbackPort: receiver.localPort)
        let received = try #require(await Self.next(from: receiver))
        #expect(received.bytes == payload)
    }

    @Test("한 번에 여러 개가 도착해도 모두 읽는다")
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

    @Test("IPv6 목적지는 sendFailed(EAFNOSUPPORT)다")
    func ipv6DestinationFails() throws {
        let socket = try DatagramSocket()
        let destination = try #require(IPEndpoint("[2001:db8::1]:9"))
        #expect(throws: SocketError.sendFailed("EAFNOSUPPORT")) {
            try socket.send([1], to: destination)
        }
    }

    @Test("너무 큰 데이터그램은 sendFailed(EMSGSIZE)이고 소켓은 계속 쓸 수 있다")
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

    // MARK: 닫기

    @Test("닫으면 흐름이 끝나고, 닫은 뒤의 보내기는 sendFailed(EBADF)다")
    func closeEndsStream() async throws {
        let socket = try DatagramSocket()
        let stream = socket.datagrams
        socket.close()
        socket.close()  // 여러 번 불러도 된다
        let ended = try await withTimeout(.seconds(5)) {
            var iterator = stream.makeAsyncIterator()
            return await iterator.next() == nil
        }
        #expect(ended)
        #expect(throws: SocketError.sendFailed("EBADF")) {
            try socket.send([1], to: IPEndpoint(address: Self.loopback, port: 9))
        }
    }

    @Test("기다리는 동안 닫아도 흐름이 끝난다")
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

    @Test("닫은 소켓의 번호를 다른 소켓이 받아도 건드리지 않는다")
    func closedSocketDoesNotTouchReusedDescriptor() async throws {
        // 닫은 소켓이 놓은 파일 기술자 번호는 곧바로 다른 소켓이 받는다. 닫은 뒤의 `send`와 `close`가 그 소켓에 닿으면
        // 새 소켓이 깨진다. 닫기를 되풀이하며 새 소켓이 계속 쓸 수 있는지 본다.
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

    @Test("소켓을 버리면 포트가 풀리고 흐름이 끝난다")
    func deinitClosesSocket() async throws {
        var port: UInt16 = 0
        var stream: AsyncStream<(bytes: [UInt8], source: IPEndpoint)>?
        do {
            let socket = try DatagramSocket()
            port = socket.localPort
            stream = socket.datagrams
        }
        // 닫기는 읽기 원천의 취소 처리기가 끝낸다. 포트를 다시 묶을 수 있을 때까지 기다린다.
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

    // MARK: 취소와 느린 소비자

    @Test("기다리던 Task를 취소하면 읽기가 끝난다")
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
        // 소켓은 열려 있고 보낼 수 있다.
        try socket.send([1], to: IPEndpoint(address: Self.loopback, port: 9))
    }

    @Test("이미 취소된 Task에서 읽으면 곧바로 끝난다")
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

    @Test("소비하지 않으면 256개까지만 쌓고 오래된 것부터 버린다")
    func slowConsumerKeepsNewest256() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        let total = 1000
        for number in 0..<total {
            // 번호를 2바이트로 싣는다. 보내기 버퍼가 차면 잠깐 쉬고 다시 보낸다.
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
        // 마지막 데이터그램이 흐름에 들어갈 때까지 기다린 뒤에야 소비를 시작한다.
        try await Task.sleep(for: .milliseconds(500))
        let marker: [UInt8] = [0xff, 0xff]
        try sender.send(marker, to: Self.destination(receiver))
        try await Task.sleep(for: .milliseconds(200))

        var numbers: [Int] = []
        while let datagram = await Self.next(from: receiver, within: .seconds(2)) {
            if datagram.bytes == marker { break }
            numbers.append(Int(datagram.bytes[0]) << 8 | Int(datagram.bytes[1]))
        }
        // 표지가 들어오며 가장 오래된 하나가 더 밀려났으므로 255개 이하다. 커널이 일부를 버렸을 수도 있다.
        #expect(numbers.count <= 255)
        #expect(!numbers.isEmpty)
        // 남은 것은 가장 나중에 온 것들이고 순서가 지켜진다.
        #expect(numbers == numbers.sorted())
        #expect(numbers.last == total - 1)
        #expect(try #require(numbers.first) >= total - 256)
    }
}

/// 보내기 버퍼를 키운 시험용 UDP 송신자. `DatagramSocket`은 보내기 버퍼를 건드리지 않으므로 기본 한도(9216바이트)를 넘는
/// 데이터그램은 이것으로 보낸다. POSIX 포인터는 시험 코드의 이 함수에만 둔다.
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
