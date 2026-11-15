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

    @Test("읽지 않고 1MiB를 넘게 쌓이면 가장 새 것들만 남고 바이트 합이 한도 이하다")
    func slowConsumerKeepsNewestWithinByteLimit() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        // 8,000바이트 × 400개 = 3.2MB. 개수 한도(256)만으로는 2MB를 쥐므로 바이트 한도(1MiB)가 먼저 작용한다.
        let size = 8000
        let total = 400
        for number in 0..<total {
            var payload = [UInt8](repeating: 0xab, count: size)
            payload[0] = UInt8(number >> 8)
            payload[1] = UInt8(number & 0xff)
            // 받는 쪽의 읽기가 커널 버퍼를 비울 틈을 준다. 한꺼번에 보내면 부하가 걸렸을 때 커널이 끝의 것들을 버려
            // "마지막 것이 남는다"가 흔들렸다. 마지막 하나는 앞의 것이 모두 흐름에 들어간 뒤에 보낸다.
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
        // 마지막 데이터그램이 흐름에 들어갈 때까지 기다린 뒤에야 소비를 시작한다.
        try await Task.sleep(for: .milliseconds(500))

        var numbers: [Int] = []
        var byteTotal = 0
        while let datagram = await Self.next(from: receiver, within: .seconds(1)) {
            byteTotal += datagram.bytes.count
            numbers.append(Int(datagram.bytes[0]) << 8 | Int(datagram.bytes[1]))
        }
        #expect(byteTotal <= 1 << 20)
        // 한도 근처까지는 남긴다(하나가 들어갈 자리만큼 모자랄 수 있고, 커널이 일부를 버렸을 수도 있다).
        #expect(byteTotal > (1 << 20) / 2)
        #expect(numbers == numbers.sorted())
        #expect(numbers.last == total - 1)
        #expect(try #require(numbers.first) > total - 256)
    }

    // MARK: 송신 큐

    @Test("enqueue한 데이터그램을 넣은 순서대로 보낸다")
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

    @Test("송신 큐는 256개를 넘으면 오래된 것부터 버린다")
    func sendQueueKeepsNewest256() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        let total = 1000
        // 한 번에 넣으므로 보내기가 꺼내 가기 전에 한도가 적용된다.
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

    @Test("송신 큐는 바이트 합 1MiB를 넘으면 오래된 것부터 버린다")
    func sendQueueKeepsNewestWithinByteLimit() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        // 8,000바이트 × 200개 = 1.6MB. 개수 한도(256) 안이므로 바이트 한도가 앞의 것을 버린다: 1MiB에는 131개가 든다.
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
        // 커널이 일부를 버렸을 수 있으므로 버려야 할 것이 오지 않았는지만 본다.
        #expect(!numbers.isEmpty)
        #expect(numbers == numbers.sorted())
        #expect(try #require(numbers.first) >= total - (1 << 20) / 8000)
    }

    @Test("UDP에 실을 수 없는 크기는 송신 큐에 넣지 않고, 뒤따르는 것은 그대로 보낸다")
    func enqueueDropsOversizedDatagram() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        // 2MiB 하나는 바이트 한도(1MiB)보다 커서, 큐에 들어가면 한도를 넘은 채 남는다.
        sender.enqueue([([UInt8](repeating: 0, count: 2 << 20), Self.destination(receiver)), ([7], Self.destination(receiver))])
        #expect(await Self.next(from: receiver)?.bytes == [7])
    }

    @Test("닫은 뒤의 enqueue는 아무것도 보내지 않는다")
    func enqueueAfterCloseSendsNothing() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        sender.close()
        sender.enqueue([([1], Self.destination(receiver))])
        #expect(await Self.next(from: receiver, within: .milliseconds(300)) == nil)
    }

    @Test("닫은 소켓의 송신 큐에 남은 것은 같은 번호를 받은 새 소켓으로 나가지 않는다")
    func closedSendQueueDoesNotUseReusedDescriptor() async throws {
        // 송신 큐를 채운 소켓을 곧바로 닫고 새 소켓을 연다(닫힌 번호를 받기 쉽다). 옛 소켓의 데이터그램이 오더라도
        // 옛 소켓의 포트에서 와야 한다. 새 소켓의 포트에서 오면 닫힌 번호에 쓴 것이다.
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
            // 앞 회차의 늦게 도착한 것을 비운다.
            while await Self.next(from: peer, within: .milliseconds(50)) != nil {}
        }
    }

    @Test("closeAfterSending은 이미 넣은 것을 보낸 뒤 닫고 포트를 놓는다")
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

    @Test("takeQueuedDatagrams는 쌓인 것을 순서대로 한꺼번에 꺼낸다")
    func takeQueuedDatagramsDrainsInOrder() async throws {
        let receiver = try DatagramSocket()
        let sender = try DatagramSocket()
        for number in 0..<30 {
            try sender.send([UInt8(number)], to: Self.destination(receiver))
        }
        // 흐름에서 하나를 받은 뒤 나머지가 큐에 쌓일 때까지 기다렸다 꺼낸다.
        let first = try #require(await Self.next(from: receiver))
        try await Task.sleep(for: .milliseconds(200))
        let rest = receiver.takeQueuedDatagrams()
        #expect(first.bytes + rest.flatMap(\.bytes) == (0..<30).map(UInt8.init))
        #expect(receiver.takeQueuedDatagrams().isEmpty)
    }

    // MARK: 인터페이스 묶기

    @Test("루프백 인터페이스에 묶은 소켓 둘이 루프백에서 주고받는다")
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

    @Test("묶지 않은 소켓과도 루프백 인터페이스에 묶은 소켓이 주고받는다")
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

    @Test("없는 인터페이스 index는 bindFailed로 던지고 포트를 쥐지 않는다")
    func unknownInterfaceIndexFails() async throws {
        // 큰 index는 어떤 기기에도 없다. 던진 뒤 소켓이 남지 않아야 하므로 같은 포트를 다시 묶을 수 있어야 한다.
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
            Issue.record("bindFailed가 아니다: \(String(describing: failure))")
            return
        }
        var rebound: DatagramSocket?
        for _ in 0..<100 where rebound == nil {
            rebound = try? DatagramSocket(port: port)
            if rebound == nil { try await Task.sleep(for: .milliseconds(20)) }
        }
        #expect(rebound != nil)
    }

    /// 노드 통합이 기대는 관찰: 물리 인터페이스에 묶은 소켓도 루프백 목적지와 주고받는다(`IP_BOUND_IF`가 막지 않는다).
    /// 그래도 계약은 루프백 목적지의 소켓은 묶지 않는다고 정한다(Go `isLocalhost`와 같은 규칙).
    @Test("en0에 묶은 소켓도 루프백 목적지로 보내고 루프백에서 온 것을 받는다", .enabled(if: if_nametoindex("en0") != 0))
    func physicalInterfaceBoundSocketExchangesOnLoopback() async throws {
        let bound = try DatagramSocket(interfaceIndex: if_nametoindex("en0"))
        let plain = try DatagramSocket()
        try bound.send([1], to: Self.destination(plain))
        #expect(try #require(await Self.next(from: plain)).bytes == [1])
        try plain.send([2], to: Self.destination(bound))
        #expect(try #require(await Self.next(from: bound)).bytes == [2])
    }

    @Test("lo0에 묶은 소켓이 비루프백 목적지로 보내면 sendFailed(ENETUNREACH)다")
    func loopbackBoundSocketCannotReachNonLoopback() throws {
        let socket = try DatagramSocket(interfaceIndex: if_nametoindex("lo0"))
        // 192.0.2.1은 문서용(TEST-NET-1) 주소다. 어디로도 가지 않는다.
        let destination = IPEndpoint(address: try #require(IPAddress("192.0.2.1")), port: 9)
        #expect(throws: SocketError.sendFailed("ENETUNREACH")) {
            try socket.send([1], to: destination)
        }
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
