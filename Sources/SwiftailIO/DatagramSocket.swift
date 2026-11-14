import Dispatch
import Darwin
import SwiftailBase
import Synchronization

/// IPv4 와일드카드(0.0.0.0)에 묶인 UDP 소켓 하나를 async 데이터그램 흐름으로 감싼다.
///
/// WireGuard·disco·STUN이 같은 소켓을 쓴다(`docs/protocol-notes/derp-stun.md` 4.10 2). 포트 하나로 여러 상대와 주고받아야
/// 해서 `Network` 프레임워크가 아니라 POSIX 소켓을 쓴다(`docs/plan.md` 4절 (c)). 부르는 쪽은 `SwiftailMagicsock`의
/// 상태 기계를 부리는 노드다. 실패는 `SocketError`로 낸다.
///
/// 지키는 것:
///
/// - **읽기는 사건으로 깨어난다.** `DispatchSource` 읽기 사건이 오면 더 읽을 것이 없을 때(`EAGAIN`)까지 읽는다. 폴링하지 않는다.
/// - **받은 것은 256개와 1MiB까지만 쌓는다.** 소비가 느리면 오래된 데이터그램부터 버린다(`ReceiveQueue`). 개수만으로는
///   256 × 65,535바이트(최악 16MiB)를 쥐므로 바이트 합으로도 묶는다(`receiveBufferByteLimit`). UDP는 어차피 손실을
///   받아들이는 전송이다.
/// - **파일 기술자는 한 번만 닫는다.** `close()`는 기술자를 상태에서 떼어 낸 뒤 읽기 원천을 취소하고, 실제 `close(2)`는
///   원천의 취소 처리기가 한다. 취소 처리기는 돌고 있던 읽기 처리기가 끝난 뒤에 돌므로 읽는 중에 기술자가 닫히지 않고,
///   `close()` 뒤의 `send`는 상태가 비어 있어 기술자를 건드리지 않는다(다른 곳이 재사용한 번호를 닫거나 쓰는 일이 없다).
/// - **인터페이스에 묶을 수 있다.** `interfaceIndex`를 주면 `IP_BOUND_IF`로 그 인터페이스로 나간다(터널 안에서
///   소켓이 터널로 되돌아가지 않게 한다. 계약 동작 N 4). 이 타입은 인터페이스를 index로만 안다.
/// - **신호로 죽지 않는다.** 소켓에 `SO_NOSIGPIPE`를 건다. Darwin은 UDP 송신에도 `EPIPE`와 SIGPIPE를 낼 수 있다.
/// - **구조적 동시성을 깨지 않는다.** 읽기는 Task가 아니라 디스패치 원천이 맡고, 흐름을 기다리는 Task가 취소되면 `for await`가
///   끝난다. 소켓을 버리면(`deinit`) 닫히고 흐름도 끝난다. 읽기 처리기는 `self`를 붙잡지 않아 소켓이 버려질 수 있다.
///
/// 소켓 주소를 다루는 `sockaddr` 재해석과 버퍼 포인터는 이 파일 아래쪽의 `receiveOne`·`sendOne`·`bind`·`localPort`에만
/// 가둔다. 커널 API가 C 구조체의 포인터를 요구하고 `sockaddr_in`을 `sockaddr`로 다시 보아야 하기 때문이며, 모든 포인터는
/// 호출 하나의 수명 안에서만 쓴다.
///
/// - `shortcut:` IPv6 소켓과 이중 스택은 만들지 않는다. 필요해지는 시점: IPv6만 되는 망을 M5 실기기에서 만날 때. 넣을 때는
///   두 소켓을 같은 포트에 묶는다(계약 "제외").
package final class DatagramSocket: Sendable {
    /// 한 번에 읽는 최대 크기. UDP 데이터그램의 이론적 최대(65,535)다. 더 큰 것은 커널이 자른다.
    private static let maximumDatagramSize = 65_535
    /// 소비하지 못하고 쌓아 두는 데이터그램 수.
    private static let bufferedDatagramCount = 256
    /// 읽지 않은 데이터그램 본문의 바이트 합의 한도(1MiB). 넘으면 오래된 것부터 버린다.
    ///
    /// 개수 한도만으로는 데이터그램당 최대 65,535바이트 × 256개 = 최악 16MiB를 쥔다. iOS 패킷 터널 확장의 한도(약 50MiB)의
    /// 3분의 1이라 받는 쪽 버퍼가 셋이면 넘친다(`docs/contracts/SwiftailTunnel.md` 동작 M). 1MiB는 그 최악의 16분의 1이다.
    /// 근거는 이 계산뿐인 제안값이라 실기기 처리량 측정에서 버림이 보이면 조정한다. 데이터그램 하나(65,535바이트)는
    /// 한도 안이므로 어떤 데이터그램도 혼자서 한도를 넘지 않는다.
    static let receiveBufferByteLimit = 1 << 20

    package typealias Datagram = (bytes: [UInt8], source: IPEndpoint)

    private struct Open {
        let descriptor: Int32
        let source: any DispatchSourceRead
        let queue: ReceiveQueue
    }

    /// 닫으면 nil. 기술자와 읽기 원천은 이 상자 안에서만 만지고, `close(2)`는 원천의 취소 처리기가 한다.
    private let state: Mutex<Open?>

    /// 묶인 포트. 0을 요청했으면 OS가 고른 값이다.
    package let localPort: UInt16

    /// 받은 데이터그램의 흐름. 구독자는 하나다. 소비가 느리면 오래된 것부터 버린다(256개). 소켓을 닫거나 버리면 끝난다.
    package let datagrams: AsyncStream<Datagram>

    /// IPv4 와일드카드에 묶는다. `port`가 0이면 OS가 고른다. 읽기는 곧바로 시작한다.
    ///
    /// `interfaceIndex`를 주면 묶기 전에 `IP_BOUND_IF`로 그 인터페이스(`if_nametoindex`나 `NWInterface.index`가 주는 번호)에
    /// 소켓을 묶는다. 그러면 소켓이 보내는 것은 그 인터페이스로 나간다. macOS에서 보면 물리 인터페이스에 묶은 소켓도
    /// 루프백과는 주고받으므로(`DatagramSocketTests`), 목적지가 여럿인 이 소켓에는 루프백 예외를 두지 않는다.
    ///
    /// - Throws: 소켓을 만들거나 묶지 못하면, 또는 인터페이스에 묶지 못하면(없는 index 등) `SocketError.bindFailed`(errno 이름).
    package init(port: UInt16 = 0, interfaceIndex: UInt32? = nil) throws(SocketError) {
        let descriptor = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { throw .bindFailed(errnoName(errno)) }
        let (boundPort, setupError) = Self.prepare(descriptor, port: port, interfaceIndex: interfaceIndex)
        guard let boundPort else {
            Darwin.close(descriptor)
            throw .bindFailed(setupError)
        }

        let output = ReceiveQueue()
        datagrams = AsyncStream(unfolding: { await output.next() })
        let queue = DispatchQueue(label: "Swiftail.DatagramSocket")
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler {
            Self.drain(descriptor, into: output)
        }
        source.setCancelHandler {
            Darwin.close(descriptor)
        }
        localPort = boundPort
        state = Mutex(Open(descriptor: descriptor, source: source, queue: output))
        source.activate()
    }

    deinit {
        close()
    }

    /// 데이터그램 하나를 보낸다. 기다리지 않는다.
    ///
    /// - Throws: `SocketError.sendFailed`(errno 이름). 닫은 소켓은 `EBADF`, IPv6 목적지는 `EAFNOSUPPORT`, 커널의 보내기
    ///   버퍼가 찼으면 `EAGAIN`이다. 부르는 쪽이 그 데이터그램을 버린다(DERP가 함께 나가거나 다시 보낸다).
    package func send(_ bytes: [UInt8], to destination: IPEndpoint) throws(SocketError) {
        guard destination.address.isIPv4 else { throw .sendFailed(errnoName(EAFNOSUPPORT)) }
        // 보내는 동안 잠금을 쥐어 `close()`가 끼어들지 못하게 한다. 비차단이라 오래 걸리지 않는다.
        let failure: Int32? = state.withLock { state in
            guard let state else { return EBADF }
            return Self.sendOne(bytes, to: destination, descriptor: state.descriptor)
        }
        if let failure { throw .sendFailed(errnoName(failure)) }
    }

    /// 소켓을 닫는다. 흐름이 끝나고 읽기가 멈춘다. 여러 번 불러도 된다.
    package func close() {
        let opened = state.withLock { state in
            defer { state = nil }
            return state
        }
        opened?.queue.finish()
        opened?.source.cancel()
    }

    // MARK: POSIX 경계

    /// 비차단으로 바꾸고 (주어졌으면) 인터페이스에 묶고 와일드카드에 묶은 뒤 OS가 정한 포트를 돌려준다. 실패하면 포트 대신
    /// errno 이름을 돌려준다. 인터페이스 묶기는 `bind(2)` 전에 한다(묶은 뒤에 걸면 이미 정한 지역 주소가 그대로다).
    private static func prepare(
        _ descriptor: Int32, port: UInt16, interfaceIndex: UInt32?
    ) -> (port: UInt16?, error: String) {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            return (nil, errnoName(errno))
        }
        // Darwin에서는 UDP `sendto`도 `EPIPE`로 실패할 수 있고(M4 관문에서 LAN 주소로 보낼 때 관찰. Go도 UDP 송신의
        // `EPIPE`를 다룬다, `net/neterror/neterror_unix.go`), 그때 커널은 SIGPIPE를 보낸다. 신호의 기본 동작은 프로세스
        // 종료이므로 꺼 둔다. 그러면 그 송신은 `sendFailed("EPIPE")`로 돌아온다.
        var noSignal: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &noSignal, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            return (nil, errnoName(errno))
        }
        if var interfaceIndex {
            guard setsockopt(
                descriptor, IPPROTO_IP, IP_BOUND_IF, &interfaceIndex, socklen_t(MemoryLayout<UInt32>.size)
            ) == 0 else { return (nil, errnoName(errno)) }
        }
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: INADDR_ANY)
        // `sockaddr_in`을 `sockaddr`로 다시 본다. bind(2)와 getsockname(2)이 주소 종류에 맞는 구조체를 `sockaddr *`로만 받는다.
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0 else { return (nil, errnoName(errno)) }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
        }
        guard named == 0 else { return (nil, errnoName(errno)) }
        return (UInt16(bigEndian: address.sin_port), "")
    }

    /// 읽을 것이 없을 때까지 읽어 흐름에 넣는다. 읽기 원천의 처리기 안에서만 부른다.
    ///
    /// 예기치 않은 오류(`EAGAIN`·`EINTR` 밖)가 나면 흐름을 끝낸다. 커널이 계속 읽을 수 있다고 알리는 소켓에서 같은 오류가
    /// 되풀이되면 처리기가 헛돌기 때문이다.
    private static func drain(_ descriptor: Int32, into output: ReceiveQueue) {
        var buffer = [UInt8](repeating: 0, count: maximumDatagramSize)
        while true {
            switch receiveOne(descriptor, into: &buffer) {
            case .datagram(let count, let source):
                output.push((Array(buffer[..<count]), source))
            case .ignored, .failed(EINTR):
                continue
            case .failed(EAGAIN):
                return
            case .failed:
                output.finish()
                return
            }
        }
    }

    /// 소비자가 아직 읽지 않은 데이터그램. `datagrams`가 여기서 하나씩 당겨 간다.
    ///
    /// 가장 새 것 `bufferedDatagramCount`개까지, 그리고 본문 바이트 합 `receiveBufferByteLimit`까지만 쥐고 넘치면 오래된
    /// 것부터 버린다. `AsyncStream`의 `bufferingNewest`는 개수로만 묶으므로 버퍼를 여기서 쥐고 `AsyncStream(unfolding:)`으로
    /// 소비자가 당겨 가게 한다(`DERPClient.EventQueue`와 같은 모양이다. 두 타깃이 서로 모르므로 따로 둔다). 구독자는 하나다.
    private final class ReceiveQueue: Sendable {
        private struct State {
            var datagrams: [Datagram] = []
            /// `datagrams`에 든 본문의 바이트 합.
            var bytes = 0
            /// 데이터그램을 기다리는 소비자.
            var waiter: CheckedContinuation<Datagram?, Never>?
            var isFinished = false
        }

        private let state = Mutex(State())

        /// 데이터그램을 넣는다. 기다리는 소비자가 있으면 곧바로 넘긴다. `finish()` 뒤에는 버린다.
        func push(_ datagram: Datagram) {
            let waiter: CheckedContinuation<Datagram?, Never>? = state.withLock { state in
                guard !state.isFinished else { return nil }
                // 기다리는 소비자가 있으면 큐는 비어 있다.
                if let waiter = state.waiter.take() { return waiter }
                if state.datagrams.count >= DatagramSocket.bufferedDatagramCount {
                    state.bytes -= state.datagrams.removeFirst().bytes.count
                }
                // 새 데이터그램이 들어갈 자리가 날 때까지 오래된 것부터 버린다. 하나는 한도보다 작으므로 끝난다.
                while state.bytes + datagram.bytes.count > DatagramSocket.receiveBufferByteLimit, !state.datagrams.isEmpty {
                    state.bytes -= state.datagrams.removeFirst().bytes.count
                }
                state.datagrams.append(datagram)
                state.bytes += datagram.bytes.count
                return nil
            }
            waiter?.resume(returning: datagram)
        }

        /// 남은 것을 다 읽으면 흐름이 끝나게 한다.
        func finish() {
            let waiter = state.withLock { state in
                state.isFinished = true
                return state.waiter.take()
            }
            waiter?.resume(returning: nil)
        }

        /// 다음 데이터그램. 없으면 올 때까지 기다린다. 끝났거나 소비자의 Task가 취소되면 nil.
        func next() async -> Datagram? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Datagram?, Never>) in
                    let ready: Datagram?? = state.withLock { state in
                        if !state.datagrams.isEmpty {
                            let datagram = state.datagrams.removeFirst()
                            state.bytes -= datagram.bytes.count
                            return .some(datagram)
                        }
                        // 이미 취소되었으면 취소 처리기가 먼저 돌았으므로 기다리지 않는다. 두 번째 구독자도 기다리게 하지 않는다.
                        if state.isFinished || Task.isCancelled || state.waiter != nil { return .some(nil) }
                        state.waiter = continuation
                        return .none
                    }
                    if let ready { continuation.resume(returning: ready) }
                }
            } onCancel: {
                state.withLock { $0.waiter.take() }?.resume(returning: nil)
            }
        }
    }

    private enum Received {
        case datagram(count: Int, source: IPEndpoint)
        /// IPv4가 아닌 출처. IPv4 소켓에서는 일어나지 않지만 해석할 수 없으면 버리고 계속 읽는다.
        case ignored
        case failed(Int32)
    }

    private static func receiveOne(_ descriptor: Int32, into buffer: inout [UInt8]) -> Received {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        // 받은 주소를 `sockaddr_in`으로 받으려고 `sockaddr *`로 다시 본다. 두 포인터는 이 호출 안에서만 산다.
        let count = buffer.withUnsafeMutableBytes { bytes in
            withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(descriptor, bytes.baseAddress, bytes.count, 0, $0, &length)
                }
            }
        }
        guard count >= 0 else { return .failed(errno) }
        // `s_addr`는 네트워크 바이트 순서다. 호스트 순서로 바꿔 상위 바이트부터 꺼낸다.
        let host = UInt32(bigEndian: address.sin_addr.s_addr)
        guard address.sin_family == sa_family_t(AF_INET),
              let ip = IPAddress(bytes: (0..<4).map { UInt8(truncatingIfNeeded: host >> UInt32(24 - 8 * $0)) })
        else { return .ignored }
        return .datagram(count: count, source: IPEndpoint(address: ip, port: UInt16(bigEndian: address.sin_port)))
    }

    /// 성공하면 nil, 실패하면 errno를 돌려준다. 데이터그램은 한 번에 다 가거나 아예 가지 않는다.
    private static func sendOne(_ bytes: [UInt8], to destination: IPEndpoint, descriptor: Int32) -> Int32? {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = destination.port.bigEndian
        // 주소 4바이트를 상위 바이트부터 호스트 정수로 모은 뒤 네트워크 바이트 순서로 바꿔 `s_addr`에 넣는다.
        address.sin_addr.s_addr = destination.address.bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }.bigEndian
        let sent = bytes.withUnsafeBytes { payload in
            withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(descriptor, payload.baseAddress, payload.count, 0, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        if sent < 0 { return errno }
        return sent == bytes.count ? nil : EMSGSIZE
    }
}

/// errno의 이름. 오류 메시지에는 이름만 담는다(주소나 바이트는 담지 않는다).
func errnoName(_ code: Int32) -> String {
    switch code {
    case EACCES: "EACCES"
    case EADDRINUSE: "EADDRINUSE"
    case EADDRNOTAVAIL: "EADDRNOTAVAIL"
    case EAFNOSUPPORT: "EAFNOSUPPORT"
    case EAGAIN: "EAGAIN"
    case EBADF: "EBADF"
    case ECONNREFUSED: "ECONNREFUSED"
    case ECONNRESET: "ECONNRESET"
    case EHOSTDOWN: "EHOSTDOWN"
    case EHOSTUNREACH: "EHOSTUNREACH"
    case EINVAL: "EINVAL"
    case EMFILE: "EMFILE"
    case EMSGSIZE: "EMSGSIZE"
    case ENETDOWN: "ENETDOWN"
    case ENETUNREACH: "ENETUNREACH"
    case ENFILE: "ENFILE"
    case ENOBUFS: "ENOBUFS"
    case ENOMEM: "ENOMEM"
    case ENXIO: "ENXIO"
    case EPIPE: "EPIPE"
    case EPERM: "EPERM"
    default: "errno \(code)"
    }
}
