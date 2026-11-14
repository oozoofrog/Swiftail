import Dispatch
import Darwin
import SwiftailBase
import Synchronization

/// IPv4 와일드카드(0.0.0.0)에 묶인 UDP 소켓 하나를 async 데이터그램 흐름과 기다리지 않는 송신 큐로 감싼다.
///
/// WireGuard·disco·STUN이 같은 소켓을 쓴다(`docs/protocol-notes/derp-stun.md` 4.10 2). 포트 하나로 여러 상대와 주고받아야
/// 해서 `Network` 프레임워크가 아니라 POSIX 소켓을 쓴다(`docs/plan.md` 4절 (c)). 부르는 쪽은 `SwiftailMagicsock`의
/// 상태 기계를 부리는 노드다. 실패는 `SocketError`로 낸다.
///
/// 지키는 것:
///
/// - **읽기는 사건으로 깨어난다.** `DispatchSource` 읽기 사건이 오면 더 읽을 것이 없을 때(`EAGAIN`)까지 읽는다. 폴링하지 않는다.
///   읽기 버퍼(65,535바이트)는 소켓마다 하나를 만들어 다시 쓴다.
/// - **보내기는 소켓의 직렬 큐가 한다.** `enqueue(_:)`는 송신 큐에 넣기만 하고, `sendto(2)`는 읽기 원천과 같은 직렬 디스패치
///   큐에서 넣은 순서대로 한다. 노드 actor가 시스템 호출을 기다리지 않는다.
/// - **받은 것과 아직 보내지 못한 것은 각각 256개와 1MiB까지만 쥔다.** 넘으면 오래된 데이터그램부터 버린다(`DatagramQueue`).
///   개수만으로는 256 × 65,535바이트(최악 16MiB)를 쥐므로 바이트 합으로도 묶는다(`queuedByteLimit`). UDP는 어차피 손실을
///   받아들이는 전송이다.
/// - **파일 기술자는 한 번만 닫고, 닫은 뒤에는 쓰지 않는다.** `close()`는 기술자를 상태에서 떼어 낸 뒤 읽기 원천을 취소하고,
///   실제 `close(2)`는 원천의 취소 처리기가 한다. 취소 처리기는 같은 직렬 큐에서 돌던 읽기·보내기가 끝난 뒤에 돌므로 그동안
///   기술자가 닫히지 않는다. `close()` 뒤에는 상태가 비어 있어 `send`도 송신 큐의 남은 것도 기술자를 건드리지 않는다(남은 것은
///   버린다. 다른 곳이 재사용한 번호에 쓰는 일이 없다).
/// - **인터페이스에 묶을 수 있다.** `interfaceIndex`를 주면 `IP_BOUND_IF`로 그 인터페이스로 나간다(터널 안에서
///   소켓이 터널로 되돌아가지 않게 한다. 계약 동작 N 4). 이 타입은 인터페이스를 index로만 안다.
/// - **신호로 죽지 않는다.** 소켓에 `SO_NOSIGPIPE`를 건다. Darwin은 UDP 송신에도 `EPIPE`와 SIGPIPE를 낼 수 있다.
/// - **구조적 동시성을 깨지 않는다.** 읽기와 보내기는 Task가 아니라 디스패치 원천과 큐가 맡고, 흐름을 기다리는 Task가 취소되면
///   `for await`가 끝난다. 소켓을 버리면(`deinit`) 닫히고 흐름도 끝난다. 읽기 처리기는 `self`를 붙잡지 않아 소켓이 버려질 수
///   있다(보내기 블록은 보낼 동안만 붙잡는다).
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
    /// 받은 큐와 송신 큐가 각각 쥐는 데이터그램 수의 한도.
    private static let queuedDatagramLimit = 256
    /// 받은 큐와 송신 큐가 각각 쥐는 데이터그램 본문의 바이트 합의 한도(1MiB). 넘으면 오래된 것부터 버린다.
    ///
    /// 개수 한도만으로는 데이터그램당 최대 65,535바이트 × 256개 = 최악 16MiB를 쥔다. iOS 패킷 터널 확장의 한도(약 50MiB)의
    /// 3분의 1이라 버퍼가 셋이면 넘친다(`docs/contracts/SwiftailTunnel.md` 동작 M). 1MiB는 그 최악의 16분의 1이다.
    /// 근거는 이 계산뿐인 제안값이라 실기기 처리량 측정에서 버림이 보이면 조정한다. 데이터그램 하나(65,535바이트)는
    /// 한도 안이므로 어떤 데이터그램도 혼자서 한도를 넘지 않는다.
    static let queuedByteLimit = 1 << 20

    package typealias Datagram = (bytes: [UInt8], source: IPEndpoint)
    /// 보낼 데이터그램과 목적지.
    package typealias OutgoingDatagram = (bytes: [UInt8], destination: IPEndpoint)

    private struct Open {
        let descriptor: Int32
        let source: any DispatchSourceRead
        let received: DatagramQueue
        let outgoing: DatagramQueue
    }

    /// 닫으면 nil. 기술자와 읽기 원천은 이 상자 안에서만 만지고, `close(2)`는 원천의 취소 처리기가 한다.
    private let state: Mutex<Open?>
    /// 읽기 원천과 송신이 함께 쓰는 직렬 큐. 기술자의 `close(2)`도 여기서 일어난다.
    private let queue: DispatchQueue

    /// 묶인 포트. 0을 요청했으면 OS가 고른 값이다.
    package let localPort: UInt16

    /// 받은 데이터그램의 흐름. 구독자는 하나다. 소비가 느리면 오래된 것부터 버린다(256개, 그리고 바이트 합 1MiB). 소켓을
    /// 닫거나 버리면 끝난다. 닫지 않았는데 끝났다면 읽기가 오류로 멈춘 것이니 `close()`하고 새로 연다.
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

        let received = DatagramQueue()
        datagrams = AsyncStream(unfolding: { await received.next().map { ($0.bytes, $0.endpoint) } })
        let queue = DispatchQueue(label: "Swiftail.DatagramSocket")
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        let buffer = ReadBuffer()
        source.setEventHandler {
            Self.drain(descriptor, using: buffer, into: received)
        }
        source.setCancelHandler {
            Darwin.close(descriptor)
        }
        localPort = boundPort
        self.queue = queue
        state = Mutex(Open(descriptor: descriptor, source: source, received: received, outgoing: DatagramQueue()))
        source.activate()
    }

    deinit {
        close()
    }

    /// 데이터그램 하나를 곧바로 보낸다. 기다리지 않는다. 노드는 `enqueue(_:)`를 쓴다.
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

    /// 데이터그램들을 송신 큐에 넣는다. 기다리지 않는다. 소켓의 직렬 큐가 넣은 순서대로 보낸다.
    ///
    /// 아직 보내지 못한 것이 256개나 바이트 합 1MiB를 넘으면 오래된 것부터 버린다. 닫은 소켓이면 버린다. 보내기 실패(IPv6
    /// 목적지, `EAGAIN`, `EHOSTUNREACH` 등)는 그 데이터그램을 버린다(DERP로 함께 나가거나 WireGuard·disco가 다시 보낸다).
    package func enqueue(_ datagrams: [OutgoingDatagram]) {
        guard let outgoing = state.withLock({ $0?.outgoing }) else { return }
        // 비어 있던 큐에 넣었을 때만 보내기를 건다. 비어 있지 않으면 이미 걸린 보내기가 아직 꺼내 가지 않았다.
        guard outgoing.append(contentsOf: datagrams.map { Envelope(bytes: $0.bytes, endpoint: $0.destination) }) else { return }
        queue.async {
            self.sendQueued()
        }
    }

    /// 받아 쌓아 둔 데이터그램을 기다리지 않고 모두 꺼낸다. 없거나 닫혔으면 빈 배열이다.
    ///
    /// `datagrams`에서 하나를 받은 뒤 불러, 그동안 쌓인 것을 묶음 하나로 처리하게 한다. 묶음은 받은 큐의 한도(256개, 1MiB)를
    /// 넘지 않는다. `datagrams`와 같은 큐에서 꺼내므로 같은 구독자만 부른다.
    package func takeQueuedDatagrams() -> [Datagram] {
        (state.withLock { $0?.received }?.takeAll() ?? []).map { ($0.bytes, $0.endpoint) }
    }

    /// 소켓을 닫는다. 흐름이 끝나고 읽기가 멈춘다. 아직 보내지 못한 데이터그램은 버린다. 여러 번 불러도 된다.
    package func close() {
        let opened = state.withLock { state in
            defer { state = nil }
            return state
        }
        opened?.received.finish()
        opened?.outgoing.finish()
        opened?.source.cancel()
    }

    /// 송신 큐에 이미 넣은 것을 보낸 뒤 닫는다. 기다리지 않는다(보내기와 닫기는 직렬 큐에서 이 순서로 일어난다).
    ///
    /// 노드가 멈출 때 쓴다: 마지막 처리가 낸 RST(netstack 계약 동작 N8)가 직접 경로로 나가게 한다. 그 밖의 닫기(재결속)는
    /// 남은 것을 버리는 `close()`다.
    package func closeAfterSending() {
        queue.async {
            self.sendQueued()
            self.close()
        }
    }

    /// 송신 큐의 것을 모두 보낸다. 직렬 큐에서만 돈다.
    ///
    /// 기술자의 `close(2)`는 같은 직렬 큐의 취소 처리기에서만 일어나므로 이 블록이 도는 동안 기술자는 열려 있다. 그래도 보낼
    /// 때마다 상태를 보아, 그사이 `close()`가 불렸으면 남은 것을 버린다.
    private func sendQueued() {
        guard let opened = state.withLock({ $0 }) else { return }
        for datagram in opened.outgoing.takeAll() {
            guard state.withLock({ $0 != nil }) else { return }
            guard datagram.endpoint.address.isIPv4 else { continue }
            _ = Self.sendOne(datagram.bytes, to: datagram.endpoint, descriptor: opened.descriptor)
        }
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

    /// 읽을 것이 없을 때까지 읽어 받은 큐에 넣는다. 읽기 원천의 처리기 안에서만 부른다.
    ///
    /// 예기치 않은 오류(`EAGAIN`·`EINTR` 밖)가 나면 흐름을 끝낸다. 읽기 원천은 여기서 멈추지 못하므로(멈추려면 기술자를
    /// 닫아야 하고, 그것은 `close()`가 상태와 함께 한다) 흐름이 끝난 것을 본 쪽이 `close()`를 불러야 한다. 노드는 그때
    /// 소켓을 새로 연다.
    private static func drain(_ descriptor: Int32, using buffer: ReadBuffer, into output: DatagramQueue) {
        buffer.bytes.withLock { bytes in
            while true {
                switch receiveOne(descriptor, into: &bytes) {
                case .datagram(let count, let source):
                    output.push(Envelope(bytes: Array(bytes[..<count]), endpoint: source))
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
    }

    /// 소켓 하나의 읽기 버퍼. 읽기 사건마다 65,535바이트를 새로 만들고 0으로 채우지 않게 하나를 다시 쓴다. 읽기 원천의
    /// 처리기(직렬 큐)만 쓰므로 잠금은 다투지 않는다. 처리기가 붙잡을 수 있게 클래스로 감싼다.
    private final class ReadBuffer: Sendable {
        let bytes = Mutex([UInt8](repeating: 0, count: DatagramSocket.maximumDatagramSize))
    }

    /// 데이터그램 하나와 상대 주소(받은 것이면 보낸 쪽, 보낼 것이면 목적지).
    private struct Envelope {
        var bytes: [UInt8]
        var endpoint: IPEndpoint
    }

    /// 데이터그램 큐. 받은 큐(소비자가 `next()`로 하나씩, 또는 `takeAll()`로 한꺼번에 당겨 간다)와 송신 큐(직렬 큐가
    /// `takeAll()`로 꺼내 보낸다)가 같은 것을 쓴다.
    ///
    /// 가장 새 것 `queuedDatagramLimit`개까지, 그리고 본문 바이트 합 `queuedByteLimit`까지만 쥐고 넘치면 오래된 것부터
    /// 버린다. `AsyncStream`의 `bufferingNewest`는 개수로만 묶으므로 버퍼를 여기서 쥐고 `AsyncStream(unfolding:)`으로
    /// 소비자가 당겨 가게 한다(`DERPClient.EventQueue`와 같은 모양이다. 두 타깃이 서로 모르므로 따로 둔다). 기다리는 소비자는
    /// 하나다. 앞에서 꺼내기는 O(1)이다(`Ring`).
    private final class DatagramQueue: Sendable {
        private struct State {
            var datagrams = Ring()
            /// 데이터그램을 기다리는 소비자.
            var waiter: CheckedContinuation<Envelope?, Never>?
            var isFinished = false
        }

        /// 한도 안의 데이터그램을 넣은 순서대로 쥔다. 꺼낸 자리는 비워 두었다가 절반이 넘으면 한꺼번에 당긴다.
        private struct Ring {
            private var slots: [Envelope?] = []
            private var head = 0
            /// 쥔 데이터그램 본문의 바이트 합.
            private(set) var bytes = 0

            var isEmpty: Bool { head == slots.count }
            var count: Int { slots.count - head }

            /// 뒤에 넣는다. 넣은 뒤 한도를 넘으면 오래된 것부터 버린다. 하나는 바이트 한도보다 작으므로 넣은 것은 남는다.
            mutating func append(_ datagram: Envelope) {
                slots.append(datagram)
                bytes += datagram.bytes.count
                while count > DatagramSocket.queuedDatagramLimit || bytes > DatagramSocket.queuedByteLimit, count > 1 {
                    _ = popFirst()
                }
            }

            mutating func popFirst() -> Envelope? {
                guard head < slots.count, let datagram = slots[head].take() else { return nil }
                head += 1
                bytes -= datagram.bytes.count
                if head == slots.count {
                    slots.removeAll(keepingCapacity: true)
                    head = 0
                } else if head >= DatagramSocket.queuedDatagramLimit, head * 2 >= slots.count {
                    slots.removeFirst(head)
                    head = 0
                }
                return datagram
            }

            mutating func removeAll() -> [Envelope] {
                let taken = slots[head...].compactMap { $0 }
                slots.removeAll(keepingCapacity: true)
                head = 0
                bytes = 0
                return taken
            }
        }

        private let state = Mutex(State())

        /// 하나를 넣는다. 기다리는 소비자가 있으면 곧바로 넘긴다. `finish()` 뒤에는 버린다.
        func push(_ datagram: Envelope) {
            let waiter: CheckedContinuation<Envelope?, Never>? = state.withLock { state in
                guard !state.isFinished else { return nil }
                // 기다리는 소비자가 있으면 큐는 비어 있다.
                if let waiter = state.waiter.take() { return waiter }
                state.datagrams.append(datagram)
                return nil
            }
            waiter?.resume(returning: datagram)
        }

        /// 여럿을 넣는다(송신 큐). 비어 있던 큐에 넣었으면 참이다(꺼내 갈 쪽을 불러야 한다). `finish()` 뒤에는 버리고 거짓이다.
        func append(contentsOf datagrams: [Envelope]) -> Bool {
            state.withLock { state in
                guard !state.isFinished, !datagrams.isEmpty else { return false }
                let wasEmpty = state.datagrams.isEmpty
                for datagram in datagrams {
                    state.datagrams.append(datagram)
                }
                return wasEmpty
            }
        }

        /// 쌓인 것을 모두 꺼낸다.
        func takeAll() -> [Envelope] {
            state.withLock { $0.datagrams.removeAll() }
        }

        /// 더 넣지 못하게 한다. 받은 큐는 남은 것을 다 읽으면 흐름이 끝난다.
        func finish() {
            let waiter = state.withLock { state in
                state.isFinished = true
                return state.waiter.take()
            }
            waiter?.resume(returning: nil)
        }

        /// 다음 데이터그램. 없으면 올 때까지 기다린다. 끝났거나 소비자의 Task가 취소되면 nil.
        func next() async -> Envelope? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Envelope?, Never>) in
                    let ready: Envelope?? = state.withLock { state in
                        if let datagram = state.datagrams.popFirst() { return .some(datagram) }
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
