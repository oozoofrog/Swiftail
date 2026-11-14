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
/// - **받은 것은 256개까지만 쌓는다.** 소비가 느리면 오래된 데이터그램부터 버린다(`AsyncStream`의 `bufferingNewest`).
///   메모리는 256 × 65,535바이트를 넘지 않는다. UDP는 어차피 손실을 받아들이는 전송이다.
/// - **파일 기술자는 한 번만 닫는다.** `close()`는 기술자를 상태에서 떼어 낸 뒤 읽기 원천을 취소하고, 실제 `close(2)`는
///   원천의 취소 처리기가 한다. 취소 처리기는 돌고 있던 읽기 처리기가 끝난 뒤에 돌므로 읽는 중에 기술자가 닫히지 않고,
///   `close()` 뒤의 `send`는 상태가 비어 있어 기술자를 건드리지 않는다(다른 곳이 재사용한 번호를 닫거나 쓰는 일이 없다).
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

    private struct Open {
        let descriptor: Int32
        let source: any DispatchSourceRead
        let continuation: AsyncStream<(bytes: [UInt8], source: IPEndpoint)>.Continuation
    }

    /// 닫으면 nil. 기술자와 읽기 원천은 이 상자 안에서만 만지고, `close(2)`는 원천의 취소 처리기가 한다.
    private let state: Mutex<Open?>

    /// 묶인 포트. 0을 요청했으면 OS가 고른 값이다.
    package let localPort: UInt16

    /// 받은 데이터그램의 흐름. 구독자는 하나다. 소비가 느리면 오래된 것부터 버린다(256개). 소켓을 닫거나 버리면 끝난다.
    package let datagrams: AsyncStream<(bytes: [UInt8], source: IPEndpoint)>

    /// IPv4 와일드카드에 묶는다. `port`가 0이면 OS가 고른다. 읽기는 곧바로 시작한다.
    ///
    /// - Throws: 소켓을 만들거나 묶지 못하면 `SocketError.bindFailed`(errno 이름).
    package init(port: UInt16 = 0) throws(SocketError) {
        let descriptor = Darwin.socket(AF_INET, SOCK_DGRAM, 0)
        guard descriptor >= 0 else { throw .bindFailed(errnoName(errno)) }
        let (boundPort, setupError) = Self.prepare(descriptor, port: port)
        guard let boundPort else {
            Darwin.close(descriptor)
            throw .bindFailed(setupError)
        }

        let (stream, output) = AsyncStream<(bytes: [UInt8], source: IPEndpoint)>.makeStream(
            bufferingPolicy: .bufferingNewest(Self.bufferedDatagramCount)
        )
        datagrams = stream
        let queue = DispatchQueue(label: "Swiftail.DatagramSocket")
        let source = DispatchSource.makeReadSource(fileDescriptor: descriptor, queue: queue)
        source.setEventHandler {
            Self.drain(descriptor, into: output)
        }
        source.setCancelHandler {
            Darwin.close(descriptor)
        }
        localPort = boundPort
        state = Mutex(Open(descriptor: descriptor, source: source, continuation: output))
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
        opened?.continuation.finish()
        opened?.source.cancel()
    }

    // MARK: POSIX 경계

    /// 비차단으로 바꾸고 와일드카드에 묶은 뒤 OS가 정한 포트를 돌려준다. 실패하면 포트 대신 errno 이름을 돌려준다.
    private static func prepare(_ descriptor: Int32, port: UInt16) -> (port: UInt16?, error: String) {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            return (nil, errnoName(errno))
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
    private static func drain(_ descriptor: Int32, into output: AsyncStream<(bytes: [UInt8], source: IPEndpoint)>.Continuation) {
        var buffer = [UInt8](repeating: 0, count: maximumDatagramSize)
        while true {
            switch receiveOne(descriptor, into: &buffer) {
            case .datagram(let count, let source):
                output.yield((Array(buffer[..<count]), source))
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
    case EPERM: "EPERM"
    default: "errno \(code)"
    }
}
