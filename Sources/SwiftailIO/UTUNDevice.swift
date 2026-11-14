// 4바이트 프로토콜 머리(읽을 때 건너뛰고 쓸 때 IP 버전으로 `AF_INET`·`AF_INET6`를 넣는 규칙)와 utun 제어 소켓의 이름 확인
// (`getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`)은 wireguard-go `tun/tun_darwin.go`의 `Name`·`Read`·`Write`를 따른다.
// 코드를 옮기지는 않았고 동작만 같다. wireguard-go는 MIT 라이선스다(Copyright (C) 2017-2023 WireGuard LLC).

import Darwin
import Dispatch
import Synchronization

/// 패킷 터널 제공자가 넘겨 준 utun 파일 기술자를 IP 패킷의 흐름과 쓰기 호출로 감싼다(`docs/contracts/SwiftailTunnel.md` 동작 U).
///
/// 노드는 이것으로 OS가 터널로 보낸 IP 패킷을 읽어 tailnet으로 보내고, tailnet에서 온 패킷을 OS에 넣는다. utun을 만들거나 인터페이스를
/// 설정하는 일은 하지 않는다. 그것은 앱의 Network Extension이 한다.
///
/// 지키는 것:
///
/// - **받은 기술자를 복제해 쓴다.** `F_DUPFD_CLOEXEC`로 복제하고 복제본에 `O_NONBLOCK`을 건다. 이 객체는 복제본만 닫는다. 호출자의
///   기술자는 닫지도 읽지도 않는다. `O_NONBLOCK`은 같은 열린 파일 설명을 공유하는 호출자의 기술자에도 걸리지만 앱은 그것으로 읽고
///   쓰지 않는다(계약 U2).
/// - **utun임을 확인한다.** 소켓 주소 계열이 `AF_SYSTEM`이고 `UTUN_OPT_IFNAME`의 이름이 `utun`으로 시작해야 한다. 확인은 복제본에서
///   읽기 호출만으로 하므로 거절해도 호출자의 기술자는 그대로다(계약 U1).
/// - **패킷마다 4바이트 머리가 붙는다.** 읽을 때 머리를 떼고 IP 패킷만 올린다. 4바이트 이하(IP 패킷이 없음)는 버리고 머리 값은 보지
///   않는다. 쓸 때 IP 버전 니블이 4면 `AF_INET`, 6이면 `AF_INET6`를 머리에 넣고 그 밖은 쓰지 않는다(계약 U3).
/// - **읽기는 사건으로 깨어난다.** `DispatchSource` 읽기 사건이 오면 더 읽을 것이 없을 때(`EAGAIN`)까지 읽는다. `read` 한 번이 패킷
///   하나이고, 읽기 버퍼(4 + 65,535바이트)는 하나를 되풀이해 쓰며 읽은 길이만 복사해 올린다(계약 U4).
/// - **쌓이는 양에 상한이 있다.** 소비가 느리면 오래된 패킷부터 256개까지만 남긴다. 한 패킷이 장치의 MTU를 넘으면 버린다. OS는 설정한
///   MTU를 넘는 패킷을 utun에 넣지 않으므로 이는 어긋난 입력에 대한 방어이고, 덕분에 쌓인 바이트가 256 × 1,420바이트(1MiB 미만)를
///   넘지 않는다(계약 M).
/// - **읽기가 끝나면 이유를 알린다.** 0바이트(끝)나 `EAGAIN`·`EINTR`가 아닌 오류는 장치가 닫힌 것이다. 흐름이 끝나고 `readFailure`가
///   `SocketError.readFailed`(errno 이름, 끝은 `EOF`)가 된다. `close()`나 버리기로 끝난 흐름은 `readFailure`가 nil이다(계약 U4).
///   `AsyncThrowingStream`은 오류 종류를 `any Error`로만 받으므로 흐름 자체는 던지지 않고 이유를 따로 둔다.
/// - **쓰기는 기다리지 않고 큐도 없다.** 실패한 패킷은 `SocketError.sendFailed`로 알리고 부르는 쪽이 버린다. 쓰기 실패는 장치가 닫혔다는
///   뜻이 아니다. 장치의 끝은 읽기 쪽이 알린다(계약 U5).
/// - **기술자는 한 번만 닫는다.** `close()`는 기술자를 상태에서 떼어 낸 뒤 읽기 원천을 취소하고, 실제 `close(2)`는 원천의 취소 처리기가
///   한다. 취소 처리기는 돌고 있던 읽기 처리기가 끝난 뒤에 돌므로 읽는 중에 닫히지 않고, `close()` 뒤의 `write`는 상태가 비어 있어
///   기술자를 건드리지 않는다(다른 곳이 재사용한 번호를 쓰는 일이 없다). 버리면(`deinit`) 닫힌다. `DatagramSocket`과 같다.
/// - **구조적 동시성을 깨지 않는다.** 읽기는 Task가 아니라 디스패치 원천이 맡고, 흐름을 기다리는 Task가 취소되면 `for await`가
///   끝난다.
///
/// 시스템 호출과 주소·문자열 버퍼의 포인터는 이 파일 아래쪽의 POSIX 경계(`duplicate`, `requireUTUN`, `readOne`, `writeOne`)에만 가둔다.
/// 커널 API가 포인터를 요구하고 `sockaddr_storage`를 `sockaddr`로 다시 보아야 하기 때문이며, 모든 포인터는 호출 하나의 수명 안에서만 쓴다.
package final class UTUNDevice: Sendable {
    /// 허용하는 MTU 범위. 아래는 첫 사용처 시험 계약, 위는 wireguard-go의 기본값(`device/tun.go`의 `DefaultMTU` 1420)이다.
    package static let supportedMTU = 1280...1420

    /// utun이 패킷마다 앞에 붙이는 프로토콜 머리의 크기.
    private static let headerLength = 4
    /// IP 패킷의 이론적 최대 길이(전체 길이 필드는 16비트).
    private static let maximumPacketLength = 65_535
    /// 소비하지 못하고 쌓아 두는 패킷 수.
    private static let bufferedPacketCount = 256

    // Darwin의 소켓 주소 계열과 옵션. `AF_SYSTEM`은 이 SDK 모듈에 있지만 제어 소켓 옵션은 `<sys/sys_domain.h>`·`<net/if_utun.h>`의
    // 매크로라서 Swift로 오지 않으므로 값을 적는다(wireguard-go `Name()`도 숫자로 적는다).
    private static let systemAddressFamily = sa_family_t(32)  // AF_SYSTEM
    private static let controlProtocol: Int32 = 2  // SYSPROTO_CONTROL
    private static let interfaceNameOption: Int32 = 2  // UTUN_OPT_IFNAME

    private struct Open {
        let descriptor: Int32
        let source: any DispatchSourceRead
        let continuation: AsyncStream<[UInt8]>.Continuation
    }

    /// 읽기 처리기가 쥐는 것. 읽기 버퍼는 처리기가 되풀이해 쓴다. 처리기는 한 번에 하나씩만 돌지만(직렬 큐) 가변 값을 `Sendable`
    /// 클로저가 붙잡을 수 없어 잠금으로 감싼다(경합하지 않는다). 읽기가 끝난 이유는 흐름을 끝내기 전에 적는다.
    private final class Reader: Sendable {
        let buffer = Mutex([UInt8](repeating: 0, count: UTUNDevice.headerLength + UTUNDevice.maximumPacketLength))
        let failure = Mutex<SocketError?>(nil)
    }

    /// 닫으면 nil. 기술자와 읽기 원천은 이 상자 안에서만 만지고, `close(2)`는 원천의 취소 처리기가 한다.
    private let state: Mutex<Open?>

    /// 앱이 `NEPacketTunnelNetworkSettings.mtu`로 적용하는 값. 노드는 이것을 설정 산출에 그대로 쓴다.
    package let mtu: Int

    private let reader: Reader

    /// OS가 터널로 보낸 IP 패킷의 흐름(머리는 뗀 것). 구독자는 하나다. 소비가 느리면 오래된 것부터 버린다(256개). `close()`나
    /// 버리기로 끝나거나 장치를 더 읽을 수 없어 끝난다. 끝난 이유는 `readFailure`다.
    package let packets: AsyncStream<[UInt8]>

    /// 읽기가 장치의 끝이나 오류로 멈췄으면 그 이유(`SocketError.readFailed`, errno 이름 또는 `EOF`). 흐름이 끝난 뒤에 읽는다.
    /// `close()`나 버리기로 끝났거나 아직 끝나지 않았으면 nil이다. 노드는 이것을 `tunnelDeviceClosed`로 알린다.
    package var readFailure: SocketError? {
        reader.failure.withLock { $0 }
    }

    /// `descriptor`가 utun 제어 소켓인지 확인하고 복제해 읽기를 시작한다.
    ///
    /// - Parameters:
    ///   - descriptor: 패킷 터널 제공자가 찾은 utun의 파일 기술자. 닫지 않는다.
    ///   - mtu: 앱이 적용하는 MTU. `supportedMTU` 안이어야 한다.
    /// - Throws: `SocketError.invalidDevice`(utun이 아니거나 닫힌·음수 기술자, MTU가 범위 밖) 또는 복제하지 못했을 때
    ///   `SocketError.readFailed`(errno 이름).
    package convenience init(duplicating descriptor: Int32, mtu: Int) throws(SocketError) {
        try self.init(duplicating: descriptor, mtu: mtu, verifying: Self.requireUTUN)
    }

    /// 복제본을 `verify`로 확인한 뒤 읽기를 시작한다. 시험이 utun 대신 `socketpair`를 붙이려고 확인을 바꿔 끼운다.
    init(
        duplicating descriptor: Int32,
        mtu: Int,
        verifying verify: (Int32) throws(SocketError) -> Void
    ) throws(SocketError) {
        guard Self.supportedMTU.contains(mtu) else { throw .invalidDevice("mtu") }
        guard descriptor >= 0 else { throw .invalidDevice("fileDescriptor") }
        let copy = try Self.duplicate(descriptor)
        do throws(SocketError) {
            try verify(copy)
            try Self.makeNonBlocking(copy)
            try Self.suppressSIGPIPE(copy)
        } catch {
            Darwin.close(copy)
            throw error
        }

        let (stream, output) = AsyncStream<[UInt8]>.makeStream(bufferingPolicy: .bufferingNewest(Self.bufferedPacketCount))
        packets = stream
        self.mtu = mtu
        let reader = Reader()
        self.reader = reader
        let queue = DispatchQueue(label: "Swiftail.UTUNDevice")
        let source = DispatchSource.makeReadSource(fileDescriptor: copy, queue: queue)
        source.setEventHandler {
            reader.buffer.withLock { Self.drain(copy, using: &$0, mtu: mtu, reader: reader, into: output) }
        }
        source.setCancelHandler {
            Darwin.close(copy)
        }
        state = Mutex(Open(descriptor: copy, source: source, continuation: output))
        source.activate()
    }

    deinit {
        close()
    }

    /// IP 패킷 하나를 장치에 쓴다. 기다리지 않는다.
    ///
    /// - Throws: `SocketError.sendFailed`(errno 이름). IP 버전이 4도 6도 아니면 `EAFNOSUPPORT`(쓰지 않는다), 닫은 장치는 `EBADF`,
    ///   커널이 받지 못하면 `EAGAIN`·`ENOBUFS`·`EMSGSIZE` 등이다. 부르는 쪽이 그 패킷을 버리고 계속한다.
    package func write(_ ipPacket: [UInt8]) throws(SocketError) {
        guard let frame = Self.frame(ipPacket) else { throw .sendFailed(errnoName(EAFNOSUPPORT)) }
        // 쓰는 동안 잠금을 쥐어 `close()`가 끼어들지 못하게 한다. 비차단이라 오래 걸리지 않는다.
        let failure: Int32? = state.withLock { state in
            guard let state else { return EBADF }
            return Self.writeOne(frame, descriptor: state.descriptor)
        }
        if let failure { throw .sendFailed(errnoName(failure)) }
    }

    /// 복제본을 닫는다. 흐름이 오류 없이 끝나고 읽기가 멈춘다. 여러 번 불러도 된다. 호출자의 기술자는 닫지 않는다.
    package func close() {
        let opened = state.withLock { state in
            defer { state = nil }
            return state
        }
        opened?.continuation.finish()
        opened?.source.cancel()
    }

    /// 복제본의 파일 기술자 번호. 닫았으면 nil. 시험이 복제본의 성질(`FD_CLOEXEC`, 닫힘)을 확인할 때만 쓴다.
    var duplicateDescriptor: Int32? {
        state.withLock { $0?.descriptor }
    }

    // MARK: 머리 붙이기·떼기 (입출력 없는 순수 함수)

    /// IP 패킷 앞에 프로토콜 머리를 붙인다. IP 버전이 4면 `00 00 00 02`(`AF_INET`), 6이면 `00 00 00 1e`(`AF_INET6`)다. 비었거나 그 밖의
    /// 버전이면 nil이다. 버전은 첫 바이트의 윗 니블이다. 머리 길이 같은 나머지 검증은 하지 않는다(커널과 엔진이 한다).
    static func frame(_ ipPacket: [UInt8]) -> [UInt8]? {
        guard let first = ipPacket.first else { return nil }
        let family: Int32
        switch first >> 4 {
        case 4: family = AF_INET
        case 6: family = AF_INET6
        default: return nil
        }
        return [0, 0, 0, UInt8(family)] + ipPacket
    }

    /// 읽은 프레임에서 머리를 떼고 IP 패킷을 돌려준다. 머리 값은 보지 않는다. 머리만 있거나 그보다 짧으면 nil이다(버린다).
    static func ipPacket(inFrame frame: ArraySlice<UInt8>) -> [UInt8]? {
        guard frame.count > headerLength else { return nil }
        return Array(frame.dropFirst(headerLength))
    }

    // MARK: POSIX 경계

    /// `F_DUPFD_CLOEXEC`로 복제한다. 번호가 닫혀 있으면 `invalidDevice`, 그 밖의 실패(예: `EMFILE`)는 `readFailed`다.
    private static func duplicate(_ descriptor: Int32) throws(SocketError) -> Int32 {
        let copy = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else {
            if errno == EBADF { throw .invalidDevice("fileDescriptor") }
            throw .readFailed(errnoName(errno))
        }
        return copy
    }

    private static func makeNonBlocking(_ descriptor: Int32) throws(SocketError) {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            throw .readFailed(errnoName(errno))
        }
    }

    /// 끊긴 소켓에 써도 SIGPIPE가 나지 않게 한다. 신호의 기본 동작은 프로세스 종료이고, 이 코드는 패킷 터널 확장 안에서 돈다.
    /// 걸어 두면 그런 쓰기는 `EPIPE`로 돌아와 `write`가 `sendFailed`로 알린다. 같은 소켓을 가리키는 호출자의 기술자에도 걸린다.
    private static func suppressSIGPIPE(_ descriptor: Int32) throws(SocketError) {
        var enabled: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw .readFailed(errnoName(errno))
        }
    }

    /// utun 제어 소켓인지 읽기 호출만으로 확인한다(계약 U1): 상대 주소의 계열이 `AF_SYSTEM`이고 인터페이스 이름이 `utun`으로 시작한다.
    /// 소켓이 아니거나(파이프) 다른 계열이면 어느 호출이든 실패하거나 계열이 다르다.
    private static func requireUTUN(_ descriptor: Int32) throws(SocketError) {
        var address = sockaddr_storage()
        var addressLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        // `getpeername`이 주소 종류에 맞는 구조체를 `sockaddr *`로만 받아서, 가장 큰 `sockaddr_storage`를 `sockaddr`로 다시 본다.
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(descriptor, $0, &addressLength) }
        }
        guard named == 0, address.ss_family == systemAddressFamily else { throw .invalidDevice("notUTUN") }

        var name = [UInt8](repeating: 0, count: Int(IFNAMSIZ))
        var nameLength = socklen_t(name.count)
        // 옵션 값을 담을 버퍼의 시작 주소와 길이를 커널에 넘긴다.
        let queried = name.withUnsafeMutableBytes {
            getsockopt(descriptor, controlProtocol, interfaceNameOption, $0.baseAddress, &nameLength)
        }
        let text = name.prefix(Int(nameLength)).prefix { $0 != 0 }
        guard queried == 0, text.starts(with: "utun".utf8) else { throw .invalidDevice("notUTUN") }
    }

    /// 읽을 것이 없을 때까지 읽어 흐름에 넣는다. 읽기 원천의 처리기 안에서만 부른다.
    ///
    /// 끝(0바이트)이나 예기치 않은 오류(`EAGAIN`·`EINTR` 밖)는 장치가 닫힌 것이므로 흐름을 오류로 끝낸다. 끝난 흐름에 다시 끝내도
    /// 아무 일이 없으므로, 처리기가 헛돌아도(커널이 계속 읽을 수 있다고 알릴 때) 소비자는 영향이 없고 `close()`가 멈춘다.
    private static func drain(
        _ descriptor: Int32,
        using buffer: inout [UInt8],
        mtu: Int,
        reader: Reader,
        into output: AsyncStream<[UInt8]>.Continuation
    ) {
        while true {
            switch readOne(descriptor, into: &buffer) {
            case .frame(let count):
                // 머리보다 짧거나 머리뿐인 것, MTU를 넘는 것은 버리고 계속 읽는다.
                if let packet = ipPacket(inFrame: buffer[..<count]), packet.count <= mtu {
                    output.yield(packet)
                }
            case .failed(EINTR):
                continue
            case .failed(EAGAIN):
                return
            case .failed(let code):
                reader.failure.withLock { $0 = .readFailed(code == 0 ? "EOF" : errnoName(code)) }
                output.finish()
                return
            }
        }
    }

    private enum Read {
        case frame(count: Int)
        /// errno. 0은 끝(읽은 바이트 0)이다.
        case failed(Int32)
    }

    private static func readOne(_ descriptor: Int32, into buffer: inout [UInt8]) -> Read {
        // 버퍼의 시작 주소와 길이를 `read(2)`에 넘긴다. 포인터는 이 호출 안에서만 산다.
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        if count < 0 { return .failed(errno) }
        return count == 0 ? .failed(0) : .frame(count: count)
    }

    /// 성공하면 nil, 실패하면 errno를 돌려준다. 패킷은 한 번에 다 가거나 아예 가지 않는다.
    private static func writeOne(_ frame: [UInt8], descriptor: Int32) -> Int32? {
        // 프레임의 시작 주소와 길이를 `write(2)`에 넘긴다. 포인터는 이 호출 안에서만 산다.
        let written = frame.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
        if written < 0 { return errno }
        return written == frame.count ? nil : EMSGSIZE
    }
}
