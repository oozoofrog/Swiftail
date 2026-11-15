// 같은 기기의 다른 프로세스가 하는 것을 흉내 내는 POSIX TCP 소켓. 원하는 출발 포트에 묶어(`SO_REUSEADDR`) 루프백
// 리스너에 건다. `sockaddr_in`을 `sockaddr`로 다시 보는 포인터는 `withSocketAddress` 안에서만 산다(커널 API가 그것만 받는다).

import Darwin

/// 시험이 쓰는 POSIX TCP 소켓 하나. 버리면 닫힌다.
final class RawLoopbackSocket: Sendable {
    struct Failure: Error, CustomStringConvertible {
        var call: String
        var code: Int32
        var description: String { "\(call): \(String(cString: strerror(code)))" }
    }

    private let descriptor: Int32

    /// `127.0.0.1:<sourcePort>`에 묶은 소켓. `sourcePort`가 0이면 시스템이 고른다. 걸지는 않는다.
    init(boundTo sourcePort: UInt16, reuseAddress: Bool) throws(Failure) {
        let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else { throw Failure(call: "socket", code: errno) }
        self.descriptor = descriptor
        var one: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw Failure(call: "setsockopt(SO_NOSIGPIPE)", code: errno)
        }
        if reuseAddress {
            guard setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
                throw Failure(call: "setsockopt(SO_REUSEADDR)", code: errno)
            }
        }
        let bound = Self.withSocketAddress(port: sourcePort) { Darwin.bind(descriptor, $0, $1) }
        guard bound == 0 else { throw Failure(call: "bind", code: errno) }
    }

    deinit {
        Darwin.close(descriptor)
    }

    /// 묶인 출발 포트.
    var localPort: UInt16 {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
        }
        return named == 0 ? UInt16(bigEndian: address.sin_port) : 0
    }

    /// `127.0.0.1:<port>`에 건다(막는 호출).
    func connect(to port: UInt16) throws(Failure) {
        let connected = Self.withSocketAddress(port: port) { Darwin.connect(descriptor, $0, $1) }
        guard connected == 0 else { throw Failure(call: "connect", code: errno) }
    }

    /// 모두 보낸다(막는 호출). 상대가 이미 끊었으면 던진다.
    func send(_ bytes: [UInt8]) throws(Failure) {
        var offset = 0
        while offset < bytes.count {
            let sent = bytes[offset...].withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, $0.count, 0) }
            guard sent > 0 else { throw Failure(call: "send", code: errno) }
            offset += sent
        }
    }

    /// 상대가 연결을 끝내기를 `seconds`초까지 기다린다(막는 호출). 끝(FIN)이나 RST를 보면 true, 그때까지 열려 있으면 false다.
    func seesEnd(within seconds: Int) -> Bool {
        var limit = timeval(tv_sec: seconds, tv_usec: 0)
        guard setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &limit, socklen_t(MemoryLayout<timeval>.size)) == 0 else { return false }
        var byte: UInt8 = 0
        while true {
            let received = recv(descriptor, &byte, 1, 0)
            if received > 0 { continue }
            return received == 0 || errno != EAGAIN
        }
    }

    /// 쓰기 방향을 닫는다(FIN).
    func finishWriting() {
        _ = shutdown(descriptor, SHUT_WR)
    }

    /// `127.0.0.1:<port>`의 `sockaddr_in`을 `sockaddr *`로 넘긴다.
    private static func withSocketAddress(port: UInt16, _ body: (UnsafePointer<sockaddr>, socklen_t) -> Int32) -> Int32 {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: UInt32(0x7F00_0001).bigEndian)
        return withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { body($0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
    }
}
