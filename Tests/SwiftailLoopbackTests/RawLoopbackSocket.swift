// A POSIX TCP socket that simulates another process on the same device. Binds to a chosen source port (`SO_REUSEADDR`) and connects to a loopback
// listener. The pointer that views `sockaddr_in` as `sockaddr` lives only inside `withSocketAddress` (the kernel API only accepts that form).

import Darwin

/// One POSIX TCP socket used by the test. Dropping it closes it.
final class RawLoopbackSocket: Sendable {
    struct Failure: Error, CustomStringConvertible {
        var call: String
        var code: Int32
        var description: String { "\(call): \(String(cString: strerror(code)))" }
    }

    private let descriptor: Int32

    /// A socket bound to `127.0.0.1:<sourcePort>`. If `sourcePort` is 0, the system chooses it. Does not connect.
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

    /// The bound source port.
    var localPort: UInt16 {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
        }
        return named == 0 ? UInt16(bigEndian: address.sin_port) : 0
    }

    /// Connects to `127.0.0.1:<port>` (blocking).
    func connect(to port: UInt16) throws(Failure) {
        let connected = Self.withSocketAddress(port: port) { Darwin.connect(descriptor, $0, $1) }
        guard connected == 0 else { throw Failure(call: "connect", code: errno) }
    }

    /// Sends all bytes (blocking). Throws if the peer already disconnected.
    func send(_ bytes: [UInt8]) throws(Failure) {
        var offset = 0
        while offset < bytes.count {
            let sent = bytes[offset...].withUnsafeBytes { Darwin.send(descriptor, $0.baseAddress, $0.count, 0) }
            guard sent > 0 else { throw Failure(call: "send", code: errno) }
            offset += sent
        }
    }

    /// Waits up to `seconds` seconds for the peer to end the connection (blocking). Returns true on EOF (FIN) or RST, and false if the connection stays open until then.
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

    /// Closes the write direction (FIN).
    func finishWriting() {
        _ = shutdown(descriptor, SHUT_WR)
    }

    /// Passes the `sockaddr_in` for `127.0.0.1:<port>` as `sockaddr *`.
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
