import Darwin
import Foundation

/// Confines POSIX address reinterpretation and buffer pointers to this file. The kernel API requires pointers.
/// All pointers live only within synchronous calls, and the owning actor serializes access to file descriptors.
final class LoopbackSocket {
    private var descriptor: Int32
    let port: UInt16

    init() throws {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw posixFailure("socket") }
        do {
            try makeNonblocking(fd)
            var address = loopbackAddress(port: 0)
            let result = withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
            guard result == 0 else { throw posixFailure("bind") }
            var length = socklen_t(MemoryLayout<sockaddr_in>.size)
            let named = withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
            }
            guard named == 0 else { throw posixFailure("getsockname") }
            descriptor = fd
            port = UInt16(bigEndian: address.sin_port)
        } catch {
            Darwin.close(fd)
            throw error
        }
    }

    deinit { if descriptor >= 0 { Darwin.close(descriptor) } }

    func close() {
        if descriptor >= 0 { Darwin.close(descriptor); descriptor = -1 }
    }

    func send(_ bytes: [UInt8], to port: UInt16) throws {
        var address = loopbackAddress(port: port)
        let count = bytes.withUnsafeBytes { buffer in
            withUnsafePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    sendto(descriptor, buffer.baseAddress, buffer.count, 0, $0,
                           socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }
        guard count == bytes.count else { throw posixFailure("sendto") }
    }

    func receive() throws -> (bytes: [UInt8], port: UInt16)? {
        var bytes = [UInt8](repeating: 0, count: 65_535)
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        let count = bytes.withUnsafeMutableBytes { buffer in
            withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(descriptor, buffer.baseAddress, buffer.count, 0, $0, &length)
                }
            }
        }
        if count < 0 {
            if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { return nil }
            throw posixFailure("recvfrom")
        }
        guard address.sin_addr.s_addr == in_addr_t(INADDR_LOOPBACK).bigEndian else {
            throw InteropFailure("Datagram from outside loopback")
        }
        return (Array(bytes.prefix(count)), UInt16(bigEndian: address.sin_port))
    }
}

private func loopbackAddress(port: UInt16) -> sockaddr_in {
    var address = sockaddr_in()
    address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    address.sin_family = sa_family_t(AF_INET)
    address.sin_port = port.bigEndian
    address.sin_addr = in_addr(s_addr: in_addr_t(INADDR_LOOPBACK).bigEndian)
    return address
}

func makeNonblocking(_ fd: Int32) throws {
    let flags = fcntl(fd, F_GETFL)
    guard flags >= 0, fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0 else {
        throw posixFailure("fcntl")
    }
}

/// Also reads Pipe without blocking so the Go process does not stall when its log fills the pipe.
func readAvailable(_ handle: FileHandle) throws -> Data {
    var bytes = [UInt8](repeating: 0, count: 65_536)
    let count = bytes.withUnsafeMutableBytes { Darwin.read(handle.fileDescriptor, $0.baseAddress, $0.count) }
    if count < 0 {
        if errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR { return Data() }
        throw posixFailure("read")
    }
    return Data(bytes.prefix(count))
}

func forceStop(_ process: Process) {
    if process.isRunning { _ = kill(process.processIdentifier, SIGKILL) }
}

private func posixFailure(_ operation: String) -> InteropFailure {
    InteropFailure("\(operation): errno=\(errno)")
}

/// Prevents a race between exit and a write from sending SIGPIPE to the test process.
func suppressBrokenPipe(_ fd: Int32) throws {
    guard fcntl(fd, F_SETNOSIGPIPE, 1) == 0 else { throw posixFailure("F_SETNOSIGPIPE") }
}
