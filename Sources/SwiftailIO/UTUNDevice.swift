// The 4-byte protocol header (skipped on read and set to `AF_INET` or `AF_INET6` by IP version on write) and utun
// control socket name check (`getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)`) follow `Name`, `Read`, and `Write` in
// wireguard-go `tun/tun_darwin.go`. Only the behavior was reproduced. wireguard-go uses the MIT license (Copyright (C)
// 2017-2023 WireGuard LLC).

import Darwin
import Dispatch
import Synchronization

/// Wraps a utun file descriptor supplied by a packet tunnel provider with a stream of IP packets and a write operation
/// (`docs/contracts/SwiftailTunnel.md` behavior U).
///
/// The node reads IP packets the OS sends to the tunnel and forwards them to the tailnet, and injects packets from the
/// tailnet into the OS. The app's Network Extension creates utun and configures the interface.
///
/// Guarantees
///
/// - **Uses a duplicate of the supplied descriptor.** Duplicates it with `F_DUPFD_CLOEXEC` and sets `O_NONBLOCK` on the
///   duplicate. This object closes only the duplicate. It neither reads nor closes the caller's descriptor.
///   `O_NONBLOCK` also applies to the caller's descriptor because it shares the open file description, but the app does
///   not read or write with it (contract U2).
/// - **Verifies that the descriptor is utun.** The socket address family must be `AF_SYSTEM` and the name from
///   `UTUN_OPT_IFNAME` must start with `utun`. The checks use only read calls on the duplicate, leaving the caller's
///   descriptor unchanged on rejection (contract U1).
/// - **Each packet has a 4-byte header.** On read, strip the header and pass up only the IP packet. Drop reads of 4
///   bytes or fewer (no IP packet) and ignore the header value. On write, put `AF_INET` in the header for IP version
///   nibble 4 and `AF_INET6` for 6. Skip all other versions (contract U3).
/// - **Read events trigger reads.** On a `DispatchSource` read event, read until there is nothing left to read
///   (`EAGAIN`). One `read` returns one packet. Reuse one read buffer (4 + 65,535 bytes) and copy only the bytes read
///   (contract U4).
/// - **The buffer is bounded.** If the consumer falls behind, drop the oldest packets to keep at most 256. Drop any
///   packet exceeding the device's MTU. The OS does not put packets exceeding the configured MTU into utun, so this
///   guards against invalid input and keeps buffered bytes within 256 × 1,420 bytes (under 1MiB) (contract M).
/// - **Reports why reads ended.** A 0-byte read (end of file) or an error other than `EAGAIN` or `EINTR` means the
///   device closed. The stream ends and `readFailure` becomes `SocketError.readFailed` (errno name, or `EOF` at end of
///   file). `readFailure` is nil when the stream ends through `close()` or release (contract U4). Because
///   `AsyncThrowingStream` accepts only `any Error` as its error type, the stream itself does not throw and the reason
///   is kept separately.
/// - **Writes neither wait nor queue.** Reports failed packets as `SocketError.sendFailed` and the caller drops them. A
///   write failure does not mean that the device has closed. Reads report when the device ends (contract U5).
/// - **Closes the descriptor exactly once.** A read failure or `close()` detaches the descriptor from the state, ends
///   the stream, and cancels the read source. The actual `close(2)` runs in the cancellation handler after the read
///   handler finishes. After close, the empty state prevents `write` from touching the descriptor, including a
///   descriptor number reused elsewhere. Release (`deinit`) closes it. This matches `DatagramSocket`.
/// - **Preserves structured concurrency.** The dispatch source handles reads without a Task. Canceling the Task waiting
///   on the stream ends `for await`.
///
/// System calls and address and string buffer pointers stay within the POSIX edge below (`duplicate`, `requireUTUN`,
/// `readOne`, `writeOne`). The kernel API requires pointers and needs `sockaddr_storage` reinterpreted as `sockaddr`.
/// Each pointer is used only for the lifetime of one call.
package final class UTUNDevice: Sendable {
    /// The supported MTU range. The lower bound comes from the first adopter's test contract. The upper bound is
    /// wireguard-go's default (`DefaultMTU` of 1420 in `device/tun.go`).
    package static let supportedMTU = 1280...1420

    /// The size of the protocol header utun prepends to each packet.
    private static let headerLength = 4
    /// The theoretical maximum length of an IP packet (the total length field is 16 bits).
    private static let maximumPacketLength = 65_535
    /// The number of unread packets that can be buffered.
    private static let bufferedPacketCount = 256

    // Darwin socket address families and options. This SDK module includes `AF_SYSTEM`. The control socket options are
    // macros in `<sys/sys_domain.h>` and `<net/if_utun.h>` that Swift does not import, so specify their values directly
    // (wireguard-go's `Name()` also uses numbers).
    private static let systemAddressFamily = sa_family_t(32)  // AF_SYSTEM
    private static let controlProtocol: Int32 = 2  // SYSPROTO_CONTROL
    private static let interfaceNameOption: Int32 = 2  // UTUN_OPT_IFNAME

    private struct Open {
        let descriptor: Int32
        let source: any DispatchSourceRead
        let continuation: AsyncStream<[UInt8]>.Continuation
    }

    /// State retained by the read handler, which reuses the read buffer. Only one handler runs at a time on the serial
    /// queue, but a `Sendable` closure cannot capture a mutable value, so wrap it in an uncontended lock. Record the
    /// reason reads ended before ending the stream.
    private final class Reader: Sendable {
        let buffer = Mutex([UInt8](repeating: 0, count: UTUNDevice.headerLength + UTUNDevice.maximumPacketLength))
        let failure = Mutex<SocketError?>(nil)
    }

    /// Nil after close. The descriptor and read source are accessed only inside this box, and the source's cancellation
    /// handler performs `close(2)`.
    private let state: Mutex<Open?>

    /// The value the app applies through `NEPacketTunnelNetworkSettings.mtu`. The node uses it unchanged when generating settings.
    package let mtu: Int

    private let reader: Reader

    /// The stream of IP packets sent by the OS to the tunnel, with headers removed. It has one subscriber. If
    /// consumption falls behind, drops the oldest packets first (256 packets). Ends on `close()`, release, or when the
    /// device can no longer be read. `readFailure` gives the reason.
    package let packets: AsyncStream<[UInt8]>

    /// The reason reads stopped if the device ended or an error occurred (`SocketError.readFailed`, with an errno name
    /// or `EOF`). Read this after the stream ends. It is nil if the stream ended through `close()` or release, or if it
    /// has not ended. The node reports this as `tunnelDeviceClosed`.
    package var readFailure: SocketError? {
        reader.failure.withLock { $0 }
    }

    /// Verifies that `descriptor` is a utun control socket, duplicates it, and starts reading.
    ///
    /// - Parameters: - descriptor: The utun file descriptor found by the packet tunnel provider. This initializer
    ///   leaves it open. - mtu: The MTU the app applies. Must be within `supportedMTU`.
    /// - Throws: `SocketError.invalidDevice` if the descriptor is not utun, is closed or negative, or the MTU is out of
    ///   range. Throws `SocketError.readFailed` (errno name) if duplication fails.
    package convenience init(duplicating descriptor: Int32, mtu: Int) throws(SocketError) {
        try self.init(duplicating: descriptor, mtu: mtu) { (copy) throws(SocketError) in try Self.requireUTUN(copy) }
    }

    /// Checks the duplicate using `verify`, then starts reading. Tests substitute the check to use `socketpair` in
    /// place of utun. Tests use `onReadEvent` to count read handler calls.
    init(
        duplicating descriptor: Int32,
        mtu: Int,
        onReadEvent: (@Sendable () -> Void)? = nil,
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
        state = Mutex(Open(descriptor: copy, source: source, continuation: output))
        source.setEventHandler { [weak self] in
            onReadEvent?()
            let failure = reader.buffer.withLock { Self.drain(copy, using: &$0, mtu: mtu, into: output) }
            if let failure { self?.close(readFailure: failure) }
        }
        source.setCancelHandler {
            Darwin.close(copy)
        }
        source.activate()
    }

    deinit {
        close()
    }

    /// Writes one IP packet to the device without waiting.
    ///
    /// - Throws: `SocketError.sendFailed` (errno name). IP versions other than 4 or 6 yield `EAFNOSUPPORT` without
    ///   writing. A closed device yields `EBADF`. If the kernel cannot accept the packet, it yields `EAGAIN`,
    ///   `ENOBUFS`, `EMSGSIZE`, or another errno. The caller drops the packet and continues.
    package func write(_ ipPacket: [UInt8]) throws(SocketError) {
        guard let frame = Self.frame(ipPacket) else { throw .sendFailed(errnoName(EAFNOSUPPORT)) }
        // Hold the lock during the write so `close()` cannot intervene. The write is nonblocking, so it finishes quickly.
        let failure: Int32? = state.withLock { state in
            guard let state else { return EBADF }
            return Self.writeOne(frame, descriptor: state.descriptor)
        }
        if let failure { throw .sendFailed(errnoName(failure)) }
    }

    /// Closes the duplicate, ending the stream without error and stopping reads. May be called multiple times. Leaves
    /// the caller's descriptor open.
    package func close() {
        close(readFailure: nil)
    }

    private func close(readFailure: SocketError?) {
        let opened = state.withLock { state -> Open? in
            guard let opened = state else { return nil }
            // The first close determines the stream's termination reason.
            if let readFailure { reader.failure.withLock { $0 = readFailure } }
            state = nil
            return opened
        }
        opened?.continuation.finish()
        opened?.source.cancel()
    }

    /// The duplicate's file descriptor number, or nil if closed. Used only by tests to check its properties (`FD_CLOEXEC`, closure).
    var duplicateDescriptor: Int32? {
        state.withLock { $0?.descriptor }
    }

    // MARK: Header Insertion and Removal (Pure Functions Without I/O)

    /// Prepends the protocol header to the IP packet. Uses `00 00 00 02` (`AF_INET`) for IP version 4 and `00 00 00 1e`
    /// (`AF_INET6`) for 6. Returns nil for empty packets or other versions. The version is the first byte's high
    /// nibble. The kernel and engine handle remaining validation, such as header length.
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

    /// Strips the header from a received frame and returns the IP packet. Ignores the header value. Returns nil to
    /// discard frames that contain only the header or are shorter than it.
    static func ipPacket(inFrame frame: ArraySlice<UInt8>) -> [UInt8]? {
        guard frame.count > headerLength else { return nil }
        return Array(frame.dropFirst(headerLength))
    }

    // MARK: POSIX Edge

    /// Duplicates with `F_DUPFD_CLOEXEC`. A closed descriptor number yields `invalidDevice`. Other failures (such as
    /// `EMFILE`) yield `readFailed`.
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

    /// Prevent SIGPIPE on writes to a disconnected socket. The default signal action terminates the process, and this
    /// code runs in the packet tunnel extension. With this option, those writes return `EPIPE` and `write` reports
    /// `sendFailed`. The option also applies to the caller's descriptor, which points to the same socket.
    private static func suppressSIGPIPE(_ descriptor: Int32) throws(SocketError) {
        var enabled: Int32 = 1
        guard setsockopt(descriptor, SOL_SOCKET, SO_NOSIGPIPE, &enabled, socklen_t(MemoryLayout<Int32>.size)) == 0 else {
            throw .readFailed(errnoName(errno))
        }
    }

    /// Returns the interface name (such as `utun3`) if `descriptor` is a utun control socket. Uses only read calls and does not duplicate it.
    ///
    /// The node uses this to validate the device in `init` without creating files or sockets, and to filter out its own
    /// utun in default interface notifications (contract U1, N1).
    ///
    /// - Throws: `SocketError.invalidDevice` for a negative or closed descriptor or a descriptor that is not utun.
    package static func interfaceName(ofUTUN descriptor: Int32) throws(SocketError) -> String {
        guard descriptor >= 0 else { throw .invalidDevice("fileDescriptor") }
        return try requireUTUN(descriptor)
    }

    /// Verifies a utun control socket using only read calls and returns its interface name (contract U1). The peer
    /// address family must be `AF_SYSTEM` and the interface name must start with `utun`. For a non-socket (such as a
    /// pipe) or another address family, a call fails or the family differs.
    @discardableResult
    private static func requireUTUN(_ descriptor: Int32) throws(SocketError) -> String {
        var address = sockaddr_storage()
        var addressLength = socklen_t(MemoryLayout<sockaddr_storage>.size)
        // `getpeername` accepts the address-family-specific struct only as `sockaddr *`, so reinterpret the largest
        // struct, `sockaddr_storage`, as `sockaddr`.
        let named = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getpeername(descriptor, $0, &addressLength) }
        }
        guard named == 0, address.ss_family == systemAddressFamily else { throw .invalidDevice("notUTUN") }

        var name = [UInt8](repeating: 0, count: Int(IFNAMSIZ))
        var nameLength = socklen_t(name.count)
        // Pass the base address and length of the option value buffer to the kernel.
        let queried = name.withUnsafeMutableBytes {
            getsockopt(descriptor, controlProtocol, interfaceNameOption, $0.baseAddress, &nameLength)
        }
        let text = name.prefix(Int(nameLength)).prefix { $0 != 0 }
        guard queried == 0, text.starts(with: "utun".utf8) else { throw .invalidDevice("notUTUN") }
        return String(decoding: text, as: UTF8.self)
    }

    /// Reads until there is nothing left and adds packets to the stream. Called only from the read source's handler.
    ///
    /// Returns end of file (0 bytes) or an unexpected error (anything other than `EAGAIN` or `EINTR`) so the handler
    /// can cancel the read source. This prevents continuing read events after EOF.
    private static func drain(
        _ descriptor: Int32,
        using buffer: inout [UInt8],
        mtu: Int,
        into output: AsyncStream<[UInt8]>.Continuation
    ) -> SocketError? {
        while true {
            switch readOne(descriptor, into: &buffer) {
            case .frame(let count):
                // Drop packets shorter than or equal to the header or exceeding the MTU, then keep reading.
                if let packet = ipPacket(inFrame: buffer[..<count]), packet.count <= mtu {
                    output.yield(packet)
                }
            case .failed(EINTR):
                continue
            case .failed(EAGAIN):
                return nil
            case .failed(let code):
                return .readFailed(code == 0 ? "EOF" : errnoName(code))
            }
        }
    }

    private enum Read {
        case frame(count: Int)
        /// The errno value. 0 means end of file (0 bytes read).
        case failed(Int32)
    }

    private static func readOne(_ descriptor: Int32, into buffer: inout [UInt8]) -> Read {
        // Pass the buffer's base address and length to `read(2)`. The pointer lives only within this call.
        let count = buffer.withUnsafeMutableBytes { Darwin.read(descriptor, $0.baseAddress, $0.count) }
        if count < 0 { return .failed(errno) }
        return count == 0 ? .failed(0) : .frame(count: count)
    }

    /// Returns nil on success or errno on failure. A packet is written in full or not at all.
    private static func writeOne(_ frame: [UInt8], descriptor: Int32) -> Int32? {
        // Pass the frame's base address and length to `write(2)`. The pointer lives only within this call.
        let written = frame.withUnsafeBytes { Darwin.write(descriptor, $0.baseAddress, $0.count) }
        if written < 0 { return errno }
        return written == frame.count ? nil : EMSGSIZE
    }
}
