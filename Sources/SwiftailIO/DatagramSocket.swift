import Dispatch
import Darwin
import SwiftailBase
import Synchronization

/// Wraps a UDP socket bound to the IPv4 wildcard address (0.0.0.0) with an async datagram stream and a nonblocking send queue.
///
/// WireGuard, disco, and STUN share the socket (`docs/protocol-notes/derp-stun.md` §4.10 item 2). A POSIX socket lets them
/// send to and receive from multiple peers on one port, which is why this uses POSIX over the `Network` framework
/// (`docs/plan.md` §4 (c)). The caller is the node that drives the `SwiftailMagicsock` state machine. Failures are
/// reported as `SocketError`.
///
/// Guarantees
///
/// - **Read events trigger reads.** On a `DispatchSource` read event, the socket reads until there is nothing more to
///   read (`EAGAIN`). It does not poll. Each socket allocates and reuses a single read buffer (65,535 bytes).
/// - **The socket's serial queue sends datagrams.** `enqueue(_:)` only adds to the send queue. Calls to `sendto(2)` run
///   in enqueue order on the same serial dispatch queue as the read source. The node actor does not wait for the system
///   call.
/// - **The receive and send queues each hold at most 256 datagrams and 1MiB.** On overflow, the oldest datagrams are
///   dropped first (`DatagramQueue`). A count limit alone would allow 256 × 65,535 bytes (16MiB in the worst case), so
///   total bytes are capped as well (`queuedByteLimit`). UDP already tolerates loss.
/// - **The socket closes its file descriptor exactly once and never uses it after closing.** `close()` removes the
///   descriptor from state and then cancels the read source, whose cancellation handler performs the actual `close(2)`.
///   The handler runs after reads and sends on the same serial queue have finished, leaving the descriptor open until
///   then. After `close()`, the state is empty, so neither `send` nor the remaining send queue touches the descriptor.
///   Queued items are dropped, preventing writes to a descriptor number reused elsewhere.
/// - **The socket can bind to an interface.** When given an `interfaceIndex`, it uses `IP_BOUND_IF` to send through
///   that interface. This keeps the socket inside the tunnel from routing back through the tunnel (contract behavior N
///   4). This type knows the interface only by index.
/// - **The socket suppresses SIGPIPE.** It sets `SO_NOSIGPIPE` because on Darwin, even a UDP send can produce
///   `EPIPE` and SIGPIPE.
/// - **The socket preserves structured concurrency.** The dispatch source and queue handle reads and sends without a
///   Task. Canceling the Task waiting on the stream ends `for await`. Releasing the socket (`deinit`) closes it and
///   ends the stream. The read handler does not retain `self`, so the socket can be released. The send block retains it
///   only while sending.
///
/// Socket address reinterpretation as `sockaddr` and buffer pointers stay inside `receiveOne`, `sendOne`, `bind`, and
/// `localPort` below. The kernel API requires pointers to C structs and treats `sockaddr_in` as `sockaddr`. Each
/// pointer is used only for the lifetime of one call.
///
/// - `shortcut:` Supports only IPv4. Add IPv6 and bind both sockets to the same port when M5 encounters an
///   IPv6-only network on a real device (contract “Exclusions”).
package final class DatagramSocket: Sendable {
    /// The maximum size of one read, the theoretical UDP datagram maximum (65,535). The kernel truncates anything larger.
    private static let maximumDatagramSize = 65_535
    /// The datagram count limit for each of the receive and send queues.
    private static let queuedDatagramLimit = 256
    /// The total datagram payload byte limit for each of the receive and send queues (1MiB). The oldest datagrams are
    /// dropped first on overflow.
    ///
    /// A count limit alone would allow a worst case of 65,535 bytes per datagram × 256 datagrams = 16MiB. That is one
    /// third of the reported iOS packet tunnel extension limit (about 50MiB). Three such buffers could hold about
    /// 48MiB before accounting for any other memory (`docs/contracts/SwiftailTunnel.md` behavior M). A 1MiB buffer
    /// holds about one sixteenth of the 16MiB worst case. This proposed value
    /// rests on that calculation alone. Adjust it if real-device throughput measurements show drops. A single datagram
    /// (65,535 bytes) fits, so no datagram exceeds the limit on its own.
    static let queuedByteLimit = 1 << 20

    package typealias Datagram = (bytes: [UInt8], source: IPEndpoint)
    /// A datagram to send and its destination.
    package typealias OutgoingDatagram = (bytes: [UInt8], destination: IPEndpoint)

    private struct Open {
        let descriptor: Int32
        let source: any DispatchSourceRead
        let received: DatagramQueue
        let outgoing: DatagramQueue
    }

    /// Nil after close. The descriptor and read source are accessed only inside this box, and the source's cancellation
    /// handler performs `close(2)`.
    private let state: Mutex<Open?>
    /// The serial queue shared by the read source and sends. The descriptor's `close(2)` also runs here.
    private let queue: DispatchQueue

    /// The bound port. If 0 was requested, the OS chose this value.
    package let localPort: UInt16

    /// The stream of received datagrams. It has one subscriber. If consumption falls behind, the oldest datagrams are
    /// dropped first (256 datagrams and 1MiB total). Closing or releasing the socket ends the stream. If it ends while
    /// the socket is open, an error stopped the reads. Call `close()` and open a new socket.
    package let datagrams: AsyncStream<Datagram>

    /// Binds to the IPv4 wildcard address. The OS chooses the port if `port` is 0. Reads start immediately.
    ///
    /// If given an `interfaceIndex`, binds the socket to that interface through `IP_BOUND_IF` before binding the
    /// address. The index is the number returned by `if_nametoindex` or `NWInterface.index`. Outgoing datagrams use
    /// that interface. On macOS, a socket bound to a physical interface can still send to and receive from loopback
    /// (`DatagramSocketTests`), so this multidestination socket has no loopback exception.
    ///
    /// - Throws: `SocketError.bindFailed` (errno name) if socket creation, address binding, or interface binding fails
    ///   (for example, if the index does not exist).
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

    /// Sends one datagram immediately without waiting. The node uses `enqueue(_:)`.
    ///
    /// - Throws: `SocketError.sendFailed` (errno name). A closed socket returns `EBADF`, an IPv6 destination returns
    ///   `EAFNOSUPPORT`, and a full kernel send buffer returns `EAGAIN`. The caller drops the datagram. It also goes
    ///   out over DERP or is sent again.
    package func send(_ bytes: [UInt8], to destination: IPEndpoint) throws(SocketError) {
        guard destination.address.isIPv4 else { throw .sendFailed(errnoName(EAFNOSUPPORT)) }
        // Hold the lock during the send so `close()` cannot intervene. The send is nonblocking, so it finishes quickly.
        let failure: Int32? = state.withLock { state in
            guard let state else { return EBADF }
            return Self.sendOne(bytes, to: destination, descriptor: state.descriptor)
        }
        if let failure { throw .sendFailed(errnoName(failure)) }
    }

    /// Enqueues datagrams for sending without waiting. The socket's serial queue sends them in enqueue order.
    ///
    /// If pending datagrams exceed 256 or 1MiB total, drops the oldest first. Drops them if the socket is closed. A
    /// send failure (IPv6 destination, `EAGAIN`, `EHOSTUNREACH`, and so on) drops that datagram. It also goes out over
    /// DERP or WireGuard or disco sends it again. Payloads too large for one UDP datagram (over 65,535 bytes) are never
    /// enqueued, so no single item can exceed the byte limit.
    package func enqueue(_ datagrams: [OutgoingDatagram]) {
        guard let outgoing = state.withLock({ $0?.outgoing }) else { return }
        let envelopes = datagrams.compactMap { datagram in
            datagram.bytes.count <= Self.maximumDatagramSize ? Envelope(bytes: datagram.bytes, endpoint: datagram.destination) : nil
        }
        // Schedule a send only when adding to an empty queue. A nonempty queue still has a scheduled send that has yet to drain it.
        guard outgoing.append(contentsOf: envelopes) else { return }
        queue.async {
            self.sendQueued()
        }
    }

    /// Takes all buffered incoming datagrams without waiting. Returns an empty array if there are none or the socket is closed.
    ///
    /// Call this after receiving one datagram from `datagrams` to process those accumulated in the meantime as one
    /// group. The group stays within the receive queue's limits (256 datagrams, 1MiB). Only the same subscriber may
    /// call it because it takes from the same queue as `datagrams`.
    package func takeQueuedDatagrams() -> [Datagram] {
        (state.withLock { $0?.received }?.takeAll() ?? []).map { ($0.bytes, $0.endpoint) }
    }

    /// Closes the socket, ending the stream and stopping reads. Drops pending outgoing datagrams. May be called more than once.
    package func close() {
        let opened = state.withLock { state in
            defer { state = nil }
            return state
        }
        opened?.received.finish()
        opened?.outgoing.finish()
        opened?.source.cancel()
    }

    /// Sends queued datagrams and then closes the socket. Returns without waiting. Sending and closing run in that order on the serial queue.
    ///
    /// The node uses this when stopping so that RSTs from its final processing (netstack contract behavior N8) go out
    /// over the direct path. Other closures (rebinding) use `close()`, which drops what is left.
    package func closeAfterSending() {
        queue.async {
            self.sendQueued()
            self.close()
        }
    }

    /// Sends everything in the send queue. Runs only on the serial queue.
    ///
    /// The descriptor's `close(2)` runs only in the cancellation handler on the same serial queue, so the descriptor
    /// stays open while this block runs. The block still checks the state for each send and drops anything left if
    /// `close()` has been called.
    private func sendQueued() {
        guard let opened = state.withLock({ $0 }) else { return }
        for datagram in opened.outgoing.takeAll() {
            guard state.withLock({ $0 != nil }) else { return }
            guard datagram.endpoint.address.isIPv4 else { continue }
            _ = Self.sendOne(datagram.bytes, to: datagram.endpoint, descriptor: opened.descriptor)
        }
    }

    // MARK: POSIX Edge

    /// Makes the socket nonblocking, binds it to the interface if provided, binds it to the wildcard address, and
    /// returns the port assigned by the OS. Returns the errno name on failure. Bind the interface before `bind(2)`.
    /// Applying the option afterward leaves the already-selected local address in place.
    private static func prepare(
        _ descriptor: Int32, port: UInt16, interfaceIndex: UInt32?
    ) -> (port: UInt16?, error: String) {
        let flags = fcntl(descriptor, F_GETFL)
        guard flags >= 0, fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) >= 0 else {
            return (nil, errnoName(errno))
        }
        // On Darwin, even UDP `sendto` can fail with `EPIPE`, as observed when sending to a LAN address at the M4 gate.
        // Go also handles `EPIPE` on UDP sends (`net/neterror/neterror_unix.go`). The kernel then sends SIGPIPE, whose
        // default action terminates the process, so disable it. The send then returns `sendFailed("EPIPE")`.
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
        // Reinterpret `sockaddr_in` as `sockaddr`. bind(2) and getsockname(2) take the address-family-specific struct only as `sockaddr *`.
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

    /// Reads until there is nothing more to read, adding datagrams to the receive queue. Called only in the read source's handler.
    ///
    /// An unexpected error (anything other than `EAGAIN` or `EINTR`) ends the stream. The read source cannot stop here
    /// because stopping requires closing the descriptor, which `close()` handles along with the state. The observer of
    /// the stream's end must call `close()`. The node then opens a new socket.
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

    /// The read buffer for one socket. Reuse it to avoid allocating and zeroing 65,535 bytes per read event. Only the
    /// read source's handler on the serial queue uses it, so there is no lock contention. A class wraps it so the
    /// handler can retain it.
    private final class ReadBuffer: Sendable {
        let bytes = Mutex([UInt8](repeating: 0, count: DatagramSocket.maximumDatagramSize))
    }

    /// A datagram and the peer address, either its source on receipt or its destination on send.
    private struct Envelope {
        var bytes: [UInt8]
        var endpoint: IPEndpoint
    }

    /// A shared datagram queue implementation for receiving and sending. The consumer pulls received datagrams one at a
    /// time with `next()` or all at once with `takeAll()`. The serial queue takes outgoing datagrams with `takeAll()`
    /// and sends them.
    ///
    /// Keeps up to the newest `queuedDatagramLimit` datagrams and `queuedByteLimit` total payload bytes, dropping the
    /// oldest first on overflow. `AsyncStream`'s `bufferingNewest` limits only the count, so the buffer lives here and
    /// the consumer pulls via `AsyncStream(unfolding:)`. This follows `DERPClient.EventQueue`'s design. The two targets
    /// are independent, so each has its own. At most one consumer waits. Removing from the front is O(1) (`Ring`).
    private final class DatagramQueue: Sendable {
        private struct State {
            var datagrams = Ring()
            /// The consumer waiting for a datagram.
            var waiter: CheckedContinuation<Envelope?, Never>?
            var isFinished = false
        }

        /// Holds datagrams within the limits in enqueue order. Leaves vacated slots empty and compacts them together
        /// once they occupy more than half.
        private struct Ring {
            private var slots: [Envelope?] = []
            private var head = 0
            /// The total payload bytes of the queued datagrams.
            private(set) var bytes = 0

            var isEmpty: Bool { head == slots.count }
            var count: Int { slots.count - head }

            /// Appends a datagram and drops the oldest first if this exceeds a limit. One datagram is smaller than the
            /// byte limit, so the appended datagram stays.
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

        /// Enqueues one datagram. Hands it directly to a waiting consumer. Drops it after `finish()`.
        func push(_ datagram: Envelope) {
            let waiter: CheckedContinuation<Envelope?, Never>? = state.withLock { state in
                guard !state.isFinished else { return nil }
                // The queue is empty if a consumer is waiting.
                if let waiter = state.waiter.take() { return waiter }
                state.datagrams.append(datagram)
                return nil
            }
            waiter?.resume(returning: datagram)
        }

        /// Enqueues multiple datagrams in the send queue. Returns true if the queue was empty and the consumer needs to
        /// be called. After `finish()`, drops them and returns false.
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

        /// Takes everything queued.
        func takeAll() -> [Envelope] {
            state.withLock { $0.datagrams.removeAll() }
        }

        /// Prevents further enqueues. The receive stream ends after the remaining datagrams are read.
        func finish() {
            let waiter = state.withLock { state in
                state.isFinished = true
                return state.waiter.take()
            }
            waiter?.resume(returning: nil)
        }

        /// Returns the next datagram, waiting for one if needed. Returns nil if finished or if the consumer's Task is canceled.
        func next() async -> Envelope? {
            await withTaskCancellationHandler {
                await withCheckedContinuation { (continuation: CheckedContinuation<Envelope?, Never>) in
                    let ready: Envelope?? = state.withLock { state in
                        if let datagram = state.datagrams.popFirst() { return .some(datagram) }
                        // If already canceled, the cancellation handler ran first, so do not wait. A second subscriber
                        // must also return without waiting.
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
        /// A non-IPv4 source. This cannot occur with an IPv4 socket, but an address that cannot be parsed is dropped and reading continues.
        case ignored
        case failed(Int32)
    }

    private static func receiveOne(_ descriptor: Int32, into buffer: inout [UInt8]) -> Received {
        var address = sockaddr_in()
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        // Reinterpret the received address as `sockaddr *` to receive it in `sockaddr_in`. Both pointers live only within this call.
        let count = buffer.withUnsafeMutableBytes { bytes in
            withUnsafeMutablePointer(to: &address) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                    recvfrom(descriptor, bytes.baseAddress, bytes.count, 0, $0, &length)
                }
            }
        }
        guard count >= 0 else { return .failed(errno) }
        // `s_addr` is in network byte order. Convert to host order, then extract the high byte first.
        let host = UInt32(bigEndian: address.sin_addr.s_addr)
        guard address.sin_family == sa_family_t(AF_INET),
              let ip = IPAddress(bytes: (0..<4).map { UInt8(truncatingIfNeeded: host >> UInt32(24 - 8 * $0)) })
        else { return .ignored }
        return .datagram(count: count, source: IPEndpoint(address: ip, port: UInt16(bigEndian: address.sin_port)))
    }

    /// Returns nil on success and errno on failure. A datagram is sent in full or not at all.
    private static func sendOne(_ bytes: [UInt8], to destination: IPEndpoint, descriptor: Int32) -> Int32? {
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = destination.port.bigEndian
        // Assemble the 4 address bytes into a host integer, high byte first, then convert to network byte order and store in `s_addr`.
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

/// The errno name. Error messages contain only this name and omit addresses and bytes.
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
