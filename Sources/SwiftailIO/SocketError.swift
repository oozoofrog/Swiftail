/// A socket or tunnel I/O failure.
///
/// `NetworkSocket` can include the Network framework's error description. POSIX I/O uses errno names, and utun
/// validation uses short reason names. Messages omit transmitted or received bytes and secrets.
///
/// Neither `send` nor `write` reports a separate send failure. The connection enters the failed state, which the next
/// `receive()` reports as `readFailed`.
package enum SocketError: Error, Sendable, Equatable {
    /// Connection creation failed or was canceled while connecting.
    case connectFailed(String)
    /// A read failed or was canceled. A normal close by the peer returns nil from `receive()`. Also used when interface
    /// addresses could not be read (`LocalInterfaceAddresses`), in which case the message is an errno name.
    case readFailed(String)
    /// The UDP socket could not be created or bound (`DatagramSocket.init`). The message is an errno name (for example, `EADDRINUSE`).
    case bindFailed(String)
    /// The datagram could not be sent (`DatagramSocket.send`). The message is an errno name. A closed socket produces
    /// `EBADF`, and an IPv6 destination produces `EAFNOSUPPORT`. The caller drops the datagram.
    case sendFailed(String)
    /// The supplied file descriptor cannot be used as a utun device (`UTUNDevice.init`). The message is a short reason
    /// name (`fileDescriptor` for a negative or closed descriptor number, `notUTUN` for a socket other than a utun
    /// control socket, or `mtu` for an out-of-range MTU). It omits numbers and paths.
    case invalidDevice(String)
}
