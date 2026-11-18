import SwiftailIO

/// The device through which the node sends and receives IP packets (`docs/contracts/SwiftailTunnel.md` behavior U,
/// `docs/contracts/SwiftailNetstack.md` behavior N).
///
/// All devices use the same processing. Packets read from the device go through engine sending (local replies or
/// sending to the tailnet). The engine's device-bound packets (from peers, MagicDNS replies, and so on) are written to
/// the device. With `.inProcess`, the in-process TCP stack is the device.
public enum TunnelDevice: Sendable {
    /// A utun control socket created by a Network Extension. The node duplicates the descriptor in `run()` and neither
    /// closes nor reads the original. `TailnetNode.init` verifies that it is utun through read-only system calls.
    ///
    /// - Parameter mtu: The value the app applies with `NEPacketTunnelNetworkSettings.mtu`. 1280…1420. The node leaves
    ///   the utun MTU in place and returns this value as `TunnelNetworkSettings.mtu`. Larger packets are dropped on
    ///   read.
    case utun(fileDescriptor: Int32, mtu: Int = 1280)
    /// An in-memory device. Write through `TailnetNode.send(_:)` and receive through `TailnetNode.inboundPackets`. Used
    /// for tests and gates, with the same processing as utun.
    case memory(mtu: Int = 1280)
    /// An in-process TCP stack. Receives packets peers send to the node's addresses and sends its own packets to the
    /// tailnet. Only this device supports `TailnetNode.listen(port:)` and `TailnetNode.connect(to:port:)`. MTU is fixed
    /// at 1280.
    ///
    /// `TailnetNode.inboundPackets` emits nothing and `TailnetNode.send(_:)` drops its input. `networkSettings` is
    /// emitted as for other devices, though the app has nothing to apply to the OS. The stack drops ICMP and UDP.
    case inProcess

    /// The MTU the app applies.
    var mtu: Int {
        switch self {
        case let .utun(_, mtu), let .memory(mtu): mtu
        // The tailnet MTU (contract M6 decision D9). The stack derives its MSS from this value.
        case .inProcess: 1280
        }
    }

    /// Validates the device. Returns its interface name (such as `utun3`) for utun, or nil for an in-memory or `.inProcess` device.
    ///
    /// Creates no files or sockets. The utun check uses only `getpeername` and `getsockopt` (behavior U1).
    func validate() throws(NodeError) -> String? {
        guard UTUNDevice.supportedMTU.contains(mtu) else {
            throw .invalidConfiguration("MTU must be \(UTUNDevice.supportedMTU.lowerBound)…\(UTUNDevice.supportedMTU.upperBound)")
        }
        guard case let .utun(descriptor, _) = self else { return nil }
        do {
            return try UTUNDevice.interfaceName(ofUTUN: descriptor)
        } catch {
            throw .invalidConfiguration("Not a utun descriptor")
        }
    }
}
