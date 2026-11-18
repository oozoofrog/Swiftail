import Foundation
import SwiftailBase
import SwiftailControl

extension EnginePeer {
    /// Maps data-plane addresses to the nodes that own them. The owner of an address is the peer with that address's single-host prefix (/32 or /128) in AllowedIPs.
    ///
    /// WireGuard checks a packet's source address against the sending peer's AllowedIPs, so the node in this table is the remote end of a connection
    /// from that address. Built by the same computation the engine uses to install peers (`eligibleNodes(in:at:)`). It omits addresses of nodes outside the data plane
    /// (expired or unsupported peers). If several nodes claim the same address, it includes only the node the engine assigned that address to (the lower node ID).
    /// It omits the local node's addresses.
    ///
    /// The node uses this table to verify connection address owners (`SwiftailNetstack` contract behavior X10), enforce per-peer limits, and answer `whoIs`. Different tables for these operations
    /// could cause the app to see another node's identity for the remote end of a connection. When an engine is present, use the table built alongside peer installation
    /// (`TailnetEngine.addressOwners`). Without an engine, this function runs the same computation directly on the netmap.
    ///
    /// - Parameter now: The current time (local wall clock) for checking key expiration.
    package static func addressOwners(in netmap: Netmap, at now: Date) -> [IPAddress: Node] {
        addressOwners(of: eligibleNodes(in: netmap, at: now))
    }

    /// Maps addresses of peers to install (`eligibleNodes(in:at:)`) to their owner nodes.
    static func addressOwners(of eligible: [(node: Node, peer: EnginePeer)]) -> [IPAddress: Node] {
        var owners: [IPAddress: Node] = [:]
        for (node, peer) in eligible {
            for prefix in peer.allowedIPs where isSingleAddress(prefix) {
                owners[prefix.address] = node
            }
        }
        return owners
    }
}
