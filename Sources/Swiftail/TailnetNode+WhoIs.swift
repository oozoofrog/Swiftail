import Foundation
import SwiftailBase

extension TailnetNode {
    /// Looks up the node that owns this tailnet address in the current netmap. Corresponds to tsnet `LocalClient().WhoIs(addr)`.
    ///
    /// Looks up only the peer the data plane considers the address's owner (the peer with that address in its WireGuard
    /// AllowedIPs) and the local node. Skips addresses in subnet routes or on nodes not installed in the data plane,
    /// for example because their key expired. Returns nil without waiting if there is no netmap yet, no node for the
    /// address, or no netmap profile for the user who created that node.
    ///
    /// To identify a connection's peer, pass `TailnetConnection.remoteEndpoint.address`. The address belongs to the
    /// peer authenticated by WireGuard. The node ends that connection if the address's owner changes
    /// (`ConnectionError.peerRemoved`).
    ///
    /// Reads the owner from the node's owner table (`addressOwners`). The engine builds it when it installs peers, and
    /// the stack's ownership check changes at the same time to use the same table. For a live connection, the answer
    /// for its remote address therefore identifies the peer on the other end when the connection was established (behavior W6). A lookup made while the
    /// connection is live keeps that meaning. If key expiration changes an address's owner, the table changes and
    /// the connection ends together when the engine handles the expiration.
    public func whoIs(_ address: IPAddress) -> PeerIdentity? {
        lastNetmap.flatMap { PeerIdentity(address: address, owners: addressOwners, in: $0) }
    }
}
