import Foundation
import Swiftail

/// One peer paired with the host (contract behavior S1).
///
/// The key is `peer.stableID`. `StableID` alone determines whether later connections belong to the paired peer. Names are display-only snapshots from
/// pairing and do not follow later changes. Removing and reregistering a node changes its `StableID`, so it is no longer paired.
public struct PairedPeer: Sendable, Equatable {
    /// The identity at pairing time.
    public let peer: PeerIdentity
    /// The peer's self-reported device name.
    public let deviceName: String
    /// The pairing time.
    public let pairedAt: Date
}
