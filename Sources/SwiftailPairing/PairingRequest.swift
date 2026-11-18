import Swiftail

/// An approval request for the host app (`PairingHost`'s `decide`). See contract behavior P5.
///
/// The peer has already proved knowledge of the offer secret. It might still be a different device that obtained the link first, so the approval screen
/// displays the SAS and asks the user to approve when it matches the SAS on the joining device's screen.
public struct PairingRequest: Sendable {
    /// The connected peer. The identity comes from the netmap entry for the address authenticated by WireGuard.
    public let peer: PeerIdentity
    /// The peer's **self-reported** device name. It is unverified. Nodes that joined using keys from the same OAuth client also share a login name,
    /// so names alone cannot distinguish devices.
    public let deviceName: String
    /// The 6-digit SAS. It matches the value the joiner's `awaitingApproval` receives.
    public let confirmationCode: String
}
