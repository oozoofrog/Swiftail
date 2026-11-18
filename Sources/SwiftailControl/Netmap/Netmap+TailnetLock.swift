import SwiftailTKA

/// Filters a netmap using tailnet lock, without I/O. `ControlClient` decides which filtering method to use.
///
/// Filters each received netmap in full (there is no separate delta path). Matches Go's decisions on a full netmap.
/// Contract `docs/contracts/SwiftailTailnetLock.md` behavior P, `docs/protocol-notes/tailnet-lock.md` §4.9
/// (origin: `tkaFilterNetmapLocked` in tailscale.com `ipn/ipnlocal/tailnet-lock.go`, BSD-3-Clause).
extension Netmap {
    /// Returns the netmap filtered using verified signing authority state (`.enforcing`).
    ///
    /// Removes peers with absent or unverified signatures and peers with keys superseded by rotation, preserving order. `UnsignedPeerAPIOnly` peers skip signature checks
    /// yet are removed if their keys are stale. The self node is retained. If its signature fails verification (locked out), populates `signingRequest` with
    /// the two values to pass to the signing device.
    ///
    /// - Parameter lockKey: This node's tailnet lock public key, used as the `tlpub:` value in the signing request.
    func filtered(by authority: Authority, lockKey: NLPublicKey) -> Netmap {
        // shortcut: verifies unchanged peer signatures again for each netmap (at least one Ed25519 verification per peer).
        // Reuse decisions when head and signature match if netmap processing time is noticeable in a tailnet with many peers.
        let admitted = authority.state.admitted(peers.map {
            PeerCredential(nodeKey: $0.key, keySignature: $0.keySignature, unsignedPeerAPIOnly: $0.unsignedPeerAPIOnly)
        })
        var result = self
        result.peers = zip(peers, admitted).compactMap { peer, isAdmitted in isAdmitted ? peer : nil }
        result.tailnetLock = TailnetLockStatus(
            mode: .enforcing, head: authority.head.text, filteredPeerCount: peers.count - result.peers.count
        )
        do {
            _ = try authority.state.authorize(selfNode.key, keySignature: selfNode.keySignature)
        } catch {
            result.tailnetLock.signingRequest = TailnetLockStatus.SigningRequest(
                nodeKey: selfNode.key.description, lockKey: lockKey.commandLineDescription
            )
        }
        return result
    }

    /// Returns the netmap when there is no basis for filtering (`.unverified`), removing all peers, including `UnsignedPeerAPIOnly`.
    ///
    /// The self node's signature cannot be assessed either, so there is no `signingRequest`.
    func withholdingPeers() -> Netmap {
        var result = self
        result.peers = []
        result.tailnetLock = TailnetLockStatus(mode: .unverified, filteredPeerCount: peers.count)
        return result
    }
}
