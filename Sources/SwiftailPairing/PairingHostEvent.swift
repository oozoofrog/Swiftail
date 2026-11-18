extension PairingHost {
    /// Changes emitted by `PairingHost` through `PairingHost.events`.
    ///
    /// Omits secrets (the offer secret and link), proofs, SAS values, and auth keys. Read the complete paired peer list using `pairedPeers`.
    public enum Event: Sendable, Equatable {
        /// Pairing succeeded and the peer was saved. If an already paired node pairs again, its entry is replaced in place with a new `pairedAt` time and this
        /// event is emitted again.
        case pairedPeerAdded(PairedPeer)
        /// `removePairedPeer(withStableID:)` removed a paired peer and saved the list. Removing an absent peer emits no event.
        case pairedPeerRemoved(stableID: String)
        /// The offer state changed.
        ///
        /// Events arrive in the order they occur. Any `.used`, `.expired`, or `.closed` after an `.opened` refers to the offer announced by that `.opened`
        /// (events for the previous offer always precede the next `.opened`). Update the offer on screen in event order, independently of when
        /// `openOffer` returns. If no events were dropped, state events refer to the current offer once the number of received
        /// `.opened` events matches the number of successful `openOffer` calls.
        case offerChanged(OfferState)
    }

    /// Events for an open offer. Only one offer can be open at a time.
    public enum OfferState: Sendable, Equatable {
        /// `openOffer(lifetime:authKey:)` opened a new offer. The previous offer becomes unusable immediately, without a separate event.
        case opened
        /// The offer was used when the joiner's proof verified. Emitted immediately before requesting approval (`decide`) for this connection. An offer can be used only once.
        case used
        /// The offer passed its expiration time unused. Emitted at that time while `run()` is active. Expiration outside `run()` is emitted when
        /// `run()` starts.
        case expired
        /// `closeOffer()` closed the open offer. No event is emitted if there was no open offer.
        case closed
    }
}
