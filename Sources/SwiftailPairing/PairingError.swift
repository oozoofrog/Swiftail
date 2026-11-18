/// Pairing and paired peer list failures (`PairingHost`, `PairingJoiner`). See contract `docs/contracts/SwiftailPairing.md` §§5 and 6.
///
/// Messages describe only what went wrong. They omit secrets, auth keys, SAS values, names, addresses, and paths.
public enum PairingError: Error, Sendable, Equatable {
    /// An unusable value. The node device is not `.inProcess`, the port is zero or in use, the lifetime is outside 1–3600 seconds, the device name
    /// is not 1–64 bytes of displayable text, or the OS socket's `localAddress` is outside the tailnet range.
    case invalidConfiguration(String)
    /// The auth key supplied to `openOffer` cannot be put in a link (including wrapped keys, contract behavior O2).
    case invalidAuthKey
    /// The node does not yet have its own FQDN, or its `run()` has ended.
    case notRunning
    /// The paired peer list file exists but could not be read (it will not be overwritten with an empty list), or its directory belongs to another user
    /// or is writable by the group or others.
    case storeUnreadable
    /// A `PairingHost` in this process already uses the same directory.
    case storeInUse
    /// Could not write the paired peer list file.
    case storeWriteFailed
    /// The host's `challenge` did not arrive within 60 seconds (name lookup failed, no route, or the host does not know this node yet).
    case unreachable
    /// The OS socket connection did not traverse the tunnel. Its local endpoint differs from this device's tailnet address (`localAddress`), or its remote
    /// endpoint is outside the tailnet range. The tunnel was disconnected or the name resolved elsewhere.
    case notOnTailnet
    /// The host did not accept the joiner. There is no open offer, the offer expired or was already used, or the secret is wrong.
    case rejected
    /// The peer failed to prove knowledge of the offer secret (an incorrect HMAC in `accepted` or `decision`). For in-process joiners,
    /// this also covers a `decision` `StableID` that differs from the connected peer's.
    case hostNotVerified
    /// The host denied pairing (user denial, this node's identity changed during approval, the paired peer list is full, or saving failed).
    case denied
    /// Approval did not arrive before the deadline.
    case timedOut
    /// The peer sent bytes outside the protocol or closed the connection before sending a decision.
    case protocolViolation
    /// The calling Task was canceled.
    case cancelled
}
