/// Determines whether the receiver is under load. Requires mac2 on handshake messages only under load.
///
/// The node public key is public, so anyone can make a message with a valid mac1, and the receiver computes X25519 each time.
/// wireguard-go detects load when its handshake queue backs up to a threshold (`IsUnderLoad`). This device has no queue and handles messages
/// where it receives them, so it checks whether `threshold` handshake messages have passed mac1 within the latest `window`
/// instead. Once it detects load, it stays under load for `underLoadAfterTime` (1 second), as in Go.
///
/// See "Sending a cookie reply" in `docs/contracts/SwiftailWireGuard.md` for the threshold rationale.
/// Origin: wireguard-go `device/device.go` `IsUnderLoad` and "Load detection" in `docs/protocol-notes/wireguard.md`.
struct HandshakeLoad {
    /// The receiver is under load if this many messages arrive within `window`.
    static let threshold = 128
    /// The time window for counting toward the threshold.
    static let window: Duration = .seconds(1)

    /// The timestamps of the last `threshold` messages. When full, `oldest` points to the oldest slot, where overwriting starts.
    private var arrivals: [ContinuousClock.Instant] = []
    private var oldest = 0
    /// The receiver stays under load until this time. Tests set this value directly to simulate load.
    var underLoadUntil: ContinuousClock.Instant?

    /// Counts a handshake message that passed mac1 and returns whether the receiver is now under load.
    ///
    /// If this message brings the count to `threshold` in an interval shorter than `window`, detects load and stays under load until
    /// `now + 1 second`. Otherwise checks whether a previously detected period is still active (it ends at that exact time, as in Go).
    mutating func record(at now: ContinuousClock.Instant) -> Bool {
        if arrivals.count < Self.threshold {
            arrivals.append(now)
        } else {
            arrivals[oldest] = now
            oldest = (oldest + 1) % Self.threshold
        }
        if arrivals.count == Self.threshold, now - arrivals[oldest] < Self.window {
            underLoadUntil = now + Constants.underLoadAfterTime
            return true
        }
        return underLoadUntil.map { now < $0 } ?? false
    }
}
