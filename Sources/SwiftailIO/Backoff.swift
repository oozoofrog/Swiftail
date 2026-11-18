/// Computes the delay before retrying a failure. This is a pure calculation with no clock or random number source.
///
/// Reconnects to the control server (30-second cap) and DERP server (5-second cap) use the same formula with different caps.
///
/// On consecutive failure n, uses `min(n² × 10ms, maximum) × [0.5, 1.5)`. It grows more slowly than 2ⁿ, and the random
/// multiplier spreads out reconnections from multiple nodes. On success, the caller resets n to 0.
///
/// (Origin: tailscale.com `util/backoff/backoff.go`, BSD-3-Clause).
package enum Backoff {
    /// Returns the delay after consecutive failure `failures`. There is no delay for 0 or fewer failures. `jitter` is a
    /// random number in [0, 1).
    package static func delay(failures: Int, maximum: Duration, jitter: Double) -> Duration {
        let n = min(max(failures, 0), 1_000)
        let base = min(Duration.milliseconds(n * n * 10), maximum)
        return base * (0.5 + jitter)
    }
}
