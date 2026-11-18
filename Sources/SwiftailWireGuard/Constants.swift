/// WireGuard protocol constants.
///
/// Values follow the "Constants and timers" table in `docs/protocol-notes/wireguard.md`
/// (origin: wireguard-go `device/constants.go`, `device/tun.go`).
enum Constants {
    /// After sending with a keypair that has exceeded this message count, start a new handshake. 2^60.
    static let rekeyAfterMessages: UInt64 = 1 << 60
    /// Counters at or above this value are neither sent nor received. 2^64 − 2^13 − 1.
    static let rejectAfterMessages: UInt64 = .max - (1 << 13)
    /// After sending with an initiator keypair older than this, start a new handshake.
    static let rekeyAfterTime: Duration = .seconds(120)
    /// The minimum interval between handshake messages and the retry interval.
    static let rekeyTimeout: Duration = .seconds(5)
    /// The exclusive upper bound of jitter added to retry and new-handshake timers (ms).
    static let rekeyTimeoutJitterMaxMilliseconds = 334
    /// Gives up when the retry count exceeds this value. RekeyAttemptTime (90 seconds) / RekeyTimeout (5 seconds).
    static let maxTimerHandshakes = 18
    /// A keypair can send only before this age and can receive through this age, inclusive.
    static let rejectAfterTime: Duration = .seconds(180)
    /// Sends a keepalive if there is nothing to send for this long after receiving data.
    static let keepaliveTimeout: Duration = .seconds(10)
    /// How long a received cookie can be used for mac2. When replying, the receiver replaces a secret older than this.
    static let cookieRefreshTime: Duration = .seconds(120)
    /// How long the device remains under load after detecting it (`UnderLoadAfterTime`).
    static let underLoadAfterTime: Duration = .seconds(1)
    /// The exclusive lower bound on the interval between accepted initiations from the same peer (flood protection).
    static let handshakeInitiationRate: Duration = .milliseconds(20)
    /// Padding aligns the final portion of transport plaintext to this multiple, subject to the MTU cap.
    static let paddingMultiple = 16
    /// The UDP payload limit (`MaxSegmentSize` for wireguard-go's default platform).
    static let maxSegmentSize = 65535
    /// The outgoing IP packet size limit. Subtract 16 for the header + 16 for the tag + 8 of headroom (`MaxContentSize`).
    static let maxContentSize = maxSegmentSize - 32 - 8
    /// The MTU for padding calculations. wireguard-go uses this value when the TUN cannot provide an MTU (`DefaultMTU`).
    static let defaultMTU = 1420
    /// The number of IP packets queued per peer before a session is established. Discards the oldest on overflow (contract value).
    static let maxStagedPackets = 64
    /// The number of last initiation timestamps retained for removed peers. Forgets the earliest removals on overflow (contract value).
    static let maxRetiredTimestamps = 1024
    /// The limit for the priority message sent first when a session is established (Tailscale fork of wireguard-go `MaxPriorityMessageContentSize`).
    static let maxPriorityMessageSize = 512
}
