/// WireGuard protocol constants.
///
/// Values follow the "Constants and timers" table in `docs/protocol-notes/wireguard.md`
/// (origin: wireguard-go `device/constants.go`, `device/tun.go`).
enum Constants {
    /// A keypair that has sent more than this starts a new handshake after sending. 2^60.
    static let rekeyAfterMessages: UInt64 = 1 << 60
    /// Counters at or above this value are neither sent nor received. 2^64 − 2^13 − 1.
    static let rejectAfterMessages: UInt64 = .max - (1 << 13)
    /// If the initiator's keypair is older than this, starts a new handshake after sending.
    static let rekeyAfterTime: Duration = .seconds(120)
    /// The minimum interval between handshake messages and the retry interval.
    static let rekeyTimeout: Duration = .seconds(5)
    /// The exclusive upper bound of jitter added to retry and new-handshake timers (ms).
    static let rekeyTimeoutJitterMaxMilliseconds = 334
    /// Gives up when the retry count exceeds this value. RekeyAttemptTime (90 seconds) / RekeyTimeout (5 seconds).
    static let maxTimerHandshakes = 18
    /// Keypairs older than this cannot be used to send or receive.
    static let rejectAfterTime: Duration = .seconds(180)
    /// Sends a keepalive if there is nothing to send for this long after receiving data.
    static let keepaliveTimeout: Duration = .seconds(10)
    /// How long a received cookie can be used for mac2. The receiver rotates the cookie-generating secret at the same interval.
    static let cookieRefreshTime: Duration = .seconds(120)
    /// How long the receiver stays under load after detecting load (`UnderLoadAfterTime`).
    static let underLoadAfterTime: Duration = .seconds(1)
    /// The minimum interval before consuming another initiation from the same peer (flood protection).
    static let handshakeInitiationRate: Duration = .milliseconds(20)
    /// Pads transport plaintext to a multiple of this value.
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
