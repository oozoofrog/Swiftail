/// The current tailnet lock state. `ControlClient` fills it for each netmap and emits it as `Netmap.tailnetLock`.
///
/// The app distinguishes four cases with this value: no lock (`.disabled`), enabled and this node is signed (`.enforcing` with nil `signingRequest`),
/// enabled and awaiting a signature (`.enforcing` with a `signingRequest`), and unverified (`.unverified`). Cases that do not resolve on their own
/// are reported separately by `issue`.
///
/// Contains only public keys and hashes. Private keys and disablement secrets are excluded.
/// Contract `docs/contracts/SwiftailTailnetLock.md` §2, behaviors N6 and P.
public struct TailnetLockStatus: Sendable, Equatable {
    public enum Mode: Sendable, Equatable {
        /// There is no lock: there is no local signing authority state, and either the server did not report it enabled or this node lacks the `tailnet-lock` capability.
        case disabled
        /// Holds verified signing authority state and filters peers with it.
        case enforcing
        /// There is no basis for filtering: the server reports an enabled lock and bootstrap has not succeeded, or the stored state could not be opened.
        /// Withholds all peers to honor the promise of no communication with unsigned nodes (Go accepts them all in this case).
        case unverified
    }

    /// The reason verified signing authority state is unavailable or could not be synchronized with the server (contract §5 TL-11b item 4). Determines what
    /// the app tells the user.
    public enum Issue: Sendable, Equatable {
        /// Obtaining verified state: the server reports an enabled lock, and bootstrap has yet to succeed. Retries automatically (`.unverified`).
        case acquiringState
        /// The stored state could not be opened (it is corrupt or fails verification). Does not resolve on its own (`.unverified`).
        /// If the user chooses to, delete it with `ControlClient.removeTailnetLockState(inDirectory:)` and restart.
        case unreadableStoredState
        /// The stored state does not connect to the chain reported by the server. Synchronization found no common ancestor (for example, state from another
        /// tailnet was left behind). `mode` is `.enforcing` and filtering continues with the stored state. A signature from the signing device cannot resolve it.
        /// If the user chooses to, delete it with `ControlClient.removeTailnetLockState(inDirectory:)` and restart.
        case storedStateDiverged
    }

    /// The two values to pass as is to `tailscale lock sign <nodeKey> <lockKey>` on the signing device. Both are public keys.
    public struct SigningRequest: Sendable, Equatable {
        /// This node's node public key (`nodekey:` + 64 hexadecimal digits).
        public var nodeKey: String
        /// This node's tailnet lock public key (`tlpub:` + 64 hexadecimal digits). Becomes the signature's rotation key.
        public var lockKey: String

        public init(nodeKey: String, lockKey: String) {
            self.nodeKey = nodeKey
            self.lockKey = lockKey
        }
    }

    public var mode: Mode
    /// The local head (52 base32 characters). Present only in `.enforcing`.
    public var head: String?
    /// The number of peers removed from the netmap. In `.enforcing`, it counts peers with missing signatures, signatures that fail verification, or keys superseded by rotation.
    /// In `.unverified`, it includes all peers reported by the server.
    public var filteredPeerCount: Int
    /// The values to pass to the signing device when the self node's signature fails verification under the current state and the node is locked out. Otherwise, `nil`.
    public var signingRequest: SigningRequest?

    /// Why verified state could not be held or synchronized with the server. Nil when there is no such issue.
    public var issue: Issue?

    /// Whether the self node is locked out, preventing communication with peers enforcing the lock until a signing device signs it.
    public var isLockedOut: Bool { signingRequest != nil }

    public init(
        mode: Mode = .disabled, head: String? = nil, filteredPeerCount: Int = 0, signingRequest: SigningRequest? = nil,
        issue: Issue? = nil
    ) {
        self.mode = mode
        self.head = head
        self.filteredPeerCount = filteredPeerCount
        self.signingRequest = signingRequest
        self.issue = issue
    }
}
