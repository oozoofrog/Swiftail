/// tailnet lock의 지금 모습. `ControlClient`가 netmap마다 채워 `Netmap.tailnetLock`으로 낸다.
///
/// 앱은 이 값 하나로 네 경우를 가른다: lock 없음(`.disabled`), 켜짐·이 노드 서명됨(`.enforcing`이고 `signingRequest`가 nil),
/// 켜짐·서명을 기다림(`.enforcing`이고 `signingRequest`가 있음), 확인하지 못함(`.unverified`). 스스로 풀리지 않는 경우는
/// `issue`가 따로 알린다.
///
/// 담는 것은 공개 키와 해시뿐이다. 개인 키와 끄기 비밀은 담지 않는다.
/// 계약 `docs/contracts/SwiftailTailnetLock.md` 2절, 동작 N6·P.
public struct TailnetLockStatus: Sendable, Equatable {
    public enum Mode: Sendable, Equatable {
        /// lock이 없다: 로컬 서명 권한 상태가 없고, 서버가 켜졌다고 알리지 않았거나 이 노드에 `tailnet-lock` capability가 없다.
        case disabled
        /// 검증한 서명 권한 상태를 쥐고 있고, 그것으로 피어를 거른다.
        case enforcing
        /// 거를 근거가 없다: 서버는 lock이 켜졌다고 하는데 부트스트랩하지 못했거나, 저장된 상태를 열지 못했다.
        /// 서명 없는 노드와 통신하지 않는다는 약속을 지키려고 피어를 하나도 올리지 않는다(Go는 이때 모두 받아들인다).
        case unverified
    }

    /// 서명 권한 상태를 검증된 채로 쥐지 못하거나 서버와 맞추지 못하는 까닭(계약 5절 TL-11b 항목 4). 앱이 사용자에게 할
    /// 안내를 가른다.
    public enum Issue: Sendable, Equatable {
        /// 검증된 상태를 얻는 중이다: 서버는 lock이 켜졌다는데 아직 부트스트랩하지 못했다. 스스로 다시 시도한다(`.unverified`).
        case acquiringState
        /// 저장된 상태를 열지 못했다(깨졌거나 검증되지 않는다). 스스로 풀리지 않는다(`.unverified`).
        /// 사용자가 고르면 `ControlClient.removeTailnetLockState(inDirectory:)`로 지우고 다시 시작한다.
        case unreadableStoredState
        /// 저장된 상태가 서버가 알린 사슬과 이어지지 않는다: 동기화에서 공통 조상을 찾지 못했다(다른 tailnet의 상태가 남은
        /// 경우 등). `mode`는 `.enforcing`이고 저장된 상태로 계속 거르며, 서명 기기가 서명해도 풀리지 않는다.
        /// 사용자가 고르면 `ControlClient.removeTailnetLockState(inDirectory:)`로 지우고 다시 시작한다.
        case storedStateDiverged
    }

    /// 서명 기기에서 `tailscale lock sign <nodeKey> <lockKey>`에 그대로 넣는 두 값. 둘 다 공개 키다.
    public struct SigningRequest: Sendable, Equatable {
        /// 이 노드의 node 공개 키(`nodekey:` + 16진 64자리).
        public var nodeKey: String
        /// 이 노드의 tailnet lock 공개 키(`tlpub:` + 16진 64자리). 서명의 회전 키가 된다.
        public var lockKey: String

        public init(nodeKey: String, lockKey: String) {
            self.nodeKey = nodeKey
            self.lockKey = lockKey
        }
    }

    public var mode: Mode
    /// 로컬 머리(base32 52자). `.enforcing`일 때만 있다.
    public var head: String?
    /// netmap에서 뺀 피어 수. `.enforcing`에서는 서명이 없거나 검증되지 않거나 회전으로 낡은 키인 피어이고,
    /// `.unverified`에서는 서버가 알린 피어 전부다.
    public var filteredPeerCount: Int
    /// 자기 노드의 서명이 지금 상태로 검증되지 않을 때(잠김) 서명 기기에 넘길 값. 잠기지 않았으면 nil이다.
    public var signingRequest: SigningRequest?

    /// 검증된 상태를 쥐지 못하거나 서버와 맞추지 못하는 까닭. 그런 까닭이 없으면 nil이다.
    public var issue: Issue?

    /// 자기 노드가 잠겨 있다: 서명 기기가 서명할 때까지 lock을 지키는 피어와 통신하지 못한다.
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
