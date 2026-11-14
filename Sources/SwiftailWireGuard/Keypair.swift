import CryptoKit

/// 핸드셰이크 한 번이 낳은 전송 세션: 송수신 키, 송신 counter, 수신 재전송 방지 창.
///
/// 백서 §5.4.6, `docs/protocol-notes/wireguard.md` "전송 키 유도"
/// (출처: wireguard-go `device/keypair.go`, `device/noise-protocol.go`).
struct Keypair {
    let sendKey: SymmetricKey
    let receiveKey: SymmetricKey
    /// 이 세션으로 오는 transport의 receiver. 핸드셰이크 때 우리가 보낸 sender다.
    let localIndex: UInt32
    /// 이 세션으로 보내는 transport의 receiver.
    let remoteIndex: UInt32
    /// initiation을 보낸 쪽인지. 시간에 따른 rekey는 초기자만 한다.
    let isInitiator: Bool
    let created: ContinuousClock.Instant
    /// 다음에 보낼 counter.
    var sendNonce: UInt64 = 0
    var replayFilter = ReplayFilter()

    init(keys: SessionKeys, localIndex: UInt32, remoteIndex: UInt32, isInitiator: Bool, created: ContinuousClock.Instant) {
        sendKey = keys.send
        receiveKey = keys.receive
        self.localIndex = localIndex
        self.remoteIndex = remoteIndex
        self.isInitiator = isInitiator
        self.created = created
    }

    /// 이 세션으로 보낼 수 있는지. counter가 바닥났거나 `rejectAfterTime` 이상 지났으면 보낼 수 없다.
    func canSend(at now: ContinuousClock.Instant) -> Bool {
        sendNonce < Constants.rejectAfterMessages && now - created < Constants.rejectAfterTime
    }

    /// 이 세션으로 온 transport를 받을 수 있는지. `rejectAfterTime`을 넘으면 받지 않는다.
    func canReceive(at now: ContinuousClock.Instant) -> Bool {
        now - created <= Constants.rejectAfterTime
    }
}

/// 한 피어의 keypair 세 칸.
///
/// - `current`: 보낼 때 쓰는 세션.
/// - `previous`: 바로 전 세션. rekey 직후 늦게 도착한 패킷을 받으려고 남겨 둔다.
/// - `next`: 응답자가 response를 보내며 만든 세션. 초기자가 이 키로 보낸 첫 패킷을 받아
///   초기자도 같은 키를 가졌음이 확인되면(key confirmation) `current`로 올린다. 그 전에는 이 키로 보내지 않는다.
///
/// 백서 §6.1, `docs/protocol-notes/wireguard.md` "keypair 교체(previous/current/next)"
/// (출처: wireguard-go `device/noise-protocol.go` `BeginSymmetricSession`, `ReceivedWithKeypair`).
struct Keypairs {
    enum Slot: CaseIterable {
        case previous, current, next
    }

    private(set) var previous: Keypair?
    var current: Keypair?
    private(set) var next: Keypair?

    /// 새 세션을 넣는다. 밀려난 keypair는 여기서 사라진다.
    mutating func install(_ keypair: Keypair) {
        if keypair.isInitiator {
            // 초기자는 확인이 필요 없으므로 바로 current가 된다. 확인되지 않은 next가 있었다면
            // 그것이 상대가 마지막으로 쓴 키일 수 있으므로 current 대신 previous로 남긴다.
            previous = next ?? current
            next = nil
            current = keypair
        } else {
            next = keypair
            previous = nil
        }
    }

    /// `next`로 온 패킷이 인증되면 부른다. `next`가 맞으면 current로 올리고 `true`.
    mutating func confirm(_ slot: Slot) -> Bool {
        guard slot == .next, let next else { return false }
        previous = current
        current = next
        self.next = nil
        return true
    }

    /// 칸의 keypair로 transport 하나를 연다: 만료 확인 → 복호화 → 재전송 창 기록. 성공했을 때만 창이 바뀐다.
    ///
    /// keypair를 꺼내 복사하지 않고 칸 안에서 바로 처리한다. 복사해 두면 재전송 창(1KB)을 기록할 때 창 전체가 복사된다.
    ///
    /// - Throws: 칸이 비었으면 `unknownPeer`, `rejectAfterTime`을 넘었으면 `noSession`, 인증에 실패하면
    ///   `authenticationFailed`, 이미 받았거나 창 밖이면 `replayed`.
    mutating func open(_ message: TransportData, in slot: Slot, at now: ContinuousClock.Instant) throws(WireGuardError) -> [UInt8] {
        switch slot {
        case .previous: try Self.open(message, in: &previous, at: now)
        case .current: try Self.open(message, in: &current, at: now)
        case .next: try Self.open(message, in: &next, at: now)
        }
    }

    private static func open(_ message: TransportData, in keypair: inout Keypair?, at now: ContinuousClock.Instant) throws(WireGuardError) -> [UInt8] {
        guard let canReceive = keypair?.canReceive(at: now) else { throw .unknownPeer }
        guard canReceive else { throw .noSession }
        guard let plaintext = keypair?.open(message) else { throw .authenticationFailed }
        // 재전송 창은 인증된 counter로만 움직인다.
        guard keypair?.replayFilter.accept(message.counter) == true else { throw .replayed }
        return plaintext
    }

    /// localIndex로 keypair가 있는 칸을 찾는다.
    func slot(forLocalIndex index: UInt32) -> Slot? {
        // 칸 셋을 집합 없이 차례로 본다. 패킷마다 부른다.
        if previous?.localIndex == index { return .previous }
        if current?.localIndex == index { return .current }
        if next?.localIndex == index { return .next }
        return nil
    }

    subscript(slot: Slot) -> Keypair? {
        get {
            switch slot {
            case .previous: previous
            case .current: current
            case .next: next
            }
        }
        set {
            switch slot {
            case .previous: previous = newValue
            case .current: current = newValue
            case .next: next = newValue
            }
        }
    }

    var localIndices: [UInt32] {
        Slot.allCases.compactMap { self[$0]?.localIndex }
    }
}
