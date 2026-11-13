import SwiftailBase

/// 장치가 아는 피어 하나의 상태 전체.
///
/// 이 값을 지우면 그 피어의 키 재료도 함께 사라진다. 전송 키는 CryptoKit `SymmetricKey`에 있어
/// 해제될 때 메모리가 지워진다. chaining key 같은 `[UInt8]` 재료는 Swift가 해제 시 지움을 보장하지 않는다.
///
/// `docs/protocol-notes/wireguard.md` "절차와 상태 기계" (출처: wireguard-go `device/peer.go`).
struct Peer {
    let publicKey: PublicKey
    var allowedIPs: [IPPrefix]
    /// 미리 계산한 DH(우리 정적 키, 피어 정적 키). 저차 점이라 0이면 `nil`이고, 그 피어와는 핸드셰이크할 수 없다.
    let staticStaticSecret: [UInt8]?
    var cookieGenerator: CookieGenerator

    /// 우리가 보낸 initiation이 response를 기다리는 중.
    var pendingHandshake: PendingHandshake?
    var keypairs = Keypairs()
    /// 세션이 서기 전에 보내려 한 IP 패킷. 빈 배열은 keepalive다.
    var staged: [[UInt8]] = []
    var timers = PeerTimers()

    /// 마지막으로 받아들인 initiation timestamp. 키 재료를 지워도 남긴다(옛 initiation 재전송 방지).
    var lastAcceptedTimestamp: TAI64N?
    var lastInitiationConsumed: ContinuousClock.Instant?
    /// 마지막으로 initiation이나 response를 보낸 시각. `rekeyTimeout` 안에는 initiation을 또 보내지 않는다.
    var lastSentHandshake: ContinuousClock.Instant?

    /// 이 피어가 장치의 index 표에 차지한 index들.
    var localIndices: Set<UInt32> {
        var indices = Set(keypairs.localIndices)
        if let pendingHandshake { indices.insert(pendingHandshake.localIndex) }
        return indices
    }

    /// 출발 주소가 이 피어의 AllowedIPs 안인지.
    func allows(source: IPAddress) -> Bool {
        allowedIPs.contains { $0.contains(source) }
    }

    /// 대기열에 넣는다. 넘치면 가장 오래된 것을 버린다.
    mutating func stage(_ packet: [UInt8]) {
        staged.append(packet)
        if staged.count > Constants.maxStagedPackets {
            staged.removeFirst(staged.count - Constants.maxStagedPackets)
        }
    }

    /// keypair·진행 중인 핸드셰이크·대기열을 모두 지운다(wireguard-go `ZeroAndFlushAll`).
    mutating func zeroKeyMaterial() {
        keypairs = Keypairs()
        pendingHandshake = nil
        staged = []
    }
}

/// `print`·`dump`·디버거가 기본 반영(reflection)으로 키 재료(chaining key, static-static DH, cookie)를
/// 펼쳐 보이지 않게 공개 정보만 드러낸다.
extension Peer: CustomReflectable {
    var customMirror: Mirror {
        Mirror(self, children: ["publicKey": publicKey, "allowedIPs": allowedIPs], displayStyle: .struct)
    }
}
