import CryptoKit
import Foundation
import SwiftailBase

/// 한 노드의 WireGuard 상태 전체(자기 정적 키와 피어들).
///
/// 입출력이 없는 상태 기계다. 소켓·TUN·타이머·시계를 갖지 않는다. 호출하는 쪽이 받은 데이터그램,
/// 보낼 IP 패킷, 현재 시각을 넣으면 상태를 바꾸고 "네트워크로 보낼 데이터그램"과 "위로 올릴 IP 패킷"을
/// 돌려준다. 값 타입이므로 소유한 쪽이 직렬로 호출하면 된다.
///
/// 주소를 다루지 않는다. Tailscale 포크의 wireguard-go에도 엔드포인트 로밍이 없고, 피어까지의 경로는
/// magicsock이 고른다. 그래서 출력은 "이 피어에게 보낼 바이트"다.
///
/// 호출 규칙: `now`는 호출마다 줄어들지 않아야 한다. 호출하는 쪽은 `nextDeadline`에 맞춰
/// `advance(to:)`를 부른다. `send`·`receive`는 기한이 지난 타이머를 먼저 처리하지 않는다.
///
/// 이 파일은 공개 API와 피어·index 표 관리를 담는다. 송신·수신·타이머 처리는 같은 이름의
/// `WireGuardDevice+…` 파일에 있다. 계약: `docs/contracts/SwiftailWireGuard.md`.
public struct WireGuardDevice: Sendable {
    /// 상태 기계가 내놓는 일.
    public enum Output: Sendable, Equatable {
        /// 네트워크로 보낼 WireGuard 메시지. 어느 경로로 보낼지는 호출하는 쪽이 정한다.
        case datagram([UInt8], to: PublicKey)
        /// 복호화와 AllowedIPs 검사를 통과한 IP 패킷.
        case ipPacket([UInt8], from: PublicKey)
        /// 피어가 보낸 것은 맞지만 올리지 않은 IP 패킷. 이유는 `malformed` 또는 `disallowedSource`다.
        /// 보낼 것도 올릴 것도 없으며, 호출하는 쪽이 지표나 로그를 남기는 데 쓴다.
        case rejectedIPPacket(WireGuardError, from: PublicKey)
        /// 부하 상태에서 mac2가 맞지 않는 핸드셰이크 메시지에 답하는 cookie reply(64바이트). 방금 받은 데이터그램의
        /// 출처로 그 길 그대로 보낸다. 핸드셰이크를 열기 전이라 보낸 피어를 모르므로 피어 경로 선택을 거치지 않는다.
        case cookieReply([UInt8])
    }

    /// 받은 데이터그램이 온 곳. 장치는 내용을 해석하지 않고 cookie를 묶고 속도 제한을 세는 데만 쓴다.
    ///
    /// 다른 출처끼리는 `address`가 달라야 하고, 같은 호스트에서 온 것은 `host`가 같아야 한다. 출처의 종류(UDP,
    /// DERP)가 다르면 두 값의 길이도 다르게 만들어 서로 겹치지 않게 한다.
    public struct Source: Hashable, Sendable {
        /// cookie가 묶이는 값. 이 값으로 답장이 실제로 닿는 단위다(UDP면 주소와 포트).
        public var address: [UInt8]
        /// 속도 제한을 함께 받는 단위(UDP면 IP 주소).
        public var host: [UInt8]

        public init(address: [UInt8], host: [UInt8]) {
            self.address = address
            self.host = host
        }
    }

    /// 이 장치의 정적 공개 키.
    public let publicKey: PublicKey
    let staticKey: Curve25519.KeyAgreement.PrivateKey
    /// 받은 핸드셰이크 메시지의 mac1을 검사하는 키. 자기 공개 키에서 나온다.
    let mac1Key: [UInt8]
    /// 부하 상태에서 mac2를 검사하고 cookie reply를 만든다. 비밀을 쥔다.
    var cookieChecker: CookieChecker
    var handshakeLoad = HandshakeLoad()
    var rateLimiter = RateLimiter()
    /// TAI64N 계산용: `monotonicOrigin` 시점의 Unix 기원부터의 경과 시간.
    private let monotonicOrigin: ContinuousClock.Instant
    private let wallClockOrigin: Duration

    var peers: [PublicKey: Peer] = [:]
    /// 우리가 배정한 index → 그 index를 가진 피어. 핸드셰이크 중인 index와 keypair의 index가 함께 있다.
    var indexTable: [UInt32: PublicKey] = [:]

    /// - Parameters:
    ///   - privateKey: 이 노드의 정적 비밀 키.
    ///   - now: 지금의 단조 시각.
    ///   - wallClock: `now` 시점의 벽시계 시각. 이후의 TAI64N timestamp는
    ///     wallClock + (호출 시각 − now)로 계산하므로 단조 증가한다. 1970년 이전은 1970년으로 본다.
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date) {
        staticKey = privateKey
        publicKey = PublicKey(privateKey.publicKey)
        mac1Key = MAC.mac1Key(for: publicKey)
        cookieChecker = CookieChecker(publicKey: publicKey)
        monotonicOrigin = now
        wallClockOrigin = .seconds(wallClock.timeIntervalSince1970)
    }

    /// 피어를 등록한다. 이미 있으면 AllowedIPs만 바꾸고 세션은 유지한다.
    public mutating func addPeer(_ peer: PublicKey, allowedIPs: [IPPrefix]) {
        if var existing = peers[peer] {
            existing.allowedIPs = allowedIPs
            peers[peer] = existing
            return
        }
        peers[peer] = Peer(
            publicKey: peer,
            allowedIPs: allowedIPs,
            staticStaticSecret: sharedSecret(staticKey, peer.rawValue),
            cookieGenerator: CookieGenerator(peer: peer)
        )
    }

    /// 피어와 그 키 재료를 지운다. 그 피어의 index로 오는 메시지는 이후 `unknownPeer`다.
    public mutating func removePeer(_ peer: PublicKey) {
        guard let removed = peers.removeValue(forKey: peer) else { return }
        for index in removed.localIndices {
            indexTable[index] = nil
        }
    }

    /// 다음에 `advance(to:)`를 불러야 하는 시각. 걸린 타이머가 없으면 `nil`.
    public var nextDeadline: ContinuousClock.Instant? {
        peers.values.compactMap { $0.timers.earliest?.deadline }.min()
    }

    // MARK: - 피어 갱신

    /// 바꾼 피어를 저장하고 index 표를 맞춘다.
    ///
    /// 처리는 늘 피어의 사본을 바꾼 뒤 성공했을 때만 이 함수로 저장한다. 그래서 오류를 던진 경로는
    /// 상태를 바꾸지 않는다.
    // shortcut: 사본을 바꾸므로 피어의 배열(재전송 창 1KB 등)이 패킷마다 복사된다. M5 실기기 측정에서 병목으로 확인되면 제자리 갱신으로 바꾼다.
    mutating func store(_ peer: Peer) {
        let previous = peers[peer.publicKey]?.localIndices ?? []
        let current = peer.localIndices
        for index in previous.subtracting(current) {
            indexTable[index] = nil
        }
        for index in current {
            indexTable[index] = peer.publicKey
        }
        peers[peer.publicKey] = peer
    }

    /// 표에 없고 이 피어의 사본에도 없는 새 index를 뽑는다. 0도 정상 값이다.
    func freshIndex(avoiding peer: Peer) -> UInt32 {
        let taken = peer.localIndices
        while true {
            let index = UInt32.random(in: .min ... .max)
            if indexTable[index] == nil, !taken.contains(index) {
                return index
            }
        }
    }

    /// now 시점의 TAI64N.
    func timestamp(at now: ContinuousClock.Instant) -> TAI64N {
        TAI64N(sinceUnixEpoch: wallClockOrigin + (now - monotonicOrigin))
    }
}

extension WireGuardDevice: CustomReflectable {
    /// 정적 비밀 키, cookie 비밀, 속도 제한 표의 출처 주소가 `print`·`dump`·디버거에 나오지 않도록 공개 키와 피어만
    /// 보인다(피어도 공개 정보만 보인다).
    public var customMirror: Mirror {
        Mirror(self, children: ["publicKey": publicKey, "peers": Array(peers.values)], displayStyle: .struct)
    }
}
