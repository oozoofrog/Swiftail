# SwiftailWireGuard 계약 (M1)

WireGuard 데이터면을 **입출력 없는 상태 기계**로 구현한다. 소켓, TUN, 타이머, 시계를 갖지 않는다. 호출하는 쪽이 받은 데이터그램·보낼 IP 패킷·현재 시각을 넣으면, 상태 기계는 상태를 바꾸고 "네트워크로 보낼 데이터그램"과 "위로 올릴 IP 패킷"을 돌려준다.

프로토콜 세부는 [protocol-notes/wireguard.md](../protocol-notes/wireguard.md)(교차 검증됨)를 따른다. 이 문서는 모듈 경계와 범위만 정한다.

## 왜 이 구조인가

- Tailscale 포크의 wireguard-go에는 엔드포인트 로밍이 없고, 피어의 실제 경로(직접 UDP·DERP)는 magicsock이 고른다. 그래서 이 모듈은 주소를 알 필요가 없다. 출력은 "이 피어에게 보낼 바이트"다.
- 시각을 인자로 받으므로 rekey(120초), 키 폐기(180초) 같은 타이머 동작을 실제 시간을 기다리지 않고 결정적으로 시험할 수 있다.
- 값 타입이므로 동시성 문제가 없다. 소유한 쪽(나중의 엔진 actor)이 직렬로 호출한다.

## 타깃

| 타깃 | 의존 | 내용 |
| --- | --- | --- |
| `SwiftailBase` | Foundation, Network | `IPAddress`, `IPPrefix`, 16진 변환 |
| `SwiftailWireGuard` | `SwiftailBase`, `SwiftailCrypto`, CryptoKit | 아래 API |

## 공개 API

### SwiftailBase

```swift
/// IPv4 또는 IPv6 주소. 문자열 해석은 Network 프레임워크의 주소 타입에 맡긴다.
public struct IPAddress: Hashable, Sendable, LosslessStringConvertible {
    public init?(_ description: String)            // "100.64.0.1", "fd7a:115c:a1e0::1"
    public init?(bytes: some Collection<UInt8>)    // 4바이트 또는 16바이트
    public var bytes: [UInt8] { get }
    public var isIPv4: Bool { get }
}

/// CIDR 접두. 저장할 때 호스트 비트를 지운다.
public struct IPPrefix: Hashable, Sendable, LosslessStringConvertible {
    public init?(_ description: String)            // "100.64.0.1/32"
    public init?(address: IPAddress, length: Int)
    public var address: IPAddress { get }
    public var length: Int { get }
    public func contains(_ address: IPAddress) -> Bool
}

extension Array where Element == UInt8 {
    public init?(hex: String)        // 길이가 홀수이거나 16진이 아니면 nil
    public var hex: String { get }   // 소문자
}
```

### SwiftailWireGuard

```swift
/// Curve25519 공개 키 32바이트. 피어를 가리키는 이름으로 쓴다.
public struct PublicKey: Hashable, Sendable, CustomStringConvertible {
    public init?(rawValue: some Collection<UInt8>)   // 32바이트가 아니면 nil
    public let rawValue: [UInt8]
    public var description: String { get }           // 로그용. 앞 8자리 16진 + "…"
}

public enum WireGuardError: Error, Sendable, Equatable {
    case malformed              // 길이·type·예약 바이트가 규격과 다름
    case unknownPeer            // 등록되지 않은 피어, 또는 모르는 receiver index
    case authenticationFailed   // mac1, AEAD 태그 불일치
    case replayed               // 핸드셰이크 timestamp·flood 검사 또는 전송 카운터 재사용
    case noSession              // 쓸 수 있는 keypair가 없음(만료 포함)
    case disallowedSource       // 복호화한 IP 패킷의 출발 주소가 피어의 AllowedIPs 밖
    case packetTooLarge
}

/// 한 노드의 WireGuard 상태 전체(자기 정적 키와 피어들).
public struct WireGuardDevice: Sendable {
    public enum Output: Sendable, Equatable {
        /// 네트워크로 보낼 WireGuard 메시지. 어느 경로로 보낼지는 호출하는 쪽이 정한다.
        case datagram([UInt8], to: PublicKey)
        /// 복호화와 AllowedIPs 검사를 통과한 IP 패킷.
        case ipPacket([UInt8], from: PublicKey)
    }

    /// wallClock은 now 시점의 벽시계 시각이다. 이후의 TAI64N timestamp는
    /// wallClock + (호출 시각 − now)로 계산하므로 단조 증가한다.
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date)

    public var publicKey: PublicKey { get }

    /// 피어를 등록한다. 이미 있으면 AllowedIPs만 바꾸고 세션은 유지한다.
    public mutating func addPeer(_ peer: PublicKey, allowedIPs: [IPPrefix])
    /// 피어와 그 키 재료를 지운다.
    public mutating func removePeer(_ peer: PublicKey)

    /// IP 패킷 하나를 피어에게 보낸다. 세션이 없으면 대기열에 넣고 핸드셰이크를 시작한다.
    public mutating func send(_ ipPacket: [UInt8], to peer: PublicKey, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output]

    /// 네트워크에서 받은 데이터그램 하나를 처리한다.
    /// 오류를 던진 경우 상태는 바뀌지 않는다(규격이 요구하는 flood 시각 기록 등은 예외이며 주석으로 밝힌다).
    public mutating func receive(_ datagram: [UInt8], at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output]

    /// now까지 기한이 지난 타이머를 모두 처리한다.
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]

    /// 다음에 advance를 불러야 하는 시각. 걸린 타이머가 없으면 nil.
    public var nextDeadline: ContinuousClock.Instant? { get }
}
```

호출 규칙: `now`는 호출마다 줄어들지 않아야 한다. `send`·`receive`도 내부에서 기한이 지난 타이머를 먼저 처리한다고 가정하지 않는다. 호출하는 쪽은 `nextDeadline`에 맞춰 `advance`를 부른다.

## M1 범위

포함(노트의 "필수" 전부):

- 메시지 4종의 직렬화·해석, mac1 생성·검사
- Noise IKpsk2 초기자·응답자. PSK는 32바이트 0으로 고정하되 KDF3 단계는 그대로 둔다
- TAI64N 생성, 피어별 timestamp 재전송 검사, initiation flood 검사(20ms)
- 전송 암복호화, 카운터, 패딩(16의 배수), keepalive, 재전송 방지 창(8128)
- keypair의 previous·current·next 전환. 응답자는 새 키로 온 첫 패킷이 AEAD와 재전송 검사를 통과한 뒤에만 next를 current로 올린다
- 타이머와 키 교체: 노트 "상수와 타이머" 표의 값 그대로. 재시도마다 initiation을 새로 만든다
- 세션이 서기 전의 송신 대기열: 피어당 최대 64개, 넘치면 가장 오래된 것을 버린다
- cookie reply의 수신 처리와 그 뒤 initiation의 mac2(상대가 부하 상태일 때 회복하는 데 필요하다)

제외(코드에 `shortcut:` 주석으로 한계를 남긴다):

- cookie reply를 **보내는** 쪽(부하 판정, rate limiter). 필요해지는 시점: 신뢰할 수 없는 네트워크에 UDP 포트를 여는 M4
- PSK 설정, persistent keepalive
- 버퍼 재사용. 지금은 패킷마다 배열을 만든다. 필요해지는 시점: M5의 실기기 처리량·메모리 측정에서 병목으로 확인될 때

## 시험

단위 시험(`Tests/SwiftailWireGuardTests`, 실제 시간 대기 없음):

1. Swift 장치 둘을 메모리에서 연결: 양쪽 역할의 핸드셰이크, 양방향 데이터, keepalive, 대기열 방출.
2. 시간 주입: 120초 뒤 초기자의 rekey, 응답자 쪽 rekey, 180초 넘은 키의 거부, 핸드셰이크 재시도(5초 + 지터)와 포기, 540초 뒤 키 재료 삭제.
3. 재전송 방지 창: wireguard-go `replay/replay_test.go`의 사례를 옮긴다(파일 머리에 출처와 MIT 라이선스).
4. 유실·변조: response 유실 뒤 복구, 옛 response가 새 핸드셰이크를 덮지 않음, 변조된 메시지가 상태를 바꾸지 않음, AllowedIPs 밖 출발 주소 거부.
5. cookie: reply 소비 뒤 mac2가 붙는다. cookie는 120초 뒤 쓰지 않는다.
6. 어떤 바이트열을 `receive`에 넣어도 죽지 않는다(길이 0~200의 무작위·경계 입력).

상호 운용 관문(`Tests/SwiftailWireGuardInteropTests`, `Tools/interop`의 wireguard-go 피어 상대, UDP 루프백):

1. Swift 초기자 → Go 응답자, Go 초기자 → Swift 응답자.
2. 양방향 IP 패킷 교환(여러 크기, 패딩 포함).
3. 실제 시간으로 120초를 넘겨 rekey 뒤에도 교환이 이어진다(Swift가 초기자인 경우와 응답자인 경우).
4. 변조·재전송한 데이터그램을 Go가 버리고 세션은 유지된다.
