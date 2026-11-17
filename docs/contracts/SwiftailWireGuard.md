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
    case replayed               // 핸드셰이크 timestamp·flood 검사, 이미 처리한 response, 전송 카운터 재사용
    case noSession              // 쓸 수 있는 keypair가 없음(만료 포함)
    case disallowedSource       // 복호화한 IP 패킷의 출발 주소가 피어의 AllowedIPs 밖(rejectedIPPacket으로만 나온다)
    case packetTooLarge
    case rateLimited            // 부하 상태에서 mac2까지 맞았지만 출처 호스트의 몫(초당 20개, 버스트 5)을 넘음
}

/// 한 노드의 WireGuard 상태 전체(자기 정적 키와 피어들).
public struct WireGuardDevice: Sendable {
    public enum Output: Sendable, Equatable {
        /// 네트워크로 보낼 WireGuard 메시지. 어느 경로로 보낼지는 호출하는 쪽이 정한다.
        case datagram([UInt8], to: PublicKey)
        /// 복호화와 AllowedIPs 검사를 통과한 IP 패킷.
        case ipPacket([UInt8], from: PublicKey)
        /// 피어가 보낸 것은 맞지만 올리지 않은 IP 패킷. 이유는 malformed 또는 disallowedSource.
        case rejectedIPPacket(WireGuardError, from: PublicKey)
        /// 부하 상태에서 mac2가 맞지 않는 핸드셰이크 메시지에 답하는 cookie reply(64바이트).
        /// 방금 받은 데이터그램의 출처로 그 길 그대로 보낸다(피어 경로 선택을 거치지 않는다).
        case cookieReply([UInt8])
    }

    /// 받은 데이터그램이 온 곳. 장치는 내용을 해석하지 않는다.
    public struct Source: Hashable, Sendable {
        public var address: [UInt8]   // cookie가 묶이는 값(UDP면 주소 ‖ 포트)
        public var host: [UInt8]      // 속도 제한 단위(UDP면 주소)
        public init(address: [UInt8], host: [UInt8])
    }

    /// wallClock은 now 시점의 벽시계 시각이다. 이후의 TAI64N timestamp는
    /// wallClock + (호출 시각 − now)로 계산하므로 단조 증가한다.
    public init(privateKey: Curve25519.KeyAgreement.PrivateKey, now: ContinuousClock.Instant, wallClock: Date)

    public var publicKey: PublicKey { get }

    /// 피어를 등록한다. 이미 있으면 AllowedIPs만 바꾸고 세션은 유지한다.
    public mutating func addPeer(_ peer: PublicKey, allowedIPs: [IPPrefix])
    /// 피어와 그 키 재료를 지운다. 마지막으로 받아들인 initiation timestamp만은 장치에 남긴다(아래 "포함").
    public mutating func removePeer(_ peer: PublicKey)
    /// 2026-11-16에 더했다. 이 피어와의 세션 키가 설 때마다 터널 안으로 먼저 보낼 평문 IP 패킷(Tailscale 포크의 priority
    /// message). nil이면 지운다. 빈 패킷은 `malformed`, 512바이트 초과는 `packetTooLarge`, 모르는 피어는 `unknownPeer`.
    public mutating func setPriorityMessage(_ message: [UInt8]?, for peer: PublicKey) throws(WireGuardError)

    /// IP 패킷 하나를 피어에게 보낸다. 세션이 없으면 대기열에 넣고 핸드셰이크를 시작한다.
    public mutating func send(_ ipPacket: [UInt8], to peer: PublicKey, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output]

    /// 네트워크에서 받은 데이터그램 하나를 처리한다.
    /// 오류를 던진 경우 상태는 바뀌지 않는다(부하 판정을 위한 기록은 예외이며 주석으로 밝힌다).
    public mutating func receive(_ datagram: [UInt8], from source: Source, at now: ContinuousClock.Instant) throws(WireGuardError) -> [Output]

    /// now까지 기한이 지난 타이머를 모두 처리한다.
    public mutating func advance(to now: ContinuousClock.Instant) -> [Output]

    /// 다음에 advance를 불러야 하는 시각. 걸린 타이머가 없으면 nil.
    public var nextDeadline: ContinuousClock.Instant? { get }
}
```

오류와 상태: `send`·`receive`가 오류를 던지면 피어 상태는 그대로다. 피어를 표 안에서 제자리로 고치므로(`edit`) 이 성질은 구조가 아니라 순서로 지킨다: 오류를 던지는 검사(mac, AEAD, timestamp·재전송 창, 만료, 크기)는 모두 피어를 고치기 전에 끝내고, 재전송 창은 인증된 counter를 받아들일 때만 바뀐다. `Tests/SwiftailWireGuardTests/FailureAtomicityTests.swift`가 거절한 입력마다 세션·카운터·재전송 창·타이머·index 표 전체가 그대로인지 비교한다. 예외는 공격을 세는 기록이다: 부하 판정을 위한 mac1 통과 수와 속도 제한 표(flood 검사의 기준 시각은 initiation을 받아들였을 때만 바뀐다). AEAD와 재전송 검사를 통과한 transport는 안의 IP 패킷이 잘못됐거나 출발 주소가 AllowedIPs 밖이어도 오류가 아니다. 인증된 피어가 보낸 것이므로 next 확정, 대기열 방출, rekey, 타이머 갱신을 정상 수신과 같이 하고(wireguard-go와 같다), 버린 패킷은 `rejectedIPPacket`으로 알린다.

시각: `wallClock`이 1970년 이전이면 1970년으로 본다.

난수: 핸드셰이크 단계는 ephemeral 키와 index를 인자로 받는 순수 함수다. 시스템 난수는 장치 계층(index, ephemeral, 재시도 지터)에서만 뽑는다.

송신 크기: 장치는 MTU를 모른다. 상한은 wireguard-go 기본값(65535 − 40)이고, 실제 크기 제한은 TUN의 MTU가 맡는다.

호출 규칙: `now`는 호출마다 줄어들지 않아야 한다. `send`·`receive`도 내부에서 기한이 지난 타이머를 먼저 처리한다고 가정하지 않는다. 호출하는 쪽은 `nextDeadline`에 맞춰 `advance`를 부른다.

## M1 범위

포함(노트의 "필수" 전부):

- 메시지 4종의 직렬화·해석, mac1 생성·검사
- Noise IKpsk2 초기자·응답자. PSK는 32바이트 0으로 고정하되 KDF3 단계는 그대로 둔다
- TAI64N 생성, 피어별 timestamp 재전송 검사, initiation flood 검사(20ms)
- 내린 피어의 마지막 timestamp: `removePeer`가 장치에 남기고(1,024개까지, 넘으면 먼저 내린 것부터 잊는다) 같은 키의 `addPeer`가 되살린다. 피어가 netmap에서 빠졌다 돌아와도 그 전에 받은 initiation의 재전송은 `replayed`다(2026-11-17 보안 검증). wireguard-go는 피어를 지우면 이 값도 버린다
- 전송 암복호화, 카운터, 패딩(16의 배수), keepalive, 재전송 방지 창(8128)
- keypair의 previous·current·next 전환. 응답자는 새 키로 온 첫 패킷이 AEAD와 재전송 검사를 통과한 뒤에만 next를 current로 올린다
- 타이머와 키 교체: 노트 "상수와 타이머" 표의 값 그대로. 재시도마다 initiation을 새로 만든다
- 세션이 서기 전의 송신 대기열: 피어당 최대 64개, 넘치면 가장 오래된 것을 버린다
- cookie reply의 수신 처리와 그 뒤 initiation의 mac2(상대가 부하 상태일 때 회복하는 데 필요하다)
- cookie reply 보내기(부하 판정, mac2 검사, 출처별 속도 제한). 2026-11-15에 더했다. 아래 "cookie reply 보내기"
- priority message(2026-11-16, Tailscale 포크 wireguard-go `SendPriorityMessage`): 시작한 쪽은 response를 받아 세션이 섰을 때 keepalive·대기열보다 먼저, 응답한 쪽은 새 세션으로 온 첫 transport로 next를 확인했을 때 대기열보다 먼저 current로 한 번 보낸다. 보낼 세션이 없으면 핸드셰이크를 시작하지 않고 그만두고, 데이터 송신으로 센다(새 핸드셰이크 타이머). rekey로 세션이 새로 서면 다시 보낸다. 시험 `Tests/SwiftailWireGuardTests/PriorityMessageTests.swift`

제외(코드에 `shortcut:` 주석으로 한계를 남긴다):

- PSK 설정, persistent keepalive
- 송수신 버퍼의 완전한 재사용. 패킷마다 결과 배열(송신은 머리·암호문·태그를 담은 배열 하나, 수신은 평문 배열)을 새로 만들고, CryptoKit이 돌려주는 `SealedBox`·`Data`에서 한 번씩 복사한다(CryptoKit에는 호출하는 쪽 버퍼에 직접 쓰는 API가 없다). `nextDeadline`·`advance`는 피어 수만큼 훑는다(피어 64명에 약 1.4µs). 필요해지는 시점: M5의 실기기 처리량·메모리 측정에서 이 복사나 피어 수가 병목으로 확인될 때. 불필요한 복사는 없앴다(2026-11-15): 패킷마다 피어 전체를 복사하던 `store`를 표 안 제자리 고치기로 바꿨고, 메시지·타이머·nonce의 중간 배열을 줄였다(1,280바이트 패킷, 릴리스 빌드, 메모리 안 장치 둘: seal 5.1→3.0µs, open 5.5→3.5µs)

## cookie reply 보내기 (2026-11-15)

node 공개 키는 비밀이 아니므로 mac1이 맞는 initiation은 누구나 만들 수 있고, 받는 쪽은 그때마다 X25519를 계산한다. 그래서 받는 쪽은 부하 상태에서 mac2를 요구하고 cookie reply로 답하며, 출처 호스트별로 속도를 제한한다(백서 §5.3, 노트 "mac1·mac2와 cookie"). 이 장치는 iOS 확장 안에서도 돈다.

1. **순서**(wireguard-go `device/receive.go`): initiation·response는 mac1을 검사하고(틀리면 `authenticationFailed`, 부하 수에 세지 않는다) → 부하 판정에 센다 → 부하이면 mac2를 검사해 틀리면 `.cookieReply`를 내고 메시지를 처리하지 않는다(X25519 전) → mac2가 맞으면 출처 `host`의 속도 제한을 넘을 때 `rateLimited` → 나머지는 부하가 아닐 때와 같다. 부하가 아닐 때는 mac2를 보지 않는다.
2. **부하 판정**(`HandshakeLoad`): Go는 핸드셰이크 큐 길이가 문턱(기본 1024/8 = 128, Tailscale iOS는 큐 64라서 8)에 이르렀는지로 본다(`device/device.go` `IsUnderLoad`, `wgengine/wgcfg/mem_ios.go`). 이 장치에는 큐가 없고 받은 자리에서 처리하므로, **mac1을 통과한 핸드셰이크 메시지가 1초보다 짧은 간격 안에 128개**에 이르면 부하로 본다. 감지한 뒤 Go와 같이 1초(`UnderLoadAfterTime`) 동안 부하로 머물고 그 시각 정각에 끝난다. 바꿀 수 있는 옵션이 아니다.
   - 근거: 응답자가 initiation 하나를 처리하는 시간은 이 개발 기기(Apple Silicon Mac, release)에서 약 211µs, cookie reply 하나는 약 20µs다(400개 평균). 문턱 128/초는 X25519 경로에 한 코어의 약 2.7%(iPhone이 1.5배 느리다고 보아도 약 4%)까지만 쓰게 하는 값이다. Go의 큐 문턱은 "처리가 밀렸다"는 뜻이라 초당 비율로 바로 옮길 수 없다. 큐가 128개 밀리려면 처리 속도(이 기기에서 초당 약 4,700개)를 넘는 입력이 와야 하므로 Go 데스크톱보다는 이르게, Go iOS(8개 밀림, 약 2ms 분량)보다는 늦게 걸린다.
   - 정상적인 tailnet: 한 피어는 핸드셰이크 메시지를 `RekeyTimeout`(5초)에 한 번보다 자주 보내지 않는다. 망이 바뀌거나 잠에서 깨어 모든 활성 피어가 한꺼번에 다시 핸드셰이크해도 1초에 피어당 많아야 2개(상대의 initiation과 우리 initiation의 response)이므로, 활성 피어 64개(한쪽만 시작하면 128개)까지는 걸리지 않는다. 잘못 걸려도 그 피어는 cookie를 받아 5초 뒤 재시도에서 mac2로 통과한다(끊기지 않고 늦어질 뿐이다).
3. **cookie와 비밀**(`CookieChecker`, wireguard-go `device/cookie.go`): cookie = MAC(비밀 32바이트, `source.address`), mac2 = MAC(cookie, mac2 앞까지). 비밀은 처음 reply를 만들 때 시스템 난수로 뽑고, 만든 지 120초(`CookieRefreshTime`)가 지난 뒤 reply를 만들 때 바꾼다. 비밀이 없거나 120초를 넘었으면 mac2는 늘 틀리다. reply = type 3 ‖ receiver(거절한 메시지의 sender) ‖ nonce 24(시스템 난수) ‖ XChaCha20-Poly1305(키 HASH("cookie--" ‖ 자기 공개 키), 평문 cookie, AAD 거절한 메시지의 mac1), 64바이트. 비밀·cookie·출처는 `description`·`dump`·오류에 나오지 않는다(`WireGuardDevice`의 `customMirror`는 공개 키와 피어만 보인다).
4. **출처별 속도 제한**(`RateLimiter`, wireguard-go `ratelimiter/ratelimiter.go`): `source.host`마다 초당 20개, 버스트 5(`packetCost` 50ms, `maxTokens` 250ms). 새 호스트는 첫 메시지를 받고 토큰 `maxTokens − packetCost`로 시작하고, 아는 호스트는 지난 시간만큼 채우되 상한을 넘지 않으며 토큰이 `packetCost`보다 클 때만 받는다.
   - **표 상한 4096개**. Go는 상한 없이 1초마다 1초 넘게 쉰 항목을 지운다. 여기서는 표가 찼을 때만 1초 넘게 쉰 항목을 지우고, 그래도 차 있으면 새 호스트를 받지 않는다(닫힌 쪽). 늦게 지워도 결과는 같다(1초 넘게 쉰 항목의 토큰은 상한까지 차 있어 새 항목과 똑같이 동작한다). 항목에는 그 출처에서 cookie를 받아 mac2를 맞춘 호스트만 들어가므로 주소를 꾸며 표를 채울 수 없고, 4096개(항목당 약 100바이트로 어림하면 약 400KB, 재지 않았다)는 큰 tailnet의 동시 재핸드셰이크보다 넉넉하다. 닫힌 쪽을 고른 까닭: 열린 쪽(오래된 항목을 밀어내기)은 실제 주소를 많이 가진 공격자가 이미 표에 있는 호스트의 몫을 지워 버릴 수 있고, 표를 키우면 메모리가 입력만큼 자란다. 상한에 닿은 동안 새 호스트는 1초 안에 쉬는 항목이 생길 때까지 핸드셰이크하지 못한다.
   - 총괄 확정(2026-11-15): 문턱 128개/1초, 표 상한 4096개와 닫힌 쪽을 그대로 쓴다. UDP 출처는 Go처럼 피어 단위로 묶지 않고 실제 주소와 포트에 묶는다(WireGuard 규격의 뜻 그대로다. 같은 피어의 UDP와 DERP cookie가 서로 맞지 않아 한 번 더 왕복할 수 있다). 실제 iPhone에서의 처리 시간과 표의 메모리는 재지 않았다.
5. **출처**: 노드가 받은 길에서 만든다(엔진 계약 N5 "cookie reply"). 장치는 `address`와 `host`를 해석하지 않는다.

시험(`Tests/SwiftailWireGuardTests/CookieReplyTests.swift`, `RateLimiterTests.swift`, 상호 운용 `cookieReplyUnderLoad`): 문턱과 창의 경계, 1초 유지, mac1이 틀린 것은 세지 않음, 실제 입력으로 문턱을 넘김, reply 형식과 Swift 소비 코드와의 왕복, 열리지 않는 본문·모르는 피어에도 X25519 전에 reply, 다른 출처의 mac2와 낡은 비밀의 cookie 거절, 비밀 교체 주기, response에도 mac2 요구, 장치에서의 속도 제한 경계, Go `TestRatelimiter`의 일정, 표 상한과 정리, 부하 상태의 임의 입력, `dump`. 상호 운용: wireguard-go가 초기자이고 Swift가 부하 상태일 때 Go가 cookie reply를 받아 mac2를 붙인 재시도로 핸드셰이크를 마친다(부하 상태는 시험 전용으로 `underLoadUntil`을 정해 만든다).

## 시험

단위 시험(`Tests/SwiftailWireGuardTests`, 실제 시간 대기 없음):

1. Swift 장치 둘을 메모리에서 연결: 양쪽 역할의 핸드셰이크, 양방향 데이터, keepalive, 대기열 방출.
2. 시간 주입: 120초 뒤 초기자의 rekey, 응답자 쪽 rekey, 180초 넘은 키의 거부, 핸드셰이크 재시도(5초 + 지터)와 포기, 540초 뒤 키 재료 삭제.
3. 재전송 방지 창: wireguard-go `replay/replay_test.go`의 사례를 옮긴다(파일 머리에 출처와 MIT 라이선스).
4. 유실·변조: response 유실 뒤 복구, 옛 response가 새 핸드셰이크를 덮지 않음, 변조된 메시지가 상태를 바꾸지 않음, AllowedIPs 밖 출발 주소 거부.
5. cookie: reply 소비 뒤 mac2가 붙는다. cookie는 120초 뒤 쓰지 않는다. 보내는 쪽은 위 "cookie reply 보내기"의 시험.
6. 어떤 바이트열을 `receive`에 넣어도 죽지 않는다(길이 0~200의 무작위·경계 입력).

상호 운용 관문(`Tests/SwiftailWireGuardInteropTests`, `Tools/interop`의 wireguard-go 피어 상대, UDP 루프백):

1. Swift 초기자 → Go 응답자, Go 초기자 → Swift 응답자.
2. 양방향 IP 패킷 교환(여러 크기, 패딩 포함).
3. 실제 시간으로 120초를 넘겨 rekey 뒤에도 교환이 이어진다(Swift가 초기자인 경우와 응답자인 경우).
4. 변조·재전송한 데이터그램을 Go가 버리고 세션은 유지된다.
