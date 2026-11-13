# Swiftail 기획

기준: `tailscale.com v1.104.6`(CapabilityVersion 148), `github.com/tailscale/wireguard-go v0.0.0-20261106233718-9e0ab45c16ca`. 프로토콜 세부는 [protocol-notes/](protocol-notes/README.md)에 둔다.

## 1. 목표

Go의 tsnet과 Tailscale 엔진 없이, Swift만으로 tailnet 노드가 된다.

1. iOS Network Extension 패킷 터널 안에서 50MiB 한도 아래로 상주한다.
2. 앱 프로세스 안에서 권한 없이 tailnet 리스너를 열고 tailnet 주소로 접속한다.
3. 첫 사용처(RemoteDebug)의 Go 코어가 Tailscale에 기대는 기능을 대체할 수 있다.
4. 라이브러리 전체를 Swift로 쓰고, 코드가 Swift 개발자에게 길잡이가 된다(5절의 코드 기준).

## 2. 첫 사용처의 요구 사항

RemoteDebug의 Go 코어가 쓰는 Tailscale 기능과 Swiftail에서 대응하는 단계다.

| RemoteDebug가 쓰는 것 | 용도 | Swiftail 단계 |
| --- | --- | --- |
| 노드 등록(인증 키, 대화형 로그인 URL, 30초 간격 로그인 재시도), 상태 파일 | 다시 시작해도 같은 노드·같은 tailnet IP | M2 |
| 상태 알림(`NeedsLogin`·`Running` 등, `authURL`) | 앱 UI | M2 |
| 터널 엔진 + utun fd, MTU 1280~1420 | iOS 패킷 터널 | M5 |
| 주소·경로·DNS 설정 산출(피어별 /32, 100.100.100.100/32, 일치 도메인) | `NEPacketTunnelNetworkSettings` | M5 |
| MagicDNS 응답(tailnet 이름, 역방향 영역. 그 밖의 이름은 SERVFAIL) | 호스트 FQDN 해석 | M5 |
| 기본 인터페이스 전환 통지 → 소켓 재결속 | Wi-Fi ↔ 셀룰러 | M5 |
| 피어까지의 경로(직접·중계) 조회 | 상태 표시 | M4 |
| `Listen("tcp", ":443")`, `Dial` | Mac의 HTTPS 서버, 프록시 모드 | M6 |
| `WhoIs`(원격 주소 → 노드·사용자) | 페어링, 요청마다 신원 확인 | M7 |
| ts.net 인증서(`CertPair`, `GetCertificate`) | iOS 설치기가 요구하는 유효한 HTTPS | M7 |

## 3. 범위

### 포함

- 제어 프로토콜(ts2021): 등록, 로그인, netmap 스트림과 증분, 키 만료 처리
- WireGuard 데이터면
- DERP 중계 클라이언트
- 직접 연결: disco, STUN, 엔드포인트 선택, 경로 전환
- 수신 패킷 필터(ACL)
- MagicDNS 응답기(tailnet 이름)
- 상태 저장
- iOS 패킷 터널 통합(utun 입출력, 설정 산출, 인터페이스 전환)
- 프로세스 내 TCP 리스너·다이얼, WhoIs, ts.net 인증서

### 제외

서브넷 라우터, 출구 노드(제공·사용), Tailscale SSH, Taildrop, Taildrive, Funnel·Serve, 피어 릴레이, 포트 매핑(UPnP·NAT-PMP·PCP), 앱 커넥터, 로그 업로드, 자동 업데이트, 기기 상태(posture) 보고, Linux·Windows.

tailnet lock(노드 키 서명 검증)은 1차 범위에서 제외한다. 이 기능을 켠 tailnet에서 Swiftail이 어떻게 동작해야 하는지는 M2에서 정한다(8절 위험 8).

## 4. 결정

### (a) 사용자 공간 TCP/IP 스택

**Swift로 직접 구현한다**(사용자 결정, 2026-11-14). 라이브러리에 C 코드를 들이지 않는다. lwIP 래핑과 Mac의 Network Extension 사용은 채택하지 않았다.

- 1차 목표(M0~M5)에는 필요 없다. iOS 패킷 터널은 OS의 스택을 쓴다. M6에서 `SwiftailNetstack` 타깃으로 만든다.
- 범위는 tailnet 안의 TCP 연결에 필요한 만큼으로 잡는다: 수동·능동 연결, MSS, 창 확장, RFC 6298 재전송 타이머, 빠른 재전송과 NewReno, 지연 ACK, 0 창 탐침, FIN·RST. IP 단편화 재조립과 SACK은 측정 뒤에 판단한다.
- WireGuard와 같은 구조로 쓴다: 소켓도 시계도 갖지 않는 상태 기계 + 가장자리의 입출력. 손실·재정렬·지연을 시험에서 결정적으로 재현할 수 있다.
- 검증 상대는 둘이다: Go 피어(gVisor netstack)와 macOS 커널 스택.

### (b) 상호 운용 시험 상대

1. **기본 관문: Go `testcontrol` + `derpserver` + `stuntest` + Go tsnet 피어.** `Tools/interop`(Go 모듈)이 한 프로세스로 띄우고 주소를 JSON으로 출력한다. 계정이 필요 없고 매번 같은 조건으로 돌릴 수 있다. RemoteDebug의 가짜 tailnet과 같은 구성이다. M1은 같은 도구가 wireguard-go 피어를 띄운다.
2. **마무리 관문: 실제 tailnet.** testcontrol은 운영 제어 서버와 다를 수 있으므로 M2·M4·M5의 끝에 한 번씩 실제 tailnet에 임시(ephemeral) 노드로 접속해 확인한다. 매번 사용자에게 먼저 알리고, 인증 키는 채팅이 아닌 비밀 입력으로 받는다.
3. headscale은 기본 관문에 넣지 않는다. 실제 tailnet을 쓸 수 없게 되면 대안으로 쓴다.

### (c) 최소 OS와 의존성

- iOS 18, macOS 15 이상. `Synchronization`(Mutex, Atomic)을 쓰기 위해서다. 첫 사용처의 배포 대상은 26.0이다.
- 코어 타깃은 외부 Swift 패키지에 의존하지 않는다. CryptoKit, Network, Foundation만 쓴다.
  - 암호: CryptoKit에 없는 것만 `SwiftailCrypto`에 직접 구현한다(BLAKE2s, XSalsa20-Poly1305, HChaCha20).
  - HTTP/2: 제어 연결 하나, 스트림 몇 개만 쓰므로 최소 클라이언트를 직접 구현한다. 운영 서버와의 상호 운용에서 문제가 반복되면 swift-nio-http2로 바꾼다.
  - TLS(제어 443, DERP): Network 프레임워크.
  - UDP(WireGuard·disco·STUN): 포트 하나로 여러 상대와 주고받아야 하므로 POSIX 소켓을 쓴다.
- 시험 도구는 Go를 쓴다(`Tools/`). 상호 운용의 상대가 Go 구현이기 때문이며, 라이브러리에는 링크되지 않는다.

### (d) 1차 목표

**M5까지: iOS 패킷 터널 노드.** Go 대비 이점(메모리)이 여기서 나오고 TCP 스택이 필요 없다. 이 시점에 RemoteDebug의 iPhone 터널 확장을 Swiftail로 바꿀 수 있고, Mac은 Go tsnet을 계속 써도 같은 tailnet에서 서로 통한다. M6·M7(Mac 호스트 대체)은 2차 목표다.

## 5. 모듈

타깃은 필요해지는 마일스톤에 만든다. 화살표는 의존 방향이다.

```
SwiftailCrypto ◄─ SwiftailWireGuard ◄─┐
       ▲◄──────── SwiftailControl  ◄──┤
       ▲◄──────── SwiftailDERP     ◄──┼─ SwiftailEngine ◄─ Swiftail ◄─ SwiftailNetstack(선택)
       ▲◄──────── SwiftailMagicsock ◄─┘
```

`SwiftailBase`(IP 주소·접두 같은 공용 값 타입)는 모든 타깃이 쓴다.

### 코드 기준

이 저장소는 프로토콜을 Swift로 어떻게 쓰는지 보여 주는 본보기이기도 하다.

- **상태 기계는 값 타입으로, 입출력은 가장자리에.** 프로토콜 로직은 소켓·시계·난수원을 갖지 않는 `struct`로 쓰고 시각은 인자로 받는다. 소켓과 타이머는 그것을 감싸는 actor가 맡는다. 시험은 시간을 직접 넘겨 결정적으로 돌린다.
- **타입 있는 오류**(`throws(SomeError)`)로 실패의 종류를 시그니처에 드러낸다.
- **안전하지 않은 도구는 이유와 함께만.** `Unsafe*` 포인터, `@unchecked Sendable`, `nonisolated(unsafe)`, 강제 언래핑·`try!`는 쓰지 않는다. POSIX 호출처럼 피할 수 없는 곳은 좁게 가두고 이유를 주석으로 남긴다.
- **신뢰할 수 없는 입력은 경계에서 한 번 해석한다.** 바이트 배열을 그대로 들고 다니지 않고 검증된 타입으로 바꾼다. 어떤 입력으로도 프로세스가 죽지 않는다.
- **이름은 Swift API Design Guidelines를 따른다.** 프로토콜 용어(initiation, cookie, netmap)는 원문을 쓴다.
- **문서 주석은 무엇을·왜를 적고 규격의 절을 가리킨다.** 파일 하나는 개념 하나를 다루고 위에서 아래로 읽힌다.
- 적게 쓴다. 본보기는 분량이 아니라 읽히는 구조에서 나온다.

| 타깃 | 마일스톤 | 책임 | 하지 않는 것 |
| --- | --- | --- | --- |
| `SwiftailBase` | M1 | IP 주소·접두, 16진 변환 | |
| `SwiftailCrypto` | M0 | BLAKE2s, HMAC·HKDF-BLAKE2s, NaCl box·secretbox, XChaCha20-Poly1305, 상수 시간 비교 | X25519, ChaCha20-Poly1305(CryptoKit 사용) |
| `SwiftailWireGuard` | M1 | Noise IKpsk2 핸드셰이크, cookie, 전송 암복호화, 재전송 방지, 타이머·키 교체, AllowedIPs | 소켓, TUN. 데이터그램 송신과 IP 패킷 전달은 주입받는다 |
| `SwiftailControl` | M2 | 키 타입과 인코딩, tailcfg 모델, 제어 Noise, 최소 HTTP/2, 등록·맵 클라이언트, netmap과 증분 적용 | 데이터면 설정 |
| `SwiftailDERP` | M3 | DERP 프레임, 연결·재연결, 지역별 연결 관리 | 홈 지역 선택 |
| `SwiftailMagicsock` | M4 | disco, STUN, 지연 측정과 홈 지역 선택, 엔드포인트 상태 기계, UDP 소켓과 재결속, WireGuard에 대한 송수신 창구 | |
| `SwiftailEngine` | M3~M5 | netmap → WireGuard 피어·필터·경로·DNS, 패킷 필터, MagicDNS 응답기, 상태 저장, TUN(utun fd, 메모리) | |
| `Swiftail` | M2~ | 공개 API(`TailnetNode`) | |
| `SwiftailNetstack` | M6 | Swift로 쓴 TCP: 리스너·다이얼 | |

### 노트에서 확인해 설계에 반영한 것

- WireGuard(포크)에는 엔드포인트 로밍이 없다. 피어의 경로는 magicsock이 고른다. `SwiftailWireGuard`는 주소를 다루지 않고 "이 피어에게 보낼 데이터그램"만 내놓는다.
- Tailscale은 PSK를 쓰지 않는다(0). cookie는 상대가 부하 상태일 때만 오므로 M1에서 수신 처리만 넣는다. mac1은 처음부터 정확해야 한다.
- 제어 Noise의 레코드 nonce는 빅엔디언 카운터이고 레코드는 4096바이트가 한도다. HTTP/2 프레임을 레코드에 나눠 싣는다. 핸드셰이크 뒤 서버가 먼저 보내는 early payload를 처리해야 한다.
- 맵 스트림과 상태 갱신(엔드포인트, Hostinfo)은 별도 요청이다. `null`·빈 배열·생략의 차이가 증분 적용의 의미를 가른다.
- 피어별 AllowedIPs와 경로는 netmap에서 계산한다. iOS는 피어별 /32가 기본이다. 유휴 피어는 WireGuard에 올리지 않는다.
- MagicDNS는 호스트 표를 미리 만들지 않고 질의마다 netmap에서 찾는다.
- disco 키는 저장하지 않고 시작할 때마다 새로 만든다. 저장해야 하는 것은 machine 키와 프로필(노드 키 포함)이다.
- 직접 경로의 신뢰 기간은 6.5초다. 만료되면 UDP와 DERP로 함께 보내며 다시 탐색한다. WireGuard 세션이 서면 Go 피어는 터널 안으로 disco 키 알림(TSMP)을 보내므로 받아서 처리해야 한다.

## 6. 공개 API 초안

마일스톤마다 필요한 부분만 확정한다. 아래는 방향이다.

```swift
public struct NodeConfiguration: Sendable {
    public var stateDirectory: URL
    public var hostname: String
    public var controlURL: URL        // 기본값은 Tailscale 제어 서버
    public var authKey: String?       // 첫 등록에만 쓴다
    public var ephemeral: Bool
}

public enum TunnelDevice: Sendable {
    case utun(fileDescriptor: Int32, mtu: Int)   // iOS 패킷 터널. fd를 복제해 쓴다
    case inProcess                               // M6: SwiftailNetstack
}

public actor TailnetNode {
    public init(configuration: NodeConfiguration, device: TunnelDevice) throws
    public func start() async throws
    public func stop() async
    public var status: NodeStatus { get }
    public nonisolated var events: AsyncStream<NodeEvent> { get }
    public func startInteractiveLogin() async throws
    public func setDefaultInterface(_ name: String)
    public func path(toPeerNamed fqdn: String) -> PeerPath?        // M4
    public func whoIs(_ address: TailnetAddress) -> PeerIdentity?  // M7
}

public enum NodeState: Sendable { case needsLogin, needsMachineAuth, starting, running, stopped, failed }

public enum NodeEvent: Sendable {
    case state(NodeState, authURL: URL?, errorMessage: String?)
    case networkSettings(TunnelNetworkSettings)   // 바뀐 경우에만
}

/// 앱이 NEPacketTunnelNetworkSettings로 옮겨 적용한다. 라이브러리는 NetworkExtension에 의존하지 않는다.
public struct TunnelNetworkSettings: Sendable, Equatable {
    public var addresses: [String]        // CIDR
    public var routes: [String]           // CIDR
    public var dnsServers: [String]
    public var dnsMatchDomains: [String]
    public var mtu: Int
}

// M6 (SwiftailNetstack)
extension TailnetNode {
    public func listen(port: UInt16) async throws -> TailnetListener
    public func dial(host: String, port: UInt16) async throws -> TailnetConnection
}
```

## 7. 마일스톤과 관문

각 마일스톤은 계약 확정 → 구현 → 단위 시험 → 상호 운용 관문 → 다른 제공자의 검토 → 커밋 순서로 진행한다. 관문 시험은 총괄이 직접 다시 돌려 확인한다. 단위 시험 통과만으로 프로토콜 동작을 주장하지 않는다.

| 단계 | 내용 | 관문(통과 조건) |
| --- | --- | --- |
| M0 ✅ | 암호 기본기 | 규격의 공개 벡터 전부, Go `x/crypto`로 만든 교차 벡터, 변조 시험 통과. 다른 제공자의 코드 검토 |
| M1 | WireGuard | wireguard-go 피어와 UDP 루프백에서: Swift가 초기자·응답자 양쪽으로 핸드셰이크, 양방향 패킷 교환, 실제 시간으로 rekey를 넘긴 뒤에도 유지, 변조·재전송 패킷 거부. cookie는 소스 트리의 벡터와 Swift끼리의 시험으로 확인 |
| M2 | 제어 프로토콜 | testcontrol에 등록하고 netmap을 받는다. Go tsnet 피어의 입장·퇴장이 반영된다. testcontrol은 기본으로 전체 맵만 보내므로 증분(피어 추가·제거·패치)은 시험 도구가 응답을 주입해 확인한다. 다시 시작하면 같은 노드 키·같은 tailnet IP. 마무리: 실제 tailnet에 임시 노드로 등록되어 관리 콘솔에 보이고, 비압축 맵 응답을 받을 수 있는지 확인한다 |
| M3 | DERP만으로 통신 | UDP 직접 경로 없이 로컬 DERP 서버만으로 Go tsnet 피어의 UDP 에코와 왕복. TCP SYN에 SYN-ACK가 돌아온다. ACL이 막은 포트의 패킷은 버려진다 |
| M4 | 직접 연결 | Go 피어와 루프백·LAN에서 직접 경로가 잡힌다(Go 쪽 상태에서 직접 주소 확인). 직접 경로를 막으면 DERP로 내려가고 풀면 다시 올라온다. 마무리: 실제 tailnet에서 NAT 뒤의 기기와 직접 경로 |
| M5 | iOS 패킷 터널 | MagicDNS는 UDP 질의만 답한다(아래 8절 위험 12). 메모리 TUN으로 RemoteDebug `docs/tunnel.md`의 시험 계약에 대응하는 항목(설정 산출, UDP·TCP·MagicDNS, 다시 시작, 엔진 정지) 통과. 실기기: 시험용 터널 앱으로 Mac의 tailnet HTTPS에 접속, FQDN 해석, Wi-Fi ↔ 셀룰러 전환 뒤 복구, 유휴·전송 중 `phys_footprint` 기록 |
| M6 | 프로세스 내 리스너(Swift TCP) | 상태 기계 단위 시험(손실·재정렬·중복·지연 주입)과, Go 피어(gVisor)·macOS 커널 스택을 상대로 한 100MB 양방향 전송의 해시 일치. 손실 1%·5% 조건에서 전송이 멈추지 않고 처리량을 기록한다 |
| M7 | RemoteDebug 대체 검증 | WhoIs, ts.net 인증서 발급, Go 상태 파일에서의 이관 여부 결정, C API 18개와의 대응표, RemoteDebug e2e 시나리오(페어링 → 설치 세션 → IPA 전송)를 Swiftail 노드로 재현. RemoteDebug 저장소를 바꾸는 일은 별도 승인 뒤에 한다 |

메모리 목표(M5): 유휴 상주 20MiB 이하를 목표로 두고 실기기 측정으로 확정한다. Go 코어의 권장 한도 설정은 28MiB였다.

## 8. 위험과 대안

| # | 위험 | 대응 |
| --- | --- | --- |
| 1 | testcontrol은 통과하지만 운영 제어 서버에서 실패한다(HTTP/2 동작, 필수 필드, 버전 요구) | M2 마무리 관문을 실제 tailnet으로 둔다. HTTP/2는 swift-nio-http2로 바꿀 수 있게 경계를 둔다 |
| 2 | 제어 프로토콜은 공개 계약이 아니다. 서버 변경으로 멈출 수 있다 | 기준 버전을 고정하고 README에 명시한다. 올릴 때 관문을 다시 돌린다 |
| 3 | 맵 응답 압축(zstd). `Compress`를 비우면 testcontrol은 비압축으로 보낸다. Go 클라이언트는 늘 zstd를 요청하므로 운영 서버가 비압축 요청을 받아 주는지는 소스로 확인되지 않는다. Apple 프레임워크에는 zstd가 없다 | M2 마무리 관문에서 확인한다. 안 되면 해제기만 직접 구현한다(RFC 8878) |
| 4 | NAT 통과 성공률이 Go보다 낮다 | DERP로 항상 통신은 된다. 포트 매핑·피어 릴레이는 측정 뒤에 판단한다 |
| 5 | iOS 확장: utun fd를 찾는 방법이 비공식이다. 확장 자신의 소켓이 터널로 되돌아올 수 있다 | RemoteDebug가 실기기에서 확인한 방법을 따른다. 소켓을 물리 인터페이스에 결속한다 |
| 6 | 직접 구현한 암호의 부채널, 감사 부재 | 상수 시간 구현 규칙, 다른 제공자의 검토, README 고지 |
| 7 | 직접 구현하는 TCP가 손실·재정렬 환경에서 멈추거나 느리다 | 상태 기계를 입출력에서 분리해 결정적 시험으로 덮고, 두 개의 독립 구현(gVisor, macOS 커널)을 상대로 확인한다. 1차 목표에는 영향 없음 |
| 8 | tailnet lock을 켠 tailnet에서 서명 검증 없이 피어를 받아들이면 그 보호가 사라진다 | M2에서 결정: 지원 전까지는 lock이 켜진 tailnet을 감지해 접속을 거부하는 쪽을 기본으로 검토한다 |
| 9 | Swift 패킷 경로의 처리량과 패킷당 할당 | M1에서 버퍼 재사용 구조를 정하고 M5에서 실기기 처리량을 잰다 |
| 10 | 비공식 클라이언트로 Tailscale 운영 서버에 접속하는 것과 이름 사용이 약관·상표에 맞는지 확인하지 못했다 | 공개 배포 전에 사용자가 확인한다. 그 전까지 저장소는 로컬에만 둔다 |
| 11 | 한 사람이 업스트림 변경을 따라가야 한다 | 범위를 좁게 유지하고(3절 제외 목록) 상호 운용 시험을 자동화한다 |
| 12 | 터널 모드의 MagicDNS는 TCP 스택 없이 UDP 질의에만 답한다. TCP 53과 MTU를 넘는 응답은 처리하지 못한다 | tailnet 이름의 A·AAAA·PTR 응답은 작다. 넘치면 잘림 표시로 답하고, TCP 53은 M6 뒤에 붙인다 |
| 13 | Go 피어는 상대의 CapabilityVersion이 121 이상이면 피어 릴레이를 쓸 수 있다고 본다. 148을 선언하면서 구현하지 않으면 상대가 릴레이 경로를 시도할 수 있다 | 모르는 disco 메시지는 무시한다. M4 관문에서 릴레이가 켜진 Go 피어와 DERP·직접 경로가 정상인지 확인한다. 낮은 버전 선언은 서버 동작이 달라질 수 있어 M2에서 따로 판단한다 |

## 9. 열린 결정

| 결정 | 기한 | 권장 |
| --- | --- | --- |
| 1차 목표를 M5(iOS 터널)로 둘지 | M5 전 | M5(M0~M4는 어느 쪽이든 같다) |
| 실제 tailnet을 마무리 관문에 쓸지, 어떤 tailnet·태그로 등록할지 | M2 마무리 전 | 임시 노드 |
| 실기기 시험용 터널 앱의 서명(팀, Network Extension 권한) | M5 전 | |
| tailnet lock이 켜진 tailnet의 처리 | M2 | 접속 거부(Go 피어도 서명 없는 노드를 netmap에서 뺀다) |
| 선언할 CapabilityVersion | M2 | 148(기준 소스와 같게) |
| Go 상태 파일(`tailscaled.state`)에서 노드 신원을 이관할지 | M7 | 이관 지원 |
| 라이선스, 공개 여부 | 공개 전 | |

## 10. 협업 방식

- 총괄(Fable 5.2): 계약, 통합, 관문 판정, 보고.
- Opus 5.5: 상태 기계가 복잡한 프로토콜 구현(WireGuard, 제어 Noise·맵, magicsock).
- Sonnet 5.5: 계약이 분명한 구현(암호 기본기, DERP 프레임, 코덱, 상태 저장, 필터).
- Haiku 5.5: 기계적 변환(벡터 옮기기, 표).
- Codex(GPT): Claude가 쓴 코드의 교차 검토, 같은 계약만 보고 쓰는 독립 시험·벡터, 노트의 사실 확인. Claude가 검토할 대상은 Codex가 쓴다.
- 암호·프로토콜 코드는 작성한 제공자와 다른 제공자가 검토한 뒤에 관문 통과로 본다.
- 프로토콜 노트는 해당 마일스톤을 시작하기 전에 다른 제공자가 Go 소스와 대조한다.
