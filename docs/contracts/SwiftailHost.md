# Swiftail 호스트 계약 (M7, 초안)

M7의 목표는 **첫 사용처(RemoteDebug)의 Mac 호스트가 Go 코어(tsnet) 없이 Swiftail만으로 지금 하는 일을 하는 것**이다(`docs/plan.md` 7절 M7). 끝에는 Go 코어 전체를 걷어낸다. M6까지 Swiftail은 프로세스 안에서 tailnet 주소로 TCP를 듣고 건다(`listen(port:)`·`connect(to:port:)`, 바이트 흐름). M7은 그 위에 Go 호스트가 Tailscale에 기대던 나머지를 더한다: 연결의 상대가 누구인지(`WhoIs`), iOS 설치기가 요구하는 유효한 HTTPS 인증서(ts.net 인증서), 그 인증서로 TLS를 끝내는 OS 리스너까지 바이트를 이어 주는 루프백 다리, 그리고 Go 상태에서 신원을 가져오는 길이다.

이 문서는 **초안**이다. 구현 전에 "첫 사용처 확인 필요"를 첫 사용처 세션에 보내 검토받고, "총괄 확인 필요"와 "사용자 확인 필요"를 정한 뒤 확정한다.

프로토콜 세부는 [whois-certs-state.md](../protocol-notes/whois-certs-state.md)(아래에서 "노트". 2026-11-15 다른 세션이 Go 소스와 RFC 원문에 대조해 검증했다. 주장별 판정은 노트 9장, 이 계약과의 대조는 노트 10장이며, 그 반영은 끝의 "노트 검증 반영" 절에 적었다)와 [dns-state-node.md](../protocol-notes/dns-state-node.md)(아래에서 "DNS 노트") 3.2·4.8·4.9를 따른다. 이 문서는 범위, 타깃, 공개 API, 동작, 한도, 시험과 관문만 정한다.

기존 계약과의 관계: [SwiftailNetstack.md](SwiftailNetstack.md)(M6)의 총괄 확인 N9(연결 위의 TLS)와 "첫 사용처 검토 결과" 1을 이 문서가 닫는다. [SwiftailTunnel.md](SwiftailTunnel.md)(M5)의 결정 D8(상태 디렉터리는 따로)과 질문 16(기존 사용자의 전환)을 이 문서가 이어받는다. 어긋나면 이 문서가 앞선다.

이미 정해진 것(첫 사용처의 답, `SwiftailNetstack.md` "첫 사용처 검토 결과"): HTTP 서버는 첫 사용처가 Swift로 쓴다(HTTP/1.1). TLS는 루프백 다리로 한다(`127.0.0.1`의 `NWListener`, ALPN `http/1.1`, 최소 TLS 1.2). 리스너는 하나, 연결은 기기당 10개 안팎이다. 프록시 모드는 옮기지 않는다. iOS에서는 `.inProcess`를 쓰지 않는다.

조사한 것: 첫 사용처 저장소의 커밋 `2814b2c`(읽기만), `tailscale.com` v1.104.6, RFC 원문, macOS SDK의 머리 파일, 노트 4.6의 작은 형식 검사(키·서명의 크기, PEM 읽기·쓰기, 서명 검증. 검증 세션이 다시 실행했다). 작성 세션이 했다고 적은 CSR·TLS·키체인 실험은 기록이 없어 확인되지 않았다(노트 8장). 이 계약은 그것을 근거로 쓰지 않는다.

## 1. 목표와 범위

| 넣는다 | 근거 |
| --- | --- |
| `whoIs`: tailnet 주소 → 노드와 사용자 | 첫 사용처는 모든 `/v1/*`·`/i/*` 요청에서 연결의 원격 주소로 신원을 확인하고 허용 목록(노드 `StableID`)에 견준다(RemoteDebug `docs/protocol.md` 3절, `core/internal/host/host.go:230-260`) |
| ts.net 인증서의 발급·저장·갱신(ACME DNS-01, Let's Encrypt) | iOS 설치기는 `https` 매니페스트와 IPA만 받는다(같은 문서 4.5, 11절). Go 호스트는 `CertPair`·`GetCertificate`로 얻는다(RemoteDebug `core/internal/node/tls.go:22-51`) |
| 제어 서버의 `set-dns` 요청 | DNS-01 레코드를 올리는 유일한 길이다(노트 3.2) |
| 루프백 다리: Swiftail 연결 ↔ `127.0.0.1`의 OS TCP 리스너, 그 리스너가 상대의 신원을 찾는 길 | `SwiftailNetstack.md` N9. 역압과 반닫힘을 정확히 잇는 일이라 Swiftail이 낸다(총괄 확인 필요 H2) |
| Go 상태 디렉터리에서 신원 가져오기(읽기 전용, 한 번) | plan 9절의 열린 결정. **설계만 넣고, 구현은 사용자 결정(U1) 뒤에 연다** |
| C API 18개의 대응표, RemoteDebug e2e 시나리오의 뼈대 재현 | plan 7절 M7 |

| 뺀다 | 까닭 | 필요해지는 시점 |
| --- | --- | --- |
| HTTP 서버, TLS 종단 | 첫 사용처가 Network 프레임워크로 한다(정해진 것) | — |
| Swift로 쓴 TLS, SecureTransport | `SwiftailNetstack.md` N9와 검토 결과 1에서 뺐다 | — |
| 인증서: TLS-ALPN-01, 와일드카드, 자기 FQDN이 아닌 이름, ARI, RSA 키, 계정 연락처·EAB, 계정 키 교체, 폐기 | 첫 사용처는 자기 FQDN 하나만 쓴다. 나머지는 Funnel·Serve용이거나 Go의 Tailscale 통합도 쓰지 않는다(노트 6장) | 그런 사용처가 생길 때 |
| `whoIs`의 capability(`CapMap`), node 키로 찾기 | 첫 사용처가 읽지 않는다(노트 4.1 7) | 앱 권한을 ACL의 grant로 나누는 사용처가 생길 때 |
| iOS에서의 인증서·다리 | iOS 터널 확장은 서버가 아니다. 타깃은 iOS에서도 빌드되지만 관문은 macOS만 본다 | iOS에서 듣는 사용처가 생길 때 |
| 프록시 모드(`rd_proxy_start`) | 호출하는 곳이 없고 Go와 함께 없어진다(검토 결과 2) | — |
| 호스트의 REST·페어링·세션·게시, 같은 네트워크 직접 연결 리스너, 업데이트 페이지 | Tailscale과 무관한 첫 사용처의 로직이다(4절 대응표) | — |
| 첫 사용처 저장소 바꾸기 | 별도 승인 뒤에 한다(plan 7절 M7) | 관문 (가) 통과 뒤 |

## 타깃과 의존 방향

| 타깃 | 종류 | M7에서 더하는 것 |
| --- | --- | --- |
| `SwiftailControl` | 기존 | `ControlClient.setDNS(name:value:)`(Noise 위의 `POST /machine/set-dns`), Go 상태 파일 읽기(`GoStateFile`, `package`) |
| `Swiftail` | 기존 | 공개: `whoIs(_:)`, `PeerIdentity`, (U1 뒤) `GoStateImport`. `package`: 인증서 타깃이 쓰는 접점(`setDNS`, 자기 FQDN·cert 도메인·상태의 흐름, 상태 디렉터리) |
| `SwiftailIO` | 기존(`package`) | `NetworkSocket`: 루프백 평문 연결, 자기 쪽 포트 읽기, 쓰기 끝내기(FIN) |
| `SwiftailCertificates` | **새 제품** | ACME 메시지와 주문 절차(값 타입), JWS·JWK, DER 쓰기와 CSR, PEM, 인증서 저장과 검증, 가장자리 `CertificateManager` |
| `SwiftailLoopback` | **새 제품** | `LoopbackBridge` |

```
SwiftailControl ◄─ Swiftail ◄─┬─ SwiftailCertificates   (CryptoKit, Security, Foundation의 URLSession)
                               └─ SwiftailLoopback       (SwiftailIO, Network)
```

- 두 새 타깃을 `Swiftail` 밖에 두는 까닭: iOS 터널 확장은 `Swiftail`만 링크하고 50MiB 한도와 바이너리 크기를 본다. ACME·DER·다리는 서버 노릇을 하는 앱만 쓴다. 같은 패키지 안이므로 `package` 접근으로 노드의 안쪽에 닿고, `Swiftail`의 공개 표면은 `whoIs` 하나만 늘어난다(총괄 확인 필요 H1).
- 새로 쓰는 시스템 프레임워크: Security(`SecCertificate`·`SecTrust`로 받은 사슬을 검증한다), Foundation의 `URLSession`(ACME 서버와의 HTTPS). plan 4절(c)의 "CryptoKit, Network, Foundation만"에 Security가 더해진다(총괄 확인 필요 H8). 외부 패키지와 C 코드는 없다.
- 첫 사용처는 `import Swiftail`, `import SwiftailBase`(`IPAddress`·`IPEndpoint`), `import SwiftailCertificates`, `import SwiftailLoopback`을 쓴다.

## 2. 공개 API 초안

### `Swiftail`

```swift
import SwiftailBase

extension TailnetNode {
    /// 이 tailnet 주소를 가진 노드가 누구인지 지금의 netmap에서 찾는다. tsnet `LocalClient().WhoIs(addr)`.
    ///
    /// 자기 노드와 피어의 주소(netmap `Addresses`의 한 주소짜리)만 찾는다. 서브넷 경로 안의 주소는 찾지 않는다.
    /// netmap이 아직 없거나, 그 주소의 노드가 없거나, 노드를 만든 사용자의 프로필이 netmap에 없으면 nil이다.
    /// 기다리지 않는다.
    ///
    /// 연결의 상대를 확인할 때는 `TailnetConnection.remoteEndpoint.address`를 넘긴다. 그 주소는 WireGuard가 인증한
    /// 피어의 것이고, 주소의 주인이 바뀌면 노드가 그 연결을 끊는다(`ConnectionError.peerRemoved`).
    public func whoIs(_ address: IPAddress) -> PeerIdentity?
}

/// tailnet 노드 하나의 신원. 제어 서버가 netmap으로 알려 준 값이다.
public struct PeerIdentity: Sendable, Equatable {
    /// 노드의 바뀌지 않는 ID(`tailcfg.Node.StableID`). 비어 있지 않다. 허용 목록의 키로 쓴다.
    public var stableID: String
    /// MagicDNS 이름에서 끝의 점을 뗀 것(`rd-phone-1a2b3c4d.tail0001.ts.net`). 이름이 없으면 빈 문자열이다.
    public var name: String
    /// 표시용 이름. Go `Node.ComputedName`의 규칙이다(동작 W4): 자기 tailnet의 접미사가 레이블 경계에서 맞을 때만
    /// 그것을 떼고 끝의 점을 뗀다(`rd-phone-1a2b3c4d`). 다른 tailnet에서 공유받은 노드는 접미사가 달라 끝 점 없는
    /// FQDN이 남는다. 결과가 비면 정리한 호스트 이름, 그것도 비면 node 공개 키의 텍스트(`nodekey:` + hex).
    public var computedName: String
    /// 노드를 만든 사용자의 로그인 이름(`alice@example.com`). 표시용이다. 태그 노드에서는 사람을 가리키지 않는다.
    public var loginName: String
}
```

`docs/plan.md` 6절 초안과 다른 점: 인자가 `TailnetAddress`가 아니라 `SwiftailBase`의 `IPAddress`다(M6의 `IPEndpoint.address`와 같은 타입).

### `SwiftailCertificates`

```swift
import CryptoKit
import Foundation
import Swiftail

/// 노드의 ts.net 이름에 발급된 인증서와 그 개인 키.
///
/// 개인 키를 담으므로 `description`과 `dump`에는 이름과 유효 기간만 드러낸다.
public struct TailnetCertificate: Sendable {
    /// 인증서의 이름(`rd-mac-1a2b3c4d.tail0001.ts.net`).
    public let domain: String
    /// DER 인증서. leaf가 먼저이고 중간 인증서가 뒤따른다. ACME 서버가 루트를 함께 보낼 수도 있으므로(RFC 8555 9.1),
    /// 사슬을 검증한 뒤 leaf가 아닌 자기 서명 인증서를 떼어 낸 것이다(동작 S6). TLS 신원에 그대로 싣는다.
    public let chain: [[UInt8]]
    /// leaf의 개인 키. `x963Representation`을 `SecKeyCreateWithData`에 넘겨 `SecKey`를 만들 수 있다.
    public let privateKey: P256.Signing.PrivateKey
    public let notBefore: Date
    public let notAfter: Date
}
extension TailnetCertificate: CustomStringConvertible, CustomReflectable {}

public struct CertificateConfiguration: Sendable {
    /// Let's Encrypt 운영 서버의 디렉터리.
    public static let letsEncryptDirectoryURL: URL
    /// ACME 디렉터리의 URL. `https`여야 한다. 시험과 스테이징에서 바꾼다.
    public var directoryURL: URL
    public init(directoryURL: URL = CertificateConfiguration.letsEncryptDirectoryURL)
}

/// 노드 자신의 ts.net 이름에 대한 인증서를 받아 두고, 만료 전에 갱신한다. tsnet `CertPair`·`GetCertificate`.
///
/// 저장은 노드의 상태 디렉터리 아래 `certs/`에 한다. 다시 시작하면 저장된 것을 검증해 다시 쓴다.
public actor CertificateManager {
    /// - Throws: 디렉터리 URL이 `https`가 아니면 `invalidConfiguration`.
    public init(node: TailnetNode, configuration: CertificateConfiguration = CertificateConfiguration()) throws(CertificateError)

    /// 인증서를 받고 갱신하는 일을 한다. `node.run()`과 같은 Task 묶음에서 돌린다. 취소될 때까지 돈다.
    ///
    /// 발급의 실패는 던지지 않고 `status`에 적는다. 사용자가 tailnet 설정을 고쳐야 하는 실패(MagicDNS·HTTPS가 꺼짐,
    /// 이름이 cert 도메인에 없음)는 netmap이 바뀌거나 `retryNow()`가 불릴 때까지 기다리고, 그 밖의 실패(ACME 서버의
    /// 거절, 연결 끊김)는 물러났다가 다시 시도한다(동작 R4). 다시 돌려도 소용없는 실패(`CertificateError`)만 던진다.
    public func run() async throws(CertificateError)

    /// 지금 쓸 인증서와, 갱신될 때마다 새 인증서. 저장된 것이 유효하면 그것부터 낸다. 한 Task만 돌 수 있다.
    /// 받아 가지 않은 것이 있으면 가장 새것 하나만 남는다.
    public nonisolated var certificates: AsyncStream<TailnetCertificate> { get }

    /// 지금의 모습: 쥔 인증서의 만료 시각, 마지막 실패, 다음 시도 시각.
    public var status: CertificateStatus { get }

    /// 물러나 기다리는 중이거나 조건을 기다리는 중이면 기다림을 끝내고 곧바로 다시 본다. 사용자가 tailnet 설정을 고친 뒤
    /// 누르는 "지금 다시 시도"다. 발급이 돌고 있거나, ACME 서버가 `Retry-After`로 알려 준 시각(속도 제한 `rateLimited`
    /// 포함) 전이면 아무 일도 하지 않는다. 그 시각 전에는 그 서버에 요청을 보내지 않는다(동작 X5).
    public func retryNow()
}

public struct CertificateStatus: Sendable, Equatable {
    /// 인증서를 받으려는 이름. 노드의 이름을 아직 모르면 nil.
    public var domain: String?
    /// 지금 쥔 인증서의 만료 시각. 없으면 nil.
    public var notAfter: Date?
    /// 마지막 시도가 실패한 까닭. 성공하면 nil로 돌아간다.
    public var lastFailure: CertificateFailure?
    /// 다음에 발급이나 갱신을 시도할 시각. ACME 서버가 `Retry-After`로 알려 준 시각이 더 늦으면 그 시각이다(7일로 묶는다.
    /// 동작 X5). 조건(로그인, MagicDNS, HTTPS, cert 도메인)을 기다리는 중이면 nil이다: 시간으로 다시 시도하지 않는다.
    public var nextAttempt: Date?
}

/// 발급이 되지 않는 까닭. 앱은 종류로 사용자 문구를 고르고, 연관 문자열은 진단에만 쓴다.
public enum CertificateFailure: Sendable, Equatable {
    /// 노드가 `.running`이 아니다.
    case nodeNotRunning
    /// tailnet에서 MagicDNS가 꺼져 있다. 사용자가 관리 콘솔에서 켜야 한다.
    case magicDNSDisabled
    /// tailnet에서 HTTPS 인증서가 꺼져 있다(netmap `DNSConfig.CertDomains`가 비었다). 사용자가 관리 콘솔에서 켜야 한다.
    case httpsNotEnabled
    /// 노드의 이름이 netmap의 cert 도메인에 없거나, 동작 C2의 이름 검사에 어긋난다.
    case domainNotAllowed
    /// 제어 서버가 DNS 레코드 요청을 받지 않았다. HTTP 상태 코드.
    case controlRejected(status: Int)
    /// ACME 서버가 성공이 아닌 HTTP 응답으로 거절했다. `status`는 HTTP 상태 코드, `type`은 문제 문서의 `type` 전체
    /// 문자열(`urn:ietf:params:acme:error:badCSR`, 서버 고유 URI, `about:blank`)이다. 문제 문서가 없거나 JSON이
    /// 아니거나 `type`이 없으면 빈 문자열이다. 256바이트로 자른다. 문제 문서의 `detail`은 싣지 않는다(식별자가 들어
    /// 있을 수 있다. 동작 K2).
    case acme(status: Int, type: String)
    /// ACME 서버의 속도 제한(`type`이 `urn:ietf:params:acme:error:rateLimited`). 서버가 알려 준 다시 시도할 시각.
    case rateLimited(retryAfter: Date?)
    /// 인증 기관이 이름의 소유를 확인하지 못했다: authorization이 `invalid`다(DNS 레코드를 찾지 못했거나 값이 달랐다).
    /// `type`은 그 challenge의 `error` 문제 문서의 `type`이다(`acme`와 같은 규칙).
    case validationFailed(type: String)
    /// 주문이 `invalid`가 되었는데 authorization의 실패가 아니다(만료, CSR·발급의 거절 등), 또는 주문을 이어 갈 수 없는
    /// authorization(`deactivated`·`expired`·`revoked`)이 있다. `type`은 주문의 `error` 문제 문서의 `type`이다.
    case orderFailed(type: String)
    /// ACME 서버의 응답이 규격이나 이 계약의 한도에 맞지 않았다(모르는 상태, 다른 이름의 authorization, 한도를 넘는
    /// 본문, `https`가 아닌 URL 등. 동작 C5·X).
    case unexpectedResponse
    /// 받은 인증서가 검증을 통과하지 못했다(이름, 기간, 사슬, 키).
    case invalidCertificate
    /// ACME 서버나 제어 서버에 닿지 못했다.
    case network(String)
    /// 발급이 기한 안에 끝나지 않았다.
    case timedOut
}

public enum CertificateError: Error, Sendable, Equatable {
    /// 디렉터리 URL이 잘못되었다. `run()`을 두 번 부른 것도 여기다.
    case invalidConfiguration(String)
    /// `certs/`를 만들거나 쓰거나 읽지 못했다. 이미 있는 `certs/`를 그룹이나 기타가 쓸 수 있는 것도 여기다(동작 S1).
    /// 메시지에는 오류 코드만 담는다.
    case storage(String)
    /// `certs/acme-account.key.pem`이 있지만 P-256 계정 키로 읽지 못했다(Go가 남긴 RSA 키, 깨진 파일, 크기 초과).
    /// 덮어쓰지 않는다: 새 계정을 만들면 그 파일이 가리키던 계정을 잃는다(동작 C4).
    case accountKeyUnreadable
}
```

### `SwiftailLoopback`

```swift
import Swiftail
import SwiftailBase

/// tailnet에서 받은 TCP 연결을 이 기기의 루프백(`127.0.0.1`) TCP 리스너로 이어 준다.
///
/// TLS와 HTTP를 OS의 스택(`NWListener`)으로 끝내려는 앱이 쓴다. 다리는 바이트를 해석하지 않는다. 루프백 연결의 저쪽에서는
/// 상대가 `127.0.0.1`로 보이므로, 서버는 받은 연결의 **출발 포트**로 `origin(forLoopbackSourcePort:)`를 물어 tailnet의
/// 상대를 안다. 표에 없는 포트는 다리가 이은 연결이 아니다(같은 기기의 다른 프로세스다). 서버는 그런 연결을 끊어야 한다.
public final class LoopbackBridge: Sendable {
    /// 루프백 연결 하나의 tailnet 쪽 상대.
    public struct Origin: Sendable, Equatable {
        /// 상대의 tailnet 주소와 포트.
        public var remoteEndpoint: IPEndpoint
        /// 잇기 시작할 때 확인한 상대의 신원. 연결이 사는 동안 바뀌지 않는다.
        public var peer: PeerIdentity
    }

    public init(node: TailnetNode)

    /// 연결 하나를 `127.0.0.1:<port>`로 잇고, 두 방향이 다 끝날 때까지 바이트를 나른다. 끝나면 두 연결을 닫고 돌아온다.
    ///
    /// 상대의 신원을 확인한 뒤에 루프백으로 건다. 부르는 Task가 취소되면 두 연결을 끊는다. 실패하면 `connection`을
    /// 끊고(RST) 던진다.
    public func forward(_ connection: TailnetConnection, toLoopbackPort port: UInt16) async throws(LoopbackBridgeError)

    /// 다리가 이은 루프백 연결의 출발 포트로 tailnet 쪽 상대를 찾는다. 기다리지 않는다.
    ///
    /// 다리는 표에 적기 전에는 그 연결로 한 바이트도 보내지 않는다. 그러므로 서버가 그 연결에서 무엇이든 받은 뒤
    /// (TLS 핸드셰이크가 끝난 뒤)에 물으면, 다리가 이은 연결은 반드시 표에 있다.
    public func origin(forLoopbackSourcePort port: UInt16) -> Origin?
}

public enum LoopbackBridgeError: Error, Sendable, Equatable {
    /// 상대 주소의 신원을 netmap에서 찾지 못했다.
    case unknownPeer
    /// 다리가 잇고 있는 연결이 상한(256)에 닿았다.
    case limitReached
    /// 루프백 포트에 걸지 못했다(듣는 쪽이 없다, 시간 초과).
    case loopbackUnavailable(String)
    /// 부른 Task가 취소되었다.
    case cancelled
}
```

### `Swiftail`(사용자 결정 U1 뒤에만)

```swift
/// Go tsnet(또는 그것을 쓴 앱)이 남긴 상태 디렉터리에서 노드 신원을 가져온다.
public enum GoStateImport {
    /// `directory`의 `tailscaled.state`에서 machine 키와 node 키를 읽어 `configuration.stateDirectory`에 Swiftail 신원으로
    /// 저장한다. Go의 파일은 고치지 않는다. 정상 등록이 끝난 프로필 하나만 가져오고, 그 밖의 상태는 거절한다(동작 G2·G3).
    /// 가져온 뒤에 띄운 노드는 제어 서버가 같은 노드로 받아들이면 같은 tailnet 주소와 같은 `StableID`로 뜬다. 서버가
    /// 그렇게 받아들이는지(`NLKey`를 0으로 보내는 등록, 같은 키의 중복 세션)는 관문 전에는 확인되지 않았다(동작 G7).
    ///
    /// 그 상태를 쓰던 Go 노드가 **멈춘 뒤에만** 부른다. 같은 node 키를 두 노드가 함께 쓰면 안 된다.
    public static func importIdentity(
        fromGoStateDirectory directory: URL, for configuration: NodeConfiguration
    ) throws(GoStateImportError)
}

public enum GoStateImportError: Error, Sendable, Equatable {
    /// 대상 디렉터리에 Swiftail 신원이 이미 있다. 덮어쓰지 않는다.
    case alreadyInitialized
    /// `tailscaled.state`가 없다.
    case noGoState
    /// 파일을 해석하지 못했다(JSON·base64·키 텍스트의 형식, 0인 machine 키 등. 동작 G2).
    case malformed
    /// 가져올 수 있는 등록된 신원이 없다: node 키가 없거나 0이거나 `LoggedOut`이 참이다. 0인 까닭이 로그인한 적 없음인지는
    /// 알 수 없다.
    case notLoggedIn
    /// 해석은 되지만 이 가져오기가 다루지 않는 상태다: 프로필이 여럿, `_current-profile`이 가리키는 키가 없음, `_profiles`와
    /// 맞지 않음, legacy 형식, 키 교체가 끝나지 않음(`OldPrivateNodeKey`가 있다). 동작 G2.
    case unsupportedState
    /// Go 상태의 제어 서버와 `configuration.controlURL`이 같은 서버라고 볼 수 없다(동작 G3).
    case controlURLMismatch
    /// 읽거나 쓰지 못했다. 메시지에는 오류 코드만 담는다.
    case storage(String)
}
```

### 쓰는 모양(Mac 호스트)

```swift
let node = try TailnetNode(configuration: configuration, device: .inProcess)
let certificates = try CertificateManager(node: node)
let bridge = LoopbackBridge(node: node)
let listener = try await node.listen(port: 443)

try await withThrowingDiscardingTaskGroup { group in
    group.addTask { try await node.run() }
    group.addTask { try await certificates.run() }
    group.addTask {
        // 인증서가 오거나 바뀔 때마다 TLS 리스너를 (다시) 띄운다. 첫 사용처의 코드다.
        for await certificate in certificates.certificates { await server.restart(with: certificate) }
    }
    for await connection in listener {
        group.addTask {
            guard let port = await server.loopbackPort else { await connection.abort(); return }
            try? await bridge.forward(connection, toLoopbackPort: port)
        }
    }
}

// 서버(첫 사용처): TLS 핸드셰이크가 끝난 연결마다 한 번
guard case let .hostPort(_, sourcePort) = nwConnection.endpoint,
      let origin = bridge.origin(forLoopbackSourcePort: sourcePort.rawValue)
else { nwConnection.cancel(); return }      // 다리가 이은 연결이 아니다
// 요청마다: origin.peer.stableID가 허용 목록에 있는가
```

## 3. 동작

번호는 시험과 검토에서 가리키는 이름이다. 값은 따로 적지 않으면 이 계약의 제안값이고 관문의 기록으로 조정한다.

### W. `whoIs`

1. **주소 표**: 노드는 netmap을 적용할 때마다 자기 노드와 모든 피어의 `Addresses` 가운데 한 주소짜리 접두(/32, /128)를 주소 → 노드 표로 만든다. `AllowedIPs`는 넣지 않는다. netmap에 있는 노드는 만료·오프라인이어도 넣는다(노트 4.1 1. Go와 같다).
2. **찾기**: IPv4-mapped IPv6 주소는 IPv4로 바꾼 뒤 찾는다(노트 4.1 2). 표에 없으면 nil이다. `ProxyMapper`에 해당하는 길은 없다.
3. **사용자**: 노드의 `User`로 `Netmap.userProfiles`에서 찾는다. 프로필이 없으면 nil이다(노트 4.1 3. 총괄 확인 필요 H11). `StableID`가 빈 노드도 nil이다(첫 사용처가 거절하는 경우다).
4. **이름**: `name`은 `Node.name`에서 끝의 점 하나를 뗀 것이다. `computedName`은 Go `Node.ComputedName`의 규칙이다(노트 4.1 5, `tailcfg/tailcfg.go:660-689`): ① 자기 tailnet의 접미사를 구한다. 자기 노드 `Name`의 양 끝 점을 모두 뗀 뒤 첫 점 뒤의 나머지이고, 점이 없으면 그 이름 그대로다(`types/netmap/netmap.go:256-270`). ② 노드의 `Name`에서 그 접미사를 Go `dnsname.TrimSuffix`처럼 뗀다: 접미사가 **레이블 경계에서** 맞을 때만(`.` + 접미사로 끝날 때만) 떼고, 끝 점을 뗀다(`util/dnsname/dnsname.go:203-239`). 그래서 `rd-a.xtail0001.ts.net.`은 `tail0001.ts.net`을 떼지 않는다. **다른 tailnet에서 공유받은 노드는 접미사가 달라 끝 점 없는 FQDN이 남는다.** ③ 결과가 비면 `Hostinfo.Hostname`에서 `.local`·`.localdomain`·`.lan`을 떼고 Go `dnsname.SanitizeLabel`로 정리한 것(63자로 자르고, 처음·끝의 영숫자가 아닌 문자를 버리고, 가운데의 구분자를 `-`로 바꾸고, DNS에 쓸 수 없는 문자를 버리고, 소문자로. 결과는 그 Go 함수와 같아야 한다. `dnsname.go:162-200`), ④ 그것도 비면 node 공개 키의 텍스트(`nodekey:` + hex)다. 자기 노드와 모든 피어에 같은 규칙을 쓴다(`control/controlclient/direct.go:1419-1434`). W1~W3·W5는 Go의 주소 조회와 같다. W3의 빈 `StableID` 거절은 Go에 없는 첫 사용처의 정책이다(노트 10장).
5. **자기 주소**: 자기 노드의 신원을 돌려준다(Go와 같다). 자기 주소로 건 연결(`SwiftailNetstack.md` 동작 N3)의 상대가 자기 자신으로 확인된다.
6. **일관성**: `whoIs`는 노드 actor 안에서 지금의 netmap을 읽는다. 주소의 주인이 바뀐 연결을 끊는 일(`SwiftailNetstack.md` 동작 X10)과 같은 actor의 같은 netmap 적용에서 일어나므로, 살아 있는 연결의 원격 주소에 대한 답은 그 연결을 맺은 피어의 것이다. 이미 끊긴 연결의 주소를 뒤늦게 물으면 새 주인이 나올 수 있다(동작 B2가 이 틈을 막는다).
7. 로그에 주소 전체와 로그인 이름을 남기지 않는다.

구현에서 정해진 것(M7-1): 주소 표를 따로 만들지 않고 질의마다 `lastNetmap`을 훑는다(M6의 MagicDNS 이름 찾기와 같다. `shortcut:`으로 남겼다). 같은 주소를 가진 노드가 여럿이면 Go의 표처럼 나중 것(자기 노드 다음에 피어를 node ID 순으로)이 이기고, 이긴 노드가 `StableID`나 프로필이 없으면 다른 노드로 넘어가지 않고 nil이다. `whoIs`는 `TailnetNode` actor의 메서드라 밖에서는 `await`로 부른다. `PeerIdentity`의 init은 `Swiftail` 안에만 있다(값은 `whoIs`가 낸다).

### D. 제어 서버의 `set-dns`

1. `ControlClient.setDNS(name:value:)`는 맵 스트림과 **같은 Noise 클라이언트**(`ControlClient`)로 `POST /machine/set-dns`를 보낸다. 본문과 머리(`Content-Type`, node 키의 부하 분산 머리)는 노트 3.2다. `Version`은 선언한 CapabilityVersion(148), `NodeKey`는 지금의 node 공개 키다. 같은 Noise 클라이언트라는 것과 같은 HTTP/2 물리 연결이라는 것은 다르다: Go는 같은 Noise client를 쓰지만 같은 연결 하나를 보장하지 않는다(노트 3.2, `control/ts2021/client.go:254-290`). Swiftail의 `ControlClient`는 `run()` 동안 연결 하나를 쥐므로 그 연결 위의 새 스트림으로 보내지만, 이것은 Swiftail의 구현 선택이고 서버가 요구한다는 근거는 없다. 다른 동작이 "같은 연결"에 기대지 않는다.
2. **Swiftail의 선택**: 제어 연결이 없으면(다시 잇는 중) 설 때까지 기다린다. 기한은 60초다. Go는 control client가 없으면 `not connected`로 곧바로 실패한다(노트 3.2, `ipn/ipnlocal/local.go:7820-7839`). 등록이 끝나지 않았으면(node 키가 없거나 0) Go처럼 곧바로 실패한다.
3. **Swiftail의 선택**: 응답 본문은 4KiB까지 읽는다. 200이 아니면 상태 코드만 실패에 싣는다(본문은 로그에도 남기지 않는다. 서버가 무엇을 적어 보내는지 모른다). 200이면 본문이 JSON 객체여야 한다(빈 본문·`null`·배열은 실패). Go보다 좁다: Go는 Noise 응답을 1MiB까지 읽고, 200이 아니면 본문을 최대 200 code point까지 오류에 싣고, 200이면 JSON 값 하나를 받아들인다(`null`도 통과. 노트 3.2). 이 셋을 "Go와 같은 동작"으로 적지 않는다.
4. `name`은 `_acme-challenge.` + 자기 cert 도메인만 받는다. 그 밖의 이름을 올리는 공개 API는 없다(`package` 접점이고, 부르는 곳은 `CertificateManager`뿐이다).
5. 노트 8장: 운영 서버가 레코드를 권한 DNS에 올린 뒤에 답하는지 모른다. Go처럼 답을 받으면 곧바로 다음 단계로 간다(동작 C6).

### C. 인증서 발급

구조: ACME의 메시지 만들기·해석과 주문 절차는 소켓도 시계도 갖지 않는 값 타입이다(plan 5절 코드 기준). 계정 키와 인증서 키는 인자로 받는다. 입력은 HTTP 응답과 시각, 출력은 "이 요청을 보내라", "이 레코드를 올려라", "이만큼 기다려라", "끝났다(사슬)", "실패했다(까닭)"다. `CertificateManager`가 `URLSession`과 노드를 붙여 그것을 돌린다. 한 가지 예외: ECDSA 서명은 CryptoKit이 안에서 난수를 뽑으므로 서명 바이트는 실행마다 다르다. 시험은 서명을 바이트로 견주지 않고 검증한다.

1. **조건**: 이 차례로 본다. ① 노드가 `.running`이 아니면 `nodeNotRunning`. ② netmap의 MagicDNS가 꺼져 있으면(`DNSConfig.Proxied`가 거짓. Go `MagicDNSEnabled`의 출처다, `ipn/ipnlocal/local.go:1541`, DNS 노트 3절) `magicDNSDisabled`(첫 사용처가 보는 조건. 노트 4.2 9). ③ `DNSConfig.CertDomains`가 비었으면 `httpsNotEnabled`. ④ 자기 이름(끝의 점을 뗀 FQDN)이 그 목록에 **정확히** 없으면 `domainNotAllowed`(노트 4.2 9). 넷 다 `status`에 적고 시간으로 다시 시도하지 않는다(`nextAttempt`는 nil). 노드의 상태나 netmap이 바뀌거나 `retryNow()`가 불릴 때만 다시 본다(동작 R4).
2. **이름 검사**: 이름은 파일 이름과 DNS 레코드 이름이 되기 전에 검사한다. 경로로 안전한지와 DNS 이름으로 맞는지는 다른 검사다: Go `validLookingCertDomain`은 경로 검사일 뿐 DNS 레이블 전체를 검증하지 않는다(노트 4.2 9, 10장). Swiftail은 DNS 이름 규칙으로 둘을 함께 닫는다(RFC 1034 3.1·3.5, RFC 1123 2.1, 노트 10장): 끝의 점 하나를 뗀 이름이 ① 점으로 나뉜 레이블 둘 이상이고, ② 레이블마다 1~63자이고, **처음과 끝은 영숫자**, 가운데는 영숫자와 `-`이고, ③ 끝 점 없는 전체 길이가 253자 이하이고, ④ `_acme-challenge.`를 붙인 레코드 이름도 253자 이하다(그래서 이름은 237자 이하가 된다). 영문자는 소문자만 받는다(파일 이름이 되므로 대소문자를 가리지 않는 파일 시스템에서 겹치지 않게 하는 이 계약의 좁힘이다). 어긋나는 이름으로는 발급하지 않고 `domainNotAllowed`로 적는다(netmap이 바뀔 때까지 기다린다. 총괄 확인 필요 H23). 이 규칙이면 `..`·`/`·`\`·`:`·NUL·`*`·밑줄은 저절로 빠진다(노트 6장의 와일드카드 제외). 이 문자 집합은 CSR의 `PrintableString`에 모두 들어간다(동작 C7, 노트 3.6).
3. **저장된 것 먼저**: `certs/`의 그 이름 파일을 읽어 동작 S3으로 검증한다. 통과하고 갱신 시점(동작 R1) 전이면 발급하지 않고 그것을 낸다.
4. **계정**: 계정 키는 **P-256만** 쓴다(노트 6장: Tailscale이 만드는 계정 키는 P-256뿐이다). `certs/acme-account.key.pem`(64KiB까지)을 PKCS#8 또는 SEC1의 P-256 키로 읽는다(Go는 SEC1로 쓰고 PKCS#1·PKCS#8·SEC1을 차례로 읽는다. 노트 3.7, S2의 두 읽기 경로는 노트 4.6에서 확인됐다). 파일이 **없을 때만** 새 키를 만들어 저장한 뒤에 쓴다. 파일이 있는데 P-256 키로 읽지 못하면(Go의 옛 RSA 계정 키, 깨진 파일, 크기 초과) 없는 것으로 보지 않고 `run()`이 `CertificateError.accountKeyUnreadable`로 끝난다. 덮어써서 Go가 쓰던 계정을 잃지 않게 한다(노트 4.8 "계정과 동시성", `feature/acme/certstore.go:361-388`). 없음 밖의 읽기 오류는 `storage`다. 계정을 찾고(`onlyReturnExisting`), `accountDoesNotExist`면 약관에 동의해 만든다. 계정의 `status`가 `valid`가 아니면 실패다(노트 4.3 3·4). 계정 URL(`kid`)은 메모리에만 둔다(시작할 때마다 다시 찾는다). 계정 키를 읽고 만들고 등록하는 일은 `CertificateManager` actor 안에서 한 번에 하나만 돈다(Go의 `accountMu`에 해당한다. 노트 4.8). 동작 C9의 한 흐름 안에서만 돌므로 actor의 재진입으로 둘이 겹치지 않는다.
5. **주문**: 식별자는 `dns` 종류의 자기 이름 하나다(`{"identifiers":[{"type":"dns","value":"<이름>"}]}`). 응답(201, `Location`이 주문 URL)의 `identifiers`가 요청한 집합과 같아야 한다. authorization의 **개수는 강제하지 않는다**: 식별자와 authorization이 1:1이라는 보장이 없고 배열의 순서에도 기대지 않는다(RFC 8555 7.1.3·7.4, 노트 4.3 5). 개수의 상한만 둔다(8개, 한도 표). 넘거나, 주문이 `pending`인데 authorization이 없으면 `unexpectedResponse`다.
   - **주문의 상태부터 가른다**(RFC 8555 7.1.3·7.1.6): `pending` → 아래 authorization 처리. `ready` → authorization을 건너뛰고 C7의 finalize로 간다. `valid`·`processing` → 이 주문에는 아직 CSR을 보내지 않았으므로 대응하는 개인 키가 없다. 그 인증서를 받지 않고 새 주문으로 다시 시작한다(한 시도에 한 번. 총괄 확인 필요 H17). `invalid` → `orderFailed`. 모르는 상태 → `unexpectedResponse`.
   - **authorization마다**(모두, 차례 무관): POST-as-GET으로 읽는다. `identifier.type`이 `dns`이고, 값이 요청한 이름과 같고, `wildcard`가 참이 아니어야 한다. 어긋나면 그 시도는 `unexpectedResponse`로 끝난다. 상태별로(RFC 8555 7.1.4·7.1.6, 노트 4.3 6): `valid` → 끝난 것이다. `pending` → `type`이 `dns-01`인 첫 challenge를 고른다(없으면 `unexpectedResponse`). challenge가 `pending`이면 C6, `processing`이면 C6의 레코드만 올리고 응답은 다시 보내지 않는다, `valid`면 건너뛴다, `invalid`면 `validationFailed`. `invalid` → `validationFailed`. `deactivated`·`expired`·`revoked` → 주문을 이어 갈 수 없다(`orderFailed`). 모르는 상태 → `unexpectedResponse`. Go는 authorization과 challenge의 상태를 보지 않고 늘 dns-01에 응답한다(노트 4.2 7). Swiftail의 이 갈래는 더 닫힌 쪽이다.
6. **레코드와 응답**: 노트 3.5의 값으로 동작 D의 `set-dns`를 보내고, 성공하면 challenge URL에 `{}`를 POST한다(200·202가 성공. 노트 4.3 7·8). TXT 레코드를 미리 찾아보지 않는다(노트 6장).
7. **기다리기, finalize, 내려받기**(RFC 8555 7.4, 노트 4.3 9~12):
   - **기다리기**: challenge에 응답한 뒤 주문 URL을 POST-as-GET으로 다시 읽는다(Go와 같다. RFC 8555 7.5.1의 전형은 authorization을 읽는 것이다. 노트 4.3 9). 간격은 동작 X5의 `Retry-After`이고, 없으면 1초다(1초는 Go의 선택값이지 RFC의 상수가 아니다. 노트 4.3 9). `pending` → 다시 읽는다. `ready` → finalize. `invalid` → 주문의 authorization을 한 번씩 다시 읽어 `invalid`인 것이 있으면 `validationFailed`, 없으면 `orderFailed`(주문의 `invalid`는 DNS 확인 실패만이 아니라 만료·CSR·발급의 거절일 수도 있다. 노트 10장). `valid`·`processing` → CSR을 보내기 전이므로 C5와 같이 새 주문으로 다시 시작한다(H17). 모르는 상태 → `unexpectedResponse`.
   - **finalize**: `ready`가 되면 **새 P-256 키**(계정 키와 다른 키. RFC 8555 11.1)를 만들고 CSR(노트 3.6. 주체 CN은 Go와 같은 `PrintableString`)로 finalize한다. 이 키와 CSR은 그 주문이 끝날 때까지 쥔다. finalize 응답(200과 주문 객체)의 `status`를 곧바로 가른다: `valid` → 내려받기. `processing` → X5의 간격으로 주문을 다시 읽어 `valid`를 기다린다(그사이 `invalid`면 위와 같이 가른다). `invalid` → 위와 같이 가른다. `ready` → **같은 키·CSR**로 finalize를 한 번 더 보낸다. `pending` → 주문의 authorization을 C5로 다시 처리한 뒤 같은 키·CSR로 finalize한다. `ready`·`pending`의 되풀이는 한 주문에 한 번이고 두 번째면 `unexpectedResponse`다(H17). 모르는 상태 → `unexpectedResponse`. finalize가 403 `orderNotReady`면 주문을 다시 읽어 그 상태로 간다(노트 4.3의 오류 표). Go는 `valid`가 아니면 갈래 없이 `WaitOrder`로 기다리고 `ready`·`valid` 어느 쪽이 와도 새 키로 finalize한다(노트 4.2 6, 9장 V110). Swiftail은 그렇게 하지 않는다.
   - **내려받기**: `certificate` URL에 POST-as-GET, `Accept: application/pem-certificate-chain`(Swiftail의 선택. Go는 `Accept`를 따로 적지 않는다. 노트 4.3 12). 해석은 동작 X3.
8. **받은 사슬의 검사**: 동작 X3. 통과하면 키 파일, 인증서 파일 순으로 저장하고(동작 S2) `certificates`에 낸다. 통과하지 못하면 아무것도 저장하지 않는다. 저장 전에 키·이름·기간·사슬을 검증하는 것은 Go보다 강한 경계다(Go는 새로 받은 사슬을 저장 전에 직접 검증하지 않는다. 노트 4.4 5). 신뢰 앵커는 S3 ⑤와 같다: 운영은 시스템 루트만, 시험은 명시적 앵커다.
9. **한 번에 하나**: 발급은 `run()` 안에서 차례로 돈다. 동시에 두 주문이 나가지 않는다. 계정 준비(C4)도 이 흐름 안에서만 돈다. `retryNow()`와 netmap의 변화는 기다림을 깨울 뿐 발급을 따로 시작하지 않는다. `CertificateManager`를 한 노드에 둘 만들지 않는다(같은 `certs/`를 두 관리자나 두 프로세스가 쓰는 것은 막지 못한다. Go의 잠금도 프로세스 사이의 파일 잠금은 아니다. 노트 4.8. 문서 주석에 적는다).
10. **기한**: HTTP 요청 하나 30초, 발급 한 번 전체 5분. 넘으면 `timedOut`이고 그 주문은 버린다(다음 시도는 새 주문이다). `Retry-After`가 알려 준 시각이 이 기한을 넘으면 그때까지 기다리지 않고 곧바로 시도를 끝낸다. 그 시각은 `status.nextAttempt`로 남는다(동작 X5).
11. **User-Agent**: `Swiftail/<버전>`이다(RFC 8555 6.1. 총괄 확인 필요 H13). Go의 `tailscaled/…`를 흉내 내지 않는다.
12. **문제 문서**(RFC 8555 6.7, RFC 7807 3.1, 노트 4.3): 오류 응답에 문제 문서를 붙이는 것은 SHOULD일 뿐이고, `type`은 ACME URN만이 아니라 서버 고유 URI나 `about:blank`일 수 있다. 그래서 오류는 HTTP 상태와 문제 문서의 `type` 전체 문자열로 든다(`acme(status:type:)`). 본문이 JSON 객체가 아니거나 `type`이 없거나 문자열이 아니면 `type`은 빈 문자열이다(RFC 7807의 기본값 `about:blank`로 채우지 않는다). `type`은 256바이트로 자른다(UTF-8 문자 경계에서). `detail`·`title`·`instance`·`subproblems`(그 안의 `identifier`)는 해석은 하되 공개 타입에 싣지 않는다(식별자가 들어 있을 수 있다. 동작 K2). Swiftail이 따로 다루는 종류는 `type`이 `urn:ietf:params:acme:error:` + 이름과 **정확히 같을 때만** 그렇게 본다: `badNonce`(X4), `accountDoesNotExist`(C4), `rateLimited`(`CertificateFailure.rateLimited`, X5), `orderNotReady`(C7). `userActionRequired`를 포함한 그 밖의 모든 `type`은 `acme(status:type:)`다. 주문과 challenge의 `error`도 문제 문서이고 같은 규칙으로 `orderFailed`·`validationFailed`의 `type`이 된다.

구현에서 정해진 것(M7-3): JWS 보호 머리는 Go `jwsEncodeJSON`과 같은 직렬화(멤버 순서 `alg`·`kid` 또는 `jwk`·`nonce`·`url`, 공백 없음, 문자열은 Go `json.Marshal`의 이스케이프 `\u003c` 등)로 적는다. 그래서 시험 6의 머리·서명 입력 바이트 일치를 Go 대조에서 요구할 수 있다. CSR의 SubjectPublicKeyInfo는 DER 쓰기로 직접 조립하며 CryptoKit `derRepresentation`과 같은 바이트임을 시험이 고정한다. 고정 키(RFC 7515 A.3)의 `certificationRequestInfo`는 Go `x509.CreateCertificateRequest`(go1.27.3)와 바이트가 같았다(구현 세션의 일회성 확인. 기준값 자료는 M7-8).

### S. 저장

1. **자리와 이름**: `<상태 디렉터리>/certs/` 아래 `<이름>.crt`(사슬, `CERTIFICATE` PEM 블록을 leaf부터), `<이름>.key`(개인 키 PEM), `acme-account.key.pem`(계정 키 PEM)이다. 자리와 이름은 Go와 같다(노트 3.7, DNS 노트 4.9 1. 총괄 확인 필요 H7). **권한**: `certs/`를 새로 만들 때는 0700이다. 이미 있는 디렉터리의 권한은 고치지 않는다(Go의 `MkdirAll`도 고치지 않는다. 생성 때의 권한은 이미 있는 항목의 검사를 대신하지 않는다. 노트 3.7·4.8). 다만 이미 있는 `certs/`를 그룹이나 기타가 쓸 수 있으면 쓰지 않고 실패한다(`run()`이 `CertificateError.storage`로 끝난다). 그런 디렉터리에서는 읽지도 않는다: 다른 사용자가 키나 계정 키를 바꿔 넣었을 수 있다(총괄 확인 필요 H20).
2. **쓰기**: 키는 CryptoKit의 `pemRepresentation`(PKCS#8 `PRIVATE KEY`)으로 쓴다(Go가 읽는다. 노트 4.6). 새로 쓰는 파일은 **모두 0600**이다(키·계정 키·인증서). Go는 인증서를 0644로 쓰지만(노트 3.7) Swiftail은 인증서도 0600으로 둔다(Go와 다른 선택. 같은 사용자의 Go는 그대로 읽는다). 파일마다 같은 디렉터리의 임시 파일에 다 쓰고 권한을 정하고 디스크에 내린 뒤 이름을 바꾼다(Go `atomicfile`과 같은 차례. 노트 3.7). 키 파일을 먼저, 인증서 파일을 나중에 쓴다(Go와 같다). **두 파일의 쓰기는 한 트랜잭션이 아니다**(Go도 아니다. 노트 3.7): 둘 사이에 멈추면 새 키와 옛 인증서가 남는다. 그래서 읽을 때 S3 ④가 키와 인증서의 짝을 확인하고, 어긋나면 없는 것으로 본다(새 발급이 둘을 다시 쓴다).
3. **읽기와 검증**: ① 두 파일을 읽는다(각 64KiB까지). ② 인증서 파일은 동작 X3 ①과 같이 처음부터 끝까지 검사한다: `CERTIFICATE` 블록만 있어야 하고 1~5장이다. ③ 키는 PKCS#8과 SEC1(`EC PRIVATE KEY`)의 P-256 키 둘 다 읽는다(Go가 쓴 파일. 노트 4.6에서 확인됐다). ④ leaf의 공개 키가 그 키의 공개 키와 같다(S2의 두 파일 사이에 멈춘 상태를 여기서 잡는다). ⑤ 사슬이 그 이름과 지금 시각으로 검증된다(`SecTrust`, SSL 서버 정책). 앵커는 **운영에서는 시스템 루트만**이다. Go와 다른 선택이다: Go는 시스템 루트로 실패하면 내장 Let's Encrypt 루트로 다시 검사하고, 비운영 디렉터리에서는 마지막 오류가 "모르는 인증 기관"이면 통과시킨다(노트 4.4 5, `feature/acme/certstore.go:440-477`). Swiftail은 내장 루트를 두지 않고 그 비운영 예외도 옮기지 않는다. 시험과 스테이징은 X3의 명시적 앵커를 주며, 앵커를 주면 그 앵커만 쓴다. 하나라도 실패하면 저장된 것이 없는 것으로 본다(지우지는 않는다. 새 발급이 덮어쓴다). 인증서의 손상은 새 발급으로 가지만 계정 키의 손상은 실패다(C4. 노트 4.8이 두 경우를 가른다).
4. 이름이 바뀌면(노드 이름·tailnet 이름 변경) 새 이름으로 새로 발급한다. 옛 파일은 남는다(`shortcut:`).
5. iOS에서 쓰게 되면 `identity.json`과 같은 보호 등급과 백업 제외가 필요하다(`SwiftailTunnel.md` 동작 P 2). M7은 넣지 않는다(제외 표).
6. **`chain`에 넣는 것**: 사슬은 leaf부터다(RFC 8555 7.4.2). 루트는 응답에서 뺄 수 있을 뿐 반드시 없는 것은 아니므로(RFC 8555 9.1, 노트 3.7), 서버가 루트를 함께 보냈을 수 있다. 받은 사슬 전체로 S3 ⑤·X3 ④의 검증을 한 **뒤에** leaf가 아닌 인증서 가운데 자기 서명 인증서(주체와 발급자가 같은 것)를 떼어 낸 것을 `TailnetCertificate.chain`으로 낸다. 파일(`<이름>.crt`)에는 받은 사슬을 그대로 쓴다(Go와 같다. 노트 3.7). 주체와 발급자를 견줄 Security API는 M7-5가 SDK 선언에서 확인한다(9절).

구현에서 정해진 것(M7-5): `certs/`는 디렉터리 기술자로 열어(`O_NOFOLLOW`) 검사하고 그 안의 파일은 `openat`·`renameatx_np`로 다룬다. 심볼릭 링크, 지금 사용자의 것이 아님(소유자 검사는 이 단위가 더한 닫힌 쪽), 그룹·기타 쓰기 가운데 하나면 `storage`다. 파일은 링크를 따라가지 않고 정규 파일만 읽는다. 없음 밖의 읽기 오류(링크, 정규 파일이 아님)는 인증서 파일도 `storage`이고, 64KiB 초과와 해석·짝·검증의 실패만 "없음"이다. 계정 키는 `RENAME_EXCL`로 써서 이미 있는 파일을 덮어쓰지 않는다. 상태 디렉터리는 만들지 않는다(없으면 쓰기는 `storage`, 읽기는 없음). S6의 자기 서명 판별은 `SecCertificateCopyNormalizedSubjectSequence`와 `…IssuerSequence`의 바이트 비교다(`SecCertificate.h`, macOS 10.12.4·iOS 10.3).

### R. 갱신과 재시도

판정은 값 타입 하나가 한다: 입력은 지금 시각, 노드의 모습(상태, 이름, cert 도메인), 쥔 인증서의 기간, 마지막 실패와 연속 실패 횟수이고, 출력은 "지금 발급", "이 시각까지 기다림", "조건을 기다림"이다. 시험은 시각을 넘겨 결정적으로 돌린다.

1. **갱신 시점**: `notBefore + (notAfter − notBefore) × 2/3`가 지나면 갱신한다(노트 4.4 1. Go가 ARI 조회에 실패했을 때 쓰는 규칙이다). ARI는 쓰지 않는다(총괄 확인 필요 H6). 이 규칙은 Let's Encrypt의 속도 제한에 닿지 않는다는 보장이 **아니다**(노트 4.5, 9장 V168): 같은 식별자 집합의 새 인증서는 7일에 5장이고 ARI 없는 갱신도 이 제한에 걸린다. 모든 제한에서 빠지는 것은 ARI 갱신으로 인정된 주문뿐이고, 그러려면 `replaces`의 이전 인증서와 식별자가 하나 이상 겹치고 그 인증서가 아직 ARI로 대체되지 않았어야 한다. 인증서 수명(운영 기본이 2027-02-10부터 64일, 선택 6일), 같은 이름의 다른 발급(상태를 지우고 다시 발급하는 일, 임시 노드), authorization 실패의 제한도 함께 걸린다.
2. **갱신 중**: 지금 인증서를 계속 쓴다. 갱신이 실패해도 만료 전에는 스트림에 아무것도 내지 않는다. 만료되면 `status.notAfter`가 지난 시각으로 남고 앱이 그것을 본다.
3. **깨어나는 때**: `run()`의 시작, 노드의 상태·이름·cert 도메인·MagicDNS가 바뀔 때, 갱신 시점, 재시도 시각, `retryNow()`. 어느 때든 ACME 서버가 알려 준 `Retry-After`의 시각 전이면 그 서버에 요청을 보내지 않는다(동작 X5).
4. **재시도 간격**: 사용자가 고쳐야 하는 실패는 시간으로 다시 시도하지 않고, 그 밖의 실패는 물러났다가 다시 시도한다(Let's Encrypt의 제한은 노트 4.5).

   | 실패 | 다음 시도 |
   | --- | --- |
   | 사용자가 고쳐야 함(`magicDNSDisabled`, `httpsNotEnabled`, `domainNotAllowed`) | 시간으로 다시 시도하지 않는다(`nextAttempt`는 nil). netmap이 바뀌거나 `retryNow()`가 불릴 때만 다시 본다 |
   | 노드가 서지 않음(`nodeNotRunning`) | 노드의 상태가 바뀔 때(`nextAttempt`는 nil) |
   | 닿지 못함·기한 초과·5xx(`network`, `timedOut`, 상태가 5xx인 `acme`), `controlRejected` | 30초에서 시작해 두 배씩, 10분 상한(첫 사용처의 지금 값) |
   | 검증 실패(`validationFailed`), `orderFailed`, `unexpectedResponse`, 그 밖의 `acme` | 15분에서 시작해 두 배씩, 6시간 상한. authorization 실패의 제한(한 시간에 5번, 12분에 하나씩 회복)에서 12분은 token bucket의 회복률이지 지킬 최소 간격이 아니다(노트 4.5, 9장 V164). 15분 시작은 그 회복률보다 느리게 잡은 선택이다. 6시간마다 끝없이 실패하면 연속 실패 제한(1,152번)에도 언젠가 닿고, 그때부터 서버가 `rateLimited`로 답한다(노트 4.5) |
   | `rateLimited` | 서버가 준 시각(동작 X5. 7일로 묶는다). 없거나 15분보다 이르면 15분 뒤 |
   | `invalidCertificate` | 6시간 뒤(발급 한 번을 이미 썼다. 같은 이름의 새 인증서는 7일에 5장이다) |

   어느 줄이든 X5의 `Retry-After` 시각이 표의 시각보다 늦으면 그 시각이 `nextAttempt`다. `CertificateError`(`storage`, `accountKeyUnreadable`)는 `run()`이 던지고 다시 시도하지 않는다.
5. 성공하면 연속 실패 횟수와 `lastFailure`를 지운다.
6. 인증서의 시각은 벽시계(`Date`)로 본다. 시계가 크게 틀린 기기에서는 검증이 실패하고 `invalidCertificate`가 된다. Go도 시계 차이를 보정하지 않는다(노트 4.4 6). 판정은 시각을 입력으로 받고, 긴 기다림(`Retry-After`, 재시도) 뒤에는 지금 시각을 새로 읽는다(노트 4.4 6).

구현에서 정해진 것(M7-5): 두 배씩 늘리는 간격의 지수는 같은 줄의 실패가 이어진 횟수이고, 줄이 바뀌면 그 줄의 처음 간격부터다. 지터는 두지 않는다(식이 정해지지 않았고 한 노드가 혼자 보내는 요청이다). `Retry-After`의 시각은 실패 기록과 따로 들고 뒤의 조건 실패나 성공으로 지우지 않는다. 조건의 변화는 조건 기다림만 끝내고 물러남은 그대로 둔다(`retryNow()`는 둘 다 끝낸다).

### X. 신뢰할 수 없는 입력

ACME 서버의 응답, 제어 서버의 응답, 디스크의 파일, 루프백의 다른 프로세스는 믿지 않는다. 어떤 입력으로도 죽지 않는다.

1. **URL**: 디렉터리·주문·authorization·challenge·finalize·인증서의 URL은 `https`이고 2,048바이트 이하여야 한다. 아니면 `unexpectedResponse`다. 호스트가 디렉터리와 같아야 한다는 제한은 두지 않는다(RFC 8555가 요구하지 않는다). 리다이렉트는 따라가지 않는다. JWS의 `url`에는 서버가 준 문자열을 다시 인코딩하지 않고 그대로 넣는다(RFC 8555 6.4, 노트 4.8). 이 제한들은 Swiftail의 것이다: Go의 ACME 경로는 `http.DefaultClient`를 써서 리다이렉트를 따르고 URL 길이를 묶지 않는다(노트 4.8).
2. **본문과 머리**: JSON 응답은 64KiB, 인증서 사슬은 256KiB까지 읽는다. 넘으면 `unexpectedResponse`다. Go의 한도와 다르다(Go의 사슬 본문 상한은 5,401,755바이트이고 인증서 한 장마다의 크기는 따로 보지 않는다. 노트 3.7·5장, 9장 V213). 모르는 필드는 무시한다. `Replay-Nonce`는 base64url 문자만으로 된 1~512바이트일 때만 쓰고 그 밖은 무시한다(RFC 8555 6.5.1. Go는 검사하지 않는다. 노트 4.3 2). `Retry-After`는 동작 X5다. `token`은 base64url 문자만으로 된 1~512바이트여야 한다(RFC 8555 8.4).
3. **받은 사슬**: ① 입력 전체를 처음부터 끝까지 검사한다. `-----BEGIN` 뒤에 `CERTIFICATE`가 아닌 것이 하나라도 있거나, 해석되지 않는 블록이 있거나, 블록 밖에 공백이 아닌 바이트가 있으면 전체를 버린다(RFC 8555 9.1·11.4, 노트 3.7. Go의 `pem.Decode` 루프는 해석되지 않는 곳에서 멈출 뿐 뒤를 거부하지 않는다). ② 1~5장. ③ leaf의 공개 키가 방금 만든 키의 공개 키와 같다. ④ 사슬이 그 이름과 지금 시각으로 검증된다(앵커는 S3 ⑤). ⑤ `notAfter − notBefore`가 1시간 이상이다(갱신 판정이 헛돌지 않게 한다). 시험에서는 검증의 신뢰 앵커를 `package` 초기화 인자로 준다(로컬 ACME 서버·스테이징의 루트. Go의 `testRoots`와 같은 자리이고, 주면 그 앵커만 쓴다). Go의 비운영 디렉터리에서 "모르는 인증 기관" 오류를 무시하는 분기는 옮기지 않는다(노트 4.4 5). 통과하면 동작 S6으로 `chain`을 만든다. 구현에서 정해진 것(M7-5): ①~⑤는 디스크에서 읽은 사슬(S3)에도 같은 검증으로 건다. 운영 앵커는 `SecTrust`의 기본 앵커(OS 신뢰 저장소)이고, 빠진 중간 인증서를 네트워크에서 받지 않는다(`SecTrustSetNetworkFetchAllowed(false)`). 기간은 `SecCertificateCopyNotValidBeforeDate`·`…AfterDate`(macOS 15·iOS 18)로 얻는다. 구현에서 정해진 것(M7-3): 블록 안은 RFC 7468 3절의 표준 문법이되 줄 길이는 묻지 않고 공백뿐인 줄은 건너뛴다. 빈 본문과 BEGIN·END의 라벨 불일치는 해석되지 않는 블록이다. 키 파일(S3 ③, C4)은 `PRIVATE KEY`·`EC PRIVATE KEY` 블록 정확히 하나만 받는다.
4. **`badNonce`**: `type`이 `urn:ietf:params:acme:error:badNonce`인 오류(동작 C12)면 그 오류 응답의 nonce로 같은 요청을 다시 서명해 보낸다(RFC 8555 6.5). 요청마다 3번까지다. nonce는 마지막 응답의 것 하나만 쥔다. Go는 응답의 nonce를 넣은 뒤 쥔 nonce를 모두 지우고 HEAD로 다시 얻는데, 이것은 옮기지 않는다(노트 4.3).
5. **`Retry-After`와 끝없는 기다림**(RFC 8555 6.6·7.4, RFC 7231 7.1.3, 노트 4.3·10장): `Retry-After`는 초 단위의 음이 아닌 정수와 HTTP 날짜를 읽는다. 둘 다 아니면 없는 것으로 본다. 날짜는 벽시계로 바꾸고 지난 시각이면 기다림이 없다.
   - 서버가 알려 준 시각 전에는 **그 ACME 서버에 새 요청을 보내지 않는다**. "그 서버"는 그 디렉터리에서 얻은 모든 URL이다(총괄 확인 필요 H21). 유효한 값을 30초·24시간 같은 상한으로 줄여 더 일찍 요청하지 않는다.
   - 주문을 다시 읽는 간격은 `Retry-After`이고, 없으면 1초, 1초보다 짧으면 1초다(늦추기만 한다).
   - 주문을 기다리던 중에 받은 시각이 발급 한 번의 기한(동작 C10의 5분)을 넘으면 그 시도는 기다리지 않고 `timedOut`으로 끝낸다. 오류 응답(`rateLimited`, 5xx 등)은 시각이 기한 안이어도 그 시도를 끝낸다(동작 R4). 어느 쪽이든 알려 준 시각을 `status.nextAttempt`로 보존하고(R4의 간격이 더 늦으면 그 시각), 그 전에는 `retryNow()`도 요청을 보내지 않는다.
   - 값이 터무니없이 멀면(7일 초과) 7일로 묶는다. 묶는 것은 "다음 시도" 시각의 위쪽 끝뿐이다. 서버가 정한 7일 이하의 대기 중에 요청을 보내는 허가가 아니다. 로컬 상태(netmap, 저장된 인증서)를 다시 보는 일은 언제든 할 수 있고 그것은 요청이 아니다.
   - `processing`·`pending`에 머무는 주문은 동작 C10의 5분 기한이 끊는다.
6. **제어 서버**: `set-dns`의 응답은 동작 D3의 한도로 읽는다. netmap의 `CertDomains`는 제어 서버가 정한다. 제어 서버는 이미 이 노드의 이름과 피어를 정하는 위치이므로 더 넓어지는 권한은 없다.
7. **디스크**: `certs/`의 인증서와 키 파일은 동작 S3으로 읽는다. 크기 한도를 넘거나 해석되지 않으면 없는 것으로 본다. 계정 키 파일은 동작 C4(읽지 못하면 실패), 디렉터리의 권한은 동작 S1이다. Go 상태 파일은 동작 G2다.
8. **루프백의 다른 프로세스**: 동작 B6·B7.

### B. 루프백 다리

```
iPhone ──tailnet(WireGuard)── TailnetConnection ── LoopbackBridge ── 127.0.0.1:P ── NWListener(TLS) ── HTTP 서버
        (TLS는 iPhone과 NWListener 사이에서 끝난다. 다리가 나르는 것은 TLS 레코드다)
```

1. **`forward`의 순서**: ① 잇고 있는 연결이 256개면 `limitReached`. ② `node.whoIs(connection.remoteEndpoint.address)`. nil이면 `unknownPeer`. ③ `127.0.0.1:<port>`로 평문 TCP를 건다(IPv4 루프백만. 기한 5초). 실패하면 `loopbackUnavailable`. ④ 루프백 연결의 자기 쪽 포트를 읽어 표에 `포트 → Origin(상대 끝점, ②의 신원)`을 적는다. ⑤ 그 뒤에 두 방향의 복사를 시작한다. ⑥ 끝나면 **표에서 지운 뒤에** 루프백 연결을 닫는다. ①~③의 실패에서는 `connection`을 RST로 끊는다.
2. **신원은 연결에 고정된다**: ②에서 확인한 신원이 그 연결이 사는 동안의 신원이다. ②와 SYN 사이에 주소의 주인이 바뀌었으면 노드가 그 연결을 이미 끊었으므로(`peerRemoved`) 읽기가 곧바로 실패하고 아무 바이트도 건너가지 않는다. 그래서 새 주인의 신원으로 옛 주인의 바이트가 처리되는 일이 없다. 서버가 요청마다 `whoIs(주소)`를 다시 부르면 이 보장이 없다: 연결이 끊긴 뒤에도 루프백 쪽에 남은 요청이 새 주인의 이름으로 읽힐 수 있다(총괄 확인 필요 H3, 첫 사용처 확인 필요 F1).
3. **복사**: tailnet → 루프백은 `read(upTo: 65_536)`으로 받은 덩어리를 루프백에 쓰고, **네트워크 스택이 받아 갈 때까지 기다린 뒤** 다음을 읽는다. 루프백 → tailnet은 루프백에서 받은 덩어리를 `write(_:)`가 돌아올 때까지 기다린 뒤 다음을 받는다. 다리가 쥐는 것은 방향마다 덩어리 하나(64KiB 이하)다. 느린 쪽이 빠른 쪽을 멈춘다(받는 창과 `write`의 역압이 그대로 이어진다).
4. **반닫힘**: tailnet 쪽이 쓰기를 닫으면(`read`가 nil) 루프백에 FIN을 보내고 반대 방향은 계속 나른다. 루프백 쪽이 닫으면 `finishWriting()`을 부르고 반대 방향은 계속 나른다. 두 방향이 다 끝나면 `forward`가 돌아온다.
5. **끊김과 취소**: 어느 쪽이든 오류(`reset`, `timedOut`, `peerRemoved`, 루프백의 실패)가 나면 두 연결을 모두 끊는다(tailnet 쪽 `abort()`, 루프백 쪽 취소). `forward`를 부른 Task가 취소되어도 같다. 노드가 멈추면(`notRunning`) 루프백 쪽을 닫는다.
6. **표의 불변 조건**: ① 적기 전에는 그 루프백 연결로 한 바이트도 보내지 않는다. ② 지운 뒤에 소켓을 닫는다(닫힌 포트를 다른 프로세스가 다시 쓰더라도 표에는 없다). ③ 다리가 쥔 루프백 연결의 4-튜플은 커널이 유일하게 지키므로 다른 프로세스가 같은 출발 포트로 같은 리스너에 붙을 수 없다. ④ 조회는 잠금 하나로 지키는 동기 호출이다.
7. **서버가 지킬 것**(첫 사용처의 몫. 문서 주석에 적는다): 리스너를 `127.0.0.1`에만 묶고 포트는 시스템이 고르게 한다. 받은 연결마다 **TLS 핸드셰이크가 끝난 뒤, 요청을 읽기 전에** `origin(forLoopbackSourcePort:)`를 묻고, nil이면 그 연결을 끊는다. 핸드셰이크 전에 물으면 다리가 아직 적지 못한 정당한 연결을 끊을 수 있다(리스너가 연결을 알리는 때와 다리가 표에 적는 때 사이에는 보장된 순서가 없다. 둘은 서로 다른 큐에서 일어난다). 평문 리스너(`listenTLS=false`)라면 첫 바이트를 받은 뒤에 묻는다.
8. **같은 기기의 다른 프로세스가 할 수 있는 것과 없는 것**: 루프백 포트에 직접 붙어 TLS 핸드셰이크까지는 할 수 있다. 표에 없으므로 서버가 끊는다(B7). tailnet 피어인 척할 수 없다. 리스너 포트를 먼저 차지하는 것: 서버가 연 포트 번호를 `forward`에 넘기므로, 서버가 죽은 뒤 다른 프로세스가 그 포트를 열면 다리가 그쪽으로 TLS 레코드를 보낼 수 있다. 그 프로세스는 인증서의 키가 없어 핸드셰이크를 끝내지 못한다(평문 리스너에서는 내용이 보인다. 시험 전용이다). 같은 사용자 권한의 프로세스가 앱의 메모리나 상태 파일을 읽는 것은 막지 않는다(첫 사용처의 비목표와 같다, RemoteDebug `docs/protocol.md` 12절).
9. **권한**: 루프백에서 듣는 쪽은 App Sandbox의 들어오는 연결 권한(`com.apple.security.network.server`), 다리와 노드의 소켓·`URLSession`은 나가는 연결 권한(`com.apple.security.network.client`)이 든다. 그 밖의 권한은 쓰지 않는다. Swiftail은 키체인을 쓰지 않는다(사슬과 키를 값으로 낸다). 키체인 없이 TLS 신원을 만드는 길(`SecKeyCreateWithData`·`SecIdentityCreate`)은 SDK 선언만 확인됐고, 샌드박스 안의 실행과 "키체인에 쓰지 않음"은 확인되지 않았다(노트 4.6·8장, 9장 V188·V189·V191). 이것을 구현의 근거로 쓰지 않는다: **첫 사용처 세션이 샌드박스 판에서 확인한다**(첫 사용처 검토 결과 5. 막히면 첫 사용처가 키체인에 넣는 길로 가고 Swiftail의 API는 그대로다).
10. **비용**: 바이트가 Swift TCP → 다리의 복사 → 커널의 루프백 TCP → TLS를 거친다. 4GiB 전송에서의 처리량과 CPU는 관문에서 잰다.

### G. Go 상태에서 가져오기(U1 뒤)

1. **한 번, 읽기 전용**: Go의 디렉터리는 읽기만 한다. 대상에 `identity.json`이 이미 있으면 `alreadyInitialized`다(가져오기가 살아 있는 Swiftail 신원을 덮지 않는다).
2. **범위와 읽기**: 가져오는 것은 **정상 등록이 끝난 프로필 하나**뿐이다(노트 4.7 3·5, 10장). `tailscaled.state`는 1MiB까지 읽는다. 바깥은 JSON 객체이고 값은 **표준 base64** 문자열이다(base64url이 아니다. 노트 4.7 5). 차례(DNS 노트 3.2, 노트 4.7 2·5): ① `_machinekey`(필수)는 `privkey:` + hex 64자다. ② `_current-profile`의 값은 `profile-<ID>`라는 **키 전체**다. ③ `_profiles`의 값은 `{프로필 ID: LoginProfile}`인 JSON 맵이다. ④ `_current-profile`이 가리키는 키의 값이 prefs JSON이다. ⑤ prefs의 `Config.PrivateNodeKey`(`privkey:` + hex 64자), `Config.OldPrivateNodeKey`, `LoggedOut`, `ControlURL`을 읽는다. `Config.NetworkLockKey`는 `nlpriv:` 머리의 다른 타입이고 읽지 않는다(노트 4.7 2, 9장 V199). 거절은 모두 닫힌 쪽이다(새 신원을 만들어 메우지 않는다. 노트 4.7 5):
   - `malformed`: 바깥이 JSON 객체가 아님, 값이 표준 base64가 아님, 키 텍스트의 형식이 틀림, **machine 키가 0**, `_current-profile`이 `profile-` 꼴이 아님, prefs·`_profiles`의 JSON이 깨짐.
   - `unsupportedState`: `_current-profile`이 없음(legacy 형식이거나 프로필이 없다. Go는 이때 빈 프로필을 만들거나 legacy prefs를 옮긴다), `_current-profile`이 가리키는 키가 없음, 그 ID가 `_profiles`에 없음(불일치), `_profiles`에 프로필이 둘 이상, `Config.OldPrivateNodeKey`가 있고 0이 아님(키 교체가 끝나지 않은 상태. Go는 재등록에도 그 키를 `OldNodeKey`로 싣는다. `control/controlclient/direct.go:718-720`, 노트 4.7 3, 9장 V202).
3. **가져오지 않는 경우**: node 키가 없거나 0이거나 `LoggedOut`이 참이면 `notLoggedIn`이다. 0인 까닭이 "로그인한 적 없음"인지는 판정하지 않는다(노트 4.7 3, 9장 V201). machine 키만 가져오지 않는다(같은 노드가 되지 않는다). **제어 서버의 비교**(한 서버에 등록한 키를 다른 서버에 내밀지 않는다. 노트 10장): ① 기본 서버: prefs의 `ControlURL`이 비었거나 `https://controlplane.tailscale.com`(Go `DefaultControlURL`)이거나 `https://login.tailscale.com`이면 Go는 기본 서버로 본다(`ipn/prefs.go:42`, `:50-54`의 `IsLoginServerSynonym`, `ipn/ipnlocal/profiles.go:701-708`. 노트 4.7 3). 문자열을 그대로 견준다. 이때 `configuration.controlURL`도 그 두 문자열 가운데 하나여야 한다(Swiftail의 기본값은 `https://controlplane.tailscale.com`이다). ② 사용자 지정 서버: 양쪽 URL의 스킴·호스트·포트가 같고, **경로가 비었거나 `/`이고, query·fragment·userinfo가 없을 때만** 같은 서버로 본다. 구성 요소는 정규화하지 않고 견준다(생략한 포트와 `:443`도 다르다고 본다). 그 밖은 모두 `controlURLMismatch`다. "스킴·호스트·포트가 같음"이 "등록한 서버가 같음"을 보장하지는 않는다: Go는 `ControlURL`의 경로까지 보존해 제어 끝점을 만든다(노트 10장 G3, `control/controlclient/direct.go:810-817`). 그래서 경로가 있는 URL은 받지 않는다.
4. **쓰기**: `NodeIdentityStore`로 저장한다(0600, 원자적, iOS의 보호 등급 그대로). `NetworkLockKey`·프로필은 옮기지 않는다(노트 4.7 3). `OldPrivateNodeKey`가 있는 상태는 G2가 이미 거절했으므로, 옮기지 않아서 Go와 달라지는 경우(키 교체 중단)는 가져오기에 들어오지 않는다.
5. **부르는 쪽이 지킬 것**: 그 상태를 쓰는 Go 노드가 멈춰 있다. 가져온 뒤에는 Go 노드를 그 상태로 다시 띄우지 않는다. Swiftail은 다른 프로세스가 같은 키를 쓰는지 알 수 없다(노트 4.7 4).
6. **인증서**: Go의 `certs/` 아래 인증서와 키 파일은 이름과 형식이 같으므로 첫 사용처가 그대로 복사하면 `CertificateManager`가 동작 S3으로 검증해 쓴다(Go의 SEC1 키를 CryptoKit이 읽는 것은 노트 4.6에서 확인됐다). 따로 API를 두지 않는다. 같은 이름의 새 인증서 한도(7일에 5장)를 아낀다. 계정 키(`acme-account.key.pem`)는 P-256일 때만 쓴다: Go가 읽을 수 있는 RSA 계정 키까지 호환한다고 보장하지 않으며, 그런 파일을 복사하면 동작 C4가 `accountKeyUnreadable`로 끝난다(노트 10장). 그때 첫 사용처는 계정 키 파일을 빼고 복사한다(새 계정을 만든다).
7. **되돌리기와 확인되지 않은 것**: Swiftail이 그 뒤에 node 키를 바꾸면(만료 뒤 재인증) Go 상태의 키는 옛것이 된다. 되돌린 Go 노드는 다시 로그인해야 할 수 있다. 서버가 옛 키를 어떻게 다루는지(거절하는지, `OldNodeKey`로만 인정하는지)는 클라이언트 소스로 결론이 나지 않는다(노트 4.7 4, 9장 V211). 가져온 노드가 같은 노드로 받아들여지는지도 **관문 전에는 확인되지 않았다**: Swiftail은 등록의 `NLKey`를 0으로 보내고(Go가 `NLKey`를 실어 등록한 노드가 0으로 다시 붙을 때의 서버 동작), 같은 node 키로 두 구현이 동시에 붙을 때의 서버·DERP 동작도 모른다(노트 4.7 4, 8장). 관문 (가) 11과 (나) 8이 이것을 본다.

### K. 비밀과 로그

1. 비밀은 ACME 계정 키, 인증서 개인 키, (가져올 때) Go 상태의 machine·node 키다. 파일은 0600이고 메모리에서는 CryptoKit의 키 타입으로만 든다. `TailnetCertificate`·`CertificateManager`의 `description`과 `dump`에 키가 나오지 않는다(`CustomReflectable`).
2. 로그(`os.Logger(subsystem: "Swiftail")`)에 남기는 것: 발급의 시작과 끝, 실패의 종류, 다음 시도까지의 간격, 인증서의 만료 날짜, 다리가 이은 연결 수. 남기지 않는 것: 키, JWS 본문, nonce, token과 키 인가, 계정 URL, ACME 문제 문서의 `detail`(식별자가 들어 있을 수 있다. `status`로만 낸다), tailnet 이름이 든 도메인 전체, 주소 전체, 로그인 이름.
3. 오류의 연관 문자열에는 키·경로·기술자 번호를 넣지 않는다(M5의 규칙).
4. 이 범위에는 비밀 값을 견주는 곳이 없다. 공개 키의 비교(동작 S3 ④, X3 ③)와 포트 번호의 조회뿐이다. 비밀 비교가 생기면 `SwiftailCrypto`의 상수 시간 비교를 쓴다.
5. **인증서는 공개된다**: Let's Encrypt가 발급한 인증서는 공개 Certificate Transparency 로그에 실리고 거기에 기기 이름과 tailnet 이름이 들어간다(Let's Encrypt의 속도 제한 문서가 발급된 인증서를 CT 로그 검색으로 찾으라고 안내한다). Go 호스트도 지금 같다. 사용자 확인 필요 U3에 적는다.

### M. 한도

| 항목 | 값 | 넘으면 |
| --- | --- | --- |
| ACME JSON 응답 | 64KiB | 그 시도 실패(`unexpectedResponse`) |
| 인증서 사슬 응답 | 256KiB, 5장 | 실패 |
| 주문의 authorization 수 | 8개(동작 C5) | `unexpectedResponse` |
| 문제 문서의 `type` | 256바이트(동작 C12) | 자른다 |
| `set-dns` 응답 본문 | 4KiB | 실패 |
| URL | 2,048바이트, `https` | 실패 |
| HTTP 요청 하나 | 30초 | `timedOut` 또는 `network` |
| 발급 한 번 | 5분 | `timedOut`(`Retry-After`가 이것을 넘어도 그때 끝낸다. 동작 X5) |
| `set-dns` | 60초 | `network` |
| `badNonce` 재시도 | 요청마다 3번 | 실패 |
| 주문 다시 읽기 간격 | `Retry-After`, 없으면 1초, 1초보다 짧으면 1초 | 늦추기만 한다. 서버의 값보다 일찍 읽지 않는다 |
| `Retry-After`로 정해지는 다음 시도 | 7일 | 7일로 묶는다(위쪽 끝만. 동작 X5) |
| 한 시도 안에서 새 주문을 다시 만듦 | 1번(동작 C5·C7, H17) | `orderFailed` |
| finalize 뒤 `ready`·`pending`의 되풀이 | 주문마다 1번(동작 C7, H17) | `unexpectedResponse` |
| 다리가 잇는 연결 | 256개(노드의 연결 상한과 같다) | `limitReached` |
| 다리가 쥐는 바이트 | 연결마다 방향당 64KiB | 읽기를 멈춘다 |
| 루프백 연결 맺기 | 5초 | `loopbackUnavailable` |
| 디스크의 인증서·키 파일 | 64KiB씩 | 없는 것으로 본다 |
| Go 상태 파일 | 1MiB | `malformed` |

## 4. C API 대응표

첫 사용처의 Go 코어가 내는 C 함수는 18개다(RemoteDebug `core/capi/include/rdcore.h`). "쓰는 쪽"의 Mac은 호스트 모드, 확장은 iPhone의 패킷 터널 확장(터널 모드)이다. Swift 쪽의 호출은 모두 `Packages/RDCore/Sources/RDCoreBridge/RDCoreBridge.swift` 한 파일을 거친다.

| # | 함수 | Go 코어가 하는 일(쓰는 tsnet·Tailscale 기능) | 쓰는 쪽 | 바뀐 뒤 |
| --- | --- | --- | --- | --- |
| 1 | `rd_start` | 설정 JSON 검증, 상태 디렉터리 하나에 핸들 하나. 호스트: `tsnet.Server{Dir, Hostname, AuthKey, ControlURL, Ephemeral}.Start`, IPN 버스 구독, 상태 점검 고루틴. 터널: `LocalBackend` + utun | Mac, 확장 | **Swiftail**: `TailnetNode(configuration:device:)`와 `run()`. 호스트는 `.inProcess`, 확장은 `.utun`(M5). 중복 시작은 `NodeError.stateDirectoryInUse`. 설정 JSON과 핸들 표는 없어진다 |
| 2 | `rd_status` | `LocalClient.Status`: 상태, 로그인 URL, 주소, cert 도메인, 자기 이름·`StableID`, 피어의 경로. 여기에 호스트의 것(`tlsReady`, `listening`, 게시·기기 수, RSS)을 더한다 | Mac, 확장 | **Swiftail**: `node.status`, `node.events`, `path(toPeerNamed:)`, `CertificateManager.status`. 나머지 필드는 첫 사용처(아래 표) |
| 3 | `rd_stop` | 리스너·호스트·노드를 닫는다(`srv.Close`) | Mac, 확장 | **Swiftail**: `run()`을 돌리는 Task 묶음의 취소 |
| 4 | `rd_host_publish` | IPA 검사·사본·목록. tsnet을 쓰지 않는다 | Mac | 첫 사용처 |
| 5 | `rd_host_unpublish` | 위와 같다 | Mac | 첫 사용처 |
| 6 | `rd_host_publish_resource` | 파일 공유 목록. tsnet을 쓰지 않는다 | Mac | 첫 사용처 |
| 7 | `rd_host_unpublish_resource` | 위와 같다 | Mac | 첫 사용처 |
| 8 | `rd_host_set_agent_board` | `GET /v1/agent`의 문서를 바꾼다 | Mac | 첫 사용처 |
| 9 | `rd_update_page_set` | 루프백 HTTP 서버(Go `net/http`). 공식 Tailscale 앱의 `serve`가 그것을 내보낸다. 코어의 tsnet과 무관하고 핸들도 없다 | Mac | 첫 사용처(Swift의 루프백 HTTP 서버). Swiftail과 무관 |
| 10 | `rd_host_set_devices` | 허용 목록을 통째로 바꾼다. 키는 노드 `StableID` | Mac | 첫 사용처. `StableID`는 `PeerIdentity.stableID` |
| 11 | `rd_host_set_direct` | 같은 네트워크 직접 연결: OS TCP 리스너, 자체 서명 P-256 인증서의 TLS 1.3(Go `crypto/tls`·`x509`), 기기 토큰 인증. tsnet을 쓰지 않는다 | Mac | 첫 사용처(`NWListener`). 인증서를 새로 만드는 코드도 첫 사용처(F9) |
| 12 | `rd_host_pairing_open` | 페어링 코드를 만든다 | Mac | 첫 사용처 |
| 13 | `rd_host_pairing_decide` | 페어링 요청을 승인·거절한다. 요청에 적힌 신원은 `WhoIs`가 준 것이다 | Mac | 첫 사용처. 신원은 `LoopbackBridge.Origin.peer` |
| 14 | `rd_proxy_start` | 루프백 CONNECT 프록시, `srv.Dial` | 호출하는 곳 없음 | **빠진다**(검토 결과 2) |
| 15 | `rd_tunnel_set_default_interface` | 기본 인터페이스 전환을 엔진에 알린다 | 확장 | **Swiftail**: `setDefaultInterface(_:)`(M5) |
| 16 | `rd_tunnel_set_path_peer` | 경로를 보고할 피어를 정한다 | 확장 | **Swiftail**: `path(toPeerNamed:)`와 `NodeEvent.peerPathChanged`(M4·M5). 따로 정해 둘 것이 없다 |
| 17 | `rd_next_event` | 사건 큐에서 하나를 기다려 꺼낸다 | Mac, 확장 | **Swiftail**: `node.events`·`node.networkSettings`·`certificates`의 `for await`. 호스트의 사건은 첫 사용처 |
| 18 | `rd_free` | C 문자열 해제 | Mac, 확장 | **빠진다** |

요약: Swiftail의 API로 바뀌는 것 6개(1·2·3·15·16·17. Mac 호스트가 쓰는 것은 그중 1·2·3·17), 첫 사용처가 Swift로 직접 쓰는 것 10개(4~13), 빠지는 것 2개(14·18).

함수 뒤에서 Go 코어가 쓰던 Tailscale 기능의 대응(Mac 호스트):

| Go 코어 | 어디서 | 바뀐 뒤 |
| --- | --- | --- |
| `srv.Listen("tcp", ":443")`, 실패 3번이면 `Error` | `node.go:780-823` | `node.listen(port: 443)`. 재시도 로직은 없앤다(검토 결과 4) |
| `tls.NewListener(ln, GetCertificate)` + `http.Server` | `tls.go:41`, `node.go:812-818` | `LoopbackBridge.forward` + 첫 사용처의 `NWListener`(TLS)와 HTTP 서버 |
| `CertPair`로 인증서 예열, 30초~10분 재시도, `tlsReady` | `tls.go:44-51`, `node.go:825-859` | `CertificateManager.run()`. `tlsReady`는 "`certificates`에서 하나를 받았고 TLS 리스너가 섰다" |
| `Up`·`Status`로 MagicDNS와 cert 도메인 확인, 꺼져 있으면 오류 문구 | `tls.go:22-32` | `CertificateFailure.magicDNSDisabled`·`httpsNotEnabled`. 문구는 첫 사용처 |
| `LocalClient.WhoIs(r.RemoteAddr)`, 5초 기한, 요청마다 | `node.go:526-546`, `host.go:230-244` | `LoopbackBridge.origin(forLoopbackSourcePort:)`(연결마다 한 번, 기다림 없음). 직접 부를 때는 `node.whoIs(_:)` |
| IPN 버스의 `ErrMessage` → `Error` 상태 | `node.go:409-458` | `run()`이 던지는 `NodeError`와 `NodeEvent.stateChanged` |
| `StartLoginInteractive`, 30초 간격 | `node.go:752-778` | M5 계약대로(`.needsLogin(URL)`, `startInteractiveLogin()`) |
| 페어링한 기기별 경로(`peerPaths`, 키는 `StableID`) | `node.go:141-163`, `:658-670` | `path(toPeerNamed:)`. 이름은 `Origin.peer.name`에서 얻는다(F10) |
| `NetworkLockStatus` 진단 로그 | `node.go:494-504` | 없다. lock이 켜진 tailnet은 `NodeError.control(.tailnetLockEnabled)`로 끝난다 |
| `logtail.Disable()`, `goMemLimitMiB`, RSS | `node.go:35-38`, `:277` | 해당 없음(로그 업로드가 없다. 메모리 한도 설정이 없다). RSS는 첫 사용처 |
| `srv.Dial` | `node.go:952` | `node.connect(to:port:)`. 시험과 진단만 쓴다 |

`rd_status` 필드의 출처(호스트 모드): `backendState`·`authURL` ← `NodeState`와 `run()`의 결과, `hostname` ← 설정, `fqdn`·`tailscaleIPs`·`certDomains` ← `NodeStatus`, `tlsReady` ← 위 표, `listening`·`publishedBuilds`·`pairedDevices`·`rssMiB`·`direct` ← 첫 사용처, `peerPaths` ← 위 표.

상태 디렉터리(Go 호스트): `tailscaled.state`, 로그 설정과 로그 버퍼, `certs/`, 그리고 첫 사용처의 `direct.json`·`direct-key.pem`·`direct-cert.pem`이 있다(노트 4.7 1). Swiftail의 상태 디렉터리는 따로 둔다(`SwiftailTunnel.md` D8): `identity.json`과 `certs/`. 직접 연결의 세 파일은 첫 사용처가 옮긴다(iPhone이 그 키를 고정한다).

## 5. 결정

### 총괄 확인 필요

| # | 무엇 | 선택지 | 권고와 까닭 |
| --- | --- | --- | --- |
| H1 | 타깃 구성 | (가) 새 제품 둘: `SwiftailCertificates`, `SwiftailLoopback` / (나) 새 제품 하나(`SwiftailHost`)에 둘 다 / (다) `Swiftail` 안에 넣는다 | (가). 둘은 서로를 모른다(인증서만, 다리만 쓰는 앱이 있을 수 있다). 타깃 하나가 개념 하나다. (다)는 iOS 터널 확장의 바이너리에 ACME·DER·Security 코드가 들어간다. 대가: `Package.swift`에 타깃 넷(시험 포함) |
| H2 | 다리를 누가 쓰는가 | (가) Swiftail의 선택 제품 / (나) 첫 사용처 | (가). 역압·반닫힘·끊김의 대응은 `TailnetConnection`의 성질(`write`의 취소가 RST가 되는 것 등)에 묶여 있고, 표의 불변 조건(동작 B6)은 보안 성질이라 한 곳에서 시험해야 한다. 다리는 공개 API만 쓴다(`package`는 `SwiftailIO`뿐) |
| H3 | 서버에 상대의 신원을 넘기는 길 | (가) 출발 포트 표 + 잇기 시작할 때 고정한 신원(`Origin.peer`) / (나) 출발 포트 표는 주소만 주고 서버가 요청마다 `whoIs(주소)` / (다) TLS 아래에 프레이머를 끼워 연결 앞에 머리말(주소와 비밀 토큰)을 싣는다 | (가). (나)는 동작 B2의 틈이 있고 요청마다 actor를 건넌다. (다)는 `NWProtocolFramer`를 TLS 아래에 둘 수 있는지 확인하지 못했다. 대가: 연결이 사는 동안 이름·로그인 이름의 변경이 반영되지 않는다(허용 목록은 `StableID`라 영향이 없다) |
| H4 | 다리의 루프백 쪽 소켓 | (가) `NWConnection`(`SwiftailIO.NetworkSocket`). 준비된 뒤 자기 포트를 읽어 적고 그 뒤에만 보낸다 / (나) POSIX 소켓: `bind(127.0.0.1:0)` → `getsockname` → 표에 적기 → `connect` | (가). 제어·DERP가 쓰는 감싸기를 다시 쓴다. 서버가 "핸드셰이크 뒤에 묻는다"(B7)만 지키면 순서가 보장된다. (나)는 연결 전에 적을 수 있어 서버가 언제 물어도 되지만 POSIX 호출과 읽기 준비 통지를 새로 쓴다. 실험(기록이 없어 확인되지 않았다. M7-9가 먼저 확인한다. 9절): `NWConnection`의 `currentPath.localEndpoint`가 준비 상태에서 포트를 주고, 리스너가 받은 연결의 `endpoint`가 그 출발 포트를 준다 |
| H5 | 인증서 API가 내는 키 | (가) `P256.Signing.PrivateKey` + DER 사슬 / (나) 거기에 `SecIdentity`를 만들어 주는 함수 | (가). 첫 사용처가 요청한 것이 "사슬 + `SecKey`로 만들 수 있는 키"다. `SecIdentity` 만들기는 다섯 줄이고(6절의 조각. SDK 선언만 확인됐고 돌려 보지 않았다) 리스너 설정과 함께 첫 사용처에 있는 것이 읽힌다 |
| H6 | 갱신 판정 | (가) 수명의 2/3 / (나) ARI(RFC 9773)와 `replaces` | (가). 최소 범위를 위한 정책 선택이다(노트 6장). 2/3만으로 속도 제한 회피가 **보장되지는 않는다**: 제한의 종류(같은 식별자 집합 7일 5장 등)와 ARI 갱신이 면제되는 조건은 노트 4.5에 있다(동작 R1). (나)는 요청 둘과 인증서 식별자 계산(일련번호·AKI의 DER 읽기. Go 포크의 일련번호 인코딩은 RFC 9773과 다르다, 노트 4.4 2)이 든다 |
| H7 | 저장 형식 | (가) Go와 같은 자리·이름·PEM(`certs/`) / (나) Swiftail만의 형식 | (가). Go가 받아 둔 인증서를 복사만으로 쓴다(동작 G6). 키는 PKCS#8로 쓰지만 Go도 읽는다(노트 3.7). 되돌릴 때도 통한다 |
| H8 | ACME의 HTTPS | (가) `URLSession`(Foundation) / (나) `NetworkSocket` 위에 HTTP/1.1 클라이언트를 직접 쓴다 | (가). Mac 호스트는 OS의 네트워크를 그대로 쓴다(터널 안이 아니다). 전송은 주입할 수 있게 해서 시험이 가짜 서버를 붙인다. 함께 정할 것: plan 4절(c)의 허용 프레임워크에 Security를 더한다 |
| H9 | 재시도 간격과 한도의 값 | 동작 R4, M의 표 | 표의 값으로 시작하고 관문 (나)의 기록으로 조정한다. 발급 한 번의 기한(5분)은 `set-dns`가 얼마나 걸리는지 모르고 잡은 값이다 |
| H10 | 시험용 ACME 서버 | (가) pebble과 challtestsrv를 `Tools/interop`에 넣는다(둘 다 MPL-2.0. 시험 도구에만 링크된다) / (나) Swift 시험 안의 가짜 ACME 서버만 / (다) Let's Encrypt 스테이징 | (가)와 (나)를 함께. (나)는 독립 시험(결정적, 오류 주입)에, (가)는 관문에 쓴다. 독립된 ACME 구현을 상대해야 "단위 시험 통과만으로 프로토콜 동작을 주장하지 않는다"(plan 7절)를 지킨다. (다)는 계정과 실제 tailnet이 필요해 관문 (나)에서만 쓴다. 확인할 것: 시험 도구의 MPL-2.0 의존이 괜찮은지(U2), 빌드가 되는지(9절) |
| H11 | 프로필이 없는 노드의 `whoIs` | (가) nil(Go와 같다) / (나) 로그인 이름을 비운 신원 | (가). 닫힌 쪽이다. 첫 사용처는 nil을 `not_paired`로 답한다 |
| H12 | Go 상태 가져오기의 모양 | (가) 읽기 전용, 한 번, 신원만(동작 G) / (나) 프로필·prefs까지 / (다) 지원하지 않는다 | U1이 "이관"이면 (가). `identity.json`에 필요한 것은 키 둘뿐이다. U1이 "재페어링"이면 (다)이고 구현 단위 M7-11을 열지 않는다 |
| H13 | ACME의 User-Agent | `Swiftail/<버전>` / 앱이 주는 문자열을 앞에 붙인다 | `Swiftail/<버전>`. 인자를 만들지 않는다. 공식 클라이언트를 흉내 내지 않는다(plan 8절 위험 10) |
| H14 | DER 쓰기·PEM·base64url의 자리 | (가) `SwiftailCertificates` 안(`internal`) / (나) `SwiftailBase`(`package`) | (가). 쓰는 곳이 CSR 하나다. 첫 사용처가 직접 연결 리스너의 자체 서명 인증서를 Swift로 만들 때 이 부품을 바라면(F9) 다시 본다 |
| H15 | 관문 (가)의 e2e 범위 | (가) 시험 타깃 안의 최소 HTTP/1.1 서버로 "페어링 → 설치 세션 → IPA 전송"의 뼈대 / (나) 첫 사용처의 호스트 코드를 끌어온다 | (가). 첫 사용처 저장소는 읽기만 한다. 실제 호스트의 e2e는 그쪽 저장소에서, 별도 승인 뒤에 한다 |
| H16 | 읽지 못한 계정 키 파일의 실패 종류(동작 C4) | (가) 새 `CertificateError.accountKeyUnreadable` / (나) 기존 `storage(String)`에 싣는다 | (가)로 적었다. 둘 다 닫힌 쪽(덮어쓰지 않고 `run()`이 끝난다)이다. 앱이 "Go가 남긴 계정 키"를 디스크 오류와 갈라 사용자에게 알릴 수 있다. 대가: 공개 case 하나 |
| H17 | 한 시도 안의 되풀이의 상한(동작 C5·C7) | (가) CSR 전에 `valid`·`processing`인 주문은 새 주문으로 한 번만 다시, finalize 뒤 `ready`·`pending`의 되풀이도 주문마다 한 번 / (나) 5분 기한만 / (다) 되풀이하지 않고 곧바로 실패 | (가)로 적었다. (나)는 서버가 같은 상태를 되풀이하면 기한까지 주문과 finalize를 거듭 보내 새 주문 제한(노트 4.5)을 쓴다. (다)는 노트 4.3 11이 제안한 갈래(같은 키·CSR로 다시 finalize)를 버린다. 두 번째에는 실패로 끝난다 |
| H18 | 규격·한도를 어긴 ACME 응답의 실패 종류 | (가) 새 `CertificateFailure.unexpectedResponse` / (나) `acme(status:type:)`에 빈 `type`으로 / (다) `network` | (가)로 적었다. 동작 C5·X가 "실패"라고만 적던 경우(모르는 상태, 다른 이름의 authorization, 한도 초과, `https`가 아닌 URL)에 공개 종류가 없었다. 재시도는 `acme`와 같은 15분~6시간이다(동작 R4) |
| H19 | `validationFailed`·`orderFailed`의 연관 값 | (가) 그 challenge·주문의 `error` 문제 문서의 `type`(256바이트로 자른다) / (나) 연관 값 없음 / (다) `detail`까지 | (가)로 적었다. 결정 4와 같은 까닭으로 `detail`은 싣지 않는다(동작 K2). `type`만으로 `dns`·`unauthorized`·`badCSR` 같은 진단은 된다 |
| H20 | 그룹·기타가 쓸 수 있는 기존 `certs/`(동작 S1) | (가) 쓰지도 읽지도 않고 `storage`로 끝난다 / (나) 쓰기만 막고 읽기는 한다 | (가)로 적었다. 총괄 결정은 "쓰지 않고 실패"까지이고 읽기는 정하지 않았다. 남이 바꿔 넣을 수 있는 디렉터리의 키를 TLS 신원으로 내면 그 사람이 트래픽을 풀 수 있으므로 읽기도 막는 쪽을 골랐다 |
| H21 | `Retry-After`의 적용 범위와 읽지 못한 값(동작 X5) | (가) 그 디렉터리에서 얻은 모든 URL에 적용, 읽지 못한 값은 없는 것으로 / (나) 응답한 URL이나 호스트에만 / (다) 읽지 못한 값은 그 시도의 실패 | (가)로 적었다. "그 서버"를 가장 넓게 잡는 것이 닫힌 쪽이다. 읽지 못한 값은 없는 것으로 보되, 주문 읽기는 1초보다 짧아지지 않고 오류 응답은 R4의 간격으로 물러나므로 요청이 늘지 않는다 |
| H22 | Go 상태의 거절을 두 오류로 가르는 기준(동작 G2) | (가) 형식이 틀리면 `malformed`, 해석은 되지만 다루지 않는 상태면 `unsupportedState` / (나) 모두 `malformed` | (가)로 적었다. 프로필 여럿·legacy·키 교체 중단은 파일이 깨진 것이 아니라 사용자가 Go 쪽에서 정리하면 되는 상태라 문구를 달리할 수 있다. 0인 machine 키는 Go가 시작할 때 만드는 값이라 깨진 것으로 본다 |
| H23 | 이름 검사(동작 C2)에 어긋나는 자기 이름의 실패 종류 | (가) `domainNotAllowed`로 적고 netmap 변화를 기다린다 / (나) 새 case / (다) `run()`이 던진다 | (가)로 적었다. 이름은 제어 서버가 정하므로 netmap이 바뀌어야 풀리고, 시간으로 다시 시도해도 같다. 앱이 보이는 문구는 "이 이름으로는 인증서를 받을 수 없다"로 같다. 대가: 관리 콘솔에서 고칠 것이 없는데 사용자 조치 갈래로 보인다 |

총괄 확정(2026-11-15, 초안 단계. 첫 사용처의 답으로 바뀔 수 있다): **H1~H15는 모두 권고대로 간다.** 덧붙이는 것:

- H4: (가)에서 서버가 TLS 핸드셰이크 전에 물으면 정당한 연결이 끊길 뿐(닫힌 쪽) 신원이 잘못 붙지는 않는다. 표에 적기 전에는 한 바이트도 보내지 않기 때문이다(동작 B6 ①). 그래서 POSIX 소켓을 새로 쓰지 않는다. F1·F4의 답이 서버의 묻는 시점을 못 지킨다고 하면 (나)로 바꾼다.
- H8: plan 4절(c)에 Security와 `URLSession`을 적었다. 두 프레임워크는 `SwiftailCertificates`만 쓴다.
- H10: 시험 도구의 MPL-2.0 의존은 `Tools/`의 Go 도구 예외 안이다. 공개할 때의 고지는 U2에서 함께 정한다.
- H12: U1의 답이 올 때까지 M7-11(Go 상태 가져오기)을 열지 않는다.
- 노트 `whois-certs-state.md`는 구현 전에 다른 세션이 Go 소스와 RFC 원문에 대조해 검증한다.

### 첫 사용처 확인 필요

커밋 `2814b2c`의 Go 코드와 문서(`core/internal/node/`, `core/internal/host/`, `core/internal/direct/`, `core/e2e/`, `docs/protocol.md`, `docs/protocol-addenda.md`)를 읽고 세운 가정과 질문이다.

| # | 질문 | 초안의 가정 | 답에 따라 달라지는 것 |
| --- | --- | --- | --- |
| F1 | 지금은 요청마다 `WhoIs`를 부른다. 바꾼 뒤에는 **연결마다 한 번** 신원을 고정하고(`Origin.peer`), 요청마다는 그 `StableID`를 허용 목록에 견주기만 해도 되는가? 주소의 주인이 바뀌면 Swiftail이 연결을 끊는다 | 된다 | H3, 동작 B2. 요청마다 다시 확인해야 한다면 서버가 `whoIs`의 `stableID`를 `Origin.peer.stableID`와 견줘 다르면 끊는 규칙을 계약에 더한다 |
| F2 | `PeerIdentity`의 필드(`stableID`, `name`, `computedName`, `tags`, `loginName`, `displayName`)로 충분한가? `computedName`은 이름이 빈 노드의 대비인데 필요한가? 태그를 단 iPhone(페어링 링크의 1회용 키, addenda J)의 `loginName`에 무엇이 오든 괜찮은가? | 충분하다. `computedName`은 지금 코드가 쓰므로 둔다 | 공개 타입. 프로필 사진 URL이나 공유자(`Sharer`)가 필요하면 더한다 |
| F3 | 인증서는 `certificates` 흐름(지금 것 + 갱신)과 `status`(만료 시각, 마지막 실패, 다음 시도)로 받는다. `tlsReady`와 "HTTPS가 꺼져 있습니다" 같은 `errorMessage`를 `CertificateFailure`의 종류로 만들 수 있는가? 실패를 사건으로도 받아야 하는가(지금은 2초마다 상태를 읽는다)? | 종류면 충분하고 사건은 필요 없다 | `CertificateStatus`·`CertificateFailure`. 사건이 필요하면 흐름을 하나 더 둔다 |
| F4 | 인증서가 갱신되면 `NWListener`를 새 신원으로 다시 띄워야 한다(리스너의 신원은 만들 때 정해진다). 포트가 바뀔 수 있어서 `forward`가 포트를 호출마다 받는다. 이 모양이 서버와 맞는가? 이미 맺은 연결은 옛 리스너에서 끝까지 가는가? | 맞다 | `forward(_:toLoopbackPort:)`의 모양. 리스너를 다리가 쥐길 바라면 범위가 커진다 |
| F5 | accept 루프는 첫 사용처가 돌고 연결마다 `forward`를 부른다. 다리의 상한은 256이다. `forward`는 연결이 끝나야 돌아온다(Task 하나가 연결 하나를 쥔다) | 맞다 | 동작 B1, 한도 |
| F6 | 가짜 tailnet(`listenTLS=false`)에서도 같은 다리로 평문 루프백 리스너에 잇는가, 아니면 `TailnetConnection` 위에서 HTTP를 바로 읽는가? | 같은 다리(서버의 입구를 하나로 둔다) | 관문 (가)의 서버 모양. 바로 읽는다면 서버가 `TailnetConnection`용 입구를 따로 갖는다 |
| F7 | Mac 호스트의 샌드박스: 커밋된 `Apps/Mac/RemoteDebugMac.entitlements`는 빈 사전이고 `README.ko.md`는 "App Sandbox를 쓰지 않는다"고 적는다. 받은 답은 "App Sandbox, 네트워크 서버·클라이언트 권한만"이다. 어느 빌드가 M7의 기준인가? 샌드박스 판의 상태 디렉터리는 컨테이너 안인가? | 샌드박스 판이 기준이고 권한은 그 둘뿐이다 | 동작 B9, 관문 (나) 7. 샌드박스 안의 실행 확인을 누가 하는지(권고: 첫 사용처 세션) |
| F8 | Go가 받아 둔 인증서(`certs/`의 세 파일)를 새 상태 디렉터리로 복사하는 일은 첫 사용처가 하는가(이관을 한다면)? | 그렇다 | 동작 G6. Swiftail이 맡길 바라면 `GoStateImport`에 인자를 더한다 |
| F9 | 직접 연결 리스너의 자체 서명 인증서: 기존 `direct-key.pem`·`direct-cert.pem`은 CryptoKit과 Security로 읽을 수 있다(노트 4.6). **새로 설치한 Mac에서 인증서를 만드는** X.509 인코딩은 첫 사용처가 쓰는가? Swiftail의 DER 쓰기 부품을 내주길 바라는가? | 첫 사용처가 쓴다. 내주지 않는다 | H14 |
| F10 | `peerPaths`는 `StableID`가 키인데 Swiftail의 경로 조회는 이름으로 한다. 이번 실행에서 접속한 기기의 이름은 `Origin.peer.name`으로 안다(접속한 적 없는 기기는 경로도 없다). 이것으로 되는가? | 된다 | 안 되면 `whoIs`에 `StableID`로 찾는 길을 더한다 |
| F11 | Go 코어는 tsnet의 로그를 `logPath` 파일에 쓴다. Swiftail은 `os.Logger`에만 남긴다. 파일에 Swiftail의 로그가 필요한가? | 필요 없다 | 필요하면 로그 받는 길을 따로 정한다(M5에도 걸린다) |
| F12 | 인증서 재시도 간격이 바뀐다(동작 R4: 검증 실패는 15분부터). 인증서를 받기 전에도 tailnet 리스너는 듣고 있고 다리는 루프백 포트가 없어 연결을 끊는다. 지금의 `listening`·`tlsReady` 표시와 어긋나는가? | 어긋나지 않는다 | 동작 R4의 값 |
| F13 | Go 코어를 걷어낸 뒤 시험 상대(가짜 iPhone)는 무엇인가? Go의 `rdtestenv peer`·`core/e2e`의 tsnet 피어를 시험 도구로 남기는가, Swiftail 노드(`connect`)로 바꾸는가? Swiftail 저장소의 관문은 Go tsnet 피어를 상대한다 | 시험 도구의 Go는 남는다 | 관문 (가) 7의 재현 범위, `Tools/interop`의 `peerHTTP` |
| F14 | 호스트의 나머지(REST, 페어링, 세션, 게시, 직접 연결, 업데이트 페이지, 사건 큐)는 모두 첫 사용처가 Swift로 쓴다. Swiftail에 바라는 것이 4절 표 밖에 더 있는가? | 없다 | 범위 |
| F15 | Mac 호스트를 임시(ephemeral) 노드로 띄우는 일이 시험 밖에도 있는가? 임시 노드가 같은 이름으로 다시 뜰 때마다 상태가 비어 있으면 인증서를 새로 받게 되고 7일에 5장 한도에 닿는다 | 운영에서는 없다 | 있으면 임시 노드에서 발급하지 않는 규칙을 더한다 |
| F16 | `WhoIs`의 5초 기한은 없어진다(`origin`·`whoIs`는 기다리지 않는다). 기한에 기대는 곳이 있는가? | 없다 | — |

### 첫 사용처 검토 결과 (2026-11-15)

첫 사용처 세션이 F1~F16에 답했다(그쪽 저장소 `2814b2c` 이후의 코드 기준). 가정이 그대로 선 것: F1, F4, F5, F6, F8, F10, F11, F13, F14, F15, F16. 초안이 바뀌는 것만 적는다.

1. **신원(F1·F2)**: 연결마다 고정한 `Origin.peer.stableID`를 요청마다 허용 목록에 견주는 것으로 지금과 같은 판정이다(허용 목록에서 지우면 다음 요청부터 막히는 것은 서버가 요청마다 목록을 보아 채운다). 호스트가 읽는 것은 `stableID`, `computedName`, `loginName`뿐이라 `PeerIdentity`에서 `tags`와 `displayName`을 뺐다. `name`은 경로 조회(`path(toPeerNamed:)`)의 열쇠라 둔다(F10: 첫 사용처가 접속한 기기의 `StableID` ↔ 이름을 기억한다. 지금 연결이 없는 기기도 이름으로 묻는다). `loginName`은 빈 문자열일 수 있다.
2. **실패의 종류(F3)**: 사용자가 스스로 고칠 수 있는 둘(`magicDNSDisabled`, `httpsNotEnabled`)이 나머지와 갈리면 된다. 앱이 그 둘에 "DNS 설정 페이지 열기"를 붙인다. `magicDNSDisabled`를 더했다. 실패를 사건으로 낼 필요는 없다(2초마다 `status`를 읽는다).
3. **갱신과 리스너(F4·F5)**: 갱신되면 첫 사용처가 새 `NWListener`를 띄워 그 포트로 `forward`를 부른다. 이미 맺은 연결은 옛 리스너에서 끝까지 가고, 옛 리스너는 새 연결만 받지 않다가 남은 연결이 끝나면 닫는다(큰 전송 중의 갱신이 끊기지 않는다). 그래서 다리는 **포트마다가 아니라 연결마다** 동작해야 하고, 옛 포트로 잇던 연결을 새 포트 때문에 끊지 않는다.
4. **다시 시도(F12)**: `status`의 다음 시도 시각을 화면에 보여 준다. 사용자가 설정을 고친 뒤 누를 **`retryNow()`**를 더했다.
5. **샌드박스(F7)**: 두 빌드가 모두 돌아야 하고 **관문의 기준은 샌드박스 판**이다. 공개 저장소의 Mac 앱은 샌드박스를 쓰지 않고(커밋된 권한 파일이 빈 것이 맞다), 스토어판이 App Sandbox(네트워크 서버·클라이언트, 사용자가 고른 파일, 북마크)를 켠다. 샌드박스 판의 상태 디렉터리는 앱 컨테이너 안이다. **샌드박스 안의 실행 확인(`SecIdentity` 만들기, 루프백 듣기, 다리)은 첫 사용처 세션이 맡는다.** 샌드박스 판에서 키체인은 쓸 수 있으므로, 키체인 없이 신원을 만드는 길이 막히면 첫 사용처가 키체인에 넣는 길로 간다(Swiftail의 API는 그대로다: 사슬과 키를 낸다).
6. **DER 부품(F9)**: 첫 사용처는 직접 연결 리스너의 자체 서명 인증서(X.509 v3)를 Swift로 새로 써야 하고, Swiftail이 DER 쓰기 부품을 공개로 내주면 쓰겠다고 했다(급하지 않다). **지금은 내지 않는다**(H14 그대로): 쓰는 곳이 CSR 하나인 내부 부품을 공개 API로 굳히지 않는다. M7-3이 끝나 부품의 모양이 선 뒤, 첫 사용처가 직접 연결을 옮길 때 다시 본다.
7. **끊김의 전달(API 의견)**: 서버가 루프백 연결을 닫으면 다리가 tailnet 쪽을 정리한다(동작 B4·B5 그대로). 반대로 **tailnet 쪽이 오류로 끝나면 루프백 쪽은 정상 닫기로 보이면 안 된다**(반쯤 받은 본문을 끝까지 받은 것으로 읽지 않게). TLS 리스너에서는 `close_notify` 없이 끝난 연결이라 서버의 TLS가 잘림으로 안다. 평문 리스너(`listenTLS=false`)에서는 RST로 끊겨야 한다. 동작 B5의 "루프백 쪽 취소"를 구현할 때 `NWConnection`의 어느 호출이 RST를 내는지 확인하고 시험으로 고정한다(관문 (가)에 항목을 더한다: tailnet 쪽을 `abort()`하면 평문 루프백 서버의 읽기가 오류로 끝난다).
8. **묻는 시점**: 서버는 `NWListener`가 넘긴 연결이 `.ready`가 된 뒤(핸드셰이크 끝) 첫 수신 전에 `origin(forLoopbackSourcePort:)`를 묻는다. H4 (가)가 선다.
9. **시험 상대(F13)**: 호스트를 옮긴 뒤 첫 사용처의 가짜 iPhone은 빠른 시험에는 Swiftail 노드(`connect`), 상호 운용에는 이 저장소 `Tools/interop`의 Go tsnet 피어를 쓴다. 그쪽 저장소에 Go 시험 도구를 새로 두지 않는다. 그래서 `Tools/interop`의 `tailnet` 도구와 README의 "Swift 노드 둘을 시험 제어 서버에 붙이기"는 첫 사용처가 쓰는 접점이다(바꿀 때 알린다).
10. **대응표**: 사실과 다른 곳은 없다. `rd_update_page_set`은 공식 Tailscale 앱에 기대는 기능이라 샌드박스 판에서는 이미 빠져 있다.
11. **관문 (가)의 최소 HTTP 서버에 대한 참고**(첫 사용처의 보안 검토에서 넘어온 것. 계약에는 영향이 없다): 상태를 바꾸는 요청의 출처 검사, 요청 본문 크기 상한과 기기별 제한, 페어링 승인은 사람이 화면에서만. 시험 타깃의 서버도 본문 크기 상한은 둔다.

### 사용자 확인 필요

| # | 무엇 | 선택지와 영향 |
| --- | --- | --- |
| U1 | 기존 기기의 전환 방식 | **새 노드로 재페어링**: Swiftail로 바뀐 기기는 새 노드(새 tailnet 주소, 새 `StableID`, 이름 충돌 시 새 이름)가 된다. Mac이 바뀌면 호스트 ID와 FQDN이 바뀌어 모든 iPhone이 다시 페어링하고 인증서도 새로 받는다. iPhone이 바뀌면 Mac의 허용 목록에 다시 올린다. 옛 노드는 관리 콘솔에서 지운다. / **Go 상태 이관**: 동작 G. 같은 노드로 이어 가고 페어링과 인증서가 남는다. 대가: 같은 키를 두 구현이 쓰지 않게 하는 순서를 첫 사용처가 지켜야 하고, 되돌리기가 깔끔하지 않으며(동작 G7), `NLKey`를 0으로 다시 붙는 것의 영향을 모른다(9절). Mac과 iPhone을 따로 정할 수 있다 |
| U2 | Swiftail의 공개 여부와 라이선스 | plan 9절. M7에서 더 걸리는 것: 시험 도구가 MPL-2.0 모듈(pebble, challtestsrv)에 의존해도 되는지(H10) |
| U3 | 실제 tailnet 관문에 내줄 것 | 관문 (나)의 "사용자에게 받을 것". HTTPS를 켠 tailnet에서 발급하면 기기 이름과 tailnet 이름이 공개 CT 로그에 실린다(동작 K5) |
| U4 | 비공식 클라이언트가 제어 서버의 `set-dns`와 Let's Encrypt를 쓰는 것 | plan 8절 위험 10의 연장이다. 공개 배포 전에 확인한다 |

## 6. 첫 사용처가 직접 쓰는 것의 조각

계약의 일부가 아니라 H5의 근거로 적은 길이다. 쓰는 함수는 SDK 선언에서 확인됐지만(노트 4.6: `SecKeyCreateWithData`의 입력 `04 ‖ X ‖ Y ‖ K` 97바이트, `SecIdentityCreate`는 키가 맞지 않으면 NULL) **이 조각을 돌린 기록은 없다**. 작성 세션이 적은 TLS·ALPN 협상과 "키체인에 쓰지 않음"의 실험은 확인되지 않았다(노트 8장, 9장 V188·V189). 구현의 근거로 쓰지 않는다: 샌드박스 판에서 돌리는 확인은 첫 사용처 세션이 한다(첫 사용처 검토 결과 5).

```swift
// TailnetCertificate → NWListener의 TLS 신원. 키체인을 쓰지 않는다.
let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyClass: kSecAttrKeyClassPrivate]
let key = SecKeyCreateWithData(Data(certificate.privateKey.x963Representation) as CFData, attributes as CFDictionary, nil)
let leaf = SecCertificateCreateWithData(nil, Data(certificate.chain[0]) as CFData)
let identity = SecIdentityCreate(nil, leaf, key)            // SecIdentity.h, macOS 10.12·iOS 11.2부터
// 중간 인증서는 sec_identity_create_with_certificates(identity, 나머지 사슬)로 싣는다(돌려 보지 않았다)
sec_protocol_options_set_local_identity(tls.securityProtocolOptions, sec_identity_create(identity))
sec_protocol_options_set_min_tls_protocol_version(tls.securityProtocolOptions, .TLSv12)
sec_protocol_options_add_tls_application_protocol(tls.securityProtocolOptions, "http/1.1")
```

## 7. 시험과 관문

### 단위 시험(소켓 없음, 시각을 넘겨 결정적으로)

`Tests/SwiftailTests`:

1. **`whoIs`**: 피어의 IPv4·IPv6 주소, 자기 주소, IPv4-mapped 주소, 없는 주소, netmap 전, `AllowedIPs`에만 있는 주소(서브넷), 프로필이 없는 노드, `StableID`가 빈 노드, 태그 노드, netmap이 바뀐 뒤의 답. `computedName`(동작 W4): 같은 tailnet의 노드(접미사를 뗌), 다른 tailnet에서 공유받은 노드(끝 점 없는 FQDN), 레이블 경계가 아닌 곳에서 접미사가 맞는 이름(`rd-a.xtail0001.ts.net.`은 떼지 않음), 점이 없는 자기 이름, 이름이 빈 노드의 호스트 이름(`.local`·`.localdomain`·`.lan`을 떼고 정리)과 node 키 텍스트. 기대값은 Go `Node.ComputedName`의 결과와 같다(관문 (가) 1).

`Tests/SwiftailControlTests`:

2. **`set-dns`**: 요청의 경로·머리·본문(키 이름, `Version` 148, `Type` `TXT`, `Value`는 따옴표 없는 43바이트), 200과 `{}`, 200과 `null`·배열·빈 본문(실패. Go는 `null`을 받는다), 200이 아닌 응답, 4KiB를 넘는 본문, 연결이 없을 때의 기다림과 기한, 등록 전의 실패.
3. **Go 상태 파일**(M7-11, 동작 G2·G3): 정상 파일(프로필 하나), 바깥 값이 base64url인 파일(`malformed`), 0인 machine 키, `_current-profile` 없음(legacy), 가리키는 키가 없음, `_profiles`와 불일치, 프로필 둘, `OldPrivateNodeKey`가 있음, node 키 0, `LoggedOut`, `NetworkLockKey`가 있어도 무시, 깨진 base64·JSON, 1MiB 초과, 대상에 신원이 이미 있음. 제어 서버: 빈 값·`https://controlplane.tailscale.com`·`https://login.tailscale.com`과 기본 설정(같음), 기본 설정과 사용자 지정 서버(다름), 같은 사용자 지정 서버의 경로 없음·`/`(같음), 경로·query·fragment·userinfo가 있음(다름), 포트를 생략한 것과 `:443`(다름).

`Tests/SwiftailCertificatesTests`(새 시험 타깃):

4. **인코딩**: base64url(RFC 4648의 벡터, 채움 없음), PEM(여러 블록, 줄 길이, 모르는 종류), DER 쓰기(길이 127·128·255·256·65,535의 경계, INTEGER 0, OID).
5. **JWK와 지문**: RFC 7638 3.1의 예는 RSA이므로 쓰지 못한다. P-256 벡터는 Go 기준값(아래)으로 본다. 지문의 입력(`{"crv":"P-256","kty":"EC","x":…,"y":…}`)은 RFC 7638이 정하므로 Go와 **바이트까지** 같아야 한다(노트 3.4). `x`·`y`가 32바이트로 채워지는지(좌표의 앞자리가 0인 키).
6. **JWS**: 보호 머리의 필드와 순서 무관한 해석, `jwk`와 `kid`가 함께 나오지 않음, POST-as-GET의 `payload`가 `""`, 서명이 64바이트(R ‖ S)이고 공개 키로 검증됨. 보호 머리와 본문의 JSON 멤버 순서는 규격이 정하지 않으므로(RFC 7515 5.1, 노트 7장 1, 9장 V222) Go와의 대조는 복호화한 머리의 **의미**, 실제 서명 입력과 서명의 상대 검증으로 한다. 머리·서명 입력의 바이트 일치는 구현이 Go와 같은 직렬화(멤버 순서, 공백 없음)를 택했을 때만 요구한다. 이 계약은 그 직렬화를 요구하지 않는다.
7. **CSR**: 주체·SAN·알고리즘의 구조(고정 키), 자기 서명 검증(Security의 CSR 해석 API가 없으므로 Go 기준값 도구가 검증한다). 주체 CN은 Go와 같은 `PrintableString`(tag 0x13)이다. `UTF8String`(0x0C)도 유효하지만 Go와 바이트가 달라진다(노트 3.6, 9장 V056·V178). `certificationRequestInfo`의 바이트가 Go와 같아야 하는 것은 **같은 공개 키, 같은 속성(extensionRequest의 SAN 하나), 같은 CN 태그, 같은 DER 규칙**일 때다(노트 7장 2, 9장 V224). 이 계약은 넷을 모두 Go와 같게 정하므로 고정 키로 바이트가 같아야 한다. DER 쓰기의 짧은·긴 길이와 양수 INTEGER의 선행 0x00(서명의 r·s)을 시험한다(노트 4.6).
8. **ACME 절차**(가짜 응답을 차례로 넣는다): 노트 4.3의 열두 단계, 계정이 이미 있음·없음, 계정 키 파일이 RSA·깨짐(`accountKeyUnreadable`, 파일은 그대로), authorization이 이미 `valid`, challenge가 이미 `processing`, 주문이 처음부터 `ready`·`valid`·`processing`(새 주문을 한 번 다시, 두 번째는 `orderFailed`), `processing`을 여러 번 거침, finalize 응답의 `valid`·`processing`·`invalid`·`ready`·`pending`·모르는 상태, finalize의 `orderNotReady`, 주문 `invalid`(authorization이 `invalid`면 `validationFailed`, 아니면 `orderFailed`), authorization의 `deactivated`·`expired`·`revoked`, `badNonce` 한 번·네 번, `rateLimited`와 `Retry-After`(초·날짜·지난 날짜·읽지 못하는 값·없음·5분 기한 초과·7일 초과), `Retry-After` 시각 전의 `retryNow()`(요청이 나가지 않음), dns-01이 없는 authorization, authorization 둘(하나는 `valid`)·아홉(상한 초과), 다른 이름·`dns`가 아닌 종류·`wildcard`인 identifier, 응답의 `identifiers`가 요청과 다름, `http` URL, 2,048바이트를 넘는 URL, 64KiB를 넘는 본문, `Replay-Nonce`가 없음·잘못된 문자. 문제 문서: `application/problem+json`, JSON이 아닌 본문, `type` 없음, `about:blank`, 서버 고유 URI, 256바이트를 넘는 `type`, `subproblems`가 있음, `badNonce`를 ACME URN이 아닌 `type`의 접미사로 흉내 낸 것(따로 다루지 않음).
9. **받은 사슬의 검사**: `PRIVATE KEY` 블록이 낀 응답, 블록 뒤나 사이의 쓰레기 바이트, 해석되지 않는 블록, 6장, 다른 키의 leaf, 다른 이름의 leaf, 만료된 leaf, 모르는 루트, 루트를 함께 보낸 사슬(검증 뒤 `chain`에서 빠지고 파일에는 남음).
10. **갱신 판정**: 2/3 전·후, 만료 뒤, 사용자가 고쳐야 하는 실패(`magicDNSDisabled`·`httpsNotEnabled`·`domainNotAllowed`)는 시간이 지나도 시도하지 않고 `nextAttempt`가 nil이며 netmap 변화와 `retryNow()`에만 깨어남, 실패 종류별 간격과 상한, `Retry-After`가 표의 간격보다 늦을 때, 성공 뒤 초기화, 이름이 바뀜.
11. **저장**: 쓰고 읽기, 새 `certs/`의 0700과 새 파일의 0600(인증서 포함), 그룹·기타가 쓸 수 있는 기존 `certs/`(읽지도 쓰지도 않고 `storage`), 권한을 고치지 않음, 키만 쓰이고 멈춘 상태(짝이 맞지 않아 없는 것으로 봄), Go가 쓴 SEC1 키 파일과 0644 인증서(자료), 64KiB 초과, 이름 검사(동작 C2: 처음·끝의 하이픈, 64자 레이블, 253자, `_acme-challenge.`를 붙이면 넘는 238자 이름, 대문자, 경로 문자).
12. **비밀**: `TailnetCertificate`와 관리자의 `description`·`dump`에 키 바이트가 없다.

`Tests/SwiftailLoopbackTests`(새 시험 타깃. 루프백 소켓을 쓴다. 자기 주소로 건 연결로 노드 하나에서 돈다):

13. **다리**: 양방향 1MiB의 해시, 한쪽 반닫힘 뒤 반대 방향 데이터, 루프백 쪽이 읽지 않을 때 tailnet 쪽이 멈춤(다리가 쥔 바이트가 한도 안), tailnet 쪽 RST·`peerRemoved`에 루프백이 닫힘, 루프백 쪽 끊김에 tailnet이 RST, `forward`의 취소, 듣는 쪽이 없는 포트, 257번째 연결.
14. **표**: 등록 전에 바이트가 건너가지 않음(서버가 첫 바이트를 받은 시점에 늘 조회됨), 끝난 뒤 조회되지 않음, 다리 밖에서 직접 건 루프백 연결의 포트가 조회되지 않음, 신원을 찾지 못한 연결은 루프백으로 걸지 않음.

### Go 기준값 대조

`Tools/interop/cmd/acmefixtures`(새 도구): 고정한 P-256 키들로 Go(`tailscale.com/tempfork/acme`와 표준 라이브러리)가 만든 JWK 문자열, 지문, 키 인가, DNS-01 TXT 값, 보호 머리 JSON, CSR(`feature/acme`의 `certRequest`와 같은 인자)을 JSON으로 낸다. 반대로 Swift가 만든 JWS와 CSR을 받아 Go가 검증하는 명령도 둔다(서명은 실행마다 다르다). 자료는 `Tests/SwiftailCertificatesTests/Fixtures/`. 대조 시험은 구현한 세션과 다른 세션이 쓴다. 바이트까지 같아야 하는 것과 의미로 견주는 것은 노트 7장 1·2대로 가른다: JWK 문자열·지문·키 인가·TXT 값·CSR의 `certificationRequestInfo`(시험 7의 네 조건 아래)는 바이트, 보호 머리 JSON은 복호화한 의미(시험 6), 서명은 상대 구현의 검증이다.

`tailnet` 도구에 더할 명령: `peerWhoIs`(Go 피어의 `LocalClient().WhoIs(주소)`를 JSON으로. `whoIs`의 대조), `goState`(Go tsnet 피어의 상태 디렉터리 경로. 가져오기의 자료), 그리고 아래 관문의 것.

### 관문 (가): 계정 없이

`Tools/interop`의 `tailnet`(testcontrol + DERP + STUN + Go tsnet 피어)을 상대로 한다. 시험은 `Tests/SwiftailInteropTests/HostTests.swift`에 두고 `SWIFTAIL_TAILNET`이 없으면 건너뛴다.

도구에 더할 것: **testcontrol에 `DNSConfig`를 준다**(cert 도메인이 생기는 조건이다. testcontrol은 `DNSConfig`가 있고 `MagicDNSDomain`이 비지 않을 때만 netmap의 `CertDomains`에 `<Hostinfo.Hostname>.<MagicDNSDomain>`을 더한다. 지금 도구는 `MagicDNSDomain`만 주므로 그대로는 `CertDomains`가 생기지 않는다. 노트 7장 4, `Tools/interop/cmd/tailnet/main.go:115`. MagicDNS 켬(`Proxied`)도 함께 준다. 동작 C1 ②), `acmeStart`(같은 프로세스에 pebble과 challtestsrv의 DNS 서버를 띄우고 디렉터리 URL과 루트 인증서를 돌려준다. testcontrol의 `OnSetDNS`를 challtestsrv의 TXT 레코드로 잇는다. 노트 7장 5의 시험 설계이고, 두 모듈을 한 프로세스에 넣어 빌드·실행한 적은 아직 없다. 노트 8장), `setDNSLog`(받은 `set-dns` 요청의 목록), `setDNSFault`(다음 요청을 거절하거나 값을 바꿔 올린다), `setCertDomains`(cert 도메인을 비우거나 채운다), `peerHTTP`(Go 피어가 tsnet으로 HTTP 요청을 보내고 상태·머리·본문의 길이와 SHA-256을 돌려준다. 신뢰할 루트를 인자로 받는다).

| # | 확인할 것 | 통과 기준 |
| --- | --- | --- |
| 1 | `whoIs` | Go 피어 둘의 IPv4·IPv6 주소와 자기 주소에 대해 `stableID`·`name`·`computedName`·`loginName`이 `peerWhoIs`의 값과 같다. 피어가 나간 뒤에는 nil |
| 2 | `set-dns` | testcontrol이 요청을 받아들이고(machine 키, node 키, 이름의 검사를 통과) `setDNSLog`의 값이 Swift가 계산한 TXT 값과 같다 |
| 3 | 발급 | pebble에서 인증서를 받는다. 사슬이 pebble 루트로 검증되고, 이름이 자기 FQDN이고, `certs/`에 세 파일이 권한대로 있다 |
| 4 | 다시 시작 | 같은 상태 디렉터리로 다시 띄우면 ACME 요청 없이 저장된 인증서가 `certificates`에 나온다 |
| 5 | `badNonce`와 authorization 재사용 | pebble의 nonce 거부를 켠 채 3이 통과한다. authorization 재사용을 켠 채 두 번째 발급이 통과한다 |
| 6 | 갱신 | 시험용 시계를 2/3 뒤로 옮기면 새 키의 새 인증서가 `certificates`에 나오고 옛 연결은 그대로다 |
| 7 | 실패 | cert 도메인이 비면 `httpsNotEnabled`, MagicDNS가 꺼져 있으면 `magicDNSDisabled`이고 요청이 나가지 않으며 `nextAttempt`가 nil이다. 되돌리면(netmap이 바뀌면) 발급한다. `set-dns` 거절이면 `controlRejected`. 틀린 TXT 값이면 `validationFailed`이고 다음 시도가 15분 뒤다 |
| 8 | **시나리오의 뼈대**: Swift 노드가 443을 듣고, 다리가 시험용 `NWListener`(TLS, 3의 인증서, ALPN `http/1.1`)로 잇고, Go 피어가 `peerHTTP`로 ① 페어링 요청(서버가 `Origin.peer`의 `stableID`·이름을 응답에 싣는다) ② 설치 세션 만들기(그 `stableID`에 묶인 토큰) ③ 매니페스트 ④ IPA 100MB를 Range 둘로 나눠 받기를 차례로 한다 | Go 피어가 pebble 루트로 TLS를 검증한다. ①의 `stableID`가 그 Go 피어의 것이다. 다른 Go 피어가 ②의 토큰으로 ④를 요청하면 서버가 거절한다(신원이 다르다). 받은 바이트의 SHA-256이 같다. 처리량을 기록한다 |
| 9 | 다리 밖의 접속 | 시험이 루프백 포트로 직접 TLS 연결을 걸면 `origin`이 nil이고 서버가 끊는다 |
| 10 | 주인이 바뀜 | 전송 중에 그 Go 피어를 tailnet에서 빼면 루프백 연결이 닫히고 `origin`이 사라진다 |
| 11 | (M7-11) 가져오기 | Go 피어를 멈추고 그 상태 디렉터리에서 가져와 띄운 Swift 노드가 같은 node 키이고, testcontrol이 같은 노드로 받아들여 같은 tailnet 주소·같은 `StableID`다. 이것은 이 관문이 처음 확인할 **기대값**이다(노트 4.7 끝, 7장 7, 9장 V233). testcontrol의 결과는 운영 서버의 `NLKey` 0 처리와 중복 세션의 동작을 보장하지 않는다(관문 (나) 8). Go가 받아 둔 것과 같은 형식의 `certs/`를 복사하면 발급 없이 쓴다 |
| 12 | 전체 | `eyebuild swift <용도> -- test` 전체 통과, 경고 0 |

### 관문 (나): 실제 tailnet과 실기기

로컬에서는 할 수 없는 것만 본다. 매번 사용자에게 먼저 알린다(plan 4절(b)).

| # | 확인할 것 | 통과 기준 |
| --- | --- | --- |
| 1 | 실제 제어 서버 | HTTPS를 켠 tailnet에 등록하면 `certDomains`에 자기 FQDN이 있다 |
| 2 | 실제 `set-dns` + Let's Encrypt **스테이징** | 스테이징 디렉터리로 발급이 끝난다(스테이징 루트를 시험 앵커로 준다). `set-dns`에 걸린 시간과 발급 전체 시간을 기록한다 |
| 3 | Let's Encrypt **운영** | 한 번 발급한다. 시스템 루트로 검증된다. 인증서의 수명을 기록한다. 다시 시작하면 저장된 것을 쓴다(발급은 관문 전체에서 두 번을 넘기지 않는다) |
| 4 | iPhone에서 | M5 터널을 켠 iPhone의 Safari와 `URLSession`이 `https://<fqdn>/`을 경고 없이 연다 |
| 5 | 설치기 | `itms-services` 링크로 매니페스트와 IPA를 받는다(첫 사용처 세션. 그쪽의 최소 HTTPS 서버나 이식한 호스트) |
| 6 | 전송 | 100MB를 받는 시간을 Wi-Fi 직접 경로에서 재고 Go 호스트의 값(`SwiftailNetstack.md` 검토 결과 5)과 나란히 적는다 |
| 7 | 샌드박스 | 첫 사용처의 샌드박스 판(권한: 네트워크 서버·클라이언트)에서 3~5가 된다. 키체인 없이 `SecIdentity`를 만드는 길, 루프백 듣기, 다리가 그 안에서 도는지는 이 관문 전에는 확인되지 않았고 첫 사용처 세션이 확인한다(첫 사용처 검토 결과 5, 노트 8장) |
| 8 | (U1이 이관이면) 실제 Go 상태 | 시험용 Go 호스트 노드의 상태를 가져와 운영 제어 서버가 같은 노드로 받아들이고(같은 주소·`StableID`. `NLKey` 0으로 다시 붙는 결과를 여기서 처음 본다), 페어링한 iPhone이 다시 페어링하지 않고 접속한다 |

사용자에게 받을 것:

- MagicDNS와 HTTPS 인증서를 켠 tailnet(관리 콘솔의 DNS 설정). 이름이 CT 로그에 실려도 되는지의 확인(U3).
- 그 tailnet의 인증 키(임시가 아닌 노드. 상태를 지우지 않고 다시 쓰므로 한 번 쓰는 키면 된다). 채팅이 아닌 비밀 입력으로 받는다. 호스트 이름은 가짜 값(`rd-mac-1a2b3c4d` 꼴)으로 정해 둔다.
- 운영 서버 발급을 해도 된다는 허락(같은 이름 7일에 5장 가운데 두 장까지 쓴다).
- M5 터널 빌드가 깔린 iPhone과, 5·7을 맡을 첫 사용처 세션.

### RemoteDebug e2e 재현의 범위

첫 사용처의 e2e는 셋이다: Go 시험(`core/e2e`. Go 호스트와 Go tsnet 피어, 가짜 tailnet, `listenTLS=false`, 22개. 터널 시험 3개는 `core/e2e/tunnel`에 따로 있다), Swift 패키지 시험(`Packages/MacHost/Tests/MacHostE2ETests`. 실제 Go 코어와 `rdtestenv`), 스크립트(`scripts/e2e-*.sh`). 모두 그쪽 호스트 코드를 돌린다.

Swiftail 저장소가 재현하는 것은 **Tailscale에 기대는 성질**뿐이다(관문 (가) 8~10): tailnet으로 들어온 연결이 TLS를 거쳐 HTTP 서버에 닿고, 서버가 상대의 `StableID`를 알고, 세션이 그 노드에 묶이고, 큰 본문이 Range로 온전히 간다. 페어링 코드의 규칙, 세션의 수명, 게시본 검사 같은 호스트의 로직은 재현하지 않는다. 그것은 첫 사용처가 호스트를 Swift로 옮긴 뒤 자기 e2e를 Swiftail 노드 위에서 돌려 확인한다(별도 승인 뒤. `SwiftailNetstack.md` 검토 결과 6의 발판을 쓴다).

## 8. 구현 단위

소유 파일이 겹치지 않게 나눈다. 단위 사이의 접점은 2절의 선언과 아래 `package` 선언이 정하고 M7-0이 확정한다.

```swift
// Swiftail (package). SwiftailCertificates가 쓴다.
extension TailnetNode {
    package func setDNS(name: String, value: String) async throws(ControlError)
    package nonisolated var certificateFacts: AsyncStream<CertificateFacts> { get }   // 상태·자기 이름·cert 도메인·MagicDNS 켬이 바뀔 때마다
    package nonisolated var stateDirectory: URL { get }
}
// SwiftailIO (package). SwiftailLoopback이 쓴다.
extension NetworkSocket {
    package static func connectLoopback(port: UInt16) async throws(SocketError) -> NetworkSocket
    package var localPort: UInt16? { get }
    package func finishWriting()
}
```

| 단위 | 내용 | 소유 파일 | 선후 |
| --- | --- | --- | --- |
| M7-0 | 총괄: 이 계약 확정(H, F의 답, U1), 노트 검증(다른 세션), `Package.swift`에 타깃 넷 추가, 위 `package` 선언의 빈 껍데기, plan 갱신 | `docs/contracts/SwiftailHost.md`, `docs/plan.md`, `docs/protocol-notes/`, `Package.swift` | 먼저 |
| M7-1 | `whoIs`와 `PeerIdentity`(동작 W), 주소 표, `computedName`의 Go 규칙(W4) | `Sources/Swiftail/PeerIdentity.swift`, `Sources/Swiftail/TailnetNode+WhoIs.swift`, `Tests/SwiftailTests/WhoIs*` | **병렬** |
| M7-2 | 제어 `set-dns`(동작 D)와 노드의 `package` 접점(MagicDNS 켬 여부를 `CertificateFacts`에 싣는다. 동작 C1 ②) | `Sources/SwiftailControl/Client/ControlClient+SetDNS.swift`, `Sources/SwiftailControl/Tailcfg/SetDNSRequest.swift`, `Sources/Swiftail/TailnetNode+Certificates.swift`, `Tests/SwiftailControlTests/SetDNS*` | **병렬** |
| M7-3 | 인코딩과 서명: base64url, PEM(입력 전체 검사), DER 쓰기(`PrintableString` 포함), JWK·지문, JWS, CSR(시험 4~7) | `Sources/SwiftailCertificates/Encoding/*`, `Sources/SwiftailCertificates/JOSE/*`, `Sources/SwiftailCertificates/CSR/*`, 같은 이름의 시험 폴더 | **병렬** |
| M7-4 | ACME 메시지와 주문 절차의 값 타입(동작 C4~C7·C12, X1·X2·X4·X5: authorization 여럿의 상태별 처리, 주문·finalize의 다섯 상태, 문제 문서, `Retry-After`), 전송 프로토콜과 `URLSession` 구현 | `Sources/SwiftailCertificates/ACME/*`, `Tests/SwiftailCertificatesTests/ACME/*`(기본 길) | M7-3의 선언이 선 뒤. 가장 크다 |
| M7-5 | 저장과 검증(동작 S, X3: 디렉터리 권한 검사, 0600, 키 짝, 시스템 루트만, `chain`의 자기 서명 떼기), 갱신 판정(동작 R: 사용자가 고칠 실패의 갈래, `Retry-After`의 보존과 7일) | `Sources/SwiftailCertificates/Store/*`, `Sources/SwiftailCertificates/Renewal/*`, 같은 이름의 시험 폴더 | **병렬**(M7-3의 PEM만 쓴다) |
| M7-6 | `CertificateManager`와 공개 타입(동작 C1~C3·C8~C11, K. 계정 키의 한 흐름과 `accountKeyUnreadable`, `retryNow()`가 `Retry-After` 전에 요청하지 않음) | `Sources/SwiftailCertificates/CertificateManager.swift`, `TailnetCertificate.swift`, `CertificateStatus.swift`, `Tests/SwiftailCertificatesTests/Manager*` | M7-2·4·5 뒤 |
| M7-7 | 독립 시험: 가짜 ACME 서버(RFC 8555의 상태 전이를 따르는 메모리 서버)와 시험 8·9의 사례. 계약과 노트만 보고 쓴다 | `Tests/SwiftailCertificatesTests/Support/*`, `Tests/SwiftailCertificatesTests/Scenarios/*` | M7-4를 쓴 세션과 **다른 세션**. 하네스는 병렬 |
| M7-8 | Go 기준값 도구와 자료, 대조 시험 | `Tools/interop/cmd/acmefixtures/`, `Tests/SwiftailCertificatesTests/Fixtures/*`, `Tests/SwiftailCertificatesTests/GoComparisonTests.swift`, `Tools/interop/README.md`의 새 절 | 도구는 **병렬**. 대조 시험은 M7-3 뒤 다른 세션 |
| M7-9 | 루프백 다리(동작 B)와 `NetworkSocket` 보탬 | `Sources/SwiftailLoopback/*`, `Sources/SwiftailIO/NetworkSocket+Loopback.swift`, `Tests/SwiftailLoopbackTests/*` | M7-1 뒤(신원). 소켓 보탬은 병렬 |
| M7-10 | 관문 (가): `tailnet` 도구의 `DNSConfig`(cert 도메인·MagicDNS), `acmeStart`·`setDNSLog`·`setDNSFault`·`setCertDomains`·`peerHTTP`·`peerWhoIs`·`goState`, 시험용 최소 HTTP/1.1 서버, `HostTests.swift` | `Tools/interop/cmd/tailnet/*`, `Tools/interop/go.mod`·`go.sum`, `Tools/interop/README.md`의 `tailnet` 절, `Tests/SwiftailInteropTests/HostTests.swift`, `Tests/SwiftailInteropTests/Support/MinimalHTTPServer.swift` | 도구는 **병렬**. 시험은 M7-6·9 뒤 |
| M7-11 | Go 상태 가져오기(동작 G: 프로필 하나의 범위, 거절 규칙과 `unsupportedState`, 제어 서버 비교). **U1이 이관일 때만 연다** | `Sources/SwiftailControl/Client/GoStateFile.swift`, `Sources/Swiftail/GoStateImport.swift`, `Tests/SwiftailControlTests/GoStateFile*`, `Tests/SwiftailTests/GoStateImport*` | 병렬 |
| M7-12 | 관문 (나)와 첫 사용처 저장소의 교체 | 첫 사용처 세션과 함께. 별도 승인 | 다른 세션의 검토와 관문 (가) 뒤 |

순서: M7-0 → (M7-1, 2, 3, 5, 7의 하네스, 8의 도구, 9의 소켓, 10의 도구, 11) 병렬 → M7-4 → M7-6, M7-9 → M7-7·8의 시험 → M7-10의 시험 → 다른 세션의 검토 → 총괄이 관문 (가)를 다시 돌림 → 관문 (나).

### 예상 규모

| 덩어리 | 라이브러리(줄) | 시험(줄) |
| --- | --- | --- |
| `whoIs` | 200 | 350 |
| `set-dns`와 접점 | 200 | 250 |
| 인코딩·JOSE·CSR | 450 | 600 |
| ACME 절차와 전송 | 1,000 | 1,900(가짜 서버 포함) |
| 저장·검증·갱신 판정 | 450 | 700 |
| `CertificateManager` | 350 | 450 |
| 루프백 다리 | 300 | 500 |
| Go 상태 가져오기 | 250 | 450 |
| Go 도구(`acmefixtures`, `tailnet` 보탬) | — | Go 800 |
| 관문 시험과 최소 HTTP 서버 | — | 700 |

라이브러리 약 3,200줄, Swift 시험 약 5,900줄이다(노트 검증 반영으로 ACME 절차의 갈래, 저장의 권한 검사, Go 상태의 거절 규칙, `computedName`이 늘었다). M6(TCP 스택)보다 작고, 직접 쓰는 형식(DER 쓰기, JWS)은 좁다. 어려움은 코드의 양이 아니라 로컬에서 확인할 수 없는 부분에 있다.

### 가장 큰 위험

1. **실제 발급은 실제 tailnet에서만 확인된다.** 운영 제어 서버의 `set-dns`가 무엇을 요구하고 언제 답하는지는 클라이언트 소스에 없고(노트 8장), testcontrol의 처리기는 시험용이다. 틀렸을 때 되풀이할 수 있는 횟수도 Let's Encrypt의 제한(같은 이름 7일에 5장, authorization 실패 한 시간에 5번)이 묶는다. 대응: pebble로 ACME 쪽을 먼저 굳히고, 실제 tailnet에서는 스테이징으로 `set-dns`를 확인한 뒤 운영 발급을 한 번만 한다.
2. **루프백 다리가 신원의 경계를 넘는다.** tailnet의 인증된 연결이 `127.0.0.1`의 익명 연결이 되므로, 표의 불변 조건(동작 B6)이나 서버의 규칙(B7) 가운데 하나가 어긋나면 같은 Mac의 다른 프로세스가 페어링한 기기로 보이거나 정당한 연결이 끊긴다. 서버 쪽 절반은 첫 사용처의 코드다. 대응: 신원을 연결에 고정하고(B2), 관문 9·10과 단위 시험 14로 양쪽을 본다. 덧붙여 4GiB 전송이 TCP 스택 둘과 복사를 거치는 비용은 재 보기 전에는 모른다.
3. **Go 상태 이관은 사용자의 실제 노드를 건드리고 되돌리기 어렵다.** 같은 node 키를 두 구현이 쓰는 순간의 서버 동작, `NLKey` 0으로 다시 붙는 영향을 모른다. 대응: 사용자 결정(U1) 전에는 구현하지 않고, 하더라도 읽기 전용·한 번·신원만으로 좁히고, 시험용 노드로 관문 (나) 8을 먼저 본다.

그 밖: App Sandbox 안에서의 동작은 이 저장소에서 돌려 보지 않았고 첫 사용처 세션이 샌드박스 판에서 확인한다(검토 결과 5, 9절). 시험 도구에 MPL-2.0 모듈이 들어온다(H10).

### `shortcut:`으로 남길 것

| 남기는 것 | 필요해지는 시점 |
| --- | --- |
| ARI와 `replaces`(H6) | 인증 기관이 갱신 시점을 앞당겨 알릴 때(대량 폐기), ARI 갱신의 제한 면제(노트 4.5의 조건)가 필요할 때. 2/3 규칙은 제한 회피를 보장하지 않는다(동작 R1) |
| 대체 사슬(`Link: rel="alternate"`) | 기본 사슬이 시스템 루트로 검증되지 않는 기기가 생길 때(노트 6장. Go의 발급 경로도 쓰지 않는다) |
| TXT 레코드의 사전 조회 | `set-dns`의 빈도가 문제가 될 때 |
| 계정 URL을 저장하지 않음(시작마다 찾는다) | 요청 하나를 아껴야 할 때 |
| 옛 이름의 인증서 파일을 지우지 않음 | 이름이 자주 바뀌는 사용처 |
| nonce 하나만 보관 | 요청을 동시에 보내게 될 때 |
| 와일드카드, 자기 FQDN 밖의 cert 도메인, TLS-ALPN-01 | Funnel·Serve에 해당하는 기능을 넣을 때 |
| `whoIs`의 `CapMap` | grant로 앱 권한을 나누는 사용처 |
| 다리의 덩어리마다의 `[UInt8]` 복사 | 관문의 처리량 기록에서 병목일 때(`SwiftailNetstack.md` 검토 결과 7과 함께) |
| 다리의 IPv6 루프백(`::1`) | 그런 리스너를 쓰는 사용처 |
| 만료 임박을 알리는 사건 | 앱이 `status`를 읽지 않게 될 때 |
| iOS에서의 인증서 파일 보호 등급 | iOS에서 듣는 사용처 |

## 9. 확인하지 못한 것

- **App Sandbox 안의 실행**: `SecIdentityCreate`·`SecKeyCreateWithData`, 루프백의 `NWListener`와 `NWConnection`, `URLSession`이 네트워크 서버·클라이언트 권한만으로 도는지. 작성 세션이 적은 Apple 실험(CSR 검증, `NWListener`의 TLS·ALPN 협상, 키체인에 쓰지 않음)은 기록이 없어 확인되지 않았고(노트 8장, 9장 V173·V179·V188·V189·V191), 검증 세션이 다시 돌린 것은 노트 4.6의 키·서명·PEM 형식 검사뿐이다(샌드박스 밖). 이것을 구현의 근거로 쓰지 않는다: **첫 사용처 세션이 샌드박스 판에서 확인한다**(첫 사용처 검토 결과 5). 첫 사용처의 커밋된 Mac 앱은 권한 파일이 비어 있다(F7). 동작 B9에 적은 권한 키의 이름도 Apple 문서와 대조하지 않았다.
- **동작 S6의 자기 서명 판별**: 주체와 발급자를 견줄 Security API를 SDK 선언과 대조하지 않았다(M7-5가 먼저 확인한다).
- **H4의 `NWConnection` 실험**(`currentPath.localEndpoint`의 포트, 리스너가 받은 연결의 `endpoint`): 노트의 검증 범위 밖이고 기록이 없다. M7-9가 먼저 확인한다.
- **운영 제어 서버의 `set-dns`**, 태그·공유 노드의 프로필, authorization 재사용(Go 흐름의 결과), `ts.net`의 등록 도메인 경계(공개 PSL로는 `tail0001.ts.net`. 운영 CA의 배포본·예외는 모른다), `CertDomains`가 있으면 MagicDNS가 늘 켜져 있는지, `NLKey` 0으로 다시 붙는 노드, 같은 node 키의 두 세션, 키 교체 뒤 옛 키의 서버 처리: 노트 8장.
- **`NWConnection`의 반닫힘**: 내용 없이 마지막 메시지로 보내면 TCP FIN이 나가는지, TLS를 끝내는 `NWListener` 쪽에서 상대의 FIN이 어떻게 보이는지. M7-9가 먼저 손으로 확인한다. HTTP/1.1은 요청·응답의 경계를 길이로 알므로 반닫힘에 기대지 않는다.
- **`NWProtocolFramer`를 TLS 아래에 두기**(H3의 (다)): 되는지 확인하지 못했다.
- **중간 인증서를 싣는 길**(`sec_identity_create_with_certificates`)과 `SecTrust`로 하는 검증: 공개 API라는 것만 확인했다.
- **pebble·challtestsrv**: 모듈(pebble `go 1.25.0`, challtestsrv `go 1.24`, 둘 다 MPL-2.0)을 받아 패키지와 함수 서명을 읽었다(노트 8장). `Tools/interop`에 넣어 빌드하지 않았고, `testcontrol`과 한 프로세스에서 도는지, `tailscale.com`의 고정 버전과 의존이 충돌하지 않는지 모른다.
- **다리의 처리량**과 큰 전송의 CPU.
- **Let's Encrypt가 지금 주는 인증서 수명**과 발급에 걸리는 시간.
- 첫 사용처의 Swift 쪽 호출 코드(`RDCoreBridge.swift`를 부르는 곳)는 함수 이름의 사용만 세었다. 호스트 앱이 상태와 사건을 어떻게 쓰는지는 Go 쪽 문서(`docs/protocol.md` 9·10절, `docs/protocol-addenda.md` A.5)에서 읽었다.

## 노트 검증 반영 (2026-11-15)

노트 10장의 대조 표와 9장에서 "틀림"으로 판정된 주장을 반영했다. 총괄 확정과 첫 사용처 검토 결과의 결정은 바꾸지 않았다. 새로 생긴 선택은 H16~H23이다.

| 노트 10장의 행 | 고친 곳 |
| --- | --- |
| W4, `computedName` 주석 | 동작 W4를 Go 규칙(레이블 경계의 접미사, 공유 노드의 FQDN, 끝 점, 호스트 이름 정리, node 키)으로 다시 적고 W3의 빈 `StableID` 거절이 첫 사용처의 정책임을 적었다. `PeerIdentity.computedName` 주석, 단위 시험 1 |
| D1~D3 | D1에 "같은 Noise 클라이언트"와 "같은 HTTP/2 연결"을 갈랐다. D2·D3을 "Swiftail의 선택"으로 적고 Go의 동작(즉시 실패, 1MiB, `null` 허용, 200 code point)을 나란히 적었다. 단위 시험 2 |
| C2 | 경로 검사와 DNS 이름 검사를 갈랐다. 레이블의 처음·끝 영숫자, 1~63자, 253자, `_acme-challenge.`를 붙인 이름의 같은 한도, `PrintableString`과의 관계, 어긋날 때의 실패 종류(H23). 단위 시험 11 |
| C4, S2, G6 | C4: P-256만, 파일이 없을 때만 새 키, 읽지 못하면 `accountKeyUnreadable`(새 `CertificateError` case, H16), actor 안의 한 흐름. S2·S3: PKCS#8·SEC1 읽기가 노트 4.6에서 확인됨. G6: RSA 계정 키를 호환한다고 보장하지 않음 |
| C5 | authorization 개수를 강제하지 않고 모두 상태별로 처리, `identifier.type`·값·`wildcard` 확인, 주문의 `ready`·`valid`·`processing` 분기, 응답 `identifiers` 확인. 한도 표에 authorization 8개. 단위 시험 8 |
| C7·R4·X2·X5·한도 표 | `Retry-After`를 줄이지 않는다. 그 시각 전에는 그 ACME 서버에 요청하지 않고, 5분 기한을 넘으면 시도를 끝내고 `nextAttempt`로 보존, 7일로 묶음(위쪽 끝만), `retryNow()`도 그 전에는 요청하지 않음(X5, C10, R3·R4, `status`·`retryNow()` 주석, H21). 1~30초·24시간의 묶음을 지웠다 |
| finalize 상태와 `validationFailed` | C7을 기다리기·finalize·내려받기로 다시 적고 다섯 상태를 모두 갈랐다. CSR 전의 `valid`는 새 주문으로(H17). `CertificateFailure`를 `validationFailed`(authorization `invalid`)와 새 `orderFailed`로 갈랐다(H19). 규격 위반에 새 `unexpectedResponse`(H18) |
| 문제 문서, `CertificateFailure.acme` | `acme(status:type:)`, `type` 전체 문자열·빈 문자열·256바이트, `detail`을 싣지 않음, ACME URN일 때만 따로 다루는 종류(새 동작 C12). 단위 시험 8 |
| C8·S3 | 운영은 시스템 루트만, 시험은 명시적 앵커, Go의 내장 루트 fallback과 비운영 예외를 따르지 않음을 "Go와 다른 선택"으로 적었다(S3 ⑤, X3, C8). 저장 전 검증이 Go보다 강한 경계임을 적었다 |
| S1~S3, `chain` 주석 | S1: 새 `certs/` 0700, 기존 디렉터리 권한은 고치지 않고 그룹·기타 쓰기면 실패(H20). S2: 새 파일 모두 0600, 두 파일이 한 트랜잭션이 아님과 S3 ④의 짝 확인. 새 동작 S6과 `chain` 주석: 루트가 올 수 있고 검증 뒤 자기 서명 인증서를 뗌. X3 ①: 입력 전체 검사 |
| R1·R4·H6·`shortcut:` | "2/3면 제한에 닿지 않는다"를 지우고 노트 4.5의 제한과 ARI 면제 조건을 가리켰다(R1, H6의 까닭, `shortcut:` 표). R4에 사용자가 고칠 실패(시간으로 다시 시도하지 않음, `nextAttempt` nil)와 그 밖의 실패를 갈랐다. 12분은 회복률이지 최소 간격이 아님, 연속 실패 제한. C1에 `magicDNSDisabled` 조건 |
| G2~G4 | G2: 프로필 하나의 범위, 표준 base64, `_current-profile`의 키 전체, `_profiles`, 거절 규칙(0인 machine 키, 가리키는 키 없음, 불일치, 프로필 여럿, legacy, `OldPrivateNodeKey`)을 `malformed`·새 `unsupportedState`로(H22). G4: `OldPrivateNodeKey` 생략과 Go의 차이 |
| G3 | 기본 서버의 동의어(빈 값, `https://controlplane.tailscale.com`, `https://login.tailscale.com`), 사용자 지정 서버는 경로가 비었거나 `/`이고 query·fragment·userinfo가 없을 때만 같음 |
| G 공개 API, G4·G7·관문 (가) 11 | `importIdentity` 주석과 G7에서 "같은 노드로 뜬다"를 "서버가 같은 노드로 받아들이면"으로 낮추고, `NLKey` 0·중복 세션·옛 키의 결과가 관문 전에는 확인되지 않았다고 적었다. 관문 (가) 11·(나) 8의 기준 |
| 시험 절 | 단위 시험 5~7과 Go 기준값 대조에서 바이트로 견주는 것과 의미로 견주는 것을 갈랐다(CN `PrintableString`과 CSR의 네 조건, JWS 직렬화). 관문 (가)의 도구에 `DNSConfig`를 더했다. 6절·B9·9절·관문 (나) 7에서 확인되지 않은 Apple 실험을 근거로 쓰지 않고 첫 사용처 검토 결과 5를 가리켰다 |

노트 9장의 "틀림" 18개가 이 계약에 남았던 곳:

- V056·V178·V224(CSR의 CN 태그, 바이트 동일의 조건): 단위 시험 7, Go 기준값 대조, 동작 C7.
- V110(`ready` 뒤에만 새 키): 동작 C7에 Go의 실제 동작과 Swiftail의 차이를 적었다.
- V142(문제 문서와 `type`): 동작 C12, `CertificateFailure.acme`.
- V162·V166·V168(속도 제한 회피의 보장): 동작 R1, H6의 까닭, `shortcut:` 표.
- V164(12분은 최소 간격): 동작 R4.
- V199(모든 키가 `privkey:`): 동작 G2.
- V201(node 키 0은 로그인한 적 없음): 동작 G3, `notLoggedIn` 주석.
- V202(`OldPrivateNodeKey`는 옮길 필요 없음): 동작 G2·G4.
- V213(인증서 한 장마다 1MiB): 동작 X2에 Go의 실제 한도를 적었다.
- V222(JWS 바이트 동일): 단위 시험 6, Go 기준값 대조.
- V242(두 모듈 모두 go1.25): 9절.
- V147(지터와 10초 상한), V151(갱신 시각 캐시), V152(갱신마다 `replaces`): 이 계약에 그 주장이 없었다(Go의 HTTP 재시도와 ARI를 옮기지 않는다).

그 밖에 머리말의 "노트는 아직 검증 전"과 "저장소 밖에서 돌린 작은 실험"을 고쳤고, 4절 대응표에 `magicDNSDisabled`, 8절의 `package` 선언 주석에 MagicDNS, 구현 단위 표와 예상 규모를 맞췄다.
