# Swiftail 페어링 계약 (M9, 초안)

M9의 목표는 **Swiftail을 쓰는 두 앱이 QR 코드나 링크 하나로 서로를 인증하는 것**이다. 한쪽(여는 쪽)이 화면에 QR과 링크를 내고, 다른 쪽(들어오는 쪽)이 그것을 읽으면 두 앱이 짝이 된다. 링크에 1회용 tailnet 인증 키를 실으면 들어오는 쪽은 로그인 없이 tailnet에 들어온 뒤 짝이 된다. 그 키를 만드는 일(Tailscale 관리 API)도 라이브러리가 한다.

이 문서는 **초안**이다. 구현 전에 다른 세션의 설계 검토를 받고 "검토에서 볼 것"을 닫은 뒤 확정한다. 5절의 전선 형식은 검토 뒤에 굳힌다.

사용자 결정(2026-11-17):

| | 결정 |
| --- | --- |
| U1 | 링크는 페어링과 tailnet 가입을 함께 맡는다. 1회용 인증 키를 만드는 일까지 라이브러리가 한다 |
| U2 | QR 그림은 CoreImage로 만든다. 읽는 쪽 카메라 화면은 앱이 만든다 |
| U3 | 라이브러리에 새 기능으로 만든다. 첫 사용처(RemoteDebug)의 지금 페어링은 그대로 두고, 옮길지는 끝난 뒤 따로 정한다 |

참고한 것: 첫 사용처의 페어링(`docs/protocol.md` 2~4.3절, `docs/protocol-addenda.md` B.3·J. 읽기만), `tailscale.com` v1.104.7 `client/tailscale/keys.go`(`CreateKeyWithExpiry`)·`cmd/get-authkey/main.go`·`feature/oauthkey/oauthkey.go`, `golang.org/x/oauth2` v0.37.0 `clientcredentials`·`internal/token.go`. 짝 맺기 절차(5절)는 Swiftail의 것이고 Go에 대응하는 것이 없다.

## 1. 범위

| 넣는다 | 까닭 |
| --- | --- |
| 제안(`PairingOffer`)과 그 링크·QR | U1·U2 |
| 짝 맺기 절차: 여는 쪽은 tailnet 리스너, 들어오는 쪽은 프로세스 안 노드 또는 OS 소켓 | 노드가 터널 확장에 있는 iOS 앱은 OS 소켓으로만 tailnet에 닿는다 |
| 여는 쪽의 짝 목록(저장, 조회, 지우기)과 연결의 상대가 짝인지 묻는 길 | 짝이 된 뒤의 연결을 가리는 데 쓴다 |
| 1회용 인증 키 발급: OAuth 클라이언트 → API 토큰 → 키 | U1 |

| 뺀다 | 까닭 |
| --- | --- |
| 카메라로 QR 읽기, 승인 화면, 링크를 받는 URL 스킴·연결 도메인 등록 | 화면과 앱 설정이다. 라이브러리는 읽은 문자열과 받은 URL을 검사한다 |
| 손으로 치는 짧은 코드 | QR과 링크만 쓴다(요청). 비밀이 256비트라 시도 횟수 제한이 필요 없다 |
| OAuth 클라이언트 비밀의 보관 | 앱이 키체인에 둔다. 라이브러리는 값을 받아 쓰고 저장하지 않는다 |
| 키 목록·지우기, 기기 목록 등 나머지 관리 API | 쓰는 곳이 없다 |
| tailnet lock용 서명된 인증 키 만들기 | 믿는 서명 키가 있어야 한다. lock이 켜진 tailnet에서 들어온 노드는 서명 전까지 잠긴다(`SwiftailTailnetLock.md`). 앱이 이미 감싼 키를 제안에 넣는 것은 된다 |
| tailnet 밖(같은 네트워크 직접 연결)에서의 인증 | 짝의 신원은 tailnet 노드 신원이다 |
| 첫 사용처 저장소 바꾸기 | U3 |

## 2. 타깃

`SwiftailPairing`(새 제품). `Swiftail`·`SwiftailBase`에 의존한다. 시스템 프레임워크는 CryptoKit(HMAC, SHA-256, 난수), Foundation의 `URLSession`(관리 API와의 HTTPS), Network(OS 소켓 쪽 들어오기), CoreImage(QR)를 쓴다. 외부 패키지와 C 코드는 없다. iOS 터널 확장은 이 타깃을 링크하지 않는다.

```
Swiftail ◄─ SwiftailPairing   (CryptoKit, Foundation, Network, CoreImage)
```

폴더: `AuthKey/`(4절), `Offer/`(3절: 제안, 링크, QR), `Protocol/`(5절의 값 타입 상태 기계), `Store/`(6절), 맨 위에 가장자리(`PairingHost`, `PairingJoiner`).

## 3. 제안과 링크

```swift
/// 여는 쪽이 낸 제안 하나. 비밀과 인증 키를 담으므로 `description`과 `dump`에서 가린다.
public struct PairingOffer: Sendable, Equatable {
    public let host: String        // 여는 노드의 MagicDNS FQDN(소문자, 끝 점 없음)
    public let port: UInt16
    public let expires: Date       // 초 단위. 판정은 여는 쪽이 한다
    public let authKey: String?    // 들어오는 쪽이 tailnet에 없으면 노드 설정에 넣는다
    // 비밀 32바이트는 공개하지 않는다(package).

    public init(url: URL) throws(PairingOfferError)
    public init(text: String) throws(PairingOfferError)   // QR에서 읽은 문자열
    public func url(base: URL) -> URL
    public func qrCode(base: URL, moduleSize: Int = 8) -> CGImage?
}
```

링크는 `<base>#v=1&h=<host>&p=<port>&s=<비밀, base64url 43자>&e=<만료, 유닉스 초>[&k=<인증 키>]`다. `base`는 앱의 것이다(`myapp://pair`, `https://example.com/pair`).

- O1. 값은 전부 조각(`#` 뒤)에 싣는다. 조각은 웹 서버로 가지 않으므로 연결 도메인의 대체 페이지나 서버 로그에 비밀이 남지 않는다. `base`에 조각이 있으면 `url(base:)`는 그것을 버린다.
- O2. 읽기는 엄격하다. `v`는 `1`만, 키는 위 여섯 개만, 같은 키는 한 번만, `h`는 올바른 DNS 이름(라벨 1~63자, `a-z0-9-`, 전체 253자 이하, 라벨 둘 이상), `p`는 1~65535의 10진수(앞자리 0 없음), `s`는 채움 없는 base64url로 정확히 32바이트, `e`는 10진수 초, `k`는 `tskey-auth-`로 시작하고 공백 없는 인쇄 가능 ASCII 1024바이트 이하. 어긋나면 `PairingOfferError`이고 오류에 값을 싣지 않는다. 조각 전체는 2048바이트 이하.
- O3. 읽는 쪽은 `base`를 보지 않는다. 어느 URL이 자기 것인지는 앱이 가린다.
- O4. `e`가 지난 제안도 읽힌다(시계가 다를 수 있다). 들어오는 쪽은 `expires`로 안내만 하고, 거절은 여는 쪽이 한다.
- O5. QR은 링크 문자열을 UTF-8 바이트로 넣은 것이다(`CIQRCodeGenerator`, 오류 정정 M). 모듈 하나를 `moduleSize` 화소로 보간 없이 키운다. 만들지 못하면 nil.

**앱이 지킬 것**: 링크는 어디서든 올 수 있다. 사용자가 직접 읽은 QR이 아니라 링크로 시작한 페어링은 짝을 맺기 전에 `host`를 보여 주고 사용자에게 묻는다. 제안의 URL과 QR은 비밀이다. 로그·분석·대화 기록에 넣지 않는다.

## 4. 인증 키 발급

```swift
public struct TailscaleOAuthClient: Sendable {   // description·dump에서 비밀을 가린다
    public var id: String
    public var secret: String      // tskey-client-…
    public var tags: [String]      // tag:… 하나 이상
    public init(id: String, secret: String, tags: [String])   // 검사는 AuthKeyIssuer.init이 한다
}

public struct AuthKeyIssuer: Sendable {           // description·dump에서 클라이언트 비밀을 가린다
    public static let defaultBaseURL: URL          // https://api.tailscale.com
    public init(client: TailscaleOAuthClient, baseURL: URL = AuthKeyIssuer.defaultBaseURL) throws(AuthKeyIssueError)
    /// 한 번만 쓸 수 있는 키 하나.
    public func issue(lifetime: Duration) async throws(AuthKeyIssueError) -> IssuedAuthKey
}

public struct IssuedAuthKey: Sendable {          // description·dump에서 key를 가린다
    public let key: String
    public let expires: Date
}

public enum AuthKeyIssueError: Error, Sendable, Equatable {   // 연관 값에 비밀·토큰·키·서버 본문이 없다
    case invalidClient, invalidTags, invalidLifetime, invalidBaseURL
    case clientRejected, unauthorized, forbidden, http(status: Int)
    case invalidResponse, network, cancelled
}
```

- K1. 요청은 Go `get-authkey`의 흐름과 같다(`x/oauth2/clientcredentials` + `client/tailscale`).
  1. `POST <base>/api/v2/oauth/token`, `Content-Type: application/x-www-form-urlencoded`. 먼저 `Authorization: Basic base64(<QueryEscape(id)>:<QueryEscape(secret)>)`와 본문 `grant_type=client_credentials`로 보낸다(`x/oauth2` `internal/token.go:186-205`). 이 시도가 **어떤 까닭으로든** 실패하면(2xx가 아님, 전송 실패, 읽지 못한 본문, `error` 필드, 빈 `access_token`) `Authorization` 없이 본문 `client_id=…&client_secret=…&grant_type=client_credentials`(키 순, `url.Values.Encode`)로 한 번만 다시 보내고 그 결과로 분류한다(`internal/token.go:226-243`의 자동 감지). Task 취소만은 다시 보내지 않는다. 방식은 기억하지 않고 호출마다 Basic부터 묻는다(K2). 2xx이고 JSON에 `error`가 없거나 비었으며 `access_token`이 비지 않아야 성공이다(`internal/token.go:269`, `:326-331`). `token_type`은 거르지 않는다. 폼 형식의 토큰 응답은 읽지 않는다.
  2. `POST <base>/api/v2/tailnet/-/keys`, `Authorization: Bearer <토큰>`, 본문은 Go `CreateKeyWithExpiry`와 같은 `{"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":[…]}}},"expirySeconds":<초>}`(`client/tailscale/keys.go:93-96`). `get-authkey`는 `CreateKey`(만료 0)를 불러 `expirySeconds`를 보내지 않으므로 관문 7의 Go 쪽은 `CreateKeyWithExpiry`를 부른다. `Content-Type: application/json`은 Swift만 붙인다(Go는 안 붙인다, `keys.go:103`, `tailscale.go:156-165`). 견줄 때 이 머리는 뺀다. 200(Go와 같다, `keys.go:112`)의 JSON에서 `key`(`tskey-auth-`로 시작)와 `expires`(RFC 3339, 소수 초가 있어도 된다)를 읽는다.
- K2. 토큰은 호출마다 새로 받고 쥐고 있지 않는다. 발급은 드문 일이다.
- K3. 본문 값은 고정이다: `reusable` 거짓, `ephemeral` 거짓(임시 노드는 StableID가 사라져 짝이 깨진다), `preauthorized` 참(승인 대기는 짝 맺기를 멈춘다). `lifetime`은 초 단위로 버리고(Go `int64(expiry.Seconds())`), 1초 미만이면 아무것도 보내지 않고 `.invalidLifetime`. 위쪽 상한은 두지 않는다(Go에 없다. 서버가 거절하면 `.http(status)`).
- K4. 검사: `id`와 `secret`은 1~512바이트이고 `A-Za-z0-9-_.~`(QueryEscape가 그대로 두는 글자)만 쓴다. `secret`은 `tskey-client-`로 시작한다. 태그는 하나 이상이고 각각 Go `tailcfg.CheckTag`(`tailcfg/tailcfg.go:766-786`) 그대로다: `tag:` 뒤가 비지 않고 첫 글자는 ASCII 영문, 나머지는 ASCII 영문·숫자·`-`. 길이 상한은 없다. `baseURL`은 `https`여야 한다(시험용으로 루프백 호스트 `127.0.0.1`·`::1`·`localhost`의 `http`만 받는다). 사용자 정보·쿼리·조각이 있으면 거절한다. 경로가 있으면 그 뒤에 `/api/v2/…`를 잇는다(Go와 같다). 어긋나면 `.invalidClient`·`.invalidTags`·`.invalidBaseURL`.
- K5. HTTP: `URLSessionConfiguration.ephemeral`, 요청마다 15초, 리다이렉트는 따르지 않는다, 응답 본문은 64KiB까지만 읽는다. 쿠키와 캐시를 쓰지 않는다.
- K6. 오류: 토큰 요청의 400·401과, 2xx인데 `error`가 있거나 `access_token`이 빈 것 → `.clientRejected`, 키 요청의 401 → `.unauthorized`, 403 → `.forbidden`(권한 `auth_keys` 쓰기나 태그가 없다), 그 밖의 상태(따르지 않은 3xx 포함) → `.http(status)`, 읽지 못한 응답(64KiB 초과, 머리에 실을 수 없는 토큰 포함) → `.invalidResponse`, 전송 실패(15초 기한 초과 포함) → `.network`, Task 취소 → `.cancelled`. 토큰 요청은 다시 보낸 뒤의 마지막 결과로 분류한다. 오류와 로그에 비밀·토큰·키·서버 본문을 넣지 않는다.
- K7. OAuth 클라이언트로 만든 키로 들어온 노드는 태그 노드다. 그 태그에서 여는 노드의 페어링 포트로 가는 연결을 tailnet 정책이 허용해야 한다(앱의 안내 몫).
- K8. 쓰지 않은 키는 만료될 때까지 살아 있다. 지우는 요청은 넣지 않는다(수명을 제안과 같게 짧게 준다).

## 5. 짝 맺기 절차

들어오는 쪽(J)이 여는 쪽(H)의 `host:port`로 TCP 연결을 건다. 연결은 WireGuard가 암호화하고 양쪽 노드 키로 인증한다. H는 연결의 원격 주소로 J의 노드 신원을 안다(`whoIs`). J는 H가 제안의 비밀을 안다는 증명으로 H를 확인한다(OS 소켓 쪽 J는 `whoIs`를 부를 수 없다).

```
J→H  hello     "SWPR" ‖ 0x01 ‖ nonceJ(32) ‖ 길이(1) ‖ 기기 이름(UTF-8, 1~64바이트)
H→J  challenge nonceH(32)
J→H  proof     HMAC-SHA256(비밀, "swiftail-pairing-1 joiner" ‖ T)
H→J  accepted  HMAC-SHA256(비밀, "swiftail-pairing-1 host" ‖ T)
H→J  decision  상태(1) ‖ [승인일 때: 길이(1) ‖ H의 StableID ‖ 길이(1) ‖ H의 표시 이름]

T = nonceJ ‖ nonceH ‖ SHA256(host) ‖ port(2, 빅 엔디언) ‖ SHA256(기기 이름)
상태: 1 승인, 2 거절, 3 승인 시간 초과
```

여는 쪽:

- P1. 연결을 받으면 먼저 `whoIs(원격 주소)`를 본다. 신원을 모르면 읽지 않고 닫는다.
- P2. 열린 제안이 없거나 만료됐으면 `hello`를 읽고 닫는다. `challenge`는 열린 제안이 있을 때만 보낸다.
- P3. `proof`는 상수 시간으로 견준다. 틀리면 아무것도 보내지 않고 닫는다. 제안은 그대로 둔다(비밀이 256비트라 틀린 시도로 태우지 않는다. 태우면 tailnet의 아무 피어나 제안을 못 쓰게 만들 수 있다).
- P4. 맞으면 그 자리에서 제안을 쓴 것으로 한다(한 번만 쓴다). 같은 비밀의 다른 연결은 그 뒤로 P2가 된다. `accepted`를 보내고 앱의 결정을 기다린다.
- P5. 앱의 결정은 `decide(PairingRequest) async -> Bool`이다. 요청에는 J의 `PeerIdentity`와 기기 이름이 있다. 120초 안에 답이 없으면 상태 3. 그 사이 연결이 끊기면 결정 Task를 취소한다.
- P6. 승인이면, 그 순간의 `whoIs`가 처음과 같은 `StableID`일 때만 짝 목록에 넣고 저장한 뒤 상태 1을 보낸다. 저장에 실패하면 상태 2다.
- P7. 한도: 절차 중인 연결 8개(넘으면 받자마자 닫는다), `hello`부터 `proof`까지 10초, 메시지는 위 길이 그대로(넘거나 모자라면 닫는다). 기기 이름은 올바른 UTF-8이어야 하고 제어 문자를 받지 않는다.
- P8. 제안은 한 번에 하나다. 새로 열면 앞의 것은 그 자리에서 못 쓴다. 수명은 기본 300초, 1~3600초.
- P9. 로그에는 요약만 남긴다(받음, 닫은 까닭, 결정). 비밀·증명·인증 키·이름·주소는 남기지 않는다.

들어오는 쪽:

- J1. `accepted`를 상수 시간으로 견준다. 틀리면 `.hostNotVerified`로 끝낸다. `proof`를 보낸 뒤에만 읽으므로 비밀은 전선에 나가지 않는다.
- J2. `decision`까지 기다린다(130초). 승인이면 `PairedHost`(`host`, `port`, `stableID`, `name`, `pairedAt`)를 돌려준다. 보관은 앱이 한다(`Codable`).
- J3. 프로세스 안 노드로 들어올 때는 `decision`의 `StableID`가 `whoIs(원격 주소)`의 것과 같아야 한다. 다르면 `.hostNotVerified`.
- J4. OS 소켓으로 들어올 때는 `NWConnection`으로 `host:port`에 건다(이름은 터널의 MagicDNS가 푼다). 연결 15초.
- J5. 호출한 Task가 취소되면 연결을 끊고 `.cancelled`.
- J6. 연결하지 못하거나 H가 말없이 닫으면 `.rejected`다(제안 없음, 만료, 틀린 비밀을 가리지 않는다).

```swift
public actor PairingHost {
    public init(node: TailnetNode, port: UInt16, storeDirectory: URL,
                decide: @escaping @Sendable (PairingRequest) async -> Bool) throws(PairingError)
    /// 듣고 절차를 돌린다. 취소될 때까지 돌아오지 않는다.
    public func run() async throws(PairingError)
    public func openOffer(lifetime: Duration = .seconds(300), authKey: String? = nil) throws(PairingError) -> PairingOffer
    public func closeOffer()
    public var pairedPeers: [PairedPeer] { get }
    public func removePairedPeer(stableID: String) throws(PairingError)
    /// 연결의 상대가 짝이면 그 항목. `whoIs`로 지금의 신원을 본다.
    public func pairedPeer(at address: IPAddress) async -> PairedPeer?
}

public enum PairingJoiner {
    public static func pair(with offer: PairingOffer, deviceName: String, node: TailnetNode)
        async throws(PairingError) -> PairedHost
    public static func pair(with offer: PairingOffer, deviceName: String)
        async throws(PairingError) -> PairedHost          // OS 소켓(노드가 터널 확장에 있는 앱)
}
```

`openOffer`는 노드의 자기 FQDN이 있어야 한다(없으면 `.notRunning`). 인증 키는 앱이 `AuthKeyIssuer`로 만들어 넘긴다.

## 6. 짝 목록

- S1. 항목은 `PairedPeer`(`stableID`, `deviceName`, `nodeName`, `loginName`, `pairedAt`)다. 열쇠는 `StableID`다. 같은 노드가 다시 짝이 되면 항목을 바꾼다.
- S2. `storeDirectory/paired-peers.json`에 둔다(`{"version":1,"peers":[…]}`). 바꿀 때마다 같은 디렉터리의 임시 파일에 쓰고 바꿔치기한다. 권한은 0600.
- S3. 파일이 없으면 빈 목록이다. 읽지 못하거나 버전이 다르면 `init`이 `.storeUnreadable`을 던진다(빈 목록으로 덮어쓰지 않는다).
- S4. 256개까지. 넘으면 새 짝은 거절(상태 2)이다.
- S5. `pairedPeer(at:)`은 `whoIs`의 `StableID`로만 찾는다. 이름은 표시용이고 판정에 쓰지 않는다.

## 7. 시험과 관문

단위(`SwiftailPairingTests`):

1. 링크: 왕복, O2의 거절 하나하나, 가린 `description`.
2. 증명: 다른 구현(Python `hmac`)으로 뽑은 고정 벡터와 일치.
3. 절차의 상태 기계: 정상, 틀린 증명, 제안 없음·만료·바뀜, 한 번만 쓰임, 잘린·넘친 메시지, 시간 초과, 한도.
4. 짝 목록: 저장·다시 읽기, 다시 짝이 됨, 깨진 파일, 한도, 권한.
5. QR: 만든 그림을 시스템 검출기로 다시 읽어 링크와 같은지.
6. 키 발급: 가짜 전송으로 요청의 모양(K1), 응답·오류의 분류(K6), 검사(K4), 가림.

상호 운용 (가)(계정 없이, `SwiftailInteropTests`):

7. Go `get-authkey`와 Swift가 같은 기록 서버에 보낸 요청이 같다(메서드, 경로, 인증 방식, 본문의 JSON 값).
8. 시험 제어 서버 위의 Swiftail 노드 둘: 제안 → 들어옴 → 승인 → 짝 목록, 그 뒤 연결에서 `pairedPeer(at:)`이 답한다. 거절, 틀린 비밀, 만료, 다시 짝이 됨.
9. 제안의 인증 키로 새 노드가 등록한 뒤 짝이 된다(시험 제어 서버의 `setAuth`).
10. OS 소켓 쪽 들어오기: 루프백 리스너에 물린 여는 쪽 상태 기계와 왕복.

(나) 실제(사용자의 OAuth 클라이언트가 필요하다):

11. 실제 관리 API로 키를 만들고, 그 키로 새 노드가 실제 tailnet에 들어와 짝이 된다.
12. iPhone 앱(터널 확장)에서 OS 소켓으로 짝 맺기. 첫 사용처를 옮길 때 본다(U3).

## 8. 검토에서 볼 것

1. 5절의 증명이 H 확인에 충분한가. `T`에 더 묶을 것이 있는가.
2. P3(틀린 시도로 제안을 태우지 않음)과 P7의 한도가 맞는가.
3. `StableID`를 짝의 열쇠로 쓰는 것(S1·S5, J3)의 전제.
4. 링크를 조각에 싣는 것(O1)이 사용자 지정 스킴과 연결 도메인 양쪽에서 문제없는가.
5. K1의 Basic 방식과 K6의 분류가 실제 API와 맞는가((나) 11에서 확인).
6. OS 소켓 쪽 들어오기(J4)가 H의 신원을 `accepted`만으로 확인하는 것의 한계.
