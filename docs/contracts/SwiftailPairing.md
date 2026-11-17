# Swiftail 페어링 계약 (M9)

M9의 목표는 **Swiftail을 쓰는 두 앱이 QR 코드나 링크 하나로 서로를 인증하는 것**이다. 한쪽(여는 쪽)이 화면에 QR과 링크를 내고, 다른 쪽(들어오는 쪽)이 그것을 읽으면 두 앱이 짝이 된다. 링크에 1회용 tailnet 인증 키를 실으면 들어오는 쪽은 로그인 없이 tailnet에 들어온 뒤 짝이 된다. 그 키를 만드는 일(Tailscale 관리 API)도 라이브러리가 한다.

2026-11-17에 다른 세션이 초안을 설계 검토했고(판정: 고친 뒤에 구현), 그 발견을 이 판에 반영했다. 무엇을 바꿨는지는 9절에 있다. 같은 날의 보안 검증이 낸 발견은 11절에 있다(절차는 판 2를 거쳐 판 3이 됐다).

사용자 결정(2026-11-17):

| | 결정 |
| --- | --- |
| U1 | 링크는 페어링과 tailnet 가입을 함께 맡는다. 1회용 인증 키를 만드는 일까지 라이브러리가 한다 |
| U2 | QR 그림은 CoreImage로 만든다. 읽는 쪽 카메라 화면은 앱이 만든다 |
| U3 | 라이브러리에 새 기능으로 만든다. 첫 사용처(RemoteDebug)의 지금 페어링은 그대로 두고, 옮길지는 끝난 뒤 따로 정한다 |

참고한 것: 첫 사용처의 페어링(`docs/protocol.md` 2~4.3절, `docs/protocol-addenda.md` B.3·J. 읽기만), `tailscale.com` v1.104.7(시험 도구는 v1.104.6으로 짓는다. 아래 파일은 두 판이 같다) `client/tailscale/keys.go`(`CreateKeyWithExpiry`)·`cmd/get-authkey/main.go`·`feature/oauthkey/oauthkey.go`·`tailcfg/tailcfg.go`(`CheckTag`), `golang.org/x/oauth2` v0.37.0 `clientcredentials`·`internal/token.go`. 짝 맺기 절차(5절)는 Swiftail의 것이고 Go에 대응하는 것이 없다.

## 1. 범위

| 넣는다 | 까닭 |
| --- | --- |
| 제안(`PairingOffer`)과 그 링크·QR | U1·U2 |
| 짝 맺기 절차: 여는 쪽은 tailnet 리스너, 들어오는 쪽은 프로세스 안 노드 또는 OS 소켓 | 노드가 터널 확장에 있는 iOS 앱은 OS 소켓으로만 tailnet에 닿는다 |
| 여는 쪽의 짝 목록(저장, 조회, 지우기) | 짝이 된 뒤의 연결을 가리는 데 쓴다 |
| 1회용 인증 키 발급: OAuth 클라이언트 → API 토큰 → 키 | U1 |

| 뺀다 | 까닭 |
| --- | --- |
| 카메라로 QR 읽기, 승인 화면, 링크를 받는 URL 스킴·연결 도메인 등록 | 화면과 앱 설정이다. 라이브러리는 읽은 문자열을 검사한다 |
| 손으로 치는 짧은 코드 | QR과 링크만 쓴다(요청). 비밀이 256비트라 시도 횟수 제한이 필요 없다 |
| OAuth 클라이언트 비밀의 보관 | 앱이 키체인에 둔다. 라이브러리는 값을 받아 쓰고 저장하지 않는다 |
| 키 목록·지우기, 기기 목록 등 나머지 관리 API | 쓰는 곳이 없다 |
| tailnet lock의 서명된(감싼) 인증 키: 만들기도, 링크에 싣기도 | 감싼 키 뒤쪽의 개인 키는 1회용이 아니다. TKA에서 철회될 때까지 아무 node 키에나 서명을 만들 수 있다(Go `tka/sig.go`). QR 사진 한 장으로 새면 안 되는 값이다 |
| tailnet 밖(같은 네트워크 직접 연결)에서의 인증 | 짝의 신원은 tailnet 노드 신원이다 |
| 첫 사용처 저장소 바꾸기 | U3 |

한계:

- **여는 쪽은 프로세스 안 노드(`.inProcess`)여야 한다.** `listen`이 그 장치에서만 된다. 노드가 터널 확장에 있는 앱은 들어오는 쪽만 된다. 그런 iPhone 앱끼리는 짝이 될 수 없다.
- **lock이 켜진 tailnet**에서는 링크의 키로 들어온 노드가 서명 전까지 잠긴다. 잠긴 노드는 여는 쪽의 netmap에 없어 짝 맺기가 `.unreachable`로 끝난다. 앱은 `status.tailnetLock`으로 서명이 필요함을 안내하고, 서명 뒤 같은 제안으로 다시 시도한다(제안의 수명을 그만큼 길게 연다).
- 들어오는 쪽이 OS 소켓이면, 짝이 된 뒤의 연결에서 상대가 그 짝인지 라이브러리로 확인할 길이 없다. 이름 풀이(MagicDNS)와 WireGuard를 믿는다. 프로세스 안 노드는 `whoIs`의 `StableID`를 `PairedHost.stableID`와 견줄 수 있다.
- OS 소켓으로 들어오는 쪽은 그 연결이 터널로 나갔는지를 라이브러리가 직접 볼 수 없다. 앱이 넘긴 이 기기의 tailnet 주소(`localAddress`)와 연결의 로컬 끝이 같은지, 원격 끝이 tailnet 대역인지를 보고, 연결이 Wi-Fi·셀룰러·유선·루프백 인터페이스로 나가지 못하게 한다(J2). 앱이 틀린 주소를 넘기면 이 검사는 뜻이 없다. 주소는 터널 확장이 노드에서 읽은 값이어야 한다.

## 2. 타깃

`SwiftailPairing`(새 제품). `Swiftail`·`SwiftailBase`에 의존한다. 시스템 프레임워크는 CryptoKit(HMAC, SHA-256, 난수), Foundation의 `URLSession`(관리 API와의 HTTPS), Network(OS 소켓 쪽 들어오기), CoreImage(QR)를 쓴다. 외부 패키지와 C 코드는 없다. iOS 터널 확장은 이 타깃을 링크하지 않는다.

```
Swiftail ◄─ SwiftailPairing   (CryptoKit, Foundation, Network, CoreImage)
```

폴더: `AuthKey/`(4절), `Offer/`(3절: 제안, 링크, QR), `Protocol/`(5절의 값 타입 상태 기계), `Store/`(6절), 맨 위에 가장자리(`PairingHost`, `PairingJoiner`).

앱은 `import Swiftail`과 `import SwiftailPairing`만으로 공개 API의 타입 이름을 모두 쓴다(2026-11-18). 공개 선언에 나오는 다른 모듈의 타입은 `Swiftail`의 `TailnetNode`·`PeerIdentity`와 `SwiftailBase`의 `IPAddress`뿐이고, `IPAddress`는 `Swiftail`이 별명으로 내보낸다(`docs/contracts/SwiftailTunnel.md` "공개 API에 나오는 다른 모듈의 타입"). `SwiftailPairing`은 따로 별명을 내지 않는다: 이 제품을 쓰는 앱은 노드를 만들려고 어차피 `Swiftail`을 가져오고, 같은 이름을 두 모듈이 내면 둘을 함께 가져온 파일에서 이름이 모호해지는 자리가 생긴다.

## 3. 제안과 링크

```swift
/// 여는 쪽이 낸 제안 하나. 비밀과 인증 키를 담으므로 `description`과 `dump`에서 가린다. `Equatable`이 아니다.
public struct PairingOffer: Sendable {
    public let host: String        // 여는 노드의 MagicDNS FQDN(소문자, 끝 점 없음)
    public let port: UInt16
    public let expires: Date       // 초 단위. 판정은 여는 쪽이 한다
    public let authKey: String?    // 들어오는 쪽이 tailnet에 없으면 노드 설정에 넣는다
    // 비밀 32바이트는 공개하지 않는다(package).

    /// 받은 URL(`url.absoluteString`)이나 QR에서 읽은 문자열.
    public init(link: String) throws(PairingOfferError)
    public func url(base: URL) -> URL
    /// 모듈 하나가 한 화소인 그림. 둘레에 4모듈의 여백이 있다. 앱이 보간 없이 키워 쓴다.
    public func qrCode(base: URL) -> CGImage?
}

public enum PairingOfferError: Error, Sendable, Equatable {
    case notAnOffer          // 조각이 없거나, 모르는 판·키, 겹친 키, 길이 초과
    case invalidHost, invalidPort, invalidSecret, invalidExpiry, invalidAuthKey
    case wrappedAuthKey      // 감싼 키(`--TL`)
}
```

링크는 `<base>#v=1&h=<host>&p=<port>&s=<비밀, base64url 43자>&e=<만료, 유닉스 초>[&k=<인증 키>]`다. `base`는 앱의 것이다(`myapp://pair`, `https://example.com/pair`).

- O1. 값은 전부 조각(`#` 뒤)에 싣는다. 조각은 서버 요청과 Referer에 실리지 않는다. `base`에 조각이 있으면 `url(base:)`는 그것을 버린다.
- O2. 읽기는 엄격하다. 첫 `#` 뒤만 본다. 조각은 2048바이트 이하이고 `%`가 없어야 한다(값의 글자가 모두 인코딩이 필요 없는 것이다). `v`는 `1`만, 키는 위 여섯 개만, 같은 키는 한 번만.
  - `h`: 올바른 DNS 이름(라벨 1~63자, `a-z0-9-`, 하이픈으로 시작·끝나지 않음, 전체 253자 이하, 라벨 둘 이상). 끝 라벨은 글자(`a-z`)로 시작해야 한다(최상위 도메인은 숫자로 시작하지 않는다. `xn--` 라벨은 된다). 숫자로 시작하는 끝 라벨은 이름이 아니라 IP 주소 꼴이므로 받지 않는다(`192.168.1.1`, `1.2`, 그리고 OS가 IPv4 주소로 읽는 16진 꼴 `192.168.1.0x1`, `1.0x7f`). 이름이어야 터널의 MagicDNS가 풀고, 주소를 적은 링크로 들어오는 쪽을 tailnet 밖의 곳에 걸게 할 수 없다. 여는 쪽도 같은 규칙으로 자기 FQDN을 본다(P9).
  - `p`: 1~65535의 10진수, 앞자리 0 없음.
  - `s`: 채움 없는 base64url 43자, 정확히 32바이트로 풀린다(남는 비트는 0).
  - `e`: 부호와 앞자리 0이 없는 1~11자리 10진수.
  - `k`: `tskey-auth-`로 시작하고 `A-Za-z0-9-`만 쓰는 256바이트 이하. `--TL`이 있으면 `.wrappedAuthKey`.
- O3. 오류에 값을 싣지 않는다. 읽는 쪽은 `base`를 보지 않는다. 어느 URL이 자기 것인지는 앱이 가린다.
- O4. `e`가 지난 제안도 읽힌다(시계가 다를 수 있다). 들어오는 쪽은 `expires`로 안내만 하고, 거절은 여는 쪽이 한다.
- O5. QR은 링크 문자열의 UTF-8 바이트다(`CIQRCodeGenerator`, 오류 정정 M). 만들지 못하면 nil.

**앱이 지킬 것**:

- 제안의 URL과 QR은 비밀이다. 로그·분석·대화 기록에 넣지 않는다.
- 가장 안전한 길은 앱 안의 카메라로 QR을 읽는 것이다. 그 문자열은 OS의 링크 배달을 거치지 않는다.
- OS가 배달하는 링크: 사용자 지정 스킴은 같은 스킴을 선언한 다른 앱이 받을 수 있다. 인증 키를 실은 링크는 연결 도메인(universal link)으로 낸다. 그 도메인의 대체 웹 페이지는 제3자 스크립트를 싣지 않고, 열리자마자 주소에서 조각을 지운다. 브라우저 기록에는 조각까지 남을 수 있다.
- 링크는 어디서든 올 수 있다. 링크로 시작한 페어링은 짝을 맺기 전에 `host`를 보여 주고 사용자에게 묻는다.
- 인증 키는 저장하지 않고 노드를 띄울 때 한 번만 넘긴다(터널 확장이면 시작 옵션으로). 이미 tailnet에 있으면 쓰지 않는다.
- **인증 키는 페어링과 묶여 있지 않다.** 링크를 얻은 쪽은 키가 살아 있는 동안, 여는 쪽의 승인과 무관하게 그 키로 tailnet에 들어온다. 승인이 막는 것은 짝이 되는 일뿐이다. 그래서 여는 앱은 키의 수명을 제안과 같게 짧게 주고(K8), 그 키의 태그가 닿을 수 있는 곳을 tailnet 정책(ACL)에서 페어링 포트와 앱 포트로만 좁힌다(K7).
- **키가 실린 링크를 여는 것은 그 링크가 가리키는 tailnet에 가입하는 일이다.** 그 tailnet의 관리자는 이 기기의 노드를 보고 정책을 정한다. 들어오는 앱은 `authKey`가 있는 제안으로 노드를 띄우기 전에 그 사실을 사용자에게 보여 주고 묻는다.

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
    /// 한 번만 쓸 수 있고 미리 승인된, 임시가 아닌 키 하나.
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
  2. `POST <base>/api/v2/tailnet/-/keys`, `Authorization: Bearer <토큰>`, 본문은 Go `CreateKeyWithExpiry`와 같은 `{"capabilities":{"devices":{"create":{"reusable":false,"ephemeral":false,"preauthorized":true,"tags":[…]}}},"expirySeconds":<초>}`(`client/tailscale/keys.go:93-96`). `get-authkey`는 `CreateKey`(만료 0)를 불러 `expirySeconds`를 보내지 않으므로 관문 8의 Go 쪽은 `CreateKeyWithExpiry`를 부른다. `Content-Type: application/json`은 Swift만 붙인다(Go는 안 붙인다, `keys.go:103`, `tailscale.go:156-165`). 견줄 때 이 머리는 뺀다. 200(Go와 같다, `keys.go:112`)의 JSON에서 `key`(`tskey-auth-`로 시작)와 `expires`(RFC 3339, 소수 초가 있어도 된다)를 읽는다.
- K2. 토큰은 호출마다 새로 받고 쥐고 있지 않는다. 발급은 드문 일이다.
- K3. 본문 값은 고정이다: `reusable` 거짓, `ephemeral` 거짓(임시 노드는 StableID가 사라져 짝이 깨진다), `preauthorized` 참(승인 대기는 짝 맺기를 멈춘다). `lifetime`은 초 단위로 버리고(Go `int64(expiry.Seconds())`), 1초 미만이면 아무것도 보내지 않고 `.invalidLifetime`. 위쪽 상한은 두지 않는다(Go에 없다. 서버가 거절하면 `.http(status)`).
- K4. 검사: `id`와 `secret`은 1~512바이트이고 `A-Za-z0-9-_.~`(QueryEscape가 그대로 두는 글자)만 쓴다. `secret`은 `tskey-client-`로 시작한다. 태그는 하나 이상이고 각각 Go `tailcfg.CheckTag`(`tailcfg/tailcfg.go:766-786`) 그대로다: `tag:` 뒤가 비지 않고 첫 글자는 ASCII 영문, 나머지는 ASCII 영문·숫자·`-`. 길이 상한은 없다. `baseURL`은 `https`여야 한다(시험용으로 루프백 호스트 `127.0.0.1`·`::1`·`localhost`의 `http`만 받는다). 사용자 정보·쿼리·조각이 있으면 거절한다. 경로가 있으면 그 뒤에 `/api/v2/…`를 잇는다(Go와 같다). 어긋나면 `.invalidClient`·`.invalidTags`·`.invalidBaseURL`.
- K5. HTTP: `URLSessionConfiguration.ephemeral`, 요청마다 15초, 리다이렉트는 따르지 않는다, 응답 본문은 64KiB까지만 읽는다. 쿠키와 캐시를 쓰지 않는다.
- K6. 오류: 토큰 요청의 400·401과, 2xx인데 `error`가 있거나 `access_token`이 빈 것 → `.clientRejected`, 키 요청의 401 → `.unauthorized`, 403 → `.forbidden`(권한 `auth_keys` 쓰기나 태그가 없다), 그 밖의 상태(따르지 않은 3xx 포함) → `.http(status)`, 읽지 못한 응답(64KiB 초과, 머리에 실을 수 없는 토큰 포함) → `.invalidResponse`, 전송 실패(15초 기한 초과 포함) → `.network`, Task 취소 → `.cancelled`. 토큰 요청은 다시 보낸 뒤의 마지막 결과로 분류한다. 오류와 로그에 비밀·토큰·키·서버 본문을 넣지 않는다.
- K7. OAuth 클라이언트로 만든 키로 들어온 노드는 태그 노드다. 그 태그에서 여는 노드의 **페어링 포트와 짝이 된 뒤 쓰는 앱 포트** 양쪽으로 가는 연결을 tailnet 정책이 허용해야 한다(앱의 안내 몫).
- K8. 쓰지 않은 키는 만료될 때까지 살아 있다. 지우는 요청은 넣지 않는다(수명을 제안과 같게 짧게 준다).

## 5. 짝 맺기 절차

들어오는 쪽(J)이 여는 쪽(H)의 `host:port`로 TCP 연결을 건다. 연결은 WireGuard가 암호화하고 양쪽 노드 키로 인증한다. H는 연결의 원격 주소로 J의 노드 신원을 안다(`whoIs`). J는 H가 제안의 비밀을 안다는 증명으로 H를 확인한다. 증명에는 양쪽이 본 연결의 두 끝을 묶는다. 중간에서 바이트를 넘겨주는 다른 노드가 끼면 두 끝이 달라져 증명이 맞지 않는다.

```
J→H  hello     "SWPR" ‖ 0x03 ‖ commitJ(32) ‖ 길이(1) ‖ 기기 이름(UTF-8, 1~64바이트)
               commitJ = SHA256("swiftail-pairing-3 commit joiner" ‖ nonceJ)
H→J  challenge 상태(1) ‖ commitH(32)           상태: 0 계속, 1 열린 제안 없음(H가 닫는다)
               commitH = SHA256("swiftail-pairing-3 commit host" ‖ nonceH)
J→H  proof     nonceJ(32) ‖ HMAC-SHA256(비밀, "swiftail-pairing-3 joiner" ‖ P)
H→J  accepted  nonceH(32) ‖ HMAC-SHA256(비밀, "swiftail-pairing-3 host" ‖ T)
H→J  decision  D ‖ HMAC-SHA256(비밀, "swiftail-pairing-3 decision" ‖ T ‖ D)
               D = 상태(1) ‖ [승인일 때: 길이(1) ‖ H의 StableID ‖ 길이(1) ‖ H의 표시 이름]
               상태: 1 승인, 2 거절, 3 승인 시간 초과

P = commitJ ‖ commitH ‖ nonceJ ‖ SHA256(제안의 host 문자열) ‖ 제안의 port(2, 빅 엔디언) ‖ SHA256(보낸 기기 이름 바이트)
    ‖ J의 주소(16) ‖ J의 포트(2) ‖ H의 주소(16) ‖ H의 포트(2)        길이 198바이트
T = P ‖ nonceH                                                    길이 230바이트
확인 숫자 = HMAC-SHA256(비밀, "swiftail-pairing-3 sas" ‖ T)의 앞 4바이트(빅 엔디언) mod 1000000, 6자리
```

**nonce 약속(판 3).** 확인 숫자는 20비트 남짓이라, 상대의 nonce를 본 뒤에 자기 nonce를 고를 수 있는 쪽은 값을 갈아 가며 원하는 숫자를 맞출 수 있다. 그래서 양쪽 nonce가 상대 값을 보기 전에 고정되게 한다. J는 `hello`에 약속 commitJ를 싣고 `proof`에서 nonceJ를 연다. H는 `challenge`에 약속 commitH를 싣고 `accepted`에서 nonceH를 연다. 어느 쪽도 약속과 다른 nonce를 열 수 없다. 두 약속의 꼬리표는 서로 달라, 상대의 약속을 되비춰 자기 약속으로 낼 수 없다.

**H가 nonce를 늦게 여는 까닭.** 제안의 비밀을 아는 쪽은 두 nonce를 알면 확인 숫자를 계산할 수 있다. H가 `challenge`에서 nonceH를 밝히면(판 2), 비밀을 아는 쪽이 `proof`를 내기 전에 숫자를 보고, 원하는 숫자가 아니면 끊고 다시 걸기를 되풀이할 수 있다(끊은 시도는 제안을 쓰지 않는다, P3). 그래서 H는 nonceH를 맞는 `proof`가 온 뒤에만 밝힌다. 그때는 제안이 이미 쓰였으므로(P4), 숫자를 본 뒤 그만두는 시도는 한 번뿐이다. `proof`는 nonceH 없이 만들 수 있어야 하므로 P에 매기고, 그 뒤의 값(`accepted`, `decision`, 확인 숫자)은 nonceH까지 든 T에 매긴다.

판 1(`0x01`, `hello`에 nonceJ)과 판 2(`0x02`, `challenge`에 nonceH, 꼬리표 `swiftail-pairing-2`)는 받지 않는다. 쓰는 곳이 없었다.

주소는 그 연결의 두 끝이다(IPv4는 IPv4-mapped IPv6 16바이트). H와 프로세스 안 J는 `TailnetConnection`의 `localEndpoint`·`remoteEndpoint`, OS 소켓 J는 준비된 `NWConnection`의 로컬·원격 끝을 쓴다. tailnet 안에서는 주소가 바뀌지 않으므로 양쪽이 같은 네 값을 본다.

여는 쪽:

- P1. 연결을 받으면 먼저 `whoIs(원격 주소)`를 본다. 신원을 모르면 읽지 않고 닫는다.
- P2. 열린 제안이 없거나 만료됐으면 `hello`를 읽은 뒤 `challenge`를 상태 1로 보내고 닫는다.
- P3. nonceH는 연결마다 새로 뽑아 쥐고, `challenge`에는 그 약속 commitH만 싣는다. `proof`를 받으면 먼저 연 nonceJ가 약속과 맞는지 본다: `SHA256("swiftail-pairing-3 commit joiner" ‖ nonceJ) == commitJ`. 다르면 형식 위반으로 아무것도 보내지 않고 닫는다. 맞으면 P를 만들어 HMAC을 상수 시간으로 견준다. 틀리면 아무것도 보내지 않고 닫는다. 어느 쪽이든, 그리고 `proof`가 오지 않고 끊기거나 기한이 지나도, 제안은 그대로 두고 nonceH는 밝히지 않는다(비밀이 256비트라 시도로 맞힐 수 없고, 틀린 시도로 태우면 tailnet의 아무 피어나 제안을 못 쓰게 만들 수 있다).
- P4. 맞으면 그 자리에서 제안을 쓴 것으로 한다(한 번만 쓴다). 같은 비밀의 다른 연결은 그 뒤로 P2가 된다. 그 뒤에 nonceH를 열어 `accepted`를 보내고 앱의 결정을 기다린다. 확인 숫자는 여기서 처음 계산된다.
- P5. 앱의 결정은 `decide(PairingRequest) async -> Bool`이다. 요청에는 J의 `PeerIdentity`, 기기 이름, 확인 숫자가 있다. **기기 이름은 상대가 스스로 밝힌 값이다.** 같은 OAuth 클라이언트의 키로 들어온 노드들은 로그인 이름이 같으므로, 승인 화면은 확인 숫자를 보여 주고 사용자가 들어오는 기기 화면의 숫자와 같을 때 승인하게 한다. 120초 안에 답이 없으면 상태 3. `decide`는 취소되면 곧 돌아와야 한다(취소를 무시하면 그 연결은 닫히지만 `run()`이 끝나지 못한다).
- P6. 결정을 기다리는 동안 읽기를 걸어 둔다. EOF·오류·어떤 바이트든 오면 끊긴 것으로 보고 결정 Task를 취소한다. 그 사이 새 제안을 열거나 `closeOffer()`를 불러도 이 결정은 계속된다.
- P7. 승인이면, 그 순간의 `whoIs`가 처음과 같은 `StableID`일 때만 짝 목록에 넣고 저장한 뒤 상태 1을 보낸다. 저장에 실패하면 상태 2다. 상태 1을 보내기 전에 끊기면 H에는 짝이 남고 J에는 없다. 다시 짝을 맺으면 항목이 바뀐다(S1).
- P8. 한도: 절차 중인 연결 8개, 그 가운데 같은 노드(`StableID`)의 것은 2개(넘으면 받자마자 닫는다. 피어 하나가 자리를 모두 쥐고 있지 못한다), 연결을 받은 때부터 `proof`까지 10초, 메시지는 위 길이 그대로(넘거나 모자라면 닫는다). 자기 차례가 아닐 때 온 바이트는 위반이다. 기기 이름은 올바른 UTF-8이어야 하고 제어 문자(Cc)와 서식 문자(Cf, 방향 바꿈 포함)를 받지 않는다. 글자를 잇는 U+200C·U+200D만은 받는다(이은 이모지, 페르시아어·인도계 문자의 이름).
- P9. 제안은 한 번에 하나다. 새로 열면 앞의 것은 그 자리에서 못 쓴다. 수명은 기본 300초, 1~3600초. `openOffer`는 `run()` 전에도 된다(연결은 `run()`이 듣기 시작해야 받는다). 노드의 자기 FQDN이 없으면 `.notRunning`, `authKey`가 O2에 어긋나면 `.invalidAuthKey`.
- P10. 로그에는 요약만 남긴다(받음, 닫은 까닭, 결정). 비밀·증명·인증 키·확인 숫자·이름·주소는 남기지 않는다.
- P11. 짝 목록과 제안의 변화를 `events`로 알린다(2026-11-18, 샘플 앱이 `pairedPeers`를 주기적으로 다시 읽던 것을 없앤다). 사건에는 비밀(제안의 비밀과 링크)·증명·확인 숫자·인증 키를 싣지 않는다: 짝이 됐을 때는 그 `PairedPeer`, 지웠을 때는 `StableID`, 제안은 상태만이다. 읽지 않은 사건은 `TailnetNode.events`처럼 가장 새 것 64개까지만 쥐고 오래된 것부터 버린다. 짝 목록은 `run()` 밖에서도 바뀌므로 흐름은 `run()`과 함께 끝나지 않고 `PairingHost`가 사라질 때 끝난다. 만료는 `run()`의 자식(`expireOffers()`)이 열린 제안의 만료 시각에 깨어나 제안을 지우며 알린다(이미 쓸 수 없던 제안이라 절차는 그대로다). 새 제안을 열면 그 만료 시각으로 다시 잔다.

들어오는 쪽:

- J1. 첫 `challenge`를 받을 때까지 60초 동안 1초 간격으로 다시 건다. 방금 tailnet에 들어온 노드는 이름 풀이와 경로, 그리고 H의 netmap에 자기가 오르는 데 시간이 걸린다(그동안 H는 P1로 닫는다). 60초가 지나면 `.unreachable`.
- J2. OS 소켓: 앱이 이 기기의 tailnet 주소(`localAddress`, 터널 확장이 노드에서 읽은 값)를 넘긴다. 그 주소가 `100.64.0.0/10`이나 `fd7a:115c:a1e0::/48` 밖이면 걸지 않고 `.invalidConfiguration`. `NWConnection`으로 `host:port`에 건다(이름은 터널의 MagicDNS가 푼다). IP 판은 `localAddress`와 같은 것으로 고정하고, Wi-Fi·셀룰러·유선·루프백 인터페이스를 금지한다(`prohibitedInterfaceTypes`. 터널 인터페이스로만 나가게). 준비된 뒤 **로컬 끝의 주소가 `localAddress`와 다르거나** 원격 끝이 위 대역 밖이면 `hello`를 보내지 않고 `.notOnTailnet`(다시 걸지 않는다). 대역만 보면 터널이 꺼진 채 같은 대역(`100.64.0.0/10`은 통신사·공유기도 쓴다)을 쓰는 로컬 네트워크의 연결이 통과한다.
- J3. `challenge`의 상태 1이면 `.rejected`. `proof`를 보낸 뒤 `accepted` 없이 닫히면 `.rejected`.
- J4. `accepted`의 nonceH가 `challenge`의 약속과 맞는지 본다: `SHA256("swiftail-pairing-3 commit host" ‖ nonceH) == commitH`. 다르면 `.hostNotVerified`. 맞으면 T를 만들어 HMAC을 상수 시간으로 견준다. 틀리면 `.hostNotVerified`. 맞으면 `awaitingApproval(확인 숫자)`를 부르고 `decision`을 기다린다(`proof`를 보낸 때부터 130초, 넘으면 `.timedOut`). `accepted` 뒤에 `decision` 없이 닫히거나 다른 바이트가 오면 `.protocolViolation`.
- J5. `decision`의 HMAC을 상수 시간으로 견준다. 틀리면 `.hostNotVerified`. 상태는 1~3만, `StableID`는 1~255바이트의 인쇄 가능 ASCII, 표시 이름은 0~64바이트의 올바른 UTF-8이고 기기 이름과 같은 글자 규칙이다(P8). 어긋나면 `.protocolViolation`. 상태 2 → `.denied`, 3 → `.timedOut`.
- J6. 승인이면 `PairedHost`(`host`, `stableID`, `name`, `pairedAt`)를 돌려준다. 보관은 앱이 한다(`Codable`). 프로세스 안 노드로 들어왔으면 `decision`의 `StableID`가 `whoIs(원격 주소)`의 것과 같아야 한다. 다르면 `.hostNotVerified`.
- J7. 호출한 Task가 취소되면 연결을 끊고 `.cancelled`.

```swift
public actor PairingHost {
    /// 노드의 장치가 `.inProcess`가 아니거나 포트가 0이면 `.invalidConfiguration`, 목록을 읽지 못하거나 디렉터리가
    /// 다른 사용자의 것이거나 그룹·기타가 쓸 수 있으면 `.storeUnreadable`, 같은 디렉터리를 쓰는 호스트가 이 프로세스에
    /// 이미 있으면 `.storeInUse`.
    public init(node: TailnetNode, port: UInt16, storeDirectory: URL,
                decide: @escaping @Sendable (PairingRequest) async -> Bool) async throws(PairingError)
    /// 듣고 절차를 돌린다. 취소될 때까지 돌아오지 않는다.
    public func run() async throws(PairingError)
    public func openOffer(lifetime: Duration = .seconds(300), authKey: String? = nil) async throws(PairingError) -> PairingOffer
    public func closeOffer()
    public var pairedPeers: [PairedPeer] { get }
    public func pairedPeer(withStableID stableID: String) -> PairedPeer?
    public func removePairedPeer(withStableID stableID: String) throws(PairingError)
    /// 짝 목록과 제안의 변화(P11). 구독자는 하나, 읽지 않은 것은 가장 새 것 64개까지. 이 호스트가 사라질 때 끝난다.
    public nonisolated var events: AsyncStream<Event> { get }

    public enum Event: Sendable, Equatable {
        case pairedPeerAdded(PairedPeer)          // 저장한 뒤. 같은 노드가 다시 짝이 되어도 나온다(S1)
        case pairedPeerRemoved(stableID: String)  // removePairedPeer가 지우고 저장한 뒤. 없는 짝이면 나오지 않는다
        case offerChanged(OfferState)
    }
    public enum OfferState: Sendable, Equatable {
        case opened    // openOffer. 앞의 제안이 밀려난 것은 따로 알리지 않는다(P9)
        case used      // 맞는 proof로 쓰였다(P4). 그 연결의 decide보다 먼저 나온다
        case expired   // run() 동안 만료 시각에. run() 밖에서 지난 만료는 run()이 시작할 때
        case closed    // closeOffer가 열린 제안을 닫았다
    }
}

public struct PairingRequest: Sendable {
    public let peer: PeerIdentity
    public let deviceName: String
    public let confirmationCode: String   // 6자리
}

public enum PairingJoiner {
    /// 프로세스 안 노드로 들어온다.
    public static func pair(with offer: PairingOffer, deviceName: String, node: TailnetNode,
                            awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in })
        async throws(PairingError) -> PairedHost
    /// OS 소켓으로 들어온다(노드가 터널 확장에 있는 앱). 터널이 연결된 뒤에 부른다.
    /// `localAddress`는 이 기기의 tailnet 주소다(터널 확장이 노드에서 읽어 앱에 넘긴 값).
    public static func pair(with offer: PairingOffer, deviceName: String, localAddress: IPAddress,
                            awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in })
        async throws(PairingError) -> PairedHost
}

public enum PairingError: Error, Sendable, Equatable {
    case invalidConfiguration(String)   // 장치, 포트, 수명, 기기 이름, tailnet 대역 밖의 localAddress
    case invalidAuthKey
    case notRunning                     // 자기 FQDN이 아직 없다, 노드가 끝났다
    case storeUnreadable, storeInUse, storeWriteFailed
    case unreachable                    // 60초 안에 challenge를 받지 못했다
    case notOnTailnet
    case rejected                       // 열린 제안이 없다, 만료, 틀린 비밀
    case hostNotVerified
    case denied
    case timedOut
    case protocolViolation
    case cancelled
}
```

짝이 된 뒤의 연결은 앱이 가린다: 연결의 신원을 `whoIs`나 다리의 `Origin.peer`로 얻고 `pairedPeer(withStableID:)`에 묻는다.

## 6. 짝 목록

- S1. 항목은 `PairedPeer`(`peer: PeerIdentity`(짝을 맺을 때의 사본), `deviceName`, `pairedAt`)다. 열쇠는 `peer.stableID`다. 같은 노드가 다시 짝이 되면 항목을 바꾼다. 판정은 `StableID`로만 하고 이름은 표시용이다. 노드가 지워졌다 다시 등록되면 `StableID`가 바뀌어 짝이 아니게 된다.
- S2. `storeDirectory/paired-peers.json`에 둔다(`{"version":1,"peers":[…]}`). 바꿀 때마다 같은 디렉터리의 임시 파일에 쓰고 바꿔치기한다. 권한은 0600. 디렉터리는 지금 사용자의 것이고 그룹·기타가 쓸 수 없어야 한다(`SwiftailCertificates`의 `certs/`와 같은 규칙). 그 디렉터리에 쓸 수 있는 쪽은 파일을 바꿔치기해 짝을 더할 수 있다.
- S3. 파일이 없으면 빈 목록이다. 읽지 못하면 `init`이 `.storeUnreadable`을 던진다(빈 목록으로 덮어쓰지 않는다): JSON이 아님, 다른 `version`, 빈 `StableID`, 겹친 `StableID`, 256개 초과, 1MiB 초과. 모르는 필드는 넘긴다. `init`이 디렉터리를 만든 뒤 그 주인과 권한을 보고, S2에 어긋나면 파일을 읽지 않고 `.storeUnreadable`이다. 파일을 여는 기술자는 모두 `O_CLOEXEC`다.
- S4. 256개까지. 꽉 찼으면 새 짝은 거절(상태 2)이다. 이미 있는 `StableID`를 바꾸는 것은 된다.
- S5. 같은 디렉터리를 쓰는 `PairingHost`는 한 프로세스에 하나다(둘이면 한쪽이 지운 짝을 다른 쪽이 되살린다). 프로세스 사이는 막지 않는다. `init`이 디렉터리를 먼저 만들고(0700, 실패하면 `.storeWriteFailed`) 심볼릭 링크를 푼 경로로 견준다.

## 7. 시험과 관문

단위(`SwiftailPairingTests`):

1. 링크: 왕복, O2의 거절 하나하나(`%`, 겹친 키, 모르는 키, 감싼 키, 각 값의 경계), 가린 `description`·`dump`, 가장 긴 링크의 QR.
2. 절차 전체의 고정 벡터: 다른 구현(Go `crypto/hmac`·`crypto/sha256`로 쓴 `Tools/interop`의 도구)으로 뽑은 commitJ·commitH·`hello`·`challenge`·P·T·`proof`·`accepted`·확인 숫자·`decision` 바이트와 일치.
3. 여는 쪽 상태 기계: 정상, 틀린 증명(제안이 남고 nonceH가 나가지 않는지), 약속과 다른 nonceJ(닫히고 제안이 남는지. `hello`와 `challenge`가 오간 뒤에는 nonceJ를 바꿀 수 없다), `challenge`까지만 하고 끊기를 되풀이하는 연결(받는 것은 commitH뿐이고, 숫자를 보려고 `proof`를 내면 제안이 쓰인다), 판 1·2의 `hello`, 제안 없음·만료·바뀜, 한 번만 쓰임, 잘린·넘친 메시지, 차례 밖 바이트, 10초·120초, 한도 8과 같은 노드 2, 기기 이름의 Cc·Cf, 결정 대기 중 끊김(결정 Task 취소), 승인 때 `StableID`가 바뀜, 저장 실패.
4. 들어오는 쪽 상태 기계: `hello`에 nonceJ가 없음, 틀린 `accepted`, 약속과 다른 nonceH(HMAC이 맞아도 `.hostNotVerified`), 확인 숫자가 `accepted` 뒤에만 나옴, 틀린 `decision` HMAC, 모르는 상태·길이 넘침·잘못된 UTF-8, 130초, 취소, 주소가 다른 T(중간에 낀 경우)로 만든 증명이 서로 맞지 않는지, tailnet 대역 밖 주소, 로컬 끝이 `localAddress`와 다른 연결.
5. 짝 목록: 저장·다시 읽기, 다시 짝이 됨, S3의 경우 하나하나, 한도, 권한, 그룹·기타가 쓸 수 있는 디렉터리, 같은 디렉터리 둘.
6. QR: 만든 그림을 시스템 검출기로 다시 읽어 링크와 같은지, 여백.
7. 키 발급: 가짜 전송으로 요청의 모양(K1), 두 번째 방식, 응답·오류의 분류(K6), 검사(K4), 가림.

상호 운용 (가)(계정 없이, `SwiftailInteropTests`):

8. Go `CreateKeyWithExpiry`(+`clientcredentials`)와 Swift가 같은 기록 서버에 보낸 요청이 같다: 메서드, 경로, Basic 값, 본문. 서버가 Basic을 거절할 때의 두 번째 요청도.
9. 시험 제어 서버 위의 Swiftail 노드 둘: 제안 → 들어옴 → 승인 → 짝 목록, 그 뒤 연결의 신원으로 `pairedPeer(withStableID:)`이 답한다. 거절, 틀린 비밀, 만료, 다시 짝이 됨, 양쪽 확인 숫자가 같음.
10. 제안의 인증 키로 새 노드가 등록한 뒤 짝이 된다(J1의 다시 걸기 포함).
11. OS 소켓 쪽 들어오기: 루프백 리스너에 물린 여는 쪽 상태 기계와 왕복(대역 검사와 인터페이스 금지는 시험에서만 끈다. 로컬 끝과 `localAddress`의 대조는 켠 채로 둔다). 로컬 끝이 `localAddress`와 다르면 아무것도 보내지 않는다.

(가)가 보지 못하는 것: 시험 제어 서버의 인증 키에는 만료·1회용·태그 정책이 없다. 태그 노드의 `whoIs`(netmap에 그 사용자 프로필이 오는지)와 실제 서버의 Basic 수용 여부는 (나)에서 본다. 시험 11은 이름 풀이와 터널을 거치지 않고, 공개 API가 거는 인터페이스 금지도 거치지 않는다(루프백이 금지 대상이다).

(나) 실제(사용자의 OAuth 클라이언트가 필요하다):

12. 실제 관리 API로 키를 만들고, 그 키로 새 노드가 실제 tailnet에 들어와 짝이 된다. 태그 노드의 `whoIs`가 답하는지 본다.
13. iPhone 앱(터널 확장)에서 OS 소켓으로 짝 맺기. 첫 사용처를 옮길 때 본다(U3). 그때까지 OS 소켓 경로는 실제 터널에서 확인되지 않은 것이다.

## 8. 확인하지 못한 것

- 실제 관리 API가 Basic과 본문 방식 가운데 무엇을 받는지, 토큰 응답이 JSON인지(폼 형식은 읽지 않는다), `expires`의 형식, 수명의 상한(관문 12).
- iOS에서 사용자 지정 스킴이 겹칠 때의 배달, 연결 도메인으로 열 때 조각이 앱까지 오는지(관문 13).
- `CIQRCodeGenerator`가 둘레 여백을 넣는지(구현이 확인하고 없으면 더한다).
- OS 소켓 J의 `NWConnection` 로컬 끝이 터널의 tailnet 주소·포트와 같은지(관문 13). J2는 이것이 같다는 데 기대므로, 다르면 OS 소켓 길은 늘 `.notOnTailnet`이 된다.
- J2의 인터페이스 금지(`prohibitedInterfaceTypes`에 Wi-Fi·셀룰러·유선·루프백)가 iOS의 패킷 터널 인터페이스를 남기는지(관문 13). 확인한 것: 개발 Mac(macOS)에서 `NWPathMonitor`가 `utun` 인터페이스를 `other` 종류로 알리고, 루프백을 금지하면 `127.0.0.1`로 거는 연결이 서지 않는다(관문 11). 확인하지 못한 것: iOS에서 패킷 터널 확장의 인터페이스가 같은 종류로 잡히는지, 그 금지 아래에서 실제 터널로 연결이 서는지. `other`에는 utun 말고도 종류를 모르는 인터페이스(AWDL, 브리지 등)가 들어가므로 이 금지는 "터널만"이 아니라 "흔한 로컬 네트워크가 아닌 것"이다. 가리는 데는 로컬 끝과 `localAddress`의 대조가 함께 쓰인다.
- MagicDNS가 여는 쪽 이름에 IPv4와 IPv6 주소를 함께 답할 때, IP 판을 `localAddress`의 것으로 고정한 연결이 그 판의 주소로 서는지(관문 13).

## 9. 설계 검토 반영 (2026-11-17)

| 발견 | 반영 |
| --- | --- |
| 감싼 인증 키의 개인 키는 1회용이 아니다 | 링크에 싣지 않는다(O2 `.wrappedAuthKey`). lock tailnet의 흐름을 1절 한계에 적음 |
| 증명이 연결의 두 끝에 묶여 있지 않아 중간에 낀 노드가 넘겨줄 수 있고, `decision`이 인증되지 않는다 | T에 두 끝의 주소·포트, `decision`에 HMAC, OS 소켓의 대역 검사(J2) |
| 링크를 얻은 쪽이 먼저 들어오면 승인 화면에서 가릴 수 없다 | 확인 숫자(P5, J4) |
| 조각도 대체 페이지 스크립트와 브라우저 기록으로 샌다. 사용자 지정 스킴은 다른 앱이 받을 수 있다 | O1을 고치고 "앱이 지킬 것"에 적음 |
| `k`에 `&`·`%`가 들어갈 수 있고 `e`에 상한이 없다 | O2의 글자 집합과 자릿수, `%` 금지 |
| 키 발급이 Go와 어긋난다(`expirySeconds`, 두 번째 인증 방식, `CheckTag`, 2xx의 `error`) | K1·K3·K4·K6, 관문 8 |
| 여는 쪽은 `.inProcess`만 된다. 조회는 다리의 `Origin.peer`와 맞아야 한다 | 1절 한계, `pairedPeer(withStableID:)` |
| 가입 직후에는 한 번의 연결 시도가 쉽게 실패한다. 연결 실패와 거절이 한데 묶였다 | J1(60초 다시 걸기), `challenge`의 상태, `.unreachable`·`.rejected` |
| 시계가 `hello`부터면 말없는 연결이 남는다. 결정 대기 중 끊김을 알 길 | P8(받은 때부터 10초), P6 |
| 기기 이름의 방향 바꿈 문자 | Cf도 거절(P8) |
| 줄일 것 | `ephemeral`·`preauthorized` 매개변수, `IssuedAuthKey.id`, `init(url:)`, `moduleSize`, `Equatable`, `PairedHost.port`를 뺌 |

## 10. 코드 검토 (2026-11-17)

작성과 다른 세션이 구현 전체를 계약 항목별로 대조했다. 판정은 "이대로 공개해도 된다"이고 발견은 낮음 셋이었다.

| 발견 | 처리 |
| --- | --- |
| 디렉터리가 생기기 전후에 심볼릭 링크를 거친 경로의 열쇠가 달라 S5가 뚫린다(재현됨) | `init`이 디렉터리를 먼저 만든다. 시험을 더함 |
| `decide`가 취소를 무시하면 `run()`이 끝나지 못한다 | 문서 주석과 P5에 적음 |
| `url(base:)`가 만들기 실패를 `base`로 숨긴다 | `preconditionFailure` |

남긴 것: 가장자리 `PairingHost`의 10초 기한·한도 8·읽기 상한을 직접 보는 시험은 없다(상태 기계 시험과 관문 9가 간접으로 본다). U+2028·U+2029는 기기 이름에 들어간다. (피어 하나가 자리 8개를 막는 것과 노드의 `StateDirectoryClaims`는 11절에서 고쳤다.)

## 11. 보안 검증 (2026-11-17)

다른 세션이 구현을 읽고 재현해 낸 발견과 그 처리다. 절차의 바이트가 바뀌어 판이 2가 됐다(판 1은 받지 않는다. 쓰는 곳이 없었다).

| 발견 | 처리 |
| --- | --- |
| 확인 숫자가 두 nonce에서 나오는데, 뒤에 nonce를 고르는 쪽이 상대 값을 본 뒤 자기 값을 갈아 원하는 숫자를 맞출 수 있다(20비트) | nonce 약속(5절): `hello`에 commitJ, `proof`에서 nonceJ를 연다. T에 commitJ를 넣고 꼬리표를 `swiftail-pairing-2`로 바꿈. 고정 벡터를 다시 냄 |
| OS 소켓의 대역 검사는 터널이 꺼진 채 같은 대역을 쓰는 로컬 네트워크의 연결을 통과시킨다 | `localAddress`(공개 API), 로컬 끝과의 대조, IP 판 고정, 인터페이스 금지(J2). 실제 터널에서의 동작은 8절 |
| tailnet 피어 하나가 연결 8개를 계속 다시 열어 짝 맺기 자리를 막는다 | 같은 `StableID`의 절차 중 연결은 2개까지(P8) |
| 제안의 `host`에 IP 주소를 적을 수 있다 | 끝 라벨이 숫자뿐이면 `.invalidHost`(O2) |
| 짝 목록 디렉터리를 남이 쓸 수 있으면 파일을 바꿔치기해 짝을 더할 수 있다 | `init`이 주인과 권한을 본다(S2·S3) |
| 인증 키는 페어링과 묶여 있지 않다. 키가 실린 링크를 여는 것은 그 tailnet에 가입하는 일이다 | 3절 "앱이 지킬 것"과 `PairingOffer.authKey`·`openOffer`의 문서 주석 |

2차(같은 날, 위의 처리를 다른 세션이 다시 확인해 남은 것). 절차의 바이트가 다시 바뀌어 판이 3이 됐다(판 2도 받지 않는다. 쓰는 곳이 없었다).

| 발견 | 처리 |
| --- | --- |
| 판 2는 여는 쪽이 `challenge`에서 nonceH를 바로 밝힌다. 제안의 비밀을 아는 쪽은 `proof`를 내기 전에 확인 숫자를 계산하고, 원하는 숫자가 아니면 끊고 다시 걸기를 되풀이할 수 있다(끊은 시도는 제안을 쓰지 않고 세는 것도 없다) | 여는 쪽도 nonce를 약속한다(5절): `challenge`에 commitH, 맞는 `proof` 뒤 `accepted`에서 nonceH. `proof`는 P에, 나머지는 T = P ‖ nonceH에 매긴다. 꼬리표를 `swiftail-pairing-3`으로 바꾸고 두 약속의 꼬리표를 가름. 고정 벡터를 다시 냄 |
| 제안의 `host`에서 끝 라벨이 숫자뿐인 것만 거절해 16진 꼴 IPv4(`192.168.1.0x1`, `1.0x7f`)가 통과한다 | 끝 라벨은 글자로 시작해야 한다(O2) |
