# PairingDemo

`SwiftailPairing`(앱끼리의 QR·링크 페어링)과 `Swiftail`의 `TailnetNode`를 Mac과 iPhone에서 돌려 보는 SwiftUI 앱이다. 한 기기가 제안을 열고(여는 쪽), 다른 기기가 그 QR이나 링크를 읽어 짝이 된다(들어오는 쪽). 두 역할은 양쪽 플랫폼에서 모두 고를 수 있고, 노드는 앱 프로세스 안에서 돈다.

## 만들기

`xcodegen` 2.46 이상과 macOS 15·iOS 18 이상을 빌드할 수 있는 Xcode가 필요하다.

```sh
cd Examples/PairingDemo
xcodegen generate
open PairingDemo.xcodeproj
```

스킴 `PairingDemo`를 "My Mac"이나 iPhone(시뮬레이터 포함)으로 실행한다.

iPhone 실기기에 설치하려면 `Config/Signing.local.xcconfig.example`을 `Config/Signing.local.xcconfig`로 복사해 개발 팀 ID와, 그 팀이 쓸 수 있는 번들 ID 앞부분을 넣는다. 이 파일은 저장소에 올라가지 않는다. Mac 앱은 기본이 임시 서명이고 App Sandbox(네트워크 클라이언트·서버)가 켜져 있다.

## 노드 시작

"노드" 칸에서 시작한다. 길은 셋이다.

| 길 | 하는 일 |
| --- | --- |
| 저장된 신원 | 전에 등록한 기기는 앱을 띄우면 스스로 이어진다 |
| 인증 키 | 키를 넣고 "노드 시작". 키는 저장하지 않는다 |
| 로그인 | 키 없이 "노드 시작" → "브라우저에서 로그인" |

상태가 "연결됨"이 되면 자기 이름, 피어 수, tailnet lock의 모습이 보인다.

## 두 기기로 짝 맺기

두 기기가 같은 tailnet에 있어야 한다. 들어오는 쪽이 아직 tailnet에 없으면 아래 "인증 키 싣기"를 쓴다.

1. 여는 쪽: 역할을 "여는 쪽"으로 두고 노드를 시작한다. "연결됨"이 되면 수명을 고르고 "제안 열기"를 누른다. QR과 링크가 나온다.
2. 들어오는 쪽: 역할을 "들어오는 쪽"으로 두고 제안을 받는다. iPhone은 "QR 코드 읽기"가 가장 안전하다. 링크를 받았으면 붙여 넣고 "링크 읽기"를 누르거나, 링크를 열어 앱으로 넘긴다.
3. 들어오는 쪽: "받은 제안"의 여는 쪽 이름이 짝을 맺으려던 기기인지 보고 "짝 맺기"를 누른다. 화면에 확인 숫자 6자리가 나온다.
4. 여는 쪽: 승인 화면의 숫자가 들어오는 기기 화면의 숫자와 같을 때만 "승인"을 누른다. 기기 이름은 상대가 스스로 밝힌 값이라 이름만으로 판단하지 않는다.
5. 들어오는 쪽: "연결 확인"을 누르면 여는 쪽이 짝에게만 돌려주는 인사 한 줄이 온다.

여는 쪽 "짝 목록"에서 짝을 지우면 그 기기의 "연결 확인"은 거절된다. 제안은 한 번만 쓰인다. 다시 짝을 맺으려면 새 제안을 연다.

짝 맺기는 포트 4747, 인사는 포트 4748을 쓴다. tailnet 정책(ACL)이 들어오는 기기에서 여는 기기의 두 포트로 가는 연결을 허용해야 한다.

제안의 QR과 링크는 비밀이다. 짝을 맺을 기기에만 보여 준다. 이 앱의 링크는 사용자 지정 스킴(`swiftail-demo://`)이라 같은 스킴을 선언한 다른 앱이 받을 수 있다. 인증 키를 실은 제안은 QR로 건넨다.

### 인증 키 싣기

들어오는 기기가 로그인 없이 tailnet에 들어오게 하려면 여는 쪽에서 "인증 키 싣기"를 켠다. Tailscale 관리 콘솔에서 만든 OAuth 클라이언트(`auth_keys` 쓰기 권한, 태그 하나 이상)의 ID, 비밀값, 태그를 넣고 "키체인에 저장"을 누른 뒤 제안을 연다. 제안마다 그 수명과 같은 1회용 키가 만들어진다. 이 키로 들어온 기기는 태그 노드가 된다.

들어오는 기기가 이미 tailnet에 있으면 제안의 키는 쓰이지 않는다.

## tailnet lock이 켜진 tailnet

인증 키로 들어온 노드는 서명되기 전까지 잠겨 있고, 잠긴 노드는 짝이 되지 못한다.

1. 여는 쪽에서 제안의 수명을 서명에 걸릴 시간보다 길게(15분이나 60분) 연다.
2. 들어오는 쪽에서 "짝 맺기"를 누른다. 노드는 "연결됨"이 되지만 "tailnet lock"이 "켜짐 · 서명을 기다림"이고, 60초 뒤 "여는 쪽에 닿지 못했습니다"로 끝난다.
3. "노드" 칸의 `tailscale lock sign …` 명령을 복사해 tailnet의 서명 기기에서 실행한다.
4. "tailnet lock"이 "켜짐 · 이 노드 서명됨"으로 바뀌면 "받은 제안"의 "짝 맺기"를 다시 누른다. 같은 제안이 그대로 쓰인다.

## 기록

단계마다의 사건이 화면의 "기록"과 `events.jsonl`(한 줄에 사건 하나: 시각, 역할, 사건 이름, 결과)에 남는다. 링크, 인증 키, OAuth 비밀값, 로그인 URL, 확인 숫자는 남지 않는다.

| 플랫폼 | 자리 |
| --- | --- |
| Mac | `~/Library/Containers/<번들 ID>/Data/Library/Application Support/<번들 ID>/events.jsonl` |
| iPhone | 앱 컨테이너의 `Library/Application Support/<번들 ID>/events.jsonl` |

## 자동화 모드

사람 손 없이 돌려 보는 검증용이다. 실행 인자 `--automation`과 루프백 제어 서버 `--control-url=http://127.0.0.1:<포트>`가 함께 있어야 켜지고, 켜지면 화면 맨 위에 "자동화 모드"가 보인다. 제어 서버는 `Tools/interop`의 `tailnet` 도구가 띄우는 시험 서버를 쓴다(`Tools/interop/README.md`).

| 인자 | 하는 일 |
| --- | --- |
| `--role=host` · `--role=joiner` | 시작할 역할 |
| `--auth-key=<키>` | 앱이 뜰 때 이 키로 노드를 등록한다. 여는 쪽이 `--open-offer`로 여는 제안에도 싣는다 |
| `--open-offer` | 노드가 연결되면 제안을 연다(수명 5분) |
| `--auto-approve` | 승인 화면 없이 승인한다 |
| `--write-offer-link` | 연 제안의 링크를 `events.jsonl` 옆의 `offer-link.txt`에 쓴다 |
| `--log-confirmation-code` | 확인 숫자를 기록에 남긴다 |

```sh
# 시험 서버가 인증 키를 요구하게 한 뒤(setAuth), Mac 앱을 여는 쪽으로 띄운다.
open -n <빌드한 PairingDemo.app> --args --automation --control-url=http://127.0.0.1:<포트> \
  --role=host --auth-key=tskey-auth-EXAMPLE --open-offer --auto-approve --write-offer-link --log-confirmation-code
```

들어오는 쪽은 같은 `--automation --control-url=… --role=joiner`로 띄우고 `offer-link.txt`의 링크를 연다.

시험 서버는 `setAuth`를 건 뒤로 모든 등록 요청에 키를 요구한다. 그래서 그 서버에서는 저장된 신원으로 다시 띄운 노드가 "등록이 거절됐습니다"로 끝난다. 앱을 다시 띄워 신원과 짝이 남는지 볼 때는 `setAuth` 없이 띄운 시험 서버를 쓴다.
