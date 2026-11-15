# Tailnet Lock(TKA) 보통 노드 노트

## 1. 머리말

| 항목 | 내용 |
| --- | --- |
| 기준 버전 | `tailscale.com` **v1.104.7**(CapabilityVersion 148, `tailscale.com/tailcfg/tailcfg.go:200`)을 읽었다. README 기준 버전 v1.104.6과는 `VERSION.txt`·`go.mod`·toolchain 파일·`k8s-operator/api-proxy/proxy{,_test}.go`·`flakehashes.json`의 8개 파일만 다르다(`diff -rq`로 확인). 이 노트가 인용한 파일은 두 버전에서 같으므로 줄 번호도 같다 |
| 의존 모듈 | `github.com/fxamacker/cbor/v2` v2.9.3, `github.com/hdevalence/ed25519consensus` v0.2.0, `golang.org/x/crypto` v0.58.0(`tailscale.com/go.mod:51`, `:80`, `:139`). Go 표준 라이브러리는 Go 1.27.3의 `src/` |
| 쓰는 마일스톤 | M8 ① Tailnet Lock(`docs/plan.md` 3절, 마일스톤 표 M8) |
| 작성 모델 | Claude Opus 5.5 (`claude-opus-5-5`), 2026-11-15 |
| 검증 | 아직 |

출처는 모듈 루트 기준 `경로:줄`이다. 모듈 접두는 `tailscale.com/`, `cbor/`(= `fxamacker/cbor/v2@v2.9.3/`), `ed25519consensus/`, `x/crypto/`(= `golang.org/x/crypto@v0.58.0/`), `go/src/`(Go 1.27.3)로 줄인다. Swiftail 저장소 파일은 `Sources/...`로 적는다. 실행해서 확인한 것은 8.1에 명령과 함께 적었다. 예시 값은 가짜이거나 Go 시험 파일에 있는 시험용 값이다.

## 2. 범위

다루는 것(서명 기기가 아닌 보통 노드)

- 자료 형식: `AUM`, `Key`, `tkatype.Signature`, `State`, `NodeKeySignature`(NKS)의 CBOR 바이트 형식, 해시·서명 입력, 텍스트 표기.
- CBOR: Go가 쓰는 인코딩·디코딩 옵션과 그것이 뜻하는 바이트 규칙, Swiftail에 필요한 부분집합.
- 검증: AUM 받아들이기, 상태 적용, 갈래(fork) 해소와 머리(head) 선택, NKS 검증(direct·rotation·credential), 끄기 비밀 검증.
- 클라이언트 절차: NL 키, 등록(서명된 인증 키, 서버의 재서명 요청), netmap 처리(부트스트랩·동기화·끄기), 피어 거르기, 로컬 저장, capability 조건.
- 이 결과물을 확인할 상호 운용 시험의 재료.

다루지 않는 것(서명 기기·관리 기능. 그 결과물을 검증하는 규칙만 위에서 다룬다)

- 다른 노드에 서명(`TailnetLockSign`, `/machine/tka/sign`), lock 켜기(`/machine/tka/init/begin`·`/init/finish`), 끄기 명령(`/machine/tka/disable`), 서명 키 더하기·빼기(`TailnetLockModify`, `UpdateBuilder`), 인증 키 감싸기(`TailnetLockWrapPreauthKey`), 복구 AUM(`MakeRetroactiveRevocation`, `revoke-keys`), 서명 딥링크(`tka/deeplink.go`), 영향받는 서명 조회(`/machine/tka/affected-sigs`), 로컬 강제 끄기(`TailnetLockForceLocalDisable`)(`tailscale.com/ipn/ipnlocal/tailnet-lock.go:696-1300`, `tailscale.com/tka/builder.go:36-187`, `tailscale.com/tka/tka.go:750-860`).
- c2n `/debug/tka/log`(`tailscale.com/feature/tailnetlock/tailnetlock.go:21-26`). tsnet은 `feature/condregister`를 들이지 않는다(`tailscale.com/tsnet/tsnet.go:181-185`).
- Go 상태 파일 이관(사용자 결정: 하지 않음).

## 3. 와이어 형식

### 3.1 CBOR 규칙

**인코딩.** `AUM.Serialize`·`NodeKeySignature.Serialize`·tailchonk 파일은 모두 `cbor.CTAP2EncOptions()`로 인코딩한다(`tailscale.com/tka/aum.go:249-260`, `tailscale.com/tka/sig.go:219-232`, `tailscale.com/tka/tailchonk.go:733-742`). 이 옵션은 다음을 뜻한다(`cbor/encode.go:641-660`, `cbor/encode.go:183-202`).

| 규칙 | 내용 | 출처 |
| --- | --- | --- |
| 정수·길이 | 가장 짧은 인코딩(RFC 8949 3장의 인자 규칙: 0~23은 첫 바이트, 그 위는 1·2·4·8바이트 빅엔디언) | `cbor/encode.go:644-646` |
| 맵 키 순서 | 인코딩된 키 바이트의 사전순(`SortBytewiseLexical`). 정수 키 1~23은 한 바이트라 숫자순과 같고, 문자열 키는 머리 바이트가 길이를 담으므로 결과적으로 짧은 것이 먼저다(Go 실행: `{"bb","a","c"}` → `a`,`c`,`bb` 순, 8.1) | `cbor/encode.go:183-187`, `cbor/encode.go:1393-1394` |
| 길이 미정 | 금지 | `cbor/encode.go:657` |
| 태그 | 금지 | `cbor/encode.go:658` |
| 실수 | 바꾸지 않음. TKA 구조에는 실수 필드가 없다("No floats!") | `cbor/encode.go:654`, `tailscale.com/tka/aum.go:131` |

구조체 필드는 `cbor:"N,keyasint"` 태그로 **정수 키 맵**이 된다. `omitempty`가 없는 필드의 Go `nil`(슬라이스·포인터)은 CBOR null(`0xf6`)로, 길이 0인 non-nil 슬라이스는 빈 바이트열(`0x40`)·빈 배열(`0x80`)로 나간다. 둘은 해시가 다르다(`tailscale.com/tka/aum_test.go:26-44`, `tailscale.com/tka/key.go:56-57`, Go 실행 8.1: `PrevAUMHash=[]byte{}` → `a201030240`). `omitempty` 필드는 nil 포인터, 길이 0 슬라이스·맵, 0 정수일 때 빠진다. 포인터가 가리키는 0은 빠지지 않는다(Go 실행: `Votes=&0` → `0600`이 남고 빈 `Meta={}`는 빠진다, 8.1).

**디코딩.** `cborDecOpts`(`tailscale.com/tka/tka.go:22-32`)로 디코딩한다. AUM·NKS·tailchonk 파일 모두 같다(`tailscale.com/tka/aum.go:268-271`, `tailscale.com/tka/sig.go:239-242`, `tailscale.com/tka/tailchonk.go:466-474`).

| 규칙 | Go의 동작 | 출처 |
| --- | --- | --- |
| 중복 맵 키 | 거절(`DupMapKeyEnforcedAPF`). 구조체 맵의 모르는 키가 겹쳐도, `Meta`의 문자열 키가 겹쳐도 거절. 다만 모르는 필드의 **값 안쪽** 맵의 중복은 거절하지 않았다 | `tailscale.com/tka/tka.go:24`, `cbor/decode.go:313-319`, Go 실행 8.1 |
| 길이 미정 | 거절 | `tailscale.com/tka/tka.go:25` |
| 태그 | 거절 | `tailscale.com/tka/tka.go:26` |
| 중첩 | 최대 16단(맨 바깥 맵이 1단). 17단이면 거절 | `tailscale.com/tka/tka.go:29`, Go 실행 8.1 |
| 배열 원소 | 최대 4096개 | `tailscale.com/tka/tka.go:30`, Go 실행 8.1 |
| 맵 쌍 | 최대 1024쌍 | `tailscale.com/tka/tka.go:31`, Go 실행 8.1 |
| 뒤에 남은 바이트 | 거절(`extraneous data`) | Go 실행 8.1 |
| 모르는 필드 | 조용히 버린다(`ExtraDecErrorNone`가 기본). 값은 실수·음수·true·undefined·잘못된 UTF-8 문자열이어도 잘 짜인(well-formed) 항목이면 건너뛴다 | `cbor/decode.go:437-446`, Go 실행 8.1 |
| 정수 키가 아닌 키 | 예: 텍스트 키 `"1"`은 필드에 맞지 않아 모르는 필드로 버린다 | Go 실행 8.1 |
| 비최단 정수, 정렬 안 된 키 | **받아들인다**(정준 형식을 강제하지 않는다) | Go 실행 8.1 |
| 알려진 필드의 타입 불일치 | 거절(음수·실수·텍스트를 `uint8`·`[]byte`에, 정수를 `Meta` 값에) | Go 실행 8.1 |
| 범위 초과 | `MessageKind` 256은 `uint8` 넘침으로 거절 | Go 실행 8.1 |
| null | 알려진 정수 필드의 null은 0이 된다(예: `MessageKind` null → 0) | Go 실행 8.1 |
| 알려진 텍스트 | 잘못된 UTF-8 거절(`UTF8RejectInvalid`가 기본) | `cbor/decode.go:456-459`, `cbor/decode.go:2317-2318`, Go 실행 8.1 |
| 맨 바깥이 맵이 아님 | 거절 | Go 실행 8.1 |

**해시는 받은 바이트가 아니라 디코딩한 값을 다시 인코딩한 바이트로 계산한다.** `AUM.Hash`·`SigHash`, `NodeKeySignature.SigHash`가 모두 구조체를 `Serialize`해서 BLAKE2s를 씌운다(`tailscale.com/tka/aum.go:274-288`, `tailscale.com/tka/sig.go:208-212`). 그래서 모르는 필드·비최단 정수·정렬 안 된 키가 섞인 입력은 받아들여지되, 해시는 그것들이 정리된 정준 인코딩의 해시다(Go 실행 8.1: 정준 입력은 `hash == blake2s(원본)`, 그렇지 않은 입력은 다름). 서명도 다시 인코딩한 바이트의 해시 위에서 검증되므로 모르는 필드는 서명으로 보호되지 않는다.

### 3.2 `Key`

`Key`는 정수 키 맵이다(`tailscale.com/tka/key.go:36-52`).

| CBOR 키 | 필드 | 타입 | 규칙 |
| ---: | --- | --- | --- |
| 1 | `Kind` | uint (`KeyKind`, uint8) | 0 `KeyInvalid`, 1 `Key25519`. 그 밖은 `StaticValidate`가 거절(`tailscale.com/tka/key.go:15-22`, `:128-132`) |
| 2 | `Votes` | uint | 1 이상 4096 이하(`tailscale.com/tka/key.go:107-113`) |
| 3 | `Public` | bstr | Ed25519 공개 키 32바이트. 길이는 `StaticValidate`가 보지 않고 서명 검증 때 32가 아니면 실패한다(`tailscale.com/tka/verify.go:25-27`, `tailscale.com/tka/sig.go:297-299`) |
| 12 | `Meta` | map(tstr→tstr), omitempty | 모든 키·값 길이 합이 512바이트 이하(`tailscale.com/tka/key.go:120-126`, `tailscale.com/tka/limits.go:18`) |

KeyID: `Key25519`는 `Public` 바이트열 자체가 KeyID다(`tailscale.com/tka/key.go:84-94`, `tailscale.com/types/key/nl.go:87-99`). `tkatype.KeyID`는 `[]byte`다(`tailscale.com/types/tkatype/tkatype.go:10-19`).

### 3.3 `tkatype.Signature`(AUM의 서명)

| CBOR 키 | 필드 | 타입 | 규칙 |
| ---: | --- | --- | --- |
| 1 | `KeyID` | bstr | 32바이트(`AUM.StaticValidate`) |
| 2 | `Signature` | bstr | 64바이트 Ed25519 서명 |

출처: `tailscale.com/types/tkatype/tkatype.go:35-40`, `tailscale.com/tka/aum.go:168-172`.

### 3.4 `AUM`

`AUM`은 정수 키 맵이다(`tailscale.com/tka/aum.go:132-156`).

| CBOR 키 | 필드 | 타입 | 비고 |
| ---: | --- | --- | --- |
| 1 | `MessageKind` | uint (`AUMKind`, uint8) | omitempty 없음 |
| 2 | `PrevAUMHash` | bstr 또는 null | omitempty 없음. 부모 없음(genesis)은 **nil=null**이어야 한다. 길이 0 bstr은 `StaticValidate`가 거절(`tailscale.com/tka/aum.go:165-167`). 길이는 `StaticValidate`가 보지 않는다. `Parent()`는 32바이트 칸에 앞에서부터 복사하지만(`tailscale.com/tka/aum.go:292-298`) 상태 적용은 `LastAUMHash` 32바이트와 `PrevAUMHash` 전체를 바이트 비교하므로 길이가 다르면 적용에서 실패한다(`tailscale.com/tka/state.go:150-155`) |
| 3 | `Key` | `Key` 맵, omitempty | AddKey |
| 4 | `KeyID` | bstr, omitempty | RemoveKey·UpdateKey. 길이 검사 없음 |
| 5 | `State` | `State` 맵, omitempty | Checkpoint |
| 6 | `Votes` | uint, omitempty(포인터) | UpdateKey |
| 7 | `Meta` | map(tstr→tstr), omitempty | UpdateKey |
| 23 | `Signatures` | 배열(`Signature` 맵), omitempty | 서명. 23은 한 바이트로 쓸 수 있는 마지막 키다 |

`MessageKind` 값과 종류별로 허용되는 필드(`tailscale.com/tka/aum.go:69-94`, `:180-222`):

| 값 | 이름 | 반드시 | 허용 안 함 |
| ---: | --- | --- | --- |
| 0 | `AUMInvalid` | — | 검사 없음(default 갈래) |
| 1 | `AUMAddKey` | `Key` | `KeyID`, `State`, `Votes`, `Meta` |
| 2 | `AUMRemoveKey` | `KeyID`(길이>0) | `Key`, `State`, `Votes`, `Meta` |
| 3 | `AUMNoOp` | — | 검사 없음 |
| 4 | `AUMUpdateKey` | `KeyID`(길이>0), `Votes`나 `Meta` 가운데 하나 이상(nil이 아님) | `Key`, `State` |
| 5 | `AUMCheckpoint` | `State` | `KeyID`, `Key`, `Votes`, `Meta` |
| 6 이상 | 모르는 종류 | — | 검사 없이 받아들인다. "옛 클라이언트는 무시해도 안전"이라는 계약(`tailscale.com/tka/aum.go:213-222`) |

`StaticValidate`는 종류와 관계없이 `Key`가 있으면 `Key.StaticValidate`, 모든 서명의 KeyID 32바이트·서명 64바이트, `State`가 있으면 체크포인트 상태 검사를 한다(`tailscale.com/tka/aum.go:159-178`). 빈 맵 `Meta`(`0xa0`)는 non-nil이라 UpdateKey 검사를 통과하지만 다시 인코딩하면 빠진다(Go 실행 8.1).

### 3.5 `State`

| CBOR 키 | 필드 | 타입 | 비고 |
| ---: | --- | --- | --- |
| 1 | `LastAUMHash` | bstr(32) 또는 null | omitempty 없음. 체크포인트 안의 상태는 반드시 null(`tailscale.com/tka/state.go:259-261`) |
| 2 | `DisablementValues` | 배열(bstr) 또는 null | omitempty 없음 |
| 3 | `Keys` | 배열(`Key`) 또는 null | omitempty 없음 |
| 4 | `StateID1` | uint64, omitempty | lock을 켤 때 16바이트 난수의 앞 8바이트(little-endian), 수명 동안 고정 |
| 5 | `StateID2` | uint64, omitempty | 뒤 8바이트 |

출처: `tailscale.com/tka/state.go:26-53`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:720-734`. Go 실행 8.1: `StateID1=2^40`은 `041b0000010000000000`.

체크포인트 상태의 정적 검사(`staticValidateCheckpoint`, `tailscale.com/tka/state.go:258-316`): `LastAUMHash` nil, `DisablementValues` 1~32개·각 32바이트·서로 다름, `Keys` 1~512개·각 `Key.StaticValidate`·KeyID 서로 다름.

### 3.6 `NodeKeySignature`(NKS)

정수 키 맵이다(`tailscale.com/tka/sig.go:74-104`). `Node.KeySignature`, `RegisterRequest/Response.NodeKeySignature`, `PeerChange.KeySignature`의 바이트가 이것이다(`tailscale.com/types/tkatype/tkatype.go:21-22`).

| CBOR 키 | 필드 | 타입 | 쓰임 |
| ---: | --- | --- | --- |
| 1 | `SigKind` | uint (uint8) | 아래 표 |
| 2 | `Pubkey` | bstr, omitempty | 허가되는 node 공개 키의 **이진 형식**: `"np"`(2바이트) + 32바이트 = 34바이트(`tailscale.com/types/key/node.go:40`, `:350-369`). credential은 쓰지 않는다 |
| 3 | `KeyID` | bstr, omitempty | direct·credential만. 신뢰 키의 KeyID |
| 4 | `Signature` | bstr, omitempty | 64바이트 Ed25519 서명 |
| 5 | `Nested` | NKS 맵, omitempty | rotation만 |
| 6 | `WrappingPubkey` | bstr, omitempty | 이 서명을 감싸는 서명에 서명할 Ed25519 공개 키(32바이트). 여러 단 rotation의 중간은 생략할 수 있고 그러면 안쪽 것을 쓴다 |

`SigKind`(`tailscale.com/tka/sig.go:26-55`):

| 값 | 이름 | 뜻 |
| ---: | --- | --- |
| 0 | `SigInvalid` | — |
| 1 | `SigDirect` | 신뢰 키(`KeyID`)가 node 키(`Pubkey`)에 직접 서명 |
| 2 | `SigRotation` | `Nested`가 허가한 회전 키(`Nested`의 `WrappingPubkey`)가 새 node 키(`Pubkey`)에 서명 |
| 3 | `SigCredential` | 신뢰 키(`KeyID`)가 다른 공개 키(`WrappingPubkey`)에 서명 권한을 위임. 혼자서는 노드를 허가하지 못하고 rotation 안에 들어간다 |

### 3.7 해시와 서명 입력

| 값 | 계산 | 출처 |
| --- | --- | --- |
| `AUMHash` | `BLAKE2s-256(Serialize(aum))`. 키 없음, 출력 32바이트. 서명(23)을 **포함**한다 | `tailscale.com/tka/aum.go:21-22`, `:273-276` |
| AUM `SigHash` | `Signatures`를 nil로 지운 복사본의 `BLAKE2s-256(Serialize)`. 23번 키가 통째로 빠진다 | `tailscale.com/tka/aum.go:278-288` |
| AUM 서명 | `Ed25519.Sign(priv, SigHash 32바이트)`(순수 Ed25519, 문맥 없음) | `tailscale.com/tka/aum.go:300-314`, `tailscale.com/types/key/nl.go:102-107` |
| NKS `SigHash` | `Signature`를 nil로 지운 복사본의 `BLAKE2s-256(Serialize)`. `Nested`는 그대로 포함 | `tailscale.com/tka/sig.go:202-212` |
| NKS 서명 | `Ed25519.Sign(priv, SigHash 32바이트)` | `tailscale.com/types/key/nl.go:109-112`, `tailscale.com/tka/sig.go:450-459` |

Ed25519 **검증 함수가 경우마다 다르다**: AUM 서명과 direct·credential NKS는 `ed25519consensus.Verify`(ZIP-215 규칙)로, rotation NKS의 바깥 서명은 Go 표준 `ed25519.Verify`로 검증한다(`tailscale.com/tka/verify.go:28`, `tailscale.com/tka/sig.go:273`, `:300`). 두 규칙의 차이는 6.1에 적는다.

### 3.8 텍스트 표기

| 표기 | 형식 | 출처 |
| --- | --- | --- |
| `AUMHash` 텍스트 | RFC 4648 base32 **표준 알파벳(대문자), 패딩 없음**, 32바이트 → 52자. 소문자는 거절. 52자가 아니면 거절. 마지막 글자의 남는 4비트는 검사하지 않는다(Go 실행 8.1: 끝 글자 `A`·`B`·`P`가 같은 해시). 그래서 두 머리를 견줄 때는 문자열이 아니라 디코딩한 32바이트로 견줘야 Go와 같다 | `tailscale.com/tka/aum.go:24-51`, Go 실행 8.1 |
| `nlpub:` | NL 공개 키 32바이트의 소문자 16진. 디코딩은 `nlpub:`과 CLI용 `tlpub:` 둘 다 받는다 | `tailscale.com/types/key/nl.go:15-30`, `:133-157`, `tailscale.com/types/key/util.go:56-85` |
| `nlpriv:` | NL 개인 키 **64바이트**(Go `ed25519.PrivateKey` = 시드 32 ‖ 공개 32)의 16진 | `tailscale.com/types/key/nl.go:34-37`, `:59-67` |
| `nodekey:` | node 공개 키 32바이트의 16진(JSON). NKS 안에서는 3.6의 `np` 이진 형식 | `tailscale.com/types/key/node.go:40`, `:350-369` |
| 서명된 인증 키 | `<인증 키>--TL<A>-<B>`. 첫 `--TL`에서 자르고 나머지를 첫 `-`에서 자른다. A = credential NKS의 CBOR, B = 64바이트 Ed25519 개인 키, 둘 다 **base64 RawStd(패딩 없음, `+/`)** | `tailscale.com/tka/sig.go:462-498`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:1226`, `:1234-1258` |

Go의 `DecodeWrappedAuthkey`는 `-`가 없거나 base64·CBOR 디코딩이 실패하면 로그만 남기고 **원래 문자열 전체**(접미사 포함)를 인증 키로 돌려준다(`tailscale.com/tka/sig.go:472-494`). 그러면 개인 키가 든 접미사가 서버로 간다. Swiftail은 지금 `--TL` 앞부분만 늘 보낸다(`Sources/SwiftailControl/Client/AuthKey.swift:10-13`). 이것은 의도된 차이로 두는 것이 안전하다.

### 3.9 제어 프로토콜의 TKA 필드(JSON)

| 메시지 | 필드 | 형식과 뜻 | 출처 |
| --- | --- | --- | --- |
| `RegisterRequest` | `NLKey` | `nlpub:` 텍스트. Go는 늘 0이 아닌 키를 싣는다 | `tailscale.com/tailcfg/tailcfg.go:1330`, `tailscale.com/control/controlclient/direct.go:721-725`, `:763` |
| `RegisterRequest` | `NodeKeySignature` | NKS CBOR의 base64(JSON `[]byte`). 없으면 null | `tailscale.com/tailcfg/tailcfg.go:1345-1350` |
| `RegisterResponse` | `NodeKeySignature` | 있으면 "지금 서명을 새 node 키에 다시 서명하라" | `tailscale.com/tailcfg/tailcfg.go:1379-1381` |
| `MapRequest` | `TKAHead` | 로컬 머리의 base32 텍스트, lock이 없으면 빈 문자열(omitzero) | `tailscale.com/tailcfg/tailcfg.go:1500-1503`, `tailscale.com/control/controlclient/direct.go:1103` |
| `MapResponse` | `TKAInfo` | `{"Head": base32, "Disabled": bool}`, 둘 다 omitempty. 첫 응답의 nil = lock 꺼짐, 그 뒤의 nil = 변화 없음 | `tailscale.com/tailcfg/tailcfg.go:2179-2187`, `tailscale.com/tailcfg/tka.go:85-102` |
| `Node` | `KeySignature` | 그 노드의 NKS(omitempty) | `tailscale.com/tailcfg/tailcfg.go:388-390` |
| `Node` | `UnsignedPeerAPIOnly` | 서명 없이 PeerAPI만 허용되는 노드. TKA 거르기에서 빠진다 | `tailscale.com/tailcfg/tailcfg.go:488-494` |
| `PeerChange` | `KeySignature` | 서명이 바뀜 | `tailscale.com/tailcfg/tailcfg.go:3055-3057` |

capability 버전 이력: 40 `Node.KeySignature`·`PeersChangedPatch.KeySignature`, 47 `Register{Request,Response}.NodeKeySignature`, 48 `Node.UnsignedPeerAPIOnly`, 51 `CapabilityTailnetLockAlpha`, 64 이름이 `CapabilityTailnetLock`로 바뀜(`tailscale.com/tailcfg/tailcfg.go:91`, `:98-99`, `:102`, `:115`). node capability 문자열은 `https://tailscale.com/cap/tailnet-lock`이다(`tailscale.com/tailcfg/nodecap/nodecap.go:74-75`, `tailscale.com/tailcfg/tailcfg.go:2513`).

### 3.10 TKA RPC(보통 노드가 쓰는 셋)

세 RPC 모두 Noise 채널(ts2021 HTTP/2) 위의 **`GET`이고 본문에 JSON을 싣는다**. Go는 `http.NewRequestWithContext(ctx, "GET", "https://unused/machine/tka/...", body)`를 `DoNoiseRequest`로 보낸다. 이 경로는 `Content-Type`과 부하 분산 머리(`Ts-Lb`)를 붙이지 않는다(그 둘은 `DoWithBody`만 붙인다). 요청마다 1분 시한이 있다. 상태가 200이 아니면 본문 전체를 오류에 담아 실패한다. 응답 본문은 JSON 한 값으로 디코딩한다(`tailscale.com/ipn/ipnlocal/tailnet-lock.go:1377-1516`, `tailscale.com/control/controlclient/direct.go:1798-1807`, `tailscale.com/control/ts2021/client.go:299-336`, `tailscale.com/tailcfg/tailcfg.go:3109`). testcontrol은 `GET`이 아니면 400으로 거절한다(`tailscale.com/tstest/integration/testcontrol/testcontrol.go:1138-1142`).

| 경로 | 요청 JSON | 응답 JSON | 응답 본문 한도 |
| --- | --- | --- | --- |
| `/machine/tka/bootstrap` | `TKABootstrapRequest{Version: 148, NodeKey, Head}`. `Head`는 로컬 머리 base32, 없으면 `""`(필드는 늘 있다) | `TKABootstrapResponse{GenesisAUM?, DisablementSecret?}`: 둘 다 base64 bstr, omitempty | 1 MiB(기본) |
| `/machine/tka/sync/offer` | `TKASyncOfferRequest{Version, NodeKey, Head, Ancestors[]}` | `TKASyncOfferResponse{Head, Ancestors[], MissingAUMs[]}`. `MissingAUMs`는 AUM CBOR의 base64 배열 | **512 MiB** |
| `/machine/tka/sync/send` | `TKASyncSendRequest{Version, NodeKey, Head, MissingAUMs[], Interactive}`. 보통 노드는 `Interactive=false` | `TKASyncSendResponse{Head}` | 1 MiB(기본) |

출처: `tailscale.com/tailcfg/tka.go:104-194`, `tailscale.com/ipn/ipnlocal/tailnet-lock.go:54-59`, `:1445`, `tailscale.com/util/httpbody/httpbody.go:34`. `Version`은 `CurrentCapabilityVersion`이다(`tailscale.com/ipn/ipnlocal/tailnet-lock.go:1379`, `:1431`, `:1478`). `NodeKey`는 `nodekey:` 텍스트다.

### 3.11 Go의 로컬 저장(tailchonk)

| 항목 | 내용 | 출처 |
| --- | --- | --- |
| 위치 | `<varRoot>/tka-profiles/<프로필 ID>/`. tsnet은 `varRoot = Server.Dir`. varRoot가 비면 메모리 저장(`ChonkMem`)과 건강 경고 | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:528-534`, `:559-572`, `tailscale.com/tsnet/tsnet.go:984` |
| AUM 파일 | `<base>/<base32(hash) 앞 2글자>/<base32(hash)>`. 내용은 `fsHashInfo{2: AUM, 3: CreatedUnix int64 omitempty, 4: PurgedUnix int64 omitempty}`의 CTAP2 CBOR. 키 1(`Children`)은 예전 것이라 다시 쓰지 않는다 | `tailscale.com/tka/tailchonk.go:334-366`, `:710-742` |
| 읽기 검사 | 파일의 AUM 해시가 파일 이름과 다르면 오류. `PurgedUnix>0`이면 없는 것으로 본다 | `tailscale.com/tka/tailchonk.go:379-394`, `:475-477` |
| 마지막 활성 조상 | `<base>/last_active_ancestor`에 해시 32바이트 원본 | `tailscale.com/tka/tailchonk.go:618-656` |
| 쓰기 | `atomicfile.WriteFile`, 파일 0644, 디렉터리 0755 | `tailscale.com/tka/tailchonk.go:315`, `:625`, `:729`, `:742` |
| 지우기 | 압축(compaction)은 `PurgedUnix`만 표시하고 지우지 않는다. lock이 꺼지면 `RemoveAll`로 디렉터리째 지운다 | `tailscale.com/tka/tailchonk.go:327-329`, `:516-523`, `:677-705` |
| 언제 여나 | 프로필의 디렉터리가 있으면 시작할 때 `tka.Open`. 없으면 lock이 꺼진 것으로 본다 | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:83-125` |

Go의 `Persist`(노드 상태 JSON)에 `NetworkLockKey`(NL 개인 키)와 `DisallowedTKAStateIDs`가 들어 있다(`tailscale.com/types/persist/persist.go:28-39`).

## 4. 절차와 상태 기계

### 4.1 AUM 하나를 받아들이는 조건(`aumVerify`)

부모 상태 `state`에 대해 다음을 모두 만족해야 한다(`tailscale.com/tka/tka.go:421-468`).

1. `StaticValidate` 통과(3.4).
2. genesis가 아니면 부모가 있어야 하고, `state.LastAUMHash`가 nil이 아니며 부모 해시와 같아야 한다.
3. 서명이 **하나 이상** 있어야 한다.
4. **모든** 서명의 KeyID가 `state`의 신뢰 키여야 하고, 그 키의 `Public`(state 안의 것. KeyID에서 꺼낸 값이 아니다)으로 `SigHash`에 대한 `ed25519consensus.Verify`가 통과해야 한다(`tailscale.com/tka/verify.go:17-36`). 모르는 키의 서명이 하나라도 있으면 거절.
5. 키가 하나뿐인 상태에서 그 키를 지우는 RemoveKey는 거절.

**`Votes` 문턱은 없다.** 신뢰 키 하나의 서명으로 충분하다. `Votes`는 갈래 해소의 가중치로만 쓰인다(`tailscale.com/tka/aum.go:316-361`, `tailscale.com/tka/tka.go:142-167`). `MakeRetroactiveRevocation`의 주석이 "손상된 키의 표 합보다 많은 서명"을 요구하지만 그것은 갈래 해소에서 이기기 위한 서명 기기 쪽 규칙이고 `aumVerify`가 강제하지 않는다(`tailscale.com/tka/tka.go:804-805`).

### 4.2 상태 적용(`applyVerifiedAUM`)

검증된 AUM을 부모 상태에 적용한다(`tailscale.com/tka/state.go:157-254`). 공통: `state.LastAUMHash`가 nil이 아니면 `PrevAUMHash`와 바이트가 같아야 한다. 결과 상태의 `LastAUMHash`는 이 AUM의 해시다(`cloneForUpdate`, `tailscale.com/tka/state.go:107-112`).

| 종류 | 적용 |
| --- | --- |
| NoOp | 상태 그대로 |
| Checkpoint | `State.StateID1/2`가 부모와 같아야 한다. 상태 전체를 체크포인트의 것으로 바꾼다 |
| AddKey | KeyID가 이미 있으면 거절. 끝에 덧붙인다. **최대 512개 검사는 여기에 없다**(`UpdateBuilder.AddKey`와 체크포인트 검사에만 있다, `tailscale.com/tka/builder.go:73-75`) |
| UpdateKey | 키가 없으면 거절. `Votes`·`Meta`를 바꾸고 `Key.StaticValidate`를 다시 통과해야 한다 |
| RemoveKey | 키가 없으면 거절. 지운다(순서 유지) |
| 그 밖 | 상태 그대로(미래 종류) |

genesis(부모 없는 AUM)는 NoOp·AddKey·Checkpoint만 허용된다(`tailscale.com/tka/tka.go:276-292`).

### 4.3 사슬, 갈래 해소, 머리

- **갈래 해소**(`pickNextAUM`): 같은 부모의 자식이 여럿이면 ① 서명 가중치(부모 상태 기준, 같은 키의 서명은 한 번만, 모르는 키는 0) 큰 것 ② 같으면 RemoveKey인 것 ③ 같으면 AUM 해시가 바이트 비교로 **작은** 것을 고른다(`tailscale.com/tka/tka.go:122-168`, `tailscale.com/tka/aum.go:324-361`).
- **앞으로 감기**(`fastForward`): 시작 상태에서 자식이 없을 때까지 위 규칙으로 하나씩 적용한다. 최대 반복 `maxIter`(`tailscale.com/tka/tka.go:193-246`).
- **특정 AUM의 상태**(`computeStateAt`): 그 AUM에서 체크포인트나 genesis를 만날 때까지 거꾸로 가고, 지나온 경로를 따라 다시 앞으로 적용한다(갈래 규칙이 아니라 경로를 따른다)(`tailscale.com/tka/tka.go:248-331`).
- **열기**(`Open`): 모든 머리(자식 없는 AUM)에서 거꾸로 가장 오래된 조상을 찾는다. 조상이 하나면 그것, 여럿이면 이전 실행의 `LastActiveAncestor`를 지난 사슬의 조상, 그것도 없으면 오류("multiple distinct chains"). 그 조상의 상태에서 앞으로 감은 끝이 머리다(`tailscale.com/tka/tka.go:68-120`, `:333-419`, `:476-498`). 최대 반복 2000(`maxScanIterations`).
- **체크포인트**: 그 시점의 상태 전체를 담은 AUM이다. 상태 계산의 시작점이 되어 그 이전 AUM이 없어도 된다(`tailscale.com/tka/tka.go:271-275`). 서명 기기는 머리에서 50개 안에 체크포인트가 없으면 새 체크포인트를 덧붙인다(`checkpointEvery = 50`, `tailscale.com/tka/builder.go:122-160`).
- **부트스트랩**(`Bootstrap`): 저장소가 비어 있어야 한다. AUM이 Checkpoint이고 `State`가 있어야 하며, **그 체크포인트 자신의 상태**를 신뢰 상태로 삼아 `aumVerify(genesis=true)`를 한다. 즉 첫 신뢰는 제어 서버가 준 체크포인트에 대한 TOFU(처음 받은 것을 믿기)다. 통과하면 저장하고 `LastActiveAncestor`를 그 해시로 둔 뒤 `Open`(`tailscale.com/tka/tka.go:527-565`).
- **AUM 들이기**(`Inform`): 목록을 오래된 것부터 처리한다. 이미 저장된 것은 건너뛴다. 각 AUM의 부모 상태는 앞서 처리한 것이거나 저장소에서 `computeStateAt`으로 구한다(부모를 모르면 오류). `aumVerify(genesis=false)`와 적용을 통과해야 한다. **하나라도 실패하면 아무것도 저장하지 않는다**. 모두 머리에서 이어지면 마지막 상태를 쓰고, 아니면 `computeActiveChain`을 다시 한다(`tailscale.com/tka/tka.go:575-676`).

### 4.4 `NodeKeySignature` 검증(`NodeKeyAuthorizedWithDetails`)

입력: 노드의 node 공개 키, NKS 바이트(`tailscale.com/tka/tka.go:685-711`).

1. 3.1 규칙으로 디코딩. 실패하면 거절.
2. 맨 바깥이 credential이면 거절("credential signatures cannot authorize nodes on their own").
3. 허가 KeyID를 찾는다: direct·credential은 자기 `KeyID`(비면 거절), rotation은 `Nested`를 따라 내려간 값(`Nested` 없으면 거절)(`tailscale.com/tka/sig.go:183-200`).
4. 그 KeyID가 **현재 상태**의 신뢰 키여야 한다.
5. `verifySignature(nodeKey, 신뢰 키)`(`tailscale.com/tka/sig.go:247-312`):
   - credential이 아니면 `Pubkey`가 `"np" ‖ nodeKey`와 바이트가 같아야 한다.
   - rotation: `Nested` 필수. 회전 키 = `Nested.WrappingPubkey`, 비었고 `Nested`가 rotation이면 더 안쪽 것(`tailscale.com/tka/sig.go:153-170`). 없거나 32바이트가 아니면 거절. 바깥 `Signature`를 표준 `ed25519.Verify`로 검증. 안쪽이 credential이 아니면 안쪽 `Pubkey`가 올바른 `np` 형식이어야 하고(값을 무엇과 견주지는 않는다), 안쪽을 그 키로 재귀 검증한다.
   - direct·credential: `Nested`가 있으면 거절. 신뢰 키가 Key25519이고 32바이트여야 하며 `ed25519consensus.Verify`.
6. 통과하면 rotation일 때 `RotationDetails{PrevNodeKeys: 안쪽 rotation·direct의 Pubkey들(새 것부터), InitialSig: 맨 안쪽의 rotation 아닌 서명}`을 돌려준다(`tailscale.com/tka/sig.go:314-348`).

깊이는 CBOR 중첩 16단이 한도다. Go 시험이 direct 위에 rotation 15겹(총 16단)이 검증됨을 보인다(`tailscale.com/tka/sig_test.go:129-196`). 노드는 자기 서명을 다시 감쌀 때 이전 node 키가 15개를 넘으면 원래 direct 서명부터 다시 감싸 사슬을 줄인다(`maybeTrimRotationSignatureChain`, `tailscale.com/tka/sig.go:394-437`).

### 4.5 끄기 비밀 검증

`DisablementKDF(secret) = Argon2i(password=secret, salt="tailscale network-lock disablement salt", t=4, m=16·1024 KiB, p=4, 출력 32바이트)`(`tailscale.com/tka/state.go:114-130`). `x/crypto`의 `argon2.Key`는 **Argon2i**(Argon2id가 아니다), 버전 `0x13`, 비밀 키 K와 연관 자료 X는 비어 있다(`x/crypto/argon2/argon2.go:48-53`, `:75-76`). 솔트는 ASCII 39바이트다. 출력이 상태의 `DisablementValues` 가운데 하나와 **상수 시간 비교**로 같으면 참이다(`tailscale.com/tka/state.go:132-141`). Go 실행 8.1: `DisablementKDF(0xa5 × 32)` = `c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f`(이 비밀은 Go 시험이 쓰는 값이다, `tailscale.com/tka/state.go:325`).

### 4.6 NL 키와 등록

1. **NL 키.** 로그인할 때 `Persist.NetworkLockKey`가 0이면 새 Ed25519 키를 만들어 노드 상태에 넣는다. 그 뒤로 바꾸지 않는다(`tailscale.com/control/controlclient/direct.go:721-725`). 공개 키를 `RegisterRequest.NLKey`에 늘 싣는다(`:763`). 이 키는 서명 기기가 이 노드를 서명할 때 회전 키(`WrappingPubkey`)로 쓰이고(lock이 잠긴 노드는 `tailscale lock sign <nodekey> <tlpub>`를 안내한다, `tailscale.com/cmd/tailscale/cli/tailnet-lock.go:245-257`), 노드가 node 키를 바꿀 때 4번의 재서명에 쓰인다. 잃으면 다음 node 키 교체 뒤 스스로 재서명하지 못한다.
2. **서명된 인증 키**(`--TL`): `DecodeWrappedAuthkey`로 인증 키·credential NKS·64바이트 개인 키를 얻는다(3.8). 서버에는 `--TL` 앞부분만 `Auth.AuthKey`로 보낸다(`tailscale.com/control/controlclient/direct.go:643`, `:779-783`). `SignByCredential`: `NKS{SigKind: rotation, Pubkey: "np"‖새 node 키, Nested: credential}`을 만들고 그 `SigHash`에 감싼 개인 키로 서명해 `RegisterRequest.NodeKeySignature`에 싣는다(`tailscale.com/tka/sig.go:439-460`, `tailscale.com/control/controlclient/direct.go:739-747`, `:768`). credential이 아니면 등록을 오류로 끝낸다.
3. **서명 없이 등록된 노드**: 등록 자체는 lock과 무관하게 진행된다(소스상 Go 클라이언트는 서명이 없어도 등록 요청을 보낸다). 서명은 서명 기기가 `/machine/tka/sign`으로 제출하면 제어 서버가 이후 맵의 `Node.KeySignature`로 나눠 준다(testcontrol의 동작: `tailscale.com/tstest/integration/testcontrol/testcontrol.go:1247-1262`). 그때까지 자기 노드는 "잠김"이다: Go는 자기 `SelfNode.KeySignature`가 현재 상태로 검증되지 않으면 건강 경고(`LockedOut`)만 낸다(`tailscale.com/ipn/ipnlocal/tailnet-lock.go:245-250`, `tailscale.com/health/healthmsg/healthmsg.go:13`). 다른 Go 피어들이 이 노드를 netmap에서 빼므로(4.9) 통신이 되지 않는다(`tailscale.com/tstest/integration/integration_test.go:2557-2569`).
4. **서버의 재서명 요청**: `RegisterResponse.NodeKeySignature`가 있으면 Go는 새 node 키를 만들어(`Regen`) 등록을 다시 한다. 이때 옛 node 키가 있고 옛 서명이 있으면 `ResignNKS(NL 개인 키, 새 node 키, 옛 서명)`을 싣는다(`tailscale.com/control/controlclient/direct.go:534-545`, `:704-738`, `:857-858`). `ResignNKS`: 옛 서명의 `Pubkey`가 새 키와 같으면 옛 서명을 그대로 쓴다. 아니면 (필요하면 줄인) 옛 서명을 `Nested`로 하는 rotation NKS를 NL 키로 서명한다(`tailscale.com/tka/sig.go:350-392`). 이 rotation이 검증되려면 옛 서명 사슬의 회전 키가 이 노드의 NL 공개 키여야 한다(4.4의 5). 재서명이 실패하면 로그만 남기고 서명 없이 등록한다(`direct.go:736-738`).

### 4.7 netmap을 받을 때의 상태 기계(`tkaSyncIfNeeded`)

netmap이 올 때마다(전체 netmap 경로) 다음을 한다(`tailscale.com/ipn/ipnlocal/local.go:2021-2063`).

- `capTailnetLock = netmap.AllCaps에 "https://tailscale.com/cap/tailnet-lock"가 있음`(`local.go:2030`, `tailscale.com/types/netmap/netmap.go:211-213`, `tailscale.com/control/controlclient/map.go:1051`).
- `TKAEnabled = lastTKAInfo != nil && !lastTKAInfo.Disabled`. `TKAInfo.Head`가 비지 않았는데 base32 디코딩이 실패하면 `TKAEnabled = false`(`tailscale.com/control/controlclient/map.go:516-518`, `:1039-1047`). `TKAInfo`가 든 응답은 증분이 아니라 전체 netmap 경로로 간다(`tailscale.com/types/netmap/nodemut.go:200-209`).

그 다음 `tkaSyncIfNeeded(nm)`(`tailscale.com/ipn/ipnlocal/tailnet-lock.go:340-437`):

1. 로컬 lock이 없고(`tka == nil`) `capTailnetLock`도 거짓이면 **아무것도 하지 않는다**.
2. node 키가 없으면 오류.
3. `isEnabled(로컬) != wantEnabled(TKAEnabled)`이면 `/machine/tka/bootstrap`을 부른다(로컬 머리를 `Head`로, 없으면 빈 문자열).
   - 켜짐 쪽(로컬 없음, 서버 켜짐): `GenesisAUM`을 디코딩. `Persist.DisallowedTKAStateIDs`에 `"<StateID1>:<StateID2>"`가 있으면 거절. 저장소(디렉터리 또는 메모리)를 만들고 `Bootstrap`(4.3). `didJustEnable = true`(`tailnet-lock.go:536-584`).
   - 꺼짐 쪽(로컬 있음, 서버 꺼짐): 4.10.
4. 로컬 lock이 있고 (로컬 머리 ≠ `nm.TKAHead` 또는 `didJustEnable`)이면 동기화(4.8)를 하고, 이어서 압축(4.11)을 한다.
5. 오류는 `[v1]` 로그로만 남긴다(`local.go:2034-2036`). 재시도·백오프는 없다(`tailnet-lock.go:47` "RPC retry/backoff was broken and has been removed"). 다음 netmap이 오면 다시 시도한다.

그 뒤 로컬 머리를 `MapRequest.TKAHead`에 반영한다. 값이 바뀌면 맵 갱신을 다시 보낸다(`local.go:2038-2051`, `tailscale.com/control/controlclient/auto.go:706-714`, `direct.go:476-489`). 끝으로 피어 거르기(4.9)를 한다(`local.go:2053-2055`). 증분 경로(`PeersChanged` 등)는 `tkaFilterDeltaMutsLocked`가 거른다(`local.go:2494-2502`).

**`TKAEnabled`인데 부트스트랩이 실패하면 로컬 lock이 없으므로 피어를 거르지 않는다**(`tailnet-lock.go:189-197`). Go는 이 경우 모든 피어를 받아들인다.

### 4.8 동기화(`tkaSyncLocked`)

1. 로컬 `SyncOffer`를 만든다: `Head` = 로컬 머리. `Ancestors` = 머리에서 거꾸로 가며(최대 1000) 만나는 **체크포인트 AUM의 해시**들(새 것부터, 가장 오래된 조상은 빼고), 끝에 가장 오래된 조상(`oldestAncestor`)의 해시(`tailscale.com/tka/sync.go:65-111`).
2. `/machine/tka/sync/offer`로 보낸다.
3. 서버 `Head`·`Ancestors`를 디코딩. 서버 머리 = 로컬 머리이면 **여기서 끝낸다**(send를 보내지 않는다)(`tailnet-lock.go:456-464`).
4. 서버 제안에 대해 `MissingAUMs`(서버가 모르는 로컬 AUM)를 **먼저** 계산한다(`tailnet-lock.go:466-472`). 교차 계산(`computeSyncIntersection`, `tailscale.com/tka/sync.go:129-212`): 머리가 같으면 최신. 서버 머리가 로컬에 있으면 로컬 머리에서 거꾸로(최대 1000) 가며 그것을 찾아 "머리 교차". 아니면 서버 `Ancestors`를 앞에서부터 보며, 그 AUM의 상태에서 앞으로 감아 로컬 머리에 닿는 첫 것을 "꼬리 교차"로 삼는다(최대 반복 2000). 없으면 `ErrNoIntersection`. 교차 AUM 다음부터 앞으로 감으며 만나는 AUM이 보낼 목록이다(`tailscale.com/tka/sync.go:214-261`).
5. 응답의 `MissingAUMs`가 있으면 모두 디코딩(하나라도 실패하면 오류)하고 `Inform`(4.3)한다.
6. 로컬 머리와 4의 목록을 `/machine/tka/sync/send`로 보낸다(`Interactive=false`).
7. 응답 `Head`가 로컬 머리와 다르면 "TKA desync" 로그만 남긴다(`tailnet-lock.go:502-508`).

### 4.9 피어 거르기(`tkaFilterNetmapLocked`)

로컬 lock이 없으면 거르지 않는다(`tailnet-lock.go:189-197`). 있으면 각 피어에 대해(`tailnet-lock.go:199-243`):

1. `UnsignedPeerAPIOnly`이면 거르지 않는다(lock 대상 아님).
2. `KeySignature`가 비었으면 뺀다.
3. `NodeKeyAuthorizedWithDetails(피어 node 키, KeySignature)`(4.4)가 실패하면 뺀다.
4. 통과한 rotation 서명의 `RotationDetails`를 모은다. **회전으로 낡은 키**(`rotationTracker`, `tailnet-lock.go:253-338`): 어떤 rotation 서명의 `PrevNodeKeys`에 든 키는 모두 낡은 키다. `InitialSig`가 direct인 rotation들을 `InitialSig.WrappingPubkey`로 묶고(낡은 키로 이미 표시된 것 제외), 한 묶음에 여럿이면 `PrevNodeKeys`가 가장 많은 하나만 남기고 나머지를 낡은 키로 한다. 가장 많은 것이 둘 이상 같으면 그 묶음 전부를 낡은 키로 한다. credential에서 시작한 사슬은 묶지 않는다(같은 재사용 인증 키로 여러 노드가 들어올 수 있으므로).
5. 2·3에서 뺀 피어와 낡은 키를 가진 피어를 순서를 지키며 netmap에서 지운다.
6. 자기 노드의 서명이 검증되지 않으면 `LockedOut` 건강 경고.

증분(`tkaFilterDeltaMutsLocked`, `tailnet-lock.go:137-183`): `NodeMutationUpsert`(새로 오거나 통째로 바뀐 피어)는 1~3을 적용해 실패하면 같은 ID의 `Remove`로 바꾼다. 낡은 키 검사(4)는 증분에서 하지 않는다. `PeerChange`의 `Key`·`KeySignature` 패치는 증분으로 처리되지 않아 전체 netmap 경로로 간다(`tailscale.com/types/netmap/nodemut.go:111-138`, `:165-170`).

`TS_UNSAFE_SKIP_NKS_VERIFICATION`이 켜지면 Go는 거르지 않는다(`tailscale.com/envknob/envknob.go:427`, `local.go:2053`). Swiftail에는 두지 않는다.

같이 동작하는 안전장치: lock과 관계없이, `UnsignedPeerAPIOnly` 피어의 AllowedIPs가 패킷 필터의 출발지와 겹치고 목적지가 있는 규칙이 하나라도 있으면 Go는 패킷 필터 전체를 nil로 하고 건강 경고를 낸다(`local.go:3459-3464`, `:3562-3599`). 서명 없는 피어는 피어 capability를 가질 수 없다(`tailscale.com/ipn/ipnlocal/node_backend.go:415-440`, `tailscale.com/wgengine/magicsock/magicsock.go:3009-3013`).

### 4.10 lock이 꺼질 때

1. 서버가 `TKAInfo.Disabled=true`(또는 `TKAInfo` 없음)로 알리면 `wantEnabled=false`가 된다(4.7).
2. 로컬 lock이 있으면 `/machine/tka/bootstrap`(로컬 머리 실음)을 불러 `DisablementSecret`을 받는다.
3. `ValidDisablement(secret)`(4.5)이 참이면 저장소를 `RemoveAll`하고 로컬 lock을 nil로 한다. 거짓이면 로그만 남기고 lock을 **유지**한다(서버가 틀린 비밀을 줘도 동기화는 계속)(`tailnet-lock.go:399-418`, `:513-526`, `tailscale.com/ipn/ipnlocal/tailnet-lock_test.go:213-299`).

`TKAInfo.Disabled`만 믿고 지우면 악의적이거나 고장 난 제어 서버가 lock 보호를 끌 수 있다. 끄기 비밀의 KDF 값은 신뢰 체크포인트에 서명되어 들어 있으므로 비밀 검증이 그 보호를 지킨다.

### 4.11 압축과 저장

Go는 동기화할 때마다 `Compact(head, {MinChain: 24, MinAge: 14일})`를 부른다(`tailnet-lock.go:427-433`, `tailscale.com/tka/limits.go:30-35`). 머리에서 24개 이상(체크포인트에 닿을 때까지 더 길 수 있음), 14일 안에 저장한 것, 그 자손, 조상 교차에 필요한 것을 남기고 나머지에 `PurgedUnix`를 표시한 뒤 `LastActiveAncestor`를 새 조상으로 바꾼다(`tailscale.com/tka/tailchonk.go:745-1048`). `oldestAncestor`가 바뀌므로 다음 `SyncOffer`의 마지막 조상도 바뀐다.

### 4.12 capability와 조건 요약

| 상황 | Go 동작 |
| --- | --- |
| 로컬 lock 없음, `tailnet-lock` cap 없음 | TKA 처리 전부 건너뜀. `TKAEnabled`여도 부트스트랩하지 않고 거르지 않는다 |
| 로컬 lock 없음, cap 있음, `TKAEnabled` | 부트스트랩 → 동기화 → 거르기 |
| 로컬 lock 있음 | cap과 무관하게 동기화·거르기·끄기 처리 |
| `ts_omit_tailnetlock`로 빌드 | 모든 TKA 함수가 아무것도 하지 않는다(`tailscale.com/ipn/ipnlocal/tailnetlock_disabled.go:19-31`) |

출처: `tailnet-lock.go:189-197`, `:363-365`.

## 5. 상수와 타이머

| 이름 | 값 | 출처 |
| --- | --- | --- |
| `maxDisablementValues` | 32 | `tailscale.com/tka/limits.go:13` |
| `maxKeys` | 512 | `tailscale.com/tka/limits.go:14` |
| `maxMetaBytes` | 512 | `tailscale.com/tka/limits.go:18` |
| `maxSyncIter` | 2000 | `tailscale.com/tka/limits.go:21` |
| `maxSyncHeadIntersectionIter` | 1000 | `tailscale.com/tka/limits.go:24` |
| `maxScanIterations` | 2000 | `tailscale.com/tka/limits.go:27` |
| `CompactionDefaults` | `MinChain` 24, `MinAge` 14일 | `tailscale.com/tka/limits.go:30-35` |
| `Key.Votes` | 1~4096 | `tailscale.com/tka/key.go:108-113` |
| CBOR 중첩·배열·맵 | 16단, 4096개, 1024쌍 | `tailscale.com/tka/tka.go:29-31` |
| rotation 재서명의 이전 키 | 최대 15개 | `tailscale.com/tka/sig.go:414-420` |
| `disablementLength` | 32 | `tailscale.com/tka/state.go:114` |
| Argon2i | t=4, m=16384 KiB, p=4, 32바이트, v=0x13 | `tailscale.com/tka/state.go:124-130`, `x/crypto/argon2/argon2.go:48` |
| `checkpointEvery`(서명 기기) | 50 | `tailscale.com/tka/builder.go:123` |
| TKA RPC 시한 | 1분 | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:1395`, `:1442`, `:1493` |
| sync/offer 응답 한도 | 512 MiB | `tailscale.com/ipn/ipnlocal/tailnet-lock.go:59`, `:1445` |
| 그 밖의 Noise 응답 한도 | 1 MiB | `tailscale.com/util/httpbody/httpbody.go:34`, `tailscale.com/control/ts2021/client.go:330-336` |

## 6. Swiftail에 필요한 최소 부분과 생략할 수 있는 부분

### 6.1 암호 기본 요소

| 요소 | 쓰는 곳 | CryptoKit | `SwiftailCrypto` | 새로 쓸 것 |
| --- | --- | --- | --- | --- |
| BLAKE2s-256(키 없음) | AUM 해시·SigHash, NKS SigHash | 없음 | 있다(`Sources/SwiftailCrypto/BLAKE2s.swift:3-4`, `:32`) | 없음 |
| Ed25519 서명 | `ResignNKS`(NL 키), `SignByCredential`(감싼 키) | `Curve25519.Signing.PrivateKey.signature(for:)`(`CryptoKit.swiftinterface:35-37`). 개인 키는 32바이트 시드(`rawRepresentation`) | 없음 | NL 키 저장. Go 형식 64바이트 감싼 키는 앞 32바이트가 시드다(`ed25519.PrivateKey` 형식) |
| Ed25519 검증(표준 규칙) | rotation NKS 바깥 서명 | `Curve25519.Signing.PublicKey.isValidSignature`(`CryptoKit.swiftinterface:31-33`) | 없음 | 규칙 일치 여부 확인(8.2) |
| Ed25519 검증(ZIP-215) | AUM 서명, direct·credential NKS | 없음(CryptoKit의 검증 규칙은 공개 문서로 확인하지 못했다) | 없음 | 아래 참고 |
| Argon2i + BLAKE2b | 끄기 비밀 | 없음 | 없음(BLAKE2b도 없다) | BLAKE2b(RFC 7693)와 Argon2i(RFC 9106). Argon2는 BLAKE2b-512와 가변 길이 H'를 쓴다(`x/crypto/argon2/argon2.go:44`, `:130-170`) |
| 상수 시간 비교 | 끄기 값 비교 | — | 있다(`Sources/SwiftailCrypto/CryptoError.swift:12`) | 없음 |

**Ed25519 검증 규칙의 차이.** `ed25519consensus.Verify`(ZIP-215)는 서명 64바이트·`sig[63]&224 == 0`, 공개 키 A와 R의 **비정준 인코딩을 받아들이고**, S는 정준(`< L`)이어야 하며, **cofactor를 곱한** 식 `[8](R' − R) = 0`을 검사한다(`ed25519consensus/ed25519.go:19-66`). Go 표준 `ed25519.Verify`는 같은 길이·비트 검사와 정준 S를 요구하고, A는 비정준 인코딩을 받아들이며(`go/src/crypto/internal/fips140/edwards25519/edwards25519.go:142`), **cofactor 없이** 계산한 R의 인코딩이 `sig[:32]`와 바이트가 같아야 한다(`go/src/crypto/internal/fips140/ed25519/ed25519.go:290-327`). 정직하게 만든 서명(Go `ed25519.Sign`)은 두 규칙에서 모두 통과한다. 차이는 작은 위수 성분·비정준 R처럼 일부러 만든 서명에서만 나타난다. 선택지:

- (가) CryptoKit 하나로 모두 검증한다. 구현 0줄. 일부러 만든 서명에서 Go와 판정이 갈릴 수 있다. CryptoKit이 더 엄격하다면 Go가 받아들이는 AUM을 Swiftail이 거절해 동기화가 멈추고, Go가 받아들이는 피어를 뺀다(보호가 약해지는 방향은 아니다). CryptoKit이 받아들이는데 ZIP-215가 거절하는 서명이 있는지는 확인하지 못했다(추정: cofactor 없는 식이 성립하면 cofactor 식도 성립하므로 없을 것).
- (나) 순수 Swift edwards25519(필드 산술, 점 해독, 이중 스칼라 곱)로 ZIP-215와 표준 규칙을 둘 다 구현한다. 크기 추정 800~1200줄과 시험 벡터(ZIP-215 벡터는 `ed25519consensus/zip215_test.go`).

판정 동일을 목표로 하면 (나)가 맞지만 크기가 크다. 결정은 구현 전에 사용자에게 묻는다.

**Argon2i 시험 벡터**: RFC 9106 5.2(Argon2i, t=3, m=32 KiB, p=4, K·X 있음)와 그것을 옮긴 `x/crypto/argon2/argon2_test.go:70`, 그리고 이 노트의 Go 실행값(4.5, K·X 없음, TKA 인자 그대로). TKA 인자는 메모리 16 MiB를 한 번 채우므로 확인은 끄기 이벤트 때만 일어난다. 크기 추정: BLAKE2b 약 120줄, Argon2i 약 200~250줄(병렬도 4는 차선 4개를 순서대로 계산해도 결과가 같다. 병렬도는 H0의 입력일 뿐이다).

### 6.2 CBOR 부분집합

- **인코딩**: major 0(uint, 1~8바이트 최단), 2(bstr), 3(tstr, `Meta`만), 4(배열), 5(맵, 정수 키는 1~23이라 한 바이트, `Meta` 문자열 키는 인코딩 바이트 사전순), 7의 null(`0xf6`)만. 정의 길이만. 필드별 nil/빈 값/omitempty 규칙(3.1~3.6)을 그대로 따라야 해시가 같다.
- **디코딩**: 알려진 필드는 위 타입만 받는다. 모르는 필드는 잘 짜인 항목이면 무엇이든(major 1 음수, major 7의 실수 16·32·64비트와 단순값, 텍스트 내용 무검사) 건너뛰어야 Go와 같다. 태그·길이 미정·중복 키(구조체·`Meta` 수준)·뒤에 남은 바이트 거절, 중첩 16·배열 4096·맵 1024 한도. 비최단 정수와 정렬 안 된 키는 받아들인다. 해시·서명 검증은 받은 바이트가 아니라 **디코딩한 값을 정준 인코딩한 바이트**로 한다(3.1).
- 값 범위: `MessageKind`·`SigKind`·`KeyKind`는 0~255(넘으면 거절), `Votes` 0~2^64−1을 읽고(`uint`, 64비트 플랫폼) 검사는 1~4096, `StateID` uint64 전 범위.
- 크기 추정: 일반 CBOR 값 디코더(건너뛰기 포함)와 다섯 구조의 매핑, 정준 인코더를 합쳐 300~450줄.

### 6.3 분류

| 기능 | 분류 | 근거 |
| --- | --- | --- |
| NL 키 생성·영구 저장, `RegisterRequest.NLKey` | 필수 | 서명 기기가 회전 키로 쓰고, node 키 교체 뒤 재서명에 쓴다(4.6). 지금 Swiftail은 0 키를 보낸다(`Sources/SwiftailControl/Tailcfg/RegisterRequest.swift:38`, `Sources/SwiftailControl/Client/NodeIdentity.swift:13-15`에 NL 키가 없다) |
| 서명된 인증 키 → `SignByCredential` | 필수 | 사전 승인 등록 경로(M8 ①) |
| `RegisterResponse.NodeKeySignature` → `ResignNKS`(사슬 줄이기 포함) | 필수 | 지금은 `tailnetLockEnabled`로 끝낸다(`Sources/SwiftailControl/Client/ControlClient+Registration.swift:76-79`) |
| `MapRequest.TKAHead` | 필수 | 서버가 노드의 머리를 안다(4.7) |
| 부트스트랩(TOFU 체크포인트 검증), 동기화 offer + `Inform` | 필수 | 서명 권한 상태의 받기·검증 |
| 갈래 해소, 여러 사슬 중 조상 선택 | 필수 | 복구 AUM은 갈래를 만든다(`tailscale.com/tka/tka.go:798-860`). 없으면 Go와 다른 머리를 고른다 |
| sync/send(머리 알림) | 필수 | Go는 머리가 다르면 늘 보낸다(4.8의 6) |
| sync/send의 `MissingAUMs` 계산(교차 알고리즘) | 선택 | 보통 노드는 AUM을 만들지 않으므로 서버가 모르는 AUM은 서버 데이터 유실 때만 생긴다. 빈 목록으로 보내면 그 복구에 기여하지 못한다. Go 동등을 원하면 구현(약 150줄) |
| NKS 검증 + 피어 거르기 + 낡은 키 추적 + 증분 거르기 | 필수(생략 불가) | 생략하면 lock 보호가 사라진다(`docs/plan.md` 8절 위험 8) |
| 끄기 비밀 검증(Argon2i) | 필수(생략 불가) | 없으면 lock이 꺼진 뒤 새 피어를 모두 빼거나, `Disabled`만 믿으면 보호를 서버에 넘긴다 |
| 자기 노드 잠김 상태 알림 | 필수(공개 API) | 사용자가 `tailscale lock sign <nodekey> <tlpub>`를 하려면 node 키와 tlpub를 알아야 한다(`tailscale.com/cmd/tailscale/cli/tailnet-lock.go:245-257`) |
| 로컬 저장 | 필수(형식 자유) | 아래 |
| 압축 | 선택(한도는 필수) | 판정에 영향 없음. 저장 크기를 묶는 방법은 필요 |
| `DisallowedTKAStateIDs` | 생략 | `TailnetLockForceLocalDisable`가 쓰는 목록이다(`tailnet-lock.go:811-835`). Swiftail에 로컬 강제 끄기가 없으면 늘 비어 있다 |
| `UnsignedPeerAPIOnly` 처리 | 기존 차이 유지 | Go는 netmap에 남기고 권한을 줄이지만 Swiftail 엔진은 그런 피어를 아예 올리지 않는다(`Sources/SwiftailEngine/EnginePeer.swift:94-103`) |
| 서명 기기 기능 전부(2장) | 생략 | M8 범위 밖(`docs/plan.md` 3절) |
| 부트스트랩 실패 시 모든 피어 수용(4.7 끝) | **Go와 다르게 하는 것을 검토** | Go는 `TKAEnabled`인데 로컬 lock이 없으면 거르지 않는다. Swiftail은 부트스트랩 전에는 피어를 올리지 않는(fail-closed) 쪽이 안전하다. 같은 판정을 원칙으로 하므로 사용자 결정이 필요 |
| cap 없는 노드의 TKA 무시(4.12) | Go와 같게 | 운영 서버가 cap을 누구에게 주는지 모른다(8.2). Go와 같게 두면 같은 판정이다 |

**저장 형식 판단.** Go 상태 이관을 하지 않으므로 tailchonk 파일 형식을 따를 필요는 없다. 판정에 영향을 주는 것은 (1) 받아들인 AUM 전부(해시로 찾고, 부모로 자식을 찾을 수 있어야 한다), (2) `LastActiveAncestor`(여러 사슬일 때의 선택, 4.3), (3) 압축을 한다면 저장 시각이다. AUM은 정준 CBOR 바이트로 두면 다시 읽을 때 해시가 같다. 프로필(노드 신원)마다 따로 두고, lock이 꺼지면 통째로 지우며, NL 개인 키는 노드 신원 저장소(`NodeIdentityStore`)에 node 키와 함께 둔다. Go처럼 시작 때 저장소에서 상태를 다시 계산(`Open`)하면 상태 자체를 저장할 필요가 없다.

## 7. 상호 운용 시험에서 확인할 것

### 7.1 Go 기준값(이미 있는 것)

| 기준값 | 위치 |
| --- | --- |
| AUM 직렬화 바이트 5종(AddKey, RemoveKey, UpdateKey, Checkpoint, Signature)와 역직렬화 | `tailscale.com/tka/aum_test.go:17-159` |
| 실제 시험 tailnet의 genesis 체크포인트(558바이트, 끄기 값 10개, 키 2개, 서명 1개) | `tailscale.com/tka/aum_test.go:171-233`. 이 노트의 Go 실행으로 해시·SigHash·`Bootstrap` 통과를 구했다(8.1) |
| AUM 사슬의 해시(AddKey `53898e43…`, RemoveKey `15d65756…`, UpdateKey `d55458a9…`, 연쇄 `f09bda3b…`→`218165fe…`, 체크포인트 `57343671…`) | `tailscale.com/tka/state_test.go:96-164` |
| 가중치 | `tailscale.com/tka/aum_test.go:235-304` |
| 서명된 인증 키 문자열(credential NKS + 64바이트 키) | `tailscale.com/tka/sig_test.go:464-501` |
| NKS direct·nested·깊은 중첩·credential·rotation 세부·재서명 | `tailscale.com/tka/sig_test.go:17-627` |
| 동기화·교차·갈래 시나리오 | `tailscale.com/tka/sync_test.go`, `tailscale.com/tka/scenario_test.go`, `tailscale.com/tka/tka_test.go`(`chaintest_test.go`의 사슬 기술 언어) |
| 클라이언트 흐름(켜짐·꺼짐·동기화·압축·거르기·낡은 키) | `tailscale.com/ipn/ipnlocal/tailnet-lock_test.go:132`, `:213`, `:301`, `:452`, `:585`, `:1088` |
| Argon2i KAT | RFC 9106 5.2, `x/crypto/argon2/argon2_test.go:70` |
| ZIP-215 서명 벡터 | `ed25519consensus/zip215_test.go` |

### 7.2 `Tools/interop`에 더할 수 있는 기준값 도구

`tailscale.com/tka`는 외부에서 쓸 수 있는 공개 API(`Create`, `Bootstrap`, `Open`, `NewUpdater`, `Inform`, `SyncOffer`, `MissingAUMs`, `NodeKeyAuthorizedWithDetails`, `DisablementKDF`, `ResignNKS`, `SignByCredential`, `DecodeWrappedAuthkey`, `ChonkMem`)를 낸다(`tailscale.com/tka/tka.go:476-711`, `tailscale.com/tka/sync.go:30-261`, `tailscale.com/tka/sig.go:350-498`, `tailscale.com/tka/state.go:124`, `tailscale.com/tka/tailchonk.go:112`). 이 노트의 실행(8.1)처럼 `Tools/interop` 모듈(지금 `tailscale.com v1.104.6`을 쓴다)에서 바로 쓸 수 있다. 도구가 낼 것:

1. AUM 사슬(genesis 체크포인트, AddKey/RemoveKey/UpdateKey/NoOp, 체크포인트, 갈래, 복구 AUM)의 정준 바이트·해시·SigHash와 단계별 기대 상태·머리.
2. 동기화 시나리오: 양쪽 저장소에서 `SyncOffer`(머리·조상), `MissingAUMs`, `Inform` 뒤 머리.
3. NKS: direct, rotation n겹(1~15), credential→rotation, 사슬 줄이기 후 바이트, 그리고 각 (node 키, NKS, 상태)에 대한 `NodeKeyAuthorizedWithDetails`의 판정과 `PrevNodeKeys`. Swift가 만든 서명은 바이트 비교가 아니라 Go 판정으로 확인한다(CryptoKit 서명이 결정적인지 확인하지 못했다, 8.2).
4. 피어 집합 시나리오: `rotationTracker` 판정. `TestRotationTracker`(`tailnet-lock_test.go:1088`)의 입력 형태를 따른다.
5. 디코더 거절 표: 8.1의 입력들과 그 판정·재인코딩 해시.
6. `DisablementKDF` 값.

### 7.3 testcontrol로 흉내 낼 수 있는 것

testcontrol은 `/machine/tka/init/begin`·`init/finish`·`bootstrap`·`sync/offer`·`sign`을 처리하고, TKA 상태가 있고 머리가 하나면 맵 응답에 `TKAInfo{Head}`를 싣는다(`tailscale.com/tstest/integration/testcontrol/testcontrol.go:418`, `:1138-1262`, `:1770-1783`). 처리기는 `tailscale.com/tstest/tkatest/tkatest.go:39-220`에 있다. `DefaultNodeCapabilities`로 `tailnet-lock` cap을 줄 수 있다(`testcontrol.go:1065-1075`, `tailscale.com/tstest/integration/integration_test.go:2521-2523`). Go 통합 시험이 이것으로 "서명된 두 노드는 통하고 서명 안 된 노드는 아무와도 통하지 않다가 서명하면 통한다"를 보인다(`integration_test.go:2517-2584`).

없는 것과 주입할 것:

| 없는 것 | 결과 | 대안 |
| --- | --- | --- |
| `sync/send` 처리기 | 머리가 다른 노드가 send를 보내면 `serveUnhandled`가 `go panic`(`testcontrol.go:413`, `:430-434`). 그래서 genesis 하나뿐인 lock만 시험할 수 있다(`lock add` 같은 AUM 추가는 불가) | testcontrol을 `Tools/interop`에 옮겨 `tkatest.HandleTKASyncSend`를 잇거나, 사슬 동기화는 7.2의 기준값으로 Swift 단위 시험에서 확인 |
| `DisablementSecret`을 주는 bootstrap, `/machine/tka/disable` | 끄기 흐름 불가(bootstrap 응답에 `GenesisAUM`만 싣는다, `testcontrol.go:1223-1225`) | 위와 같음. 또는 `AddRawMapResponse`로 `TKAInfo{Disabled: true}`를 주입하되 bootstrap 응답은 바꿀 수 없다 |
| 등록 요청의 `NodeKeySignature` 저장 | 서명된 인증 키로 등록해도 노드에 서명이 붙지 않는다(testcontrol에 `NodeKeySignature` 처리 없음) | Swift가 만든 NKS를 Go 판정(7.2의 3)으로 확인하고, `UpdateNode`로 `KeySignature`를 넣어 맵 전파를 시험(`testcontrol.go:1315-1320`) |
| `TKAInfo.Disabled`, 다른 머리 | — | `AddRawMapResponse`(`testcontrol.go:337-339`)로 주입 |

tsnet 피어는 `LocalClient`로 `TailnetLockInit`·`TailnetLockSign`·`TailnetLockWrapPreauthKey`·`TailnetLockStatus`를 부를 수 있다(`tailscale.com/client/local/tailnetlock.go:22-151`, LocalAPI 처리기 `tailscale.com/ipn/localapi/tailnetlock.go:21-33`). 따라서 `Tools/interop/cmd/tailnet`(testcontrol + tsnet, `Tools/interop/cmd/tailnet/main.go:132`, `:193`)에 다음 관문을 얹을 수 있다.

1. testcontrol에 `tailnet-lock` cap. tsnet 서명 노드 A·B가 `TailnetLockInit`(A·B의 NL 키, 끄기 값 N개).
2. Swift 노드 S가 등록 → 부트스트랩 → 머리가 A와 같은지(`TailnetLockStatus().Head`).
3. 서명 안 된 상태: S의 netmap에 A·B가 남고(A·B는 서명됨) A·B의 netmap에서 S가 빠진다. S는 자기 잠김을 보고한다.
4. A가 `TailnetLockSign(S의 node 키, S의 NL 공개 키)` → S가 A·B의 netmap에 나타나고 통신된다.
5. 서명 안 된 tsnet 노드 C를 더하면 S와 A가 둘 다 C를 뺀다.
6. 피어 집합 비교: 같은 시점에 A의 `TailnetLockStatus().VisiblePeers`·`FilteredPeers`(`tailnet-lock.go:641-668`)와 S가 남긴 피어 집합을 node ID로 견준다. `UnsignedPeerAPIOnly` 피어는 Swiftail이 원래 올리지 않으므로 비교에서 따로 다룬다.
7. (testcontrol을 넓힌 경우) A가 키를 더해 AUM을 늘리고 S가 sync로 따라오는지, 끄기 비밀로 끄면 S가 상태를 지우는지, 틀린 비밀이면 유지하는지.
8. node 키 교체: S가 node 키를 바꾸고 `ResignNKS`로 재서명 → A의 판정이 통과하고 옛 키는 낡은 키로 빠지는지.

## 8. 실행 기록과 확인하지 못한 것

### 8.1 실행 기록

모든 실행은 `$(eyebuild dir tka-note)` 아래의 임시 Go 모듈에서 했다. 환경: `GOMODCACHE=$(eyebuild dir ref-src)/gomod GOPROXY=off GOSUMDB=off GOFLAGS=-modcacherw GOTOOLCHAIN=local`, Go 1.27.3. v1.104.7은 `go >= 1.27.4`를 요구해 빌드되지 않았으므로 `tailscale.com v1.104.6`을 썼다(인용 파일이 두 버전에서 같음은 1장). 명령은 `go mod tidy && go run .`.

| 확인한 것 | 결과 |
| --- | --- |
| genesis 체크포인트(`aum_test.go:181`) | 558바이트, 다시 인코딩하면 원본과 같음. 앞 8바이트 `a4010502f605a501`(맵 4쌍: 1, 2=null, 5=State 맵 5쌍, 23). `Hash` = `JJRRHYGNBVUWY77ZY436U35DVPHXPY4C5HPQZA2PHUPBNM5252UA`(hex `4a6313e0cd0d696c7ff9c737ea6fa3abcf77e382e9df0c834f3d1e16b3baeea8`) = 원본의 BLAKE2s-256. `SigHash` = `f34f12d83807a70bd9d7c5bef557ebfa453846cdfff1ce5c60d18d7a9facf325`. `tka.Bootstrap(ChonkMem, genesis)` 오류 없음, 머리 = 위 해시 |
| `DisablementKDF(0xa5 × 32)` | `c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f` |
| 서명된 인증 키(`sig_test.go:479`) | 인증 키 부분이 `--TL` 앞과 같음, 개인 키 64바이트, credential NKS의 KeyID 32·WrappingPubkey 32·서명 64바이트, CBOR 맵 4쌍(키 1,3,4,6) |
| `NodePublic.MarshalBinary` | 34바이트, 접두 `"np"` |
| 인코딩 | `UpdateKey{KeyID:[1], Votes:&0, Meta:{}}` → `a4010402f60441010600`. `Meta{"bb","a","c"}` → 키 순서 `a`,`c`,`bb`. `NoOp{PrevAUMHash: []byte{}}` → `a201030240`. 빈 `Keys`·`DisablementValues`는 `80`, `StateID1=2^40`은 `041b0000010000000000`, `StateID2=0`은 빠짐 |
| 디코딩: 받아들임 | 모르는 키(정수·실수·음수·true·undefined·잘못된 UTF-8·중첩 맵·텍스트 키), 모르는 값 안쪽의 중복 키, 비최단 정수(값·키), 정렬 안 된 키, `PrevAUMHash` 생략, 종류 9, `MessageKind` null(→0), 빈 `Meta` 맵, 체크포인트 상태의 2·33바이트 `LastAUMHash`(정적 검사에서 거절됨). 정준이 아닌 입력은 모두 `Hash ≠ BLAKE2s(원본)` |
| 디코딩: 거절 | 구조체·`Meta`의 중복 키, 길이 미정 맵, 태그, 뒤에 남은 바이트, 빈 입력, 맨 바깥 배열, 종류 256·음수·실수, `PrevAUMHash` 텍스트, `Meta` 값 정수·잘못된 UTF-8, 잘린 바이트열, 중첩 17단, 배열 4097개, 맵 1025쌍 |
| `AUMHash.UnmarshalText` | 소문자·패딩·51자 거절. 끝 글자 `A`/`B`/`P`는 같은 해시로 받아들임 |

출력은 `$(eyebuild dir tka-note)/run1.txt`~`run4.txt`에 두었다가 `eyebuild rm tka-note`로 지웠다.

### 8.2 확인하지 못한 것

- **운영 제어 서버의 동작**(소스에 없다): `tailnet-lock` node cap을 어떤 노드에 주는지(lock이 켜진 tailnet의 모든 노드인지), bootstrap이 늘 genesis를 주는지 아니면 나중 체크포인트를 주는지(`Bootstrap` 주석은 둘 다 허용, `tailscale.com/tka/tka.go:532`), `RegisterResponse.NodeKeySignature`를 언제 보내는지, 서명된 인증 키로 등록한 노드의 서명을 어떻게 저장·배포하는지, 서명 안 된 노드의 등록을 받아들이는지·어떤 응답을 주는지, `NLKey`가 0인 등록을 받아들이는지(`control-map.md` 4.6에서도 미확인), 관리 콘솔에서 서명할 때 회전 키로 등록 요청의 `NLKey`를 쓰는지, `UnsignedPeerAPIOnly`를 언제 주는지, sync/send의 `Interactive=false` 요청을 어떻게 검사하는지, TKA RPC에 429·503·Retry-After를 쓰는지, 응답 크기의 실제 분포.
- **CryptoKit Ed25519**: 검증 규칙(cofactor 사용 여부, 비정준 A·R 처리)과 서명이 결정적인지(RFC 8032처럼) 무작위인지. `swiftinterface`에는 선언만 있다(`CryptoKit.swiftinterface:31-37`). 6.1의 "CryptoKit이 더 엄격할 것"은 추정이다.
- **인용 버전 차이**: 읽은 소스는 v1.104.7, 실행은 v1.104.6(Go 1.27.3이 v1.104.7을 빌드하지 못함). 인용 파일이 같음은 `diff -rq`로 확인했지만 v1.104.7 자체로 돌린 결과는 없다.
- **Go 시험을 직접 돌리지 않았다**: `tka`·`ipnlocal`·통합 시험(`TestTailnetLock`)은 실행하지 않고 소스만 읽었다. 7.1의 해시 값은 시험 파일에 적힌 기대값이다.
- `ipnlocal/tailnet-lock_test.go:164-165`의 주석은 "최신이어도 offer/send가 불린다"고 하지만 코드(`tailnet-lock.go:461-464`)는 머리가 같으면 send를 보내지 않는다. 코드를 따랐다.
- `ed25519consensus`와 표준 검증이 갈리는 구체적 서명 예를 만들어 보지 않았다(`ed25519consensus/zip215_test.go`를 읽지 않음).
- `Compact`의 세부(`markAncestorIntersectionAUMs`, `markDescendantAUMs`)는 대강만 읽었다(`tailscale.com/tka/tailchonk.go:846-1004`).
- Go `encoding/json`이 `TKABootstrapRequest.Head`의 빈 문자열을 늘 싣는 것은 구조체에 omitempty가 없다는 데서 추론했다(`tailscale.com/tailcfg/tka.go:113-115`). 실제 바이트는 보지 않았다.
- 부트스트랩 실패 뒤 Go가 피어를 거르지 않는 것(4.7)이 운영에서 실제로 일어나는지(서버가 `TKAEnabled`인데 bootstrap이 실패하는 경우)는 모른다.
