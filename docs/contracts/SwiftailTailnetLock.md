# Swiftail Tailnet Lock 계약 (M8 ①, 초안)

M8 ①의 목표는 **lock이 켜진 tailnet에서 Go 노드와 같은 판정을 내는 보통 노드**다(`docs/plan.md` 3절, 7절 M8). 등록되고(서명된 인증 키 `--TL`, 또는 서명 기기가 뒤에 서명), 서명 권한 상태(TKA)를 받아 검증·저장하고, 서명되지 않은 피어를 netmap에서 거르고, lock이 꺼지는 것을 끄기 비밀로 확인한 뒤에만 받아들인다. 첫 사용처(RemoteDebug)의 Mac 호스트가 속한 tailnet은 lock이 켜져 있어서, 이 기능이 Mac 호스트 교체의 선행 조건이다.

이 문서는 **초안**이다. 구현 전에 "총괄 확인 필요"와 "사용자 확인 필요"를 정하고, "첫 사용처 확인 필요"를 첫 사용처 세션에 보낸 뒤 확정한다.

프로토콜 세부는 [tailnet-lock.md](../protocol-notes/tailnet-lock.md)(아래에서 "노트". 2026-11-15 다른 세션이 `tailscale.com` v1.104.7 소스와 실행으로 검증했다)만 따른다. 노트에 없어서 Go 원본을 직접 읽은 곳은 `경로:줄`(모듈 `tailscale.com@v1.104.7` 기준)을 달았다. 이 문서는 범위, 타깃, API, 동작, 한도, 결정, 시험과 관문만 정한다.

기존 계약과의 관계: [SwiftailControl.md](SwiftailControl.md) 단위 4의 동작 2("`--TL`을 담고 있으면 그 앞부분만 보낸다")에 서명 만들기를 더하고, 동작 4의 "`TKAInfo`로 tailnet lock이 켜진 것을 알면 `tailnetLockEnabled`로 끝낸다"와 `ControlError.tailnetLockEnabled`를 없앤다. [SwiftailHost.md](SwiftailHost.md) 4절 표의 "`NetworkLockStatus` 진단 로그 → 없다. lock이 켜진 tailnet은 `tailnetLockEnabled`로 끝난다"를 이 문서의 `TailnetLockStatus`로 바꾼다. plan 8절 위험 8과 9절의 "tailnet lock이 켜진 tailnet의 처리"를 이 문서가 닫는다. 어긋나면 이 문서가 앞선다.

이미 정해진 것(다시 논의하지 않는다):

- **Ed25519 검증은 순수 Swift로 직접 구현한다**(사용자 결정, 2026-11-15. 노트 6.1의 (나)). ZIP-215 규칙과 Go 표준 규칙 둘 다. 서명 만들기는 CryptoKit(`Curve25519.Signing`)을 쓴다.
- 암호 기본 요소 둘은 다른 세션이 만드는 **선행 단위**다: `Sources/SwiftailCrypto/Ed25519Verification.swift`(`Ed25519Verification.isValidZIP215(signature:message:publicKey:) -> Bool`, `isValidStandard(signature:message:publicKey:) -> Bool`, 인자는 `[UInt8]`), `Sources/SwiftailCrypto/BLAKE2b.swift`·`Argon2i.swift`(`BLAKE2b.hash(_:outputByteCount:key:)`, `Argon2i.derive(password:salt:iterations:memoryKiB:parallelism:outputByteCount:) -> [UInt8]`). 이 계약은 그 선언에만 기댄다.
- Go 상태 이관은 하지 않는다. 저장 형식을 Go(tailchonk)와 맞추지 않는다(노트 6.3).
- 라이브러리는 전부 Swift, 값 타입 상태 기계와 가장자리 입출력, 타입 있는 오류, 경계에서의 입력 검증(plan 5절 코드 기준).

## 1. 목표와 범위

| 넣는다 | 근거(노트) |
| --- | --- |
| NL 키의 생성·저장, `RegisterRequest.NLKey`에 늘 싣기 | 4.6 1, 6.3 |
| 서명된 인증 키(`--TL`)의 해석과 `SignByCredential` | 3.8, 4.6 2 |
| 서버의 재서명 요청(`RegisterResponse.NodeKeySignature`) → `ResignNKS`(사슬 줄이기 포함) | 4.4 끝, 4.6 4 |
| `MapRequest.TKAHead` | 3.9, 4.7 |
| 부트스트랩(처음 받은 체크포인트를 믿는 TOFU), 동기화(offer·send), AUM 들이기(`Inform`) | 4.3, 4.8 |
| AUM 검증과 상태 적용, 갈래 해소, 머리 계산 | 4.1~4.3 |
| NKS 검증(direct·rotation·credential), 피어 거르기, 회전으로 낡은 키 | 4.4, 4.9 |
| 끄기 비밀 검증 뒤에만 lock을 지우기 | 4.5, 4.10 |
| 자기 노드가 잠겨 서명을 기다리는 상태를 앱에 알리기 | 4.6 3, 6.3 |
| 서명 권한 상태의 로컬 저장과 다시 시작 뒤 이어 가기 | 3.11, 6.3 |
| 서명 기기가 만든 것(AUM 사슬, 복구 AUM이 만든 갈래, 서명, 감싼 인증 키)의 **검증** | 2장 |

| 뺀다 | 까닭 | 필요해지는 시점 |
| --- | --- | --- |
| 서명 기기 노릇: 다른 노드에 서명, lock 켜기·끄기 명령, 서명 키 더하기·빼기, 인증 키 감싸기, 복구 AUM 만들기, 서명 딥링크, 영향받는 서명 조회 | M8 범위 밖(plan 3절, 노트 2장) | Swiftail 노드가 서명 기기가 되어야 하는 사용처 |
| 로컬 강제 끄기와 `DisallowedTKAStateIDs` | 강제 끄기가 없으면 목록이 늘 비어 있다(노트 6.3) | 강제 끄기를 넣을 때 |
| `TS_UNSAFE_SKIP_NKS_VERIFICATION`에 해당하는 스위치 | 거르기를 끄는 길을 두지 않는다(노트 4.9) | — |
| c2n `/debug/tka/log` | tsnet도 들이지 않는다(노트 2장) | — |
| 압축(compaction) | 결정 L7. 판정을 바꾸지 않고 저장만 줄인다 | 저장이 한도(동작 M)에 닿는 tailnet이 보고될 때 |
| `UnsignedPeerAPIOnly` 피어를 데이터면에 올리기 | 지금도 올리지 않는다(`Sources/SwiftailEngine/EnginePeer.swift:94-103`). 기존 차이를 유지한다(노트 6.3) | Funnel 진입 같은 기능을 넣을 때 |
| Go 상태(tailchonk, `Persist.NetworkLockKey`) 읽기 | 사용자 결정 | — |

## 타깃과 의존 방향

| 타깃 | 종류 | M8 ①에서 더하는 것 |
| --- | --- | --- |
| `SwiftailCrypto` | 기존 | (선행 단위, 진행 중) `Ed25519Verification`, `BLAKE2b`, `Argon2i` |
| `SwiftailTKA` | **새 타깃**(`package` 접근, 제품으로 내보내지 않는다) | CBOR 읽기·쓰기, `AUMHash`·`TrustedKey`·`AUMSignature`·`AUM`·`AuthorityState`·`NodeKeySignature`, 서명 권한 상태 기계 `Authority`, NKS 검증과 만들기, 서명된 인증 키 해석. 소켓·파일·시계가 없다 |
| `SwiftailControl` | 기존 | NL 키(`NodeIdentity`·`NodeIdentityStore`), tailcfg 보탬(TKA RPC 셋, `MapRequest.TKAHead`), 등록 요청의 서명, TKA RPC, 저장(`TailnetLockStore`), netmap을 받을 때의 절차와 피어 거르기, `TailnetLockStatus`, `Netmap`·`ControlError` 변경 |
| `Swiftail` | 기존 | `NodeStatus.tailnetLock`, `NodeEvent.tailnetLockChanged` |

```
SwiftailBase ◄─┐
SwiftailCrypto ◄─ SwiftailTKA ◄─ SwiftailControl ◄─ SwiftailEngine ◄─ Swiftail
                  (CryptoKit)
```

- **새 타깃을 두는 까닭**(결정 L1): ① Go의 경계와 같다. 자료 형식과 검증은 `tka` 패키지, 절차는 `ipnlocal`·`controlclient`다(노트 3·4장). ② 입출력이 없는 순수 로직이라 `SwiftailControl`의 의존(HTTP/2, 소켓)이 필요 없고, Go 기준값과의 대조 시험을 제어 클라이언트 없이 돌린다. ③ 소유 파일이 타깃 단위로 갈려 병렬로 구현하고 따로 검토받는다(8절). ④ `package` 접근이라 공개 표면이 늘지 않는다(`SwiftailNetstack`과 같은 방식).
- CBOR은 `SwiftailTKA` 안에 둔다. 쓰는 곳이 TKA 하나다(`SwiftailHost.md` H14와 같은 판단). `SwiftailCrypto`에는 암호 기본 요소만 둔다.
- iOS 터널 확장도 lock이 켜진 tailnet의 노드가 되므로 선택 제품으로 떼지 않는다. `SwiftailControl`의 의존이 된다.
- `SwiftailControl`의 공개 표면에는 TKA 타입이 나오지 않는다(`TailnetLockStatus`는 문자열과 수만 담는다).

### 지금 lock 처리가 있는 곳

| 자리 | 지금 | 바뀐 뒤 |
| --- | --- | --- |
| `Sources/SwiftailControl/Tailcfg/RegisterRequest.swift:20`, `:32`, `:38`, `:44` | `nlKey`는 기본값 `.zero`, `nodeKeySignature`는 빈 값. 필드와 부호화(`:76`, `:82`)는 이미 있다 | 값을 채운다(동작 R) |
| `Sources/SwiftailControl/Client/ControlClient+Registration.swift:44-53` | 등록 요청을 만들 때 NL 키와 서명을 넣지 않는다 | 동작 R2·R5 |
| `Sources/SwiftailControl/Client/ControlClient+Registration.swift:76-79` | `RegisterResponse.NodeKeySignature`가 오면 `ControlError.tailnetLockEnabled` | 새 node 키로 재서명해 다시 등록(동작 R6) |
| `Sources/SwiftailControl/Client/AuthKey.swift:10-13` | `--TL` 뒤를 버리고 앞부분만 돌려준다 | 앞부분은 그대로 서버로, 뒤는 해석해 서명에 쓴다(동작 R3) |
| `Sources/SwiftailControl/Client/NodeIdentity.swift:12-31`, `NodeIdentityStore.swift`(`identity.json`) | machine 키와 node 키만 | NL 키를 더한다(동작 R1) |
| `Sources/SwiftailControl/Tailcfg/NLPublicKey.swift:5-9` | "lock을 구현하지 않지만 필드는 늘 보낸다" | 주석만 고친다 |
| `Sources/SwiftailControl/Tailcfg/MapRequest.swift` | `TKAHead`가 없다 | 더한다(동작 N4) |
| `Sources/SwiftailControl/Tailcfg/TKAInfo.swift:6`, `MapResponse.swift:48` | 해독만 한다 | 그대로 |
| `Sources/SwiftailControl/Netmap/MapSession.swift:44`, `:99-101`, `:218` | `TKAInfo`를 세션에 쥐고 `tailnetLockEnabled = !disabled`. `Head`는 해석하지 않는다(`shortcut:`) | Go의 `TKAEnabled`·`TKAHead` 규칙으로 계산한다(동작 N1) |
| `Sources/SwiftailControl/Netmap/MapSession.swift:158`, `:240`, `:255`, `Tailcfg/Node.swift:34`, `PeerChange.swift:29` | `KeySignature`를 netmap에 반영한다 | 그대로(거르기의 입력) |
| `Sources/SwiftailControl/Netmap/Netmap.swift:23` | `tailnetLockEnabled: Bool` | `tailnetLock: TailnetLockStatus` |
| `Sources/SwiftailControl/Client/ControlClient+MapPoll.swift:82`, `:101-104`, `ControlClient.swift:142-143` | `lastTKAInfo`를 기록하고, lock이 켜진 netmap이면 `tailnetLockEnabled`로 끝낸다 | 절차를 돌고 거른 netmap을 낸다(동작 N·P) |
| `Sources/SwiftailControl/Client/ControlError.swift:25`, `:33` | `case tailnetLockEnabled` | 없앤다(결정 L5) |
| `Sources/SwiftailControl/Tailcfg/Node.swift:66`, `:146`, `Sources/SwiftailEngine/EnginePeer.swift:94-103` | `UnsignedPeerAPIOnly` 피어의 `allowedIPs`를 자기 주소로 줄이고, 엔진에 올리지 않는다 | 그대로(동작 P1) |
| `Sources/Swiftail/NodeError.swift:9`, `Sources/Swiftail/TailnetNode.swift:477`, `Sources/SwiftailCertificates/CertificateManager.swift:392` | `tailnetLockEnabled`를 가리키는 주석과 `switch` 갈래 | 갈래를 지운다 |
| 첫 사용처 `Apps/iOSTunnel/SwiftailTunnelEngine.swift:180`(읽기만) | `.control(.tailnetLockEnabled)`에 사용자 문구를 붙인다 | 첫 사용처가 지운다(첫 사용처 확인 필요 F1) |

## 2. API 초안

### `SwiftailTKA` (`package`)

```swift
import CryptoKit
import SwiftailBase

// MARK: CBOR (노트 3.1, 6.2)

/// 디코딩한 CBOR 자료 항목. TKA 구조가 쓰는 종류와, 모르는 필드를 건너뛰는 데 필요한 나머지다.
package enum CBORValue: Sendable, Equatable {
    case unsigned(UInt64)
    /// 음의 정수 `-1 - n`. 모르는 필드의 키와 값으로만 나타난다.
    case negative(UInt64)
    case bytes([UInt8])
    /// 텍스트의 바이트. 여기서는 UTF-8을 검사하지 않는다(모르는 필드의 값은 잘못된 UTF-8이어도 건너뛴다. 동작 D6).
    case text([UInt8])
    case array([CBORValue])
    case map([CBORPair])
    /// null(0xf6)과 undefined(0xf7). 다시 쓸 때는 0xf6이다. Go 디코더는 undefined를 null과 똑같이 다뤄 알려진 필드에서
    /// 그 필드의 0 값으로 읽는다(`fxamacker/cbor` `decode.go`의 `nextCBORNil`. TL-1이 확인해 초안의 선언을 고쳤다).
    case null
    /// major 7의 나머지(false·true·단순값·실수). 값을 쥐지 않는다. 알려진 필드에는 올 수 없다.
    case simpleOrFloat
}
package struct CBORPair: Sendable, Equatable {
    package var key: CBORValue
    package var value: CBORValue
}

package enum CBORError: Error, Sendable, Equatable {
    case truncated          // 빈 입력, 항목 중간에서 끝남
    case trailingBytes      // 첫 항목 뒤에 바이트가 남음
    case indefiniteLength
    case tag
    case malformed          // 예약된 추가 정보 등 잘 짜이지 않은 항목
    case nestingTooDeep     // 17단
    case arrayTooLong       // 4,097개
    case mapTooLong         // 1,025쌍
}

package enum CBOR {
    /// 항목 하나를 읽는다. 입력 전체가 정확히 항목 하나여야 한다. 한도와 거절 목록은 동작 D.
    package static func decode(_ bytes: [UInt8]) throws(CBORError) -> CBORValue
}

/// 정준(CTAP2) 인코딩을 한 방향으로 써 나간다. 길이 미정·태그·실수를 쓰는 길이 없다.
/// 맵의 쌍은 부르는 쪽이 정준 순서로 쓴다(구조의 정수 키는 오름차순, `Meta`는 동작 E3).
package struct CBORWriter: Sendable {
    package init()
    package private(set) var bytes: [UInt8]
    package mutating func unsigned(_ value: UInt64)        // 가장 짧은 길이
    package mutating func byteString(_ value: [UInt8])
    package mutating func textString(utf8 value: [UInt8])
    package mutating func null()
    package mutating func arrayHeader(count: Int)
    package mutating func mapHeader(count: Int)
}

// MARK: 자료 형식 (노트 3.2~3.8)

/// AUM의 해시 32바이트(Go `tka.AUMHash`). 비교는 바이트로 한다(텍스트는 끝 글자가 달라도 같은 해시일 수 있다. 노트 3.8).
package struct AUMHash: Sendable, Hashable {
    package init?(_ bytes: [UInt8])          // 32바이트가 아니면 nil
    /// base32 표준 알파벳(대문자), 패딩 없음, 52자. 소문자·패딩·다른 길이는 nil.
    package init?(text: String)
    package var bytes: [UInt8] { get }
    package var text: String { get }
}

/// `Meta`의 한 쌍. Swift `String`으로 바꾸지 않는다: `String`의 비교는 유니코드 정규 동등이라 Go의 바이트 비교와 다르고,
/// 그 차이는 다시 인코딩한 해시를 바꾼다(동작 E3).
package struct MetaEntry: Sendable, Equatable {
    package var key: [UInt8]      // 검증된 UTF-8
    package var value: [UInt8]    // 검증된 UTF-8
}

/// 서명 권한을 가진 키(Go `tka.Key`). KeyID는 `publicKey` 바이트 그 자체다.
package struct TrustedKey: Sendable, Equatable {
    package var kind: UInt8               // 1 = Key25519
    package var votes: UInt64
    /// nil은 CBOR null이다. null과 빈 바이트열은 인코딩이 다르므로 구분한다(동작 E4).
    package var publicKey: [UInt8]?
    package var meta: [MetaEntry]         // 정준 순서. 비면 인코딩에서 빠진다
    package func validate() throws(TKAError)          // Go `Key.StaticValidate`
}

/// AUM에 붙는 서명(Go `tkatype.Signature`).
package struct AUMSignature: Sendable, Equatable {
    package var keyID: [UInt8]
    package var signature: [UInt8]
}

/// 서명 권한 상태를 바꾸는 메시지 하나(Go `tka.AUM`).
package struct AUM: Sendable, Equatable {
    package var messageKind: UInt8
    package var prevAUMHash: [UInt8]?     // nil = 부모 없음(null로 인코딩)
    package var key: TrustedKey?
    package var keyID: [UInt8]            // 비면 인코딩에서 빠진다
    package var state: AuthorityState?
    package var votes: UInt64?            // 0이어도 있으면 인코딩한다
    package var meta: [MetaEntry]?        // nil과 빈 맵은 검증에서만 다르다(인코딩에서는 둘 다 빠진다)
    package var signatures: [AUMSignature]

    /// 한도(동작 M)와 동작 D의 규칙으로 읽는다. 정적 검사는 하지 않는다.
    package init(decoding bytes: [UInt8]) throws(TKAError)
    /// 정준 CBOR. 해시와 서명 검증은 받은 바이트가 아니라 이것으로 한다(동작 E5).
    package func serialized() -> [UInt8]
    package var hash: AUMHash { get }                  // BLAKE2s-256(serialized())
    package var signatureHash: [UInt8] { get }         // 서명을 지운 것의 BLAKE2s-256
    package func validate() throws(TKAError)           // Go `AUM.StaticValidate`
}

/// 어느 AUM까지 적용한 뒤의 신뢰 상태(Go `tka.State`).
package struct AuthorityState: Sendable, Equatable {
    package var lastAUMHash: AUMHash?
    package var disablementValues: [[UInt8]]
    package var keys: [TrustedKey]
    package var stateID1: UInt64
    package var stateID2: UInt64
    /// 검증된 AUM을 적용한 새 상태(Go `applyVerifiedAUM`). 동작 A6.
    package func applying(_ update: AUM) throws(TKAError) -> AuthorityState
}

/// node 키에 대한 서명(Go `tka.NodeKeySignature`). `nested`는 간접 저장한다(값 타입의 재귀).
package struct NodeKeySignature: Sendable, Equatable {
    package var kind: UInt8               // 1 direct, 2 rotation, 3 credential
    package var publicKey: [UInt8]        // "np" ‖ node 공개 키 32바이트
    package var keyID: [UInt8]
    package var signature: [UInt8]
    package var nested: NodeKeySignature? { get set }
    package var wrappingPublicKey: [UInt8]
    package init(decoding bytes: [UInt8]) throws(TKAError)
    package func serialized() -> [UInt8]
    package var signatureHash: [UInt8] { get }
}

// MARK: 서명 권한 상태 기계 (노트 4.1~4.5, 4.8)

/// 동기화에서 주고받는 제안: 머리와, 교차점을 찾을 조상들(Go `tka.SyncOffer`).
package struct SyncOffer: Sendable, Equatable {
    package var head: AUMHash
    package var ancestors: [AUMHash]
}

/// 통과한 rotation 서명의 내력(Go `tka.RotationDetails`). 낡은 키를 가리는 데 쓴다(동작 P4).
package struct RotationDetails: Sendable, Equatable {
    package var previousNodeKeys: [NodePublicKey]     // 새것부터
    package var initialSignature: NodeKeySignature    // 맨 안쪽의 rotation이 아닌 서명
}

/// 피어 하나의 판정 입력.
package struct PeerCredential: Sendable {
    package var nodeKey: NodePublicKey
    package var keySignature: [UInt8]
}

/// tailnet의 서명 권한 상태. 받아들인 AUM 전부와 거기서 계산한 머리·신뢰 상태를 쥔 값 타입이다.
/// 소켓·파일·시계를 갖지 않는다. 저장은 `aums`를 가장자리(`TailnetLockStore`)가 적는다.
package struct Authority: Sendable {
    /// 서버가 준 체크포인트 하나로 시작한다(Go `Bootstrap`). 그 체크포인트 자신의 상태로 서명을 검증한다(동작 F5).
    package init(bootstrappingWith checkpoint: AUM) throws(TKAError)
    /// 저장해 둔 AUM들에서 다시 계산한다(Go `Open`). 동작 F6·T3.
    package init(opening stored: [AUM], bootstrap: AUMHash) throws(TKAError)

    package var head: AUMHash { get }
    package var state: AuthorityState { get }
    /// 부트스트랩한 AUM의 해시. 저장소의 하나뿐인 뿌리다.
    package var bootstrap: AUMHash { get }
    /// 받아들인 AUM 전부(활성 사슬과 갈래). 저장할 것이다.
    package var aums: [AUM] { get }

    /// AUM 묶음을 받은 순서대로 들인다(Go `Inform`). 하나라도 실패하면 아무것도 바뀌지 않는다(동작 F4).
    package mutating func inform(_ updates: [AUM]) throws(TKAError)
    /// 서버에 보낼 제안(Go `SyncOffer`). 동작 Y1.
    package func syncOffer() throws(TKAError) -> SyncOffer
    /// 상대의 제안에 견줘 상대가 모르는 로컬 AUM(Go `MissingAUMs`). 동작 Y4.
    package func missingAUMs(for remote: SyncOffer) throws(TKAError) -> [AUM]

    /// 이 node 키가 지금 상태로 인가되는가(Go `NodeKeyAuthorizedWithDetails`). 인가되지 않으면 던진다.
    /// 바깥 서명이 rotation이면 내력을, direct면 nil을 돌려준다. 동작 S.
    package func authorize(_ nodeKey: NodePublicKey, keySignature: [UInt8]) throws(TKAError) -> RotationDetails?
    /// 피어 집합의 판정: 서명 검증과 회전으로 낡은 키(Go `tkaFilterNetmapLocked`의 2~5). 입력과 같은 순서의 "남긴다".
    package func admitted(_ peers: [PeerCredential]) -> [Bool]
    /// 끄기 비밀이 맞는가(Go `ValidDisablement`). Argon2i로 16MiB를 한 번 쓴다(동작 X).
    package func isValidDisablement(secret: [UInt8]) -> Bool
}

// MARK: 서명 만들기 (노트 3.8, 4.6)

/// `--TL`이 붙은 인증 키를 해석한 것. 감싼 개인 키를 쥐므로 `description`과 `dump`에 내용을 드러내지 않는다.
package struct WrappedAuthKey: Sendable {
    /// 서버에 보낼 부분(`--TL` 앞).
    package let controlValue: String
    /// `--TL`이 없으면 nil. 있는데 동작 R3의 검사에 하나라도 어긋나면 던진다(서버로 아무것도 보내기 전에).
    package init?(parsing authKey: String) throws(TKAError)
    /// 새 node 키에 대한 서명(Go `SignByCredential`): credential을 안에 넣은 rotation NKS의 정준 바이트.
    package func keySignature(for nodeKey: NodePublicKey) throws(TKAError) -> [UInt8]
}

extension NodeKeySignature {
    /// 옛 서명을 새 node 키로 이어 서명한다(Go `ResignNKS`, 사슬 줄이기 포함). 동작 R7.
    package static func resigned(
        _ previous: [UInt8], for nodeKey: NodePublicKey, with lockKey: Curve25519.Signing.PrivateKey
    ) throws(TKAError) -> [UInt8]
}

package enum TKAError: Error, Sendable, Equatable {
    case cbor(CBORError)
    /// CBOR로는 읽히지만 구조에 맞지 않는다: 맨 바깥이 맵이 아님, 받지 않는 키 종류, 중복 키, 알려진 필드의 타입·범위, 잘못된 UTF-8.
    case invalidStructure
    /// 정적 검사 실패(`StaticValidate`, 체크포인트 상태 검사).
    case invalidAUM
    case emptyUpdate            // 빈 묶음
    case missingParent          // 부모 없는 AUM을 들이려 함, 부모를 모름
    case unsigned               // 서명 없음
    case untrustedSigner        // 신뢰 키가 아닌 KeyID의 서명
    case invalidSignature
    /// 적용 실패: 부모 해시 불일치, 이미 있는 키, 없는 키, 마지막 키 제거, StateID 불일치, 고친 키의 검사 실패.
    case rejectedUpdate
    case notACheckpoint         // 부트스트랩에 체크포인트가 아닌 AUM
    case corruptStore           // 저장된 AUM이 사슬을 이루지 않는다(동작 T3)
    case iterationLimit
    case noIntersection
    /// node 키가 인가되지 않는다(동작 S의 어느 단계든).
    case unauthorized
    case invalidAuthKey         // `--TL` 뒤가 동작 R3에 어긋난다
    case signingFailed
    case limitExceeded          // 이 계약의 한도(동작 M)
}
```

`SignByCredential`·`ResignNKS`는 CryptoKit의 서명을 쓰므로 순수 함수가 아니다(CryptoKit은 같은 키·메시지에도 매번 다른 서명을 낸다. 노트 8.1). 시험은 서명 바이트를 견주지 않고 검증한다(`SwiftailHost.md` 동작 C의 ECDSA와 같은 예외다).

### `SwiftailControl`

```swift
/// tailnet lock의 지금 모습. `ControlClient`가 netmap마다 채운다. 개인 키와 비밀은 담지 않는다.
public struct TailnetLockStatus: Sendable, Equatable {
    public enum Mode: Sendable, Equatable {
        /// lock이 없다: 로컬 서명 권한 상태가 없고, 서버가 켜졌다고 알리지 않았거나 이 노드에 `tailnet-lock` capability가 없다.
        case disabled
        /// 검증한 서명 권한 상태를 쥐고 있고, 그것으로 피어를 거른다.
        case enforcing
        /// 거를 근거가 없다: 서버는 lock이 켜졌다고 하는데 부트스트랩하지 못했거나, 저장된 상태를 열지 못했다.
        /// 피어를 하나도 올리지 않는다(사용자 확인 필요 U1).
        case unverified
    }
    public var mode: Mode
    /// 로컬 머리(base32 52자). `.enforcing`일 때만 있다.
    public var head: String?
    /// 서명이 없거나 검증되지 않거나 낡은 키라서 netmap에서 뺀 피어 수.
    public var filteredPeerCount: Int
    /// 자기 노드의 서명이 지금 상태로 검증되지 않을 때(잠김), 서명 기기에 넘길 값. 잠기지 않았으면 nil이다.
    public var signingRequest: SigningRequest?
    /// 자기 노드가 잠겨 있다: 서명 기기가 서명할 때까지 lock을 지키는 피어와 통신하지 못한다.
    public var isLockedOut: Bool { get }

    /// 서명 기기에서 `tailscale lock sign <nodeKey> <lockKey>`에 넣는 두 값. 둘 다 공개 키다.
    public struct SigningRequest: Sendable, Equatable {
        public var nodeKey: String      // `nodekey:` + 16진
        public var lockKey: String      // `tlpub:` + 16진
    }
}

public struct Netmap: Sendable, Equatable {
    // …
    /// tailnet lock의 모습. `peers`는 이것으로 이미 걸러져 있다(`ControlClient`가 내는 netmap).
    public var tailnetLock: TailnetLockStatus          // `tailnetLockEnabled: Bool`을 대신한다
}

public struct NodeIdentity: Sendable {
    // …
    /// tailnet lock 키(NL 키). 한 번 만들면 바꾸지 않는다. `init()`이 새로 만든다.
    public var lockKey: Curve25519.Signing.PrivateKey
}

public enum ControlError: Error, Sendable {
    // `tailnetLockEnabled`를 없앤다. 새 case는 없다.
    // `--TL` 뒤가 잘못된 인증 키는 `invalidConfiguration`이다(동작 R3).
}

// package·internal
public struct MapRequest {
    /// 로컬 머리의 base32. lock 상태가 없으면 빈 문자열이고 JSON에서 빠진다(`TKAHead`, omitzero).
    public var tkaHead: String
}
/// 서버가 알린 lock 상태(Go `netmap.TKAEnabled`·`TKAHead`). `MapSession`이 계산한다(동작 N1).
package struct ServerLockState: Sendable, Equatable {
    package var isEnabled: Bool
    package var head: AUMHash?
}
extension MapSession.Update {
    /// 세션의 지금 값. netmap이 바뀌지 않은 응답에도 싣는다.
    package var serverLock: ServerLockState
}
/// netmap을 받았을 때 할 일(Go `tkaSyncIfNeeded`의 갈래). 입출력 없는 판정이다(동작 N2).
enum TailnetLockPlan: Equatable {
    case nothing
    case bootstrap                 // 로컬 없음, 서버 켜짐
    case synchronize               // 로컬 있음, 머리 다름
    case verifyDisablement         // 로컬 있음, 서버 꺼짐
    init(localHead: AUMHash?, hasCapability: Bool, server: ServerLockState)
}
/// 서명 권한 상태를 상태 디렉터리의 파일 하나에 둔다(동작 T).
struct TailnetLockStore: Sendable {
    init(directory: URL)
    func load() throws(ControlError) -> Authority?        // 파일이 없으면 nil. 열지 못하면 던진다
    func save(_ authority: Authority) throws(ControlError)
    func remove() throws(ControlError)
}
// tailcfg: TKABootstrapRequest/Response, TKASyncOfferRequest/Response, TKASyncSendRequest/Response (internal, Codable)
extension ControlClient {
    func tkaBootstrap(head: AUMHash?, over connection: ControlConnection) async throws -> TKABootstrapResponse
    func tkaSyncOffer(_ offer: SyncOffer, over connection: ControlConnection) async throws -> TKASyncOfferResponse
    func tkaSyncSend(head: AUMHash, missing: [AUM], over connection: ControlConnection) async throws -> TKASyncSendResponse
}
```

`ControlClient`의 공개 선언(`init`, `Configuration`, `Event`, `run()`)은 바뀌지 않는다. `Event.netmap`이 싣는 netmap이 걸러진 것이 되고 `tailnetLock`을 담는다. 저장 자리는 `NodeIdentityStore`의 디렉터리에서 얻는다(새 인자가 없다).

### `Swiftail`

```swift
public struct NodeStatus: Sendable, Equatable {
    // …
    /// tailnet lock의 모습. netmap 전에는 `.disabled`다.
    public var tailnetLock: TailnetLockStatus
}

public enum NodeEvent: Sendable, Equatable {
    // …
    /// tailnet lock의 모습이 바뀌었다. 같은 값은 다시 내지 않는다. 처음 값은 `.disabled`이고 그것은 내지 않는다.
    case tailnetLockChanged(TailnetLockStatus)
}
```

`NodeState`와 `NodeError`의 case는 바뀌지 않는다(결정 L4). 잠긴 노드의 상태는 Go와 같이 `.running`까지 가고, 잠김은 `tailnetLock.isLockedOut`으로 안다. `NodeError.control`이 싣던 `tailnetLockEnabled`는 더 나오지 않는다.

쓰는 모양(앱):

```swift
for await event in node.events {
    if case let .tailnetLockChanged(lock) = event, let request = lock.signingRequest {
        // 서명 기기에서: tailscale lock sign <request.nodeKey> <request.lockKey>
    }
}
```

## 3. 동작

번호는 시험과 검토에서 가리키는 이름이다. 괄호 안의 절 번호는 노트의 것이다. "Swiftail의 선택"이라고 적은 것은 Go에 없는 규칙이고, 나머지는 Go와 같은 판정을 내야 한다.

### E. CBOR 인코딩

1. 정준(CTAP2) 인코딩만 쓴다: 정수와 길이는 가장 짧게, 정의 길이만, 태그·실수 없음(3.1, 6.2).
2. 구조는 정수 키 맵이다. 키는 `Key` 1·2·3·12, `AUMSignature` 1·2, `AUM` 1~7·23, `State` 1~5, NKS 1~6이고(3.2~3.6) 모두 한 바이트라 숫자 오름차순이 정준 순서다.
3. `Meta`는 텍스트 → 텍스트 맵이다. 쌍의 순서는 **인코딩한 키 바이트의 사전순**이다(머리 바이트가 길이를 담으므로 짧은 키가 먼저다. `a`, `c`, `bb`. 3.1). 키와 값은 받은 UTF-8 바이트 그대로 쓴다.
4. 빠지는 것과 남는 것(3.1, 3.4~3.6): omitempty 필드는 비면 뺀다(`AUM`의 `Key`·`KeyID`·`State`·`Meta`·`Signatures`, `Key.Meta`, `State.StateID1/2`가 0, NKS의 `Pubkey`·`KeyID`·`Signature`·`Nested`·`WrappingPubkey`). `AUM.Votes`는 값이 0이어도 있으면 쓴다(`0600`). omitempty가 아닌 필드는 늘 쓴다: `AUM.MessageKind`, `AUM.PrevAUMHash`(없으면 null `f6`), `Key.Kind`·`Votes`·`Public`(null이면 `f6`, 길이 0이면 `40`), `Signature.KeyID`·`Signature`, `State.LastAUMHash`(없으면 null), `State.DisablementValues`·`Keys`, NKS의 `SigKind`. 기준 바이트: `UpdateKey{KeyID:[1], Votes:0, Meta:{}}` → `a4010402f60441010600`, `NoOp{PrevAUMHash: 길이 0}` → `a201030240`, `StateID1=2^40` → `041b0000010000000000`(8.1).
5. **해시와 서명 입력은 받은 바이트가 아니라 디코딩한 값을 다시 인코딩한 바이트다**(3.1, 3.7). `AUMHash` = BLAKE2s-256(정준 AUM, 서명 포함). AUM `SigHash` = `Signatures`를 뺀 것의 BLAKE2s-256. NKS `SigHash` = `Signature`를 뺀 것의 BLAKE2s-256(`Nested`는 그대로). 모르는 필드, 비최단 정수, 정렬 안 된 키는 받아들이되 해시에서는 사라진다.
6. 판정에 쓰이는 값에서 null과 빈 값을 가려 쥐는 곳은 셋이다: `AUM.prevAUMHash`, `AUM.votes`, `TrustedKey.publicKey`. `TrustedKey.publicKey`의 null과 길이 0은 **쓰기에서만** 가린다(`f6`과 `40`). KeyID로 견줄 때는 같은 키다: null로 AddKey한 뒤 빈 값으로 AddKey하면 "이미 있는 키"다(실행 확인). `State`의 배열과 `LastAUMHash`는 가리지 않는다: 받아들여지는 체크포인트에서는 배열이 비지 않고 `LastAUMHash`가 null이기 때문이다(3.5). 그래서 정적 검사를 통과하지 못하는 입력의 재인코딩 바이트는 Go와 다를 수 있고, 대조 시험은 그런 입력에서 판정만 견준다(7절).

### D. CBOR 디코딩과 거절

AUM과 NKS에 같은 규칙을 쓴다(3.1의 `Unmarshal` 경로).

1. **항목 수준에서 거절**: 빈 입력, 잘린 항목, 첫 항목 뒤에 남은 바이트, 길이 미정, 태그(모르는 필드의 값 안에 있어도), 중첩 17단(맨 바깥 맵이 1단), 원소 4,097개의 배열, 1,025쌍의 맵(3.1, 6.2, 8.1). RFC 8949의 잘 짜임 규칙에 어긋나는 나머지도 거절한다: 예약된 추가 정보 28~30(모든 주요 타입), 정수의 31, 짝 없는 `ff`, 두 바이트로 쓴 32 미만 단순값(`f800`~`f81f`. `f820`은 받는다). 한 바이트 단순값 0~19와 255는 받는다(모르는 필드의 값으로). 이 줄은 `tkafixtures`의 실행으로 확정했다(`tka-fixtures.json`의 `cbor`).
2. **받아들임**: 비최단 정수(값과 키), 비최단 맵 머리와 바이트열 길이, 정렬 안 된 키(3.1, 실행 확인).
3. **구조 맵의 키**(AUM·`Key`·`State`·`Signature`·NKS): 받는 키는 양의 정수 2^63−1 이하, 음의 정수(−2^63까지), 올바른 UTF-8 텍스트다. 그 밖의 키(bstr, 실수, true·false·null·undefined, 배열, 맵, 2^63 이상의 정수, 잘못된 UTF-8 텍스트)는 거절한다(3.1).
4. **중복 키**: 구조 맵과 `Meta`에서 같은 키가 두 번 나오면 거절한다. 알려진 키든 모르는 키든 음수 키든 같고, 한쪽을 비최단으로 써도 같은 키다(값으로 견준다. 실행 확인). 모르는 필드의 **값 안쪽** 맵의 중복은 거절하지 않는다(3.1).
5. **알려진 필드**는 정수 키로만 찾는다. 텍스트 키 `"1"`·`"MessageKind"`는 모르는 필드다(3.1). 타입이 맞지 않으면 거절한다(정수 자리에 음수·실수·텍스트, 바이트열 자리에 텍스트, `Meta`의 키나 값이 true·배열 같은 것, `Signatures`의 원소가 맵도 null도 아님). **Go가 받아들여서 받아들이는 것**(`tkafixtures`의 실행으로 확정. 초안은 거절로 적었었다): ① **바이트열 자리의 정수 배열**: 원소가 모두 0~255면 그 바이트열로 읽는다(다시 쓰면 바이트열이다. `PrevAUMHash`, `Key.Public`, 서명의 KeyID·Signature, `DisablementValues`의 원소, NKS `Pubkey`에서 확인. 원소가 256 이상이거나 음수면 거절). ② **`Meta`의 null·undefined 키나 값**은 빈 문자열로 읽는다(다시 쓰면 `60`). ③ `Signatures`의 null 원소는 디코딩되고 정적 검사에서 거절된다. ④ AddKey의 `Public`은 null·없음·빈 값·31바이트·33바이트가 모두 디코딩된다(그 KeyID로 RemoveKey·UpdateKey도 통과한다. 33바이트 KeyID로 단 서명은 정적 검사에서 거절된다). 범위: `MessageKind`·`SigKind`·`Key.Kind`는 255까지(256은 거절), `Votes`·`StateID`는 `UInt64` 전 범위. null과 undefined는 그 필드의 0 값(정수 0, 없음)이 된다. `Meta`의 텍스트는 올바른 UTF-8이어야 한다(3.1, 6.2).
6. **모르는 필드**는 조용히 버린다. 값은 잘 짜인 항목이면 무엇이든 된다(음수, 실수, 단순값, 잘못된 UTF-8 텍스트, 중첩 맵). D1의 한도와 금지는 그 안에도 적용된다(3.1, 6.2).
7. 맨 바깥이 배열·정수·바이트열·텍스트면 거절한다. **맨 바깥이 null(`f6`)이나 undefined(`f7`)면 받아들인다**: 모든 필드가 0 값인 구조가 된다(AUM은 종류 0·부모 없음으로 읽혀 `a2010002f6`으로 다시 쓰이고 정적 검사를 통과한다. NKS는 `a10100`). Go가 그렇게 한다(`tkafixtures`의 실행으로 확정. 초안과 노트 3.1은 "맵이 아니면 거절"로 적었었다).
8. **Swiftail의 선택**: 체크포인트 `State`의 `LastAUMHash`가 null이 아니면 디코딩에서 거절한다. Go는 길이가 2든 33이든 읽어 들인 뒤 정적 검사에서 거절한다(3.5, 8.1). 그 AUM이 거절된다는 판정은 같다. 텍스트인 `LastAUMHash`는 Go도 디코딩에서 거절한다.
9. 디코딩 전에 바이트 길이를 본다(동작 M). 어떤 입력으로도 프로세스가 죽지 않는다.

### A. AUM 검증과 상태 적용

1. **정적 검사**(3.4, 3.5): `PrevAUMHash`가 길이 0인 바이트열이면 거절(null은 된다. 길이는 보지 않는다). `Key`가 있으면 `Kind`가 1, `Votes`가 1~4,096, `Meta`의 키·값 길이 합이 512바이트 이하(3.2). 모든 서명의 KeyID가 32바이트, 서명이 64바이트. `State`가 있으면 체크포인트 검사: `LastAUMHash` 없음, `DisablementValues` 1~32개·각 32바이트·서로 다름, `Keys` 1~512개·각각 검사 통과·KeyID 서로 다름. 종류별: AddKey는 `Key` 필수이고 `KeyID`·`State`·`Votes`·`Meta` 금지, RemoveKey는 `KeyID`(길이>0) 필수이고 `Key`·`State`·`Votes`·`Meta` 금지, UpdateKey는 `KeyID`(길이>0)와 `Votes`나 `Meta` 가운데 하나 이상(빈 맵 `Meta`도 "있음"이다) 필수이고 `Key`·`State` 금지, Checkpoint는 `State` 필수이고 `KeyID`·`Key`·`Votes`·`Meta` 금지. NoOp(3), 종류 0, 6 이상은 종류별 검사가 없다.
2. **부모**(4.1 2): 부모 없는 AUM이 아니면 부모 상태의 `LastAUMHash`가 있고 `PrevAUMHash`와 바이트가 같아야 한다. 길이가 32가 아닌 `PrevAUMHash`는 여기서 떨어진다(3.4).
3. **서명**(4.1 3·4, 3.7): 하나 이상 있어야 한다. **모든** 서명의 KeyID가 부모 상태의 신뢰 키여야 하고, 그 키의 `Public`(상태 안의 값. 32바이트가 아니면 실패)으로 `SigHash`에 대한 `Ed25519Verification.isValidZIP215`가 참이어야 한다. 모르는 키의 서명이 하나라도 섞이면 거절한다.
4. `Votes`의 문턱은 없다. 신뢰 키 하나의 서명으로 충분하다(4.1).
5. 키가 하나뿐인 상태에서 그 키를 지우는 RemoveKey는 거절한다(4.1 5).
6. **적용**(4.2): 결과 상태의 `LastAUMHash`는 이 AUM의 해시다. NoOp는 그대로. Checkpoint는 `StateID1/2`가 부모와 같아야 하고 상태 전체를 체크포인트의 것으로 바꾼다. AddKey는 KeyID가 이미 있으면 거절하고 끝에 덧붙인다(512개 검사는 여기에 없다). UpdateKey는 키가 없으면 거절하고, `Votes`·`Meta`를 바꾼 키가 A1의 키 검사를 다시 통과해야 한다. RemoveKey는 키가 없으면 거절하고 순서를 지키며 지운다. 그 밖의 종류는 상태를 그대로 둔다.
7. **종류 0(`AUMInvalid`)과 6 이상**은 서명이 맞으면 받아들이고 머리가 옮겨 간다(4.2, 8.1. 결정 L10). 부모 없는 자리에서는 NoOp·AddKey·Checkpoint만 된다(4.2).

### F. 사슬, 갈래 해소, 머리

1. **갈래 해소**(4.3 `pickNextAUM`): 같은 부모의 자식이 여럿이면 ① 서명 가중치가 큰 것(부모 상태의 `Votes` 합. 같은 키의 서명은 한 번만, 모르는 키는 0) ② 같으면 RemoveKey인 것 ③ 같으면 AUM 해시가 바이트 비교로 작은 것.
2. **머리**: 뿌리(부트스트랩 AUM)의 상태에서 자식이 없을 때까지 F1로 하나씩 적용한 끝이다(4.3 `fastForward`).
3. **어느 AUM의 상태**(4.3 `computeStateAt`): 그 AUM에서 체크포인트나 뿌리를 만날 때까지 거꾸로 가고, 지나온 경로를 따라 다시 적용한다(갈래 규칙이 아니라 경로를 따른다).
4. **들이기**(4.3 `Inform`): 빈 묶음은 오류. 받은 순서대로 처리하고 정렬하지 않는다. 이미 쥔 AUM은 건너뛴다. 부모 없는 AUM은 오류. 각 AUM의 부모 상태는 같은 묶음에서 앞서 처리한 것이거나 F3으로 구하고, 부모를 모르면 오류. A1~A6을 통과해야 한다. **하나라도 실패하면 그 앞의 것까지 아무것도 들이지 않는다.** 모두 통과하면 머리를 다시 계산한다.
5. **부트스트랩**(4.3 `Bootstrap`): 상태가 비어 있을 때만 한다. AUM이 Checkpoint이고 `State`가 있어야 하며, 그 체크포인트 **자신의 상태**를 부모 상태 삼아 A1·A3을 검사한다. 첫 신뢰는 제어 서버가 준 체크포인트에 대한 TOFU다. 서버가 genesis가 아닌 나중 체크포인트를 주어도 같다(8.2).
6. **다시 열기**: Swiftail의 저장소는 뿌리가 하나다(F4가 부모를 모르는 AUM을 받지 않고, 압축하지 않는다. 결정 L7). 그래서 Go `Open`의 "여러 사슬 가운데 조상 고르기"(4.3, 8.2의 미확인 항목)에 닿지 않는다. 열 때 그 불변 조건을 검사한다: 뿌리가 기록된 부트스트랩 해시 하나이고, 나머지는 모두 부모가 저장소에 있다. 어긋나면 `corruptStore`다. 뿌리부터 F2로 다시 계산하며 A1~A6을 다시 검사한다(Swiftail의 선택. 결정 L14).
7. 반복 한도(5장): 부모 상태를 찾아 거꾸로 가기 2,000, 동기화의 머리 교차 1,000, 꼬리 교차의 앞으로 감기 2,000. 뿌리부터 머리까지의 재계산(F2·F6)에는 Go의 2,000을 쓰지 않는다: 압축하지 않는 저장소에서는 사슬이 그보다 길어질 수 있다. 저장 한도(동작 M)가 그 상한이다(Swiftail의 선택).

### S. NKS 검증

`Authority.authorize`(4.4). 어느 단계든 실패하면 인가되지 않는다.

1. 동작 D로 디코딩한다.
2. 맨 바깥이 credential이면 거절한다.
3. 허가 KeyID: direct·credential은 자기 `KeyID`(비면 거절), rotation은 `Nested`를 따라 내려간 값(`Nested`가 없으면 거절).
4. 그 KeyID가 **지금 상태**의 신뢰 키여야 한다.
5. 서명 검증(재귀):
   - credential이 아니면 `Pubkey`가 `"np"` ‖ node 공개 키 32바이트와 같아야 한다.
   - **rotation**: `Nested` 필수. 회전 키는 `Nested.WrappingPubkey`이고, 비었고 `Nested`가 rotation이면 더 안쪽 것이다. 없거나 32바이트가 아니면 거절. 바깥 `Signature`는 그 키로 **`Ed25519Verification.isValidStandard`**(Go 표준 규칙)로 검증한다. 안쪽이 credential이 아니면 안쪽 `Pubkey`가 올바른 `np` 형식(34바이트)이어야 하고, 안쪽을 그 키로 다시 검증한다.
   - **direct·credential**: `Nested`가 있으면 거절. 신뢰 키가 `Key25519`이고 `Public`이 32바이트여야 하며 **`isValidZIP215`**로 검증한다.
6. 통과한 rotation은 내력을 돌려준다: `previousNodeKeys`는 안쪽 서명들 가운데 `Pubkey`가 비지 않은 것의 키(새것부터, 맨 안쪽 direct의 키 포함), `initialSignature`는 맨 안쪽의 rotation 아닌 서명이다. credential의 `Pubkey`에 값이 들어 있는데 `np` 형식으로 읽히지 않으면 검증 전체가 실패한다(4.4 6).
7. 깊이는 CBOR 중첩 16단이 한도다. direct 위에 rotation 15겹까지 검증된다(4.4).

### X. 끄기 비밀

1. `Authority.isValidDisablement(secret:)`는 `Argon2i.derive(password: secret, salt: "tailscale network-lock disablement salt"(ASCII 39바이트), iterations: 4, memoryKiB: 16384, parallelism: 4, outputByteCount: 32)`의 결과가 상태의 `DisablementValues` 가운데 하나와 **상수 시간 비교**(`constantTimeEqual`)로 같을 때 참이다(4.5). Argon2**i**이고 버전 `0x13`, 비밀 키와 연관 자료는 비어 있다.
2. 빈 비밀도 그대로 KDF에 넣는다(Go와 같은 판정. 서버가 비밀을 주지 않으면 빈 값이다).
3. 기준값: 비밀 `0xa5` × 32 → `c3fea8a0d70ede2555990ca60d70a8a03cbe627d2c9f3cb0e2ba7093d0884e2f`(4.5).
4. 16MiB를 한 번 쓰고 끝나면 놓는다. 절차가 한 번에 하나만 돌므로(동작 N3) 겹쳐 돌지 않는다. 같은 비밀은 다시 계산하지 않는다(동작 O6).

### R. NL 키와 등록

1. **NL 키**(4.6 1): `NodeIdentity`가 쥐고 `identity.json`에 `"NLKey":"nlpriv:<16진 128자리>"`(시드 32 ‖ 공개 32. Go의 텍스트 형식, 3.8)로 저장한다. 읽을 때 뒤 32바이트가 시드로 만든 공개 키와 같은지 확인하고 다르면 `storage`다. `NLKey`가 없는 옛 신원 파일을 읽으면 새 키를 만들고 **첫 요청을 보내기 전에 저장한다**(저장하지 않고 등록하면 다시 시작할 때 다른 키가 나간다). 한 번 정하면 바꾸지 않는다: 잃으면 다음 node 키 교체 뒤 스스로 재서명하지 못한다.
2. `RegisterRequest.NLKey`에 늘 0이 아닌 공개 키를 싣는다(4.6 1).
3. **인증 키의 해석**(3.8): `run()`이 첫 연결 전에 한 번 한다. `--TL`이 없으면 평범한 인증 키다. 있으면 첫 `--TL`에서 자르고 나머지를 첫 `-`에서 잘라 A·B를 얻는다. 다음 가운데 하나라도 어긋나면 `ControlError.invalidConfiguration`으로 끝내고 **서버로 아무것도 보내지 않는다**: 문자열 전체 16KiB 이하. `-`가 있다. A·B가 패딩 없는 표준 base64(`+/`)의 정규형이다. A가 8KiB 이하이고 동작 D로 읽히는 NKS이며 종류가 credential이고 `WrappingPubkey`가 32바이트다. **B가 정확히 64바이트다.** B의 앞 32바이트(시드)로 만든 공개 키가 B의 뒤 32바이트와 같고 A의 `WrappingPubkey`와도 같다. Go는 디코딩이 실패하면 개인 키가 든 원문 전체를 서버로 보내고, B가 64바이트가 아니면 panic한다(3.8). Swiftail은 어느 쪽도 하지 않는다(결정 L12·L13).
4. **서버로 가는 것**: `Auth.AuthKey`에는 `--TL` 앞부분만 싣는다(4.6 2). 감싼 개인 키(B)와 credential(A)의 원문은 어떤 요청에도 싣지 않는다. 서버의 거절 메시지에서 인증 키 원문과 앞부분을 가리는 기존 규칙(`SwiftailControl.md` 동작 2)은 그대로다.
5. **요청의 서명**(Go의 순서 그대로. 4.6 2·4): ① 옛 node 키가 있고 서버가 방금 준 옛 서명이 있으면 R7의 재서명. 실패하면 로그만 남기고 서명 없이 등록한다. ② 아니고 감싼 인증 키를 실어 보내는 요청이면 `WrappedAuthKey.keySignature(for:)`(= rotation NKS{`Pubkey`: `"np"` ‖ 새 node 키, `Nested`: credential}의 `SigHash`에 감싼 키로 서명). 실패하면 등록을 오류로 끝낸다. ③ 그 밖에는 서명 없이(null) 등록한다. 서명 없는 등록은 lock과 무관하게 진행되고, 서명은 서명 기기가 뒤에 올린다(4.6 3).
6. **서버의 재서명 요청**(4.6 4): `RegisterResponse.NodeKeySignature`가 비지 않으면 새 node 키를 만들어 다시 등록한다. `OldNodeKey`는 저장된 지금의 node 키이고, 재서명의 입력은 **방금 받은 응답의 바이트**다(로컬에 저장한 서명이 아니다). 응답은 지금처럼 `Error` → `NodeKeySignature` → `NodeKeyExpired` → `AuthURL` 순으로 본다. 한 번의 등록에서 재서명 요청은 한 번만 따른다. 두 번째로 오면 연결 오류로 보고 물러났다가 다시 잇는다(Swiftail의 선택. Go는 두 번째 응답의 재서명 요청을 버린다, `control/controlclient/direct.go:534-545`. 그 뒤의 Go 상태는 확인하지 못했다, 9절).
7. **재서명**(4.4 끝, 4.6 4 `ResignNKS`): 옛 서명의 `Pubkey`가 새 키와 같으면 옛 서명을 그대로 쓴다. 아니면 옛 서명을 `Nested`로 하는 rotation NKS를 NL 키로 서명한다. 지금 서명의 `Pubkey`와 안쪽 키를 합한 수가 15개를 넘으면, 맨 안쪽 rotation 아닌 서명 위에 가장 최근 키 14개만 NL 키로 다시 서명해 감싼 뒤 새 rotation을 씌운다. 만든 서명은 스스로 검증하지 않고 보낸다(Go와 같다. 결정 L9): 옛 사슬의 회전 키가 자기 NL 공개 키가 아니면(`--TL`로 등록한 노드, `WrappingPubkey` 없이 서명된 direct) 이 서명은 검증되지 않고, 노드는 다시 서명받을 때까지 잠긴다. 그 경우를 로그에 종류로 남기고, 잠김은 다음 netmap에서 `signingRequest`로 드러난다.
8. 등록이 끝나도 서명이 맞는지는 여기서 알 수 없다. 자기 서명의 판정은 netmap의 자기 노드 `KeySignature`로 한다(동작 P6).

### N. netmap을 받을 때

구조: 판정(`TailnetLockPlan`, `Authority`)은 값 타입이고, RPC와 파일은 `ControlClient`가 맡는다. **거르지 않은 netmap은 `ControlClient` 밖으로 나가지 않는다**(결정 L2).

1. **서버가 알린 상태**(4.7, 4.10 1): `MapSession`이 계산한다. `isEnabled` = 이 맵 세션에서 받은 마지막 `TKAInfo`가 있고 `Disabled`가 아님. `Head`가 비지 않았는데 `AUMHash(text:)`로 읽히지 않으면 `isEnabled`는 거짓이다. `TKAInfo`가 없는 응답은 "변화 없음"이고, 세션의 처음에는 없는 상태다(맵 스트림마다 새 `MapSession`). capability는 자기 노드의 `capMap`에 `https://tailscale.com/cap/tailnet-lock`이 있는지다.
2. **할 일**(4.7, 4.12. `TailnetLockPlan`):

   | 로컬 상태 | capability | 서버 | 할 일 |
   | --- | --- | --- | --- |
   | 없음 | 없음 | 무엇이든 | 없음. 거르지 않는다(사용자 확인 필요 U2) |
   | 없음 | 있음 | 꺼짐 | 없음 |
   | 없음 | 있음 | 켜짐 | `bootstrap`: 부트스트랩 RPC(`Head` 빈 문자열) → 동작 F5 → 저장 → 곧바로 동기화(동작 Y) |
   | 있음 | 무관 | 켜짐, 머리 같음 | 없음 |
   | 있음 | 무관 | 켜짐, 머리 다름 | `synchronize`(동작 Y) |
   | 있음 | 무관 | 꺼짐 | `verifyDisablement`(동작 O) |

   머리는 32바이트로 견준다(3.8).
3. **차례**: 할 일이 있는 netmap은 그 절차가 끝날 때까지(성공이든 실패든) 내지 않고 쥔다. Go가 동기화한 뒤에 거르는 것과 같은 차례다(4.7). 절차는 한 연결에서 한 번에 하나만 돈다(Go의 `tkaSyncLock`). 맵 스트림 읽기는 멈추지 않고, 그사이 온 netmap은 가장 새것 하나만 쥔다. 절차가 끝나면 가장 새 netmap을 그때의 상태로 걸러 낸다. 할 일이 없는 netmap은 곧바로 걸러 낸다(결정 L3).
4. **머리 알리기**(3.9, 4.7): 맵 요청(스트림과 상태 올리기 둘 다)의 `TKAHead`에 로컬 머리를 싣는다. 절차 뒤 머리가 마지막으로 올린 값과 달라졌으면 상태 올리기 요청을 한 번 더 보낸다(Go `SetTKAHead` → `updateControl`, `control/controlclient/auto.go:706-714`). 저장된 상태가 있으면 첫 요청부터 싣는다(Swiftail의 선택. Go의 첫 요청이 싣는지는 확인하지 못했다, 9절).
5. **실패**(4.7 5): RPC 실패, 응답 해독 실패, 검증 실패는 종류만 로그에 남긴다. `run()`을 끝내지 않는다. 로컬 상태가 있으면 예전 상태로 계속 거른다. 다음 netmap이 오거나 서버가 알린 머리가 바뀌면 다시 시도한다. TKA RPC에는 429·`Retry-After` 처리가 없다(3.10).
6. **`.unverified`**(사용자 확인 필요 U1): 서버가 켜졌다고 알리고 capability가 있는데 절차가 끝난 뒤에도 로컬 상태가 없으면(부트스트랩 실패), 또는 저장된 상태를 열지 못했으면, 피어를 비운 netmap을 내고 `mode`를 `.unverified`로 한다. Go는 이때 거르지 않고 모든 피어를 받아들인다(4.7 끝). 부트스트랩 실패는 다음 netmap을 기다리지 않고 물러나며 다시 시도한다(5초에서 두 배씩, 5분까지. Swiftail의 선택: 닫힌 쪽에서는 다음 netmap까지 피어가 없기 때문이다). 열지 못한 저장소는 다시 시도해도 같으므로 시도하지 않는다(동작 T4).
7. **시작**: `run()`이 첫 연결 전에 저장소를 연다(동작 T3). 연결이 끊겨 다시 이어도 메모리의 상태는 그대로 쥔다.

### Y. 동기화

`Authority`가 있을 때(4.8).

1. **제안**: `head`는 로컬 머리. `ancestors`는 머리에서 거꾸로 가며(최대 1,000) 만나는 체크포인트 AUM의 해시(새것부터, 뿌리는 빼고), 끝에 뿌리의 해시.
2. `/machine/tka/sync/offer`로 보낸다. 응답의 `Head`·`Ancestors`를 `AUMHash(text:)`로 읽는다(읽히지 않으면 실패).
3. 서버 머리가 로컬 머리와 같으면 **여기서 끝낸다**(send를 보내지 않는다).
4. 서버가 모르는 로컬 AUM을 **먼저** 계산한다(`missingAUMs(for:)`, 결정 L8): 서버 머리가 로컬에 있으면 로컬 머리에서 거꾸로(최대 1,000) 가며 찾아 머리 교차. 아니면 서버 `ancestors`를 앞에서부터 보며, 그 AUM의 상태에서 앞으로 감아(최대 2,000) 로컬 머리에 닿는 첫 것이 꼬리 교차. 서버 조상이 로컬에 없으면 다음 조상으로 넘어가고, 그 밖의 실패(반복 한도 등)는 곧바로 오류다. 교차가 없으면 `noIntersection`. 교차 AUM 다음부터 로컬 머리까지가 보낼 목록이다. **이 계산이 실패하면 동기화 전체를 끝낸다**: 5도 6도 하지 않는다.
5. 응답의 `MissingAUMs`가 있으면 모두 디코딩하고(하나라도 실패하면 오류) 동작 F4로 들인다. 통과하면 저장한다(동작 T2).
6. 로컬 머리와 4의 목록을 `/machine/tka/sync/send`로 보낸다(`Interactive` false, 목록이 비어도 `[]`). 응답 `Head`가 로컬 머리와 다르면 로그만 남긴다.
7. **RPC의 형식**(3.10): 셋 다 Noise 채널 위의 **`GET`이고 본문에 JSON**을 싣는다. `Content-Type`과 부하 분산 머리를 붙이지 않는다. `Version`은 148, `NodeKey`는 `nodekey:` 텍스트, JSON 키는 Go 필드 이름 그대로다. `TKABootstrapRequest.Head`는 비어도 `""`로 늘 있다. `MissingAUMs`와 `GenesisAUM`·`DisablementSecret`은 base64다. 요청마다 시한 60초. 200이 아니면 실패이고 본문은 로그에 남기지 않는다(Swiftail의 선택. Go는 본문을 오류에 담는다). 응답 본문 한도는 동작 M.

### P. 피어 거르기

`mode`가 `.enforcing`일 때 netmap마다 **전체를 다시** 거른다(4.9. 결정 L11).

1. `UnsignedPeerAPIOnly` 피어는 거르지 않는다(lock 대상이 아니다). netmap에는 남고, 엔진은 지금처럼 올리지 않는다(`Sources/SwiftailEngine/EnginePeer.swift:94-103`). 그래서 Go가 그런 피어와 패킷 필터가 겹칠 때 필터를 비우는 안전장치(4.9 끝)는 필요 없다.
2. `KeySignature`가 비었으면 뺀다.
3. 동작 S가 실패하면 뺀다.
4. **회전으로 낡은 키**(4.9 4 `rotationTracker`): 통과한 rotation 서명의 `previousNodeKeys`에 든 키는 모두 낡은 키다. `initialSignature`가 direct인 rotation들을 그 `WrappingPubkey`로 묶고(이미 낡은 키로 표시된 것은 빼고), 한 묶음에 여럿이면 `previousNodeKeys`가 가장 많은 하나만 남기고 나머지를 낡은 키로 한다. 가장 많은 것이 둘 이상 같으면 그 묶음 전부를 낡은 키로 한다. credential에서 시작한 사슬은 묶지 않는다.
5. 2·3에서 뺀 피어와 낡은 키를 가진 피어를 순서를 지키며 netmap에서 지운다. 지운 수가 `filteredPeerCount`다. 그 피어의 주소는 `whoIs`와 MagicDNS에서도 없는 노드다(둘 다 netmap을 읽는다).
6. **자기 노드**는 빼지 않는다. 자기 node 키와 자기 `KeySignature`가 동작 S를 통과하지 못하면 `signingRequest`를 채운다(Go의 `LockedOut` 건강 경고. 4.6 3, 4.9 6). 이때 서명된 피어는 netmap에 남지만, lock을 지키는 피어가 이 노드를 빼므로 통신은 되지 않는다.
7. `.disabled`면 거르지 않는다. `.unverified`면 피어를 모두 뺀다(`UnsignedPeerAPIOnly` 포함. 동작 N6).
8. 거르기를 끄는 설정은 없다(4.9).

### O. lock이 꺼질 때

1. **세션의 처음부터 `TKAInfo`가 없는 것**은 "서버가 꺼졌다고 알림"이고, **도중에 빠진 것**은 "변화 없음"이다(4.10 1, 동작 N1). 그래서 켜진 상태에서 `TKAInfo` 없는 증분을 받아도 아무 일도 하지 않고, 다시 이은 맵 스트림의 첫 응답에 `TKAInfo`가 없으면 2로 간다. `TKAInfo.Disabled`가 참이면 도중이어도 2로 간다.
2. 로컬 상태가 없으면 할 일이 없다. 있으면 부트스트랩 RPC를 **로컬 머리를 실어** 불러 `DisablementSecret`을 받는다(4.10 2).
3. 동작 X가 참이면 저장소를 지우고(동작 T5) 로컬 상태를 없앤 뒤 `TKAHead`를 비워 알린다. netmap은 거르지 않고 내고 `mode`는 `.disabled`다.
4. 거짓이면(틀린 비밀, 빈 비밀) 로그만 남기고 **lock을 유지한다**. 서버가 알린 머리(없음)와 로컬 머리가 다르므로 동기화(동작 Y)를 이어서 한다(4.10 3, `ipn/ipnlocal/tailnet-lock.go:410`, `:423`). 부트스트랩 RPC 자체가 실패하면 절차를 거기서 끝낸다(동작 N5). 어느 쪽이든 계속 예전 상태로 거른다.
5. `TKAInfo.Disabled`만 믿고 지우지 않는다. 끄기 값은 신뢰 체크포인트에 서명되어 있으므로, 비밀 검증이 제어 서버가 lock을 끄지 못하게 지킨다(4.10).
6. **Swiftail의 선택**: 한 연결에서 같은 비밀을 다시 받으면 KDF를 다시 돌리지 않는다(거절한 비밀의 BLAKE2s-256을 메모리에만 쥔다). 서버가 `Disabled`를 되풀이해 보내도 16MiB 계산이 netmap마다 돌지 않게 한다. 판정은 같다.

### T. 저장

1. **자리와 형식**(결정 L6): 상태 디렉터리의 파일 하나 `tailnet-lock.cbor`. 내용은 정준 CBOR 맵 `{1: 형식 버전(1), 2: 부트스트랩 AUM의 해시(32바이트), 3: [받아들인 AUM의 정준 바이트, 받아들인 순서]}`와 그 바이트의 BLAKE2s-256 32바이트를 이어 붙인 것이다. AUM을 정준 바이트로 두므로 다시 읽으면 해시가 같다(6.3). 신뢰 상태 자체는 저장하지 않고 열 때 다시 계산한다.
2. **쓰기**: 부트스트랩이 통과한 뒤, 들이기가 새 AUM을 받아들인 뒤에 파일 전체를 다시 쓴다. 같은 디렉터리의 임시 파일에 다 쓰고 0600으로 정하고 디스크에 내린 뒤 이름을 바꾼다(`NodeIdentityStore`와 같은 차례). iOS의 데이터 보호 등급과 백업 제외도 `identity.json`과 같게 건다(`SwiftailTunnel.md` 동작 P 2). **쓰기가 실패해도 판정은 바뀌지 않는다**: 메모리의 상태로 계속 거르고, 종류를 로그에 남기고, 다음 변화 때 다시 쓴다. 다시 시작하면 저장된 것까지만 이어 가고 동기화가 나머지를 채운다. 한 번도 쓰지 못했으면 다시 시작할 때 부트스트랩부터 한다(Go가 상태 디렉터리 없이 메모리 저장소를 쓸 때와 같다, 3.11).
3. **읽기**: 파일이 없으면 로컬 상태 없음이다. 있으면 크기 한도(동작 M), 끝 32바이트의 해시, CBOR, 형식 버전, AUM마다 동작 D, 그리고 동작 F6을 차례로 본다.
4. **열지 못함**: 3의 어느 것이든 실패하면 파일을 고치거나 지우지 않고 `mode`를 `.unverified`로 한다(동작 N6. 사용자 확인 필요 U1). 서버가 lock이 꺼졌다고 알려도 같다: 끄기 값을 모르므로 그 말을 확인할 수 없다. 풀려면 앱이 노드를 멈추고 그 파일을 지운다. 그러면 다음 시작에 다시 부트스트랩한다. Go는 이때 저장소를 고칠 때까지 거르지 않는다(4.7 끝).
5. **지우기**: 끄기 비밀이 맞았을 때만 파일을 지운다(동작 O3). 지우지 못하면 메모리의 상태는 없애고 로그를 남기며, 다음 시작에 그 파일이 다시 열려 lock이 유지된다(닫힌 쪽).
6. `shortcut:` 한 상태 디렉터리로 다른 tailnet에 다시 로그인하면 옛 tailnet의 상태가 남아 새 tailnet의 피어가 모두 걸러진다(Go는 프로필마다 따로 둔다, 3.11). 필요해지는 시점: 상태 디렉터리 하나로 tailnet을 바꾸는 사용처. 그 전에는 앱이 상태 디렉터리를 새로 쓴다(`SwiftailHost.md` U1의 답과 같다).

### M. 한도

| 항목 | 값 | 출처 | 넘으면 |
| --- | --- | --- | --- |
| CBOR 중첩, 배열, 맵 | 16단, 4,096개, 1,024쌍 | Go(5장) | 디코딩 거절 |
| `Key.Votes` | 1~4,096 | Go | 정적 검사 실패 |
| `Meta`의 키·값 길이 합 | 512바이트 | Go | 정적 검사 실패 |
| 체크포인트의 끄기 값, 키 | 1~32개, 1~512개 | Go | 정적 검사 실패 |
| 재서명 사슬의 이전 키 | 15개 | Go | 줄인다(동작 R7) |
| 동기화의 머리 교차, 꼬리 교차, 부모 상태 찾기 | 1,000 / 2,000 / 2,000 | Go | 그 계산 실패 |
| TKA RPC 시한 | 60초 | Go | 그 절차 실패 |
| 부트스트랩·sync/send 응답 본문 | 1MiB | Go | 실패 |
| sync/offer 응답 본문 | **8MiB** | Swiftail(Go는 512MiB. 맵 프레임 한도와 같게 낮춘다) | 실패 |
| AUM 하나의 바이트 | 512KiB | Swiftail(키 512개에 `Meta`를 가득 채운 체크포인트가 약 350KiB) | 디코딩 전에 거절 |
| NKS 하나의 바이트 | 8KiB | Swiftail(16겹이 약 3KiB) | 거절(그 피어는 빠진다) |
| 인증 키 문자열, 그 안의 credential | 16KiB, 8KiB | Swiftail | `invalidConfiguration` |
| 감싼 개인 키 | 정확히 64바이트 | Swiftail(동작 R3) | `invalidConfiguration` |
| 한 번에 들이는 AUM | 4,096개 | Swiftail | 그 묶음 거절 |
| 쥐는 AUM 전체 | 4,096개, 정준 바이트 합 16MiB | Swiftail(결정 L7) | 그 묶음 거절(`limitExceeded`). 예전 상태로 계속 거른다 |
| 저장 파일 | 17MiB | Swiftail | 열지 못함(동작 T4) |
| `.unverified`의 재시도 간격 | 5초~5분 | Swiftail | — |

Swiftail의 한도는 제안값이고 관문의 기록으로 조정한다. Go보다 낮은 한도는 닫힌 쪽이다: 넘으면 받지 않을 뿐, 거르기를 풀지 않는다.

### K. 비밀과 로그

1. 비밀은 NL 개인 키, 인증 키 전체와 그 안의 감싼 개인 키, 서버가 준 끄기 비밀이다. NL 키는 `identity.json`(0600)에만 있고 메모리에서는 CryptoKit의 키 타입으로 쥔다. 감싼 키는 `WrappedAuthKey` 안에만 있다. 끄기 비밀은 KDF에 넣은 뒤 버리고 저장하지 않는다.
2. `NodeIdentity`·`WrappedAuthKey`·`ControlClient.Configuration`의 `description`과 `dump`에 개인 키·감싼 키·인증 키가 나오지 않는다(`CustomReflectable`). `TailnetLockStatus`가 담는 것은 공개 키와 해시뿐이다.
3. 감싼 개인 키는 어떤 요청에도 실리지 않는다(동작 R4). 시험이 등록 요청의 바이트에서 이것을 확인한다.
4. 비밀과 견주는 곳은 끄기 값 하나이고 상수 시간 비교를 쓴다(동작 X1). 감싼 키의 공개 키 일치(동작 R3)는 공개 값의 비교다.
5. 로그(`os.Logger(subsystem: "Swiftail")`, 범주 `tailnet-lock`)에 남기는 것: `mode`의 변화, 절차의 종류와 실패의 종류, 들인 AUM 수, 거른 피어 수, 자기 노드의 잠김 여부. 남기지 않는 것: 키(공개 키 포함), 인증 키, 끄기 비밀, 서명과 AUM의 바이트, 서버 오류 본문, 피어의 이름·주소. 오류의 연관 문자열에 키·경로를 넣지 않는다.
6. 저장 파일에는 비밀이 없다(AUM은 공개 키와 서명, 끄기 값은 KDF의 출력이다). 그래도 0600으로 둔다: 바꿔 넣으면 신뢰 상태가 바뀐다.

## 4. C API·Go 동작 대응표

첫 사용처의 C 함수 18개(`SwiftailHost.md` 4절) 가운데 lock에 닿는 것은 셋이다.

| 함수 | Go 코어가 하는 일 | 바뀐 뒤 |
| --- | --- | --- |
| `rd_start` | 설정의 `AuthKey`를 tsnet에 넘긴다. `--TL`이 붙은 키면 tsnet이 서명을 만들어 등록한다 | `NodeConfiguration.authKey`에 같은 문자열을 넘긴다(동작 R3~R5). 형식이 틀리면 `run()`이 `NodeError.invalidConfiguration`을 던진다 |
| `rd_status` | lock 상태를 싣지 않는다. 시작마다 한 번 `LocalClient.NetworkLockStatus`를 불러 켜짐·머리 유무·자기 서명 여부·신뢰 키 수·거른 피어 수를 로그에 남긴다(RemoteDebug `core/internal/node/node.go:492-504`) | `node.status.tailnetLock`(`mode`, `head`, `filteredPeerCount`, `signingRequest`). 신뢰 키 수는 싣지 않는다 |
| `rd_next_event` | lock에 관한 사건이 없다 | `NodeEvent.tailnetLockChanged` |

Go 함수와 Swiftail의 대응(출처 줄은 노트의 것이고, `tkaSyncLocked`의 시작 줄과 testcontrol은 이 문서가 직접 읽었다):

| Go | 출처 | Swiftail |
| --- | --- | --- |
| `cbor.CTAP2EncOptions`, `cborDecOpts` | `cbor/encode.go:641-660`, `tka/tka.go:22-32` | `CBORWriter`, `CBOR.decode`(동작 E·D) |
| `AUM.Serialize`·`Unserialize` | `tka/aum.go:249-271` | `AUM.serialized()`, `AUM(decoding:)` |
| `AUM.Hash`·`SigHash` | `tka/aum.go:273-288` | `AUM.hash`, `AUM.signatureHash` |
| `AUM.StaticValidate`, `Key.StaticValidate`, `staticValidateCheckpoint` | `tka/aum.go:159-222`, `tka/key.go:107-132`, `tka/state.go:258-316` | `AUM.validate()`, `TrustedKey.validate()`(동작 A1) |
| `AUMHash.MarshalText`·`UnmarshalText` | `tka/aum.go:24-51` | `AUMHash.text`, `AUMHash(text:)` |
| `aumVerify`, `signatureVerify` | `tka/tka.go:421-468`, `tka/verify.go:17-36` | `Authority`의 안쪽(동작 A2~A5) |
| `State.applyVerifiedAUM` | `tka/state.go:157-254` | `AuthorityState.applying(_:)`(동작 A6) |
| `AUM.Weight`, `pickNextAUM`, `fastForward`, `computeStateAt` | `tka/aum.go:316-361`, `tka/tka.go:122-331` | `Authority`의 안쪽(동작 F1~F3) |
| `Bootstrap` | `tka/tka.go:527-565` | `Authority(bootstrappingWith:)`(동작 F5) |
| `Open`, `computeActiveChain` | `tka/tka.go:68-120`, `:333-419`, `:476-498` | `Authority(opening:bootstrap:)`(동작 F6. 뿌리 하나로 좁혔다) |
| `Inform` | `tka/tka.go:584-676` | `Authority.inform(_:)`(동작 F4) |
| `SyncOffer`, `MissingAUMs`, `computeSyncIntersection` | `tka/sync.go:65-261` | `Authority.syncOffer()`, `missingAUMs(for:)`(동작 Y1·Y4) |
| `NodeKeyAuthorizedWithDetails`, `verifySignature`, `rotationDetails` | `tka/tka.go:685-711`, `tka/sig.go:247-348` | `Authority.authorize(_:keySignature:)`(동작 S) |
| `DisablementKDF`, `ValidDisablement` | `tka/state.go:114-141` | `Authority.isValidDisablement(secret:)`(동작 X) |
| `DecodeWrappedAuthkey`, `SignByCredential` | `tka/sig.go:439-498` | `WrappedAuthKey(parsing:)`, `keySignature(for:)`(동작 R3·R5) |
| `ResignNKS`, `maybeTrimRotationSignatureChain` | `tka/sig.go:350-437` | `NodeKeySignature.resigned(_:for:with:)`(동작 R7) |
| `doLogin`의 NL 키·서명·감싼 키, `doLoginOrRegen` | `control/controlclient/direct.go:534-545`, `:643`, `:704-747`, `:763-783` | `ControlClient`의 등록(동작 R) |
| `mapSession`의 `lastTKAInfo`, `TKAEnabled`·`TKAHead` | `control/controlclient/map.go:99`, `:516-518`, `:1039-1047` | `MapSession`의 `serverLock`(동작 N1) |
| `SetTKAHead`, `MapRequest.TKAHead` | `control/controlclient/auto.go:706-714`, `direct.go:476-489`, `:1103` | `MapRequest.tkaHead`와 상태 올리기(동작 N4) |
| `tkaSyncIfNeeded` | `ipn/ipnlocal/tailnet-lock.go:340-437` | `TailnetLockPlan`과 `ControlClient`의 절차(동작 N) |
| `tkaBootstrapFromGenesisLocked` | `ipn/ipnlocal/tailnet-lock.go:536-584` | 동작 N2의 `bootstrap` |
| `tkaSyncLocked` | `ipn/ipnlocal/tailnet-lock.go:444-511` | 동작 Y |
| `tkaApplyDisablementLocked` | `ipn/ipnlocal/tailnet-lock.go:513-526` | 동작 O |
| `tkaFetchBootstrap`, `tkaDoSyncOffer`, `tkaDoSyncSend` | `ipn/ipnlocal/tailnet-lock.go:1377-1516` | `ControlClient.tkaBootstrap`·`tkaSyncOffer`·`tkaSyncSend`(동작 Y7) |
| `tkaFilterNetmapLocked`, `rotationTracker` | `ipn/ipnlocal/tailnet-lock.go:189-338` | `Authority.admitted(_:)`와 `ControlClient`의 거르기(동작 P) |
| `tkaFilterDeltaMutsLocked` | `ipn/ipnlocal/tailnet-lock.go:137-183` | 없다. netmap마다 전체를 거른다(결정 L11) |
| `initTKALocked`, tailchonk(`FS`) | `ipn/ipnlocal/tailnet-lock.go:83-125`, `tka/tailchonk.go` | `TailnetLockStore`(동작 T. 형식이 다르다) |
| `NetworkLockStatus` | `ipn/ipnlocal/tailnet-lock.go:641-668` | `TailnetLockStatus` |
| `Compact` | `tka/tailchonk.go:745-1048` | 없다(결정 L7) |
| 서명 기기의 것(`TailnetLockSign`·`Init`·`Modify`·`Disable`, `UpdateBuilder`, `MakeRetroactiveRevocation`, `TailnetLockWrapPreauthKey`) | `ipn/ipnlocal/tailnet-lock.go:696-1300`, `tka/builder.go`, `tka/tka.go:750-860` | 없다(1절) |

## 5. 결정

권고의 기준: **Go와 같은 판정이 기본**이다. Go가 열린 쪽으로 실패하는 곳에서만 닫힌 쪽을 검토했고, 닫힌 쪽으로 바꾸면 가용성이 달라지는 것은 "사용자 확인 필요"로 뺐다.

### 총괄 확인 필요

| # | 무엇 | 선택지 | 권고와 까닭 |
| --- | --- | --- | --- |
| L1 | 타깃 구성 | (가) 새 타깃 `SwiftailTKA`(`package`, 제품 아님) + `SwiftailControl`·`Swiftail` 보탬 / (나) `SwiftailControl` 안의 폴더 / (다) CBOR은 `SwiftailBase`, 나머지는 `SwiftailControl` | **(가)**. "타깃과 의존 방향"의 네 까닭. 대가: `Package.swift`에 타깃 둘(시험 포함), `SwiftailControl`의 의존 하나 |
| L2 | 절차와 거르기를 누가 하는가 | (가) `ControlClient`: 거른 netmap만 낸다 / (나) 노드(`Swiftail`): 제어는 RPC만 내준다 | **(가)**. RPC의 연결과 `TKAHead`를 `ControlClient`가 쥐고 있고, `SwiftailControl`만 쓰는 사용자에게도 거르지 않은 netmap이 나가지 않는다. 사건 버퍼가 넘쳐 오래된 사건이 버려져도 netmap이 lock 상태를 함께 싣고 있어 어긋나지 않는다 |
| L3 | 절차와 맵 스트림의 차례(동작 N3) | (가) 절차는 따로 돌고, 절차가 필요한 netmap만 끝날 때까지 쥔다 / (나) 맵을 읽는 루프 안에서 차례로 돈다(Go와 같은 모양) | **(가)**. (나)는 RPC 셋(각 60초)을 도는 동안 맵 스트림을 읽지 않아 120초 감시에 걸리고, `.unverified`의 재시도(동작 N6)를 넣을 자리가 없다. 대가: "쥔 netmap"이라는 상태 하나. 어디서 도는지(기존 신호 통로, 따로 둔 Task)는 TL-7이 정하되 상태 올리기의 물러나기에 막히지 않아야 한다 |
| L4 | 자기 노드의 잠김을 앱에 알리는 길 | (가) `NodeStatus.tailnetLock` + `NodeEvent.tailnetLockChanged`. `NodeState`는 그대로 / (나) `NodeState`에 `.needsLockSignature`를 더한다(`needsMachineAuth`와 같은 자리) | **(가)**. Go의 상태(`ipn.State`)도 잠긴 노드를 `Running`으로 두고 건강 경고로 알린다(노트 4.6 3). (나)는 `.running`에 기대는 곳(`connect(to:port:)`의 `notRunning`, 인증서 발급의 `nodeNotRunning`)이 잠긴 동안 막혀 Go와 달라지고, `.unverified`는 따로 알릴 길이 또 필요하다. 대가: 사건을 듣지 않는 앱은 `.running`인데 통신이 안 되는 까닭을 모른다(첫 사용처 확인 필요 F2) |
| L5 | `ControlError.tailnetLockEnabled` | (가) 없앤다 / (나) 쓰지 않는 채로 남긴다 | **(가)**. 던지는 곳이 없어진다. 대가: 그 case를 `switch`에 적은 코드가 컴파일되지 않는다(이 저장소 세 곳과 첫 사용처 한 곳. "지금 lock 처리가 있는 곳") |
| L6 | 저장 형식과 위치(동작 T) | (가) 상태 디렉터리의 파일 하나(`tailnet-lock.cbor`, 0600, 원자적 쓰기, 끝에 해시) / (나) 하위 디렉터리(0700)에 AUM마다 파일 하나(0600)와 뿌리 파일(tailchonk의 모양) | **(가)**. 자료가 작고(체크포인트 하나가 수백 바이트~수십 KiB) 드물게 바뀐다. 파일 하나를 통째로 바꾸면 AUM 집합과 뿌리 기록이 어긋난 채 남는 상태가 없다. Go와 형식을 맞출 까닭이 없다(이관하지 않는다). 대가: 변화마다 전체를 다시 쓴다. (나)는 디렉터리 권한 검사(이미 있는 디렉터리를 남이 쓸 수 있는지)와 파일 사이의 일관성 검사가 더 든다 |
| L7 | 압축 | (가) 하지 않는다. 한도(4,096개·16MiB)로 묶는다 / (나) Go처럼 동기화마다(`MinChain` 24, `MinAge` 14일) | **(가)**. 저장이 자라는 양: 키 변경 하나에 AUM 하나(약 100~200바이트), 50개마다 체크포인트 하나(키 10개면 약 0.6KiB, 512개면 수십 KiB). 키 10개인 tailnet의 변경 1,000번이 약 160KiB다. 압축하지 않으면 저장소의 뿌리가 늘 부트스트랩 AUM 하나라, Go `Open`의 조상 고르기(노트 8.2의 미확인 항목)를 구현하지 않아도 된다. **판정의 차이**: 압축한 Go 노드는 오래된 갈래의 부모를 잊어 그 갈래의 AUM이 든 묶음을 거절하지만, Swiftail은 받아들인다. 받은 지 14일이 안 된 Go 노드와 같은 판정이다(노트 4.11). 한도에 닿으면 새 AUM을 받지 못해 상태가 멈춘다(닫힌 쪽) |
| L8 | `MissingAUMs` 계산(동작 Y4) | (가) 구현한다(약 150줄) / (나) 늘 빈 목록을 보낸다 | **(가)**. 생략하면 Go가 동기화를 멈추는 조건(교차 계산 실패 → `Inform`도 send도 하지 않음, 노트 4.8 4)이 달라지고, 모든 경우에 결과가 같은지 노트가 확인하지 못했다(6.3). 같은 판정이 기준이므로 넣는다 |
| L9 | 재서명과 검증되지 않는 서명(동작 R7) | (가) Go와 같이 만들어 보낸다. 검증되지 않을 것을 알면 로그에 남긴다 / (나) 회전 키가 자기 NL 키가 아니면 서명 없이 등록한다 / (다) 그때 감싼 인증 키가 있으면 `SignByCredential`로 새 서명을 만든다 | **(가)**. 재서명은 넣는다(노트 6.3 필수). 다른 노드의 판정은 (가)와 (나)가 같고(둘 다 잠긴다), 운영 서버가 검증되지 않는 서명과 빈 서명을 달리 다루는지 모르므로(9절) 선에 나가는 것을 Go와 같게 둔다. (다)는 Go보다 나은 결과를 내지만 Go에 없는 등록 경로다. 필요해지는 시점: `--TL`로 등록한 노드의 키 교체가 실제로 잠김을 일으킬 때 |
| L10 | 종류 0(`AUMInvalid`)의 AUM | (가) Go처럼 부모 없는 자리가 아니면 받아들인다 / (나) 거절한다 | **(가)**. 거절하면 그런 AUM이 든 사슬에서 Swiftail의 상태가 그 앞에 멈추고, 그 뒤의 키 제거를 따라가지 못해 Go보다 **더 많은** 키를 믿게 된다(노트 6.1의 CryptoKit 경로와 같은 실패 모양). 엄격해 보이는 쪽이 열린 쪽이다. 이런 AUM은 신뢰 키를 가진 쪽만 만든다 |
| L11 | 증분에서의 거르기 | (가) netmap마다 전체를 거른다(낡은 키 포함) / (나) Go처럼 증분에서는 서명 검증만 | **(가)**. `MapSession`이 응답마다 전체 netmap을 내므로 증분 경로가 따로 없다. Go는 증분으로 들어온 낡은 키의 피어를 다음 전체 netmap까지 남긴다(노트 4.9). Swiftail은 곧바로 뺀다. Go가 전체 netmap에서 내리는 판정과 같고, 그 사이에만 더 닫혀 있다 |
| L12 | `--TL` 뒤가 해석되지 않는 인증 키(동작 R3) | (가) 등록 전에 `invalidConfiguration` / (나) Go처럼 원문 전체를 인증 키로 보낸다 / (다) 지금처럼 앞부분만 보내고 서명 없이 등록 | **(가)**. (나)는 감싼 개인 키를 서버로 보낸다. (다)는 사용자가 서명된 키를 넘겼는데 조용히 잠긴 노드가 된다 |
| L13 | 감싼 개인 키의 검사(동작 R3) | (가) 64바이트, 시드의 공개 키 = 뒤 32바이트 = credential의 `WrappingPubkey` / (나) 길이만 | **(가)**. Go는 길이가 틀리면 panic하고, 뒤 32바이트를 다시 계산하지 않는다(노트 3.8). 어긋난 키로 만든 서명은 검증되지 않으므로 등록 전에 알린다 |
| L14 | 저장소를 열 때의 재검증(동작 F6) | (가) 정적 검사와 서명 검증을 다시 한다 / (나) Go처럼 적용만 다시 한다 | **(가)**. 받아들일 때와 같은 규칙이라 판정은 같고, 파일이 바뀌어 든 것을 서명까지 본다. 비용은 시작할 때 AUM 수만큼의 Ed25519 검증이다 |
| L15 | 관문 (가)의 testcontrol 보탬(7절) | (가) testcontrol을 `Tools/interop/internal/testcontrol`로 옮겨 적고(약 2,000줄, BSD-3-Clause 머리말) sync/send·disable·끄기 비밀·등록 서명을 더한다 / (나) 빌드할 때 `-overlay`로 파일 하나를 testcontrol 패키지에 얹는다(`mapfixtures`의 방식) / (다) 더하지 않고 genesis 하나뿐인 lock만 관문에서 본다 | **(가)**. testcontrol의 TKA 저장소(`tkaStorage`)와 Noise 안쪽 mux는 밖에서 닿지 않는다(`tstest/integration/testcontrol/testcontrol.go:199-201`, `:476-503`). 처리기 없는 `/machine/tka/sync/send`는 프로세스를 panic시킨다(노트 7.3). (나)는 줄 수가 적지만 `tailnet` 도구의 빌드가 모듈 사본과 overlay에 묶이고 `go vet ./...`가 깨지지 않게 빌드 태그로 갈라야 한다. (다)는 사슬이 자란 뒤의 동기화와 끄기를 관문에서 볼 수 없다. 대가: 기준 버전을 올릴 때 사본을 다시 맞춘다 |
| L16 | Go보다 낮춘 한도(동작 M) | sync/offer 응답 8MiB(Go 512MiB), AUM 512KiB, 쥐는 AUM 4,096개·16MiB | 표의 값으로 시작한다. iOS 확장의 메모리 한도 때문이다. 넘으면 받지 않을 뿐 거르기를 풀지 않는다. 대가: 아주 오래 떨어져 있던 노드가 한 번에 받을 AUM이 한도를 넘으면 따라잡지 못한다 |
| L17 | Go에 없는 보탬 | `.unverified`의 재시도(동작 N6), 같은 끄기 비밀의 재계산 생략(동작 O6), 첫 요청부터 `TKAHead`(동작 N4), 두 번째 재서명 요청의 처리(동작 R6), `LastAUMHash`가 있는 체크포인트를 디코딩에서 거절(동작 D8) | 넣는다. 판정을 바꾸지 않거나 닫힌 쪽이다. N6은 U1이 Go와 같은 쪽으로 정해지면 뺀다 |

### 사용자 확인 필요

닫힌 쪽으로 바꾸면 "Go 노드는 통신되는데 Swiftail 노드는 안 되는" 때가 생기는 것들이다.

| # | 무엇 | 선택지와 영향 | 권고 |
| --- | --- | --- | --- |
| U1 | lock이 켜졌는데 검증된 상태가 없을 때(동작 N6·T4) | **(가) Go와 같이 통과(fail-open)**: 부트스트랩이 실패하거나 저장된 상태를 열지 못하면 거르지 않고 모든 피어를 받아들인다. 저장소가 깨진 경우는 고칠 때까지 계속된다(노트 4.7 끝). 가용성은 Go와 같다. 그동안 lock의 보호가 없다: 제어 서버가 부트스트랩을 실패시키기만 하면 서명 없는 노드를 netmap에 넣을 수 있다. / **(나) 피어를 올리지 않음(fail-closed)**: 그동안 `mode`가 `.unverified`이고 피어가 없다. 부트스트랩 실패는 5초~5분 간격으로 다시 시도한다. 저장소를 열지 못한 경우는 앱이 `tailnet-lock.cbor`를 지워야 풀린다(지우면 다시 TOFU로 시작한다). 영향: 제어 서버의 TKA RPC가 일시적으로 실패하는 동안, 그리고 파일이 깨졌을 때 Go 노드는 통신되고 Swiftail 노드는 안 된다. 이것이 운영에서 얼마나 일어나는지는 모른다(노트 8.2) | **(나)**. lock을 켠 tailnet의 관리자가 기대하는 것은 "서명 없는 노드와 통신하지 않는다"이고, Go의 이 동작은 그것이 깨지는 길이다. 처음 등록할 때의 부트스트랩은 한 번이고, 그 뒤로는 저장된 상태로 거른다(동기화 실패는 예전 상태로 계속 거르므로 가용성이 줄지 않는다) |
| U2 | `tailnet-lock` capability가 없는 노드(동작 N2의 첫 줄) | **(가) Go와 같이**: 로컬 상태가 없고 capability가 없으면 서버가 lock이 켜졌다고 알려도 부트스트랩하지 않고 거르지 않는다(노트 4.12). / **(나)** capability와 무관하게 서버가 켜졌다고 알리면 부트스트랩하고 거른다. 영향: 운영 서버가 capability를 어느 노드에 주는지 모른다(노트 8.2). 일부 노드에만 준다면 (나)에서 그 밖의 노드가 부트스트랩 RPC를 거절당할 수 있고, U1이 (나)면 그 노드는 피어가 없다 | **(가)**. 서버의 뜻을 모르는 채로 닫으면 lock을 쓰지 않는 노드까지 멈출 수 있다. 관문 (나)에서 실제 tailnet의 노드가 capability를 받는지 기록하고 다시 본다 |
| U3 | 실제 tailnet 관문에 내줄 것 | 7절 관문 (나)의 "사용자에게 받을 것": lock이 켜진 tailnet, 서명 기기에서 만든 서명된 인증 키, 서명 기기에서의 `tailscale lock sign` 한 번 | — |

**사용자의 답(2026-11-15)**:

- U1: **(나) 피어를 올리지 않는다.** 검증된 상태가 생길 때까지 `mode`는 `.unverified`이고 피어가 없다. 동작 N6의 재시도가 선다(L17).
- U2: **(가) Go와 같이.** 관문 (나)에서 lock이 켜진 실제 tailnet의 노드가 `tailnet-lock` capability를 받는지 기록하고, 늘 받는다면 닫힌 쪽으로 바꿀지 다시 묻는다.
- U3: 관문 (나) 때 요청한다. 첫 사용처의 Mac 호스트가 속한 tailnet은 lock이 켜져 있다(plan 7절 M8).
- 그에 앞선 결정: Ed25519 검증은 순수 Swift로 직접 구현한다(노트 6.1의 (나). `SwiftailCrypto`의 `Ed25519Verification`).

**총괄 확정(2026-11-15)**: L1~L17은 모두 권고대로 간다. 덧붙이는 것:

- TL-0에서 2절 선언의 빈 껍데기는 만들지 않는다. 단위가 순서대로(TL-1 → TL-2 → TL-3·4) 들어오므로 앞 단위의 실제 선언이 뒤 단위의 접점이 된다. `Package.swift`의 타깃과 자리표 파일만 둔다.
- L16의 한도를 넘어 따라잡지 못하는 노드는 예전 상태로 계속 거른다(열리지 않는다). 그 경우를 로그에 남긴다(동작 K5의 "절차의 종류와 실패의 종류").
- F1~F3은 첫 사용처 세션에 보냈다. 답이 오기 전에도 `SwiftailTKA`(TL-1~TL-5)는 진행한다. F의 답이 바꾸는 것은 `Swiftail`의 표면(TL-8)뿐이다.

### 첫 사용처 확인 필요

| # | 질문 | 초안의 가정 | 답에 따라 달라지는 것 |
| --- | --- | --- | --- |
| F1 | `ControlError.tailnetLockEnabled`가 없어진다. iPhone 터널 앱의 `Apps/iOSTunnel/SwiftailTunnelEngine.swift:180`이 그 case에 문구를 붙이고 있다. 지워도 되는가 | 된다(그 줄만 지우면 된다) | L5. 남겨야 하면 쓰지 않는 case로 둔다 |
| F2 | 잠긴 노드는 `.running`이고 `tailnetLock.signingRequest`가 있다. Mac 호스트와 터널 앱이 `tailnetLockChanged`를 듣고 "서명 기기에서 `tailscale lock sign <nodeKey> <lockKey>`를 돌리라"는 안내를 띄울 수 있는가. `.unverified`(피어 없음)에도 문구가 필요하다 | 띄운다 | L4. 상태 하나로 받고 싶으면 (나)를 다시 본다 |
| F3 | Mac 호스트를 새 노드로 등록할 때(`SwiftailHost.md` U1) 어느 길을 쓰는가: 서명된 인증 키(`--TL`)인가, 로그인한 뒤 서명 기기에서 서명하는 것인가 | 둘 다 된다 | 관문 (나)의 차례. 서명된 인증 키는 1회용이면 다시 등록할 때마다 새로 만들어야 한다 |

### 구현하며 정해진 것

- **TL-1(CBOR, 2026-11-15)**: `CBORValue.null`이 undefined(0xf7)도 담는다(위 선언). `CBOR.decode`는 중복 키를 거절하지 않는다: 모르는 필드의 값 안쪽 중복은 Go도 받아들이므로, 구조 맵과 `Meta`의 중복(동작 D4)은 자료 형식(TL-2)이 거절한다. 맵은 받은 순서와 중복을 그대로 쥔다. 쓰기는 쌍의 순서를 부르는 쪽에 맡긴다(동작 E3의 `Meta` 순서는 TL-2). AUM 512KiB·NKS 8KiB 한도(동작 D9·M)는 구조마다 달라 TL-2가 `CBOR.decode`를 부르기 전에 본다. 거절의 까닭이 Go와 갈래가 다른 곳 둘(2^63 이상의 길이·원소 수. 둘 다 거절)은 판정에 영향이 없다. 실행으로 확정하지 않은 디코더 입력(예약된 추가 정보 28~30, major 0·1·6의 31, 짝 없는 `ff`, 두 바이트로 쓴 32 미만 단순값, undefined 키)은 TL-5의 도구가 확정한다.

- **TL-5 도구(`tkafixtures`, 2026-11-15)**: Go `tka`의 판정 426개를 `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json`에 넣었다(go1.27.3, `tailscale.com` v1.104.6). 실행해 보니 초안과 다르게 Go가 받아들이는 디코더 입력이 있어 동작 D1·D2·D4·D5·D7과 E6을 고쳤다(맨 바깥 null, 바이트열 자리의 정수 배열, `Meta`의 null, null 공개 키와 빈 공개 키의 KeyID). 그 밖의 확정: 음수 키는 −2^63까지 받고 그 아래는 거절, 중첩 16단·맨 바깥 맵 1,024쌍까지, `AUMHash` 텍스트의 끝 글자는 남는 비트를 검사하지 않는다(`A`·`B`·`P`는 같은 해시). 의도된 차이로 남는 것: Go는 `nlpriv:`의 뒤 32바이트를 검사하지 않고 Swiftail은 검사한다(동작 R1). 감싼 키가 63바이트일 때 Go는 panic한다(노트가 적은 메시지와 문구만 다르다). 도구가 뽑지 못한 것: 부모 없는 자리의 RemoveKey(공개 API로 닿지 않는다).

### 첫 사용처 검토 결과 (2026-11-15)

첫 사용처 세션(RemoteDebug)이 L4·L5와 "지금 lock 처리가 있는 곳"을 읽고 답했다.

- **F1**: 지운다(L5 (가)). 그쪽에서 그 case를 적은 곳은 `Apps/iOSTunnel/SwiftailTunnelEngine.swift`의 두 군데(`kind(of:)`, `message(for:)`)이고, TL-8의 커밋으로 올릴 때 그쪽이 두 갈래를 지운다.
- **F2**: (가)로 받는다. `NodeState`의 새 case는 필요 없다. 그쪽 어댑터는 `node.events`의 사건마다 `node.status`를 읽어 앱에 넘기므로, 새 안내 화면("서명 기기에서 서명 필요", "lock 상태를 확인하지 못해 연결을 열지 않음")은 그쪽이 만든다(Go 코어에는 없던 화면이다). 그 대신 계약이 지켜야 하는 것 넷(TL-7·TL-8의 요구이고 시험 21·22와 관문 (가) 2·3이 본다):
  1. **첫 `.running`과 lock 정보 사이에 틈이 없다.** 잠긴 노드가 `.running`이 되는 시점에 `NodeStatus.tailnetLock`이 이미 채워져 있다: 같은 netmap에서 나오는 사건은 `tailnetLockChanged`가 `stateChanged(.running)`보다 먼저이고, 어느 사건을 받은 시점에 읽은 `status`도 그 netmap의 lock 모습을 담고 있다. "연결됨"이 잠깐 보였다 안내로 바뀌지 않는다.
  2. **`status` 하나로 네 경우를 가른다**: lock 꺼짐(`mode == .disabled`) / 켜짐·내 노드 서명됨(`.enforcing`, `signingRequest == nil`) / 켜짐·서명 기다림(`.enforcing`, `signingRequest != nil`) / `.unverified`.
  3. **두 값은 `tailscale lock sign`에 그대로 붙여 넣는 문자열**이다(`nodekey:…`, `tlpub:…`. 2절의 선언대로 `String`). 둘 다 공개 키이므로 화면과 클립보드에 내도 된다. Swiftail은 로그에 남기지 않는다(동작 K5). 첫 사용처도 기기 로그에 올리지 않는다.
  4. **서명이 끝나면 다시 시작 없이 풀린다.** 서명 기기가 서명한 뒤의 netmap에서 `tailnetLockChanged`가 오고 `signingRequest`가 nil이 된다. 그 뒤 피어가 올라오는 것은 기존 사건으로 안다.
- **F3**: 사용자 결정이라 그쪽이 사용자에게 물었다(답 대기). 참고: 지금 Mac 호스트의 흐름은 브라우저 로그인이고 인증 키 입력 화면이 없다. 그래서 "로그인 뒤 서명 기기에서 서명"이 지금 화면과 가깝고 그 길에는 F2의 서명 안내 화면이 필요하다. 서명된 인증 키(`--TL`)의 길은 Mac에 인증 키 입력을 새로 만들어야 한다. Swiftail은 둘 다 지원한다(관문 (나) 1·2).

## 6. 첫 사용처가 고칠 것

계약의 일부가 아니라 F1~F3의 근거로 적는다. 저장소를 바꾸는 일은 별도 승인 뒤에 한다(plan 7절 M7).

- `switch`에서 `.control(.tailnetLockEnabled)` 갈래를 지운다.
- `node.events`에서 `.tailnetLockChanged`를 받는다. `signingRequest`가 있으면 두 값을 보여 준다(복사할 수 있게). `mode == .unverified`면 "tailnet lock 상태를 확인하지 못해 연결을 열지 않았다"는 뜻의 문구를 보인다.
- 상태 디렉터리를 지우는 "로그인 초기화"는 `tailnet-lock.cbor`도 함께 지운다(같은 디렉터리라 저절로 그렇게 된다).
- Go 코어의 lock 진단 로그(`core/internal/node/node.go:492-504`)는 Swiftail의 로그(동작 K5)가 대신한다.

## 7. 시험과 관문

### 단위 시험(소켓 없음, 시각 없음)

`Tests/SwiftailTKATests`(새 시험 타깃):

1. **CBOR 쓰기**: 정수 0·23·24·255·256·65,535·65,536·2^32−1·2^32·2^64−1의 최단 인코딩, 길이의 경계, null. 동작 E4의 기준 바이트 셋. `Meta{"bb","a","c"}`의 순서.
2. **CBOR 읽기의 받아들임·거절 표**(노트 8.1의 두 표가 기준값이다): 받아들임은 모르는 정수 키(값이 정수·실수·음수·true·undefined·잘못된 UTF-8 텍스트·중첩 맵), 모르는 음수 키, 모르는 텍스트 키(`"MessageKind"`·`"messagekind"`·`"1"`), 모르는 값 안쪽의 중복 키, 비최단 정수(값·키), 정렬 안 된 키, `PrevAUMHash` 생략, 종류 9, `MessageKind` null, 빈 `Meta`, 2^63−1 정수 키, 단순값 99·float64 값. 거절은 구조·`Meta`의 중복 키(알려진·모르는 정수·텍스트·음수), 길이 미정 맵과 바이트열, 태그(모르는 값 안의 `c24101` 포함), 뒤에 남은 바이트, 빈 입력, 맨 바깥 배열, 종류 256·음수·실수, `PrevAUMHash` 텍스트, `Meta`의 bstr 키·정수 키·bstr 값·정수 값·잘못된 UTF-8, 잘린 바이트열, bstr·실수(`f93c00`)·true·null·배열 키, 잘못된 UTF-8 텍스트 키(`61ff`), 2^64−1 정수 키, `Signatures`의 맵 아닌 원소, 중첩 16단(받음)과 17단, 배열 4,096개(받음)와 4,097개, 맵 1,024쌍(받음)과 1,025쌍. 한 바이트씩 자른 모든 접두와 임의 바이트로 죽지 않음.
3. **해시**: genesis 체크포인트(노트 7.1, 558바이트)의 재인코딩이 원본과 같고 `hash`가 `4a6313e0…eea8`, `signatureHash`가 `f34f12d8…f325`(8.1). 정준이 아닌 입력은 `hash ≠ BLAKE2s(원본)`. `AUMHash(text:)`: 소문자·패딩·51자·53자 거절, 끝 글자 `A`·`B`·`P`가 같은 해시이고 `Q`는 다른 해시.
4. **정적 검사**(동작 A1): 종류마다 필수·금지 필드, `Votes` 0·1·4,096·4,097, `Meta` 512·513바이트, 서명의 KeyID 31·33바이트와 서명 63·65바이트, 체크포인트의 끄기 값 0·1·32·33개와 31바이트·중복, 키 0·1·512·513개와 중복, 길이 0인 `PrevAUMHash`, 빈 맵 `Meta`의 UpdateKey.
5. **검증과 적용**(동작 A2~A7): 서명 없음, 모르는 키의 서명이 섞임, 틀린 서명, 33바이트 `PrevAUMHash`, 이미 있는 키의 AddKey, 없는 키의 RemoveKey·UpdateKey, 마지막 키 제거, StateID가 다른 체크포인트, 종류 0과 9가 머리를 옮김, 부모 없는 자리의 RemoveKey.
6. **갈래 해소**(동작 F1): 가중치가 큰 쪽, 같은 키의 서명 둘은 한 번, 같으면 RemoveKey, 같으면 해시가 작은 쪽. 갈래의 진 쪽에 자식이 붙어도 머리가 바뀌지 않음.
7. **들이기**(동작 F4): 빈 묶음, 부모 없는 AUM, 부모를 모르는 AUM, 이미 쥔 AUM, 묶음 가운데 하나가 틀리면 아무것도 들지 않음, 순서가 뒤바뀐 묶음, 갈래를 만드는 묶음 뒤의 머리.
8. **부트스트랩과 다시 열기**(동작 F5·F6): 체크포인트가 아닌 AUM, 자기 상태의 키로 서명되지 않은 체크포인트, 저장한 것을 다시 열면 같은 머리와 상태, 뿌리가 둘인 저장, 부모가 빠진 저장, 서명이 바뀐 저장.
9. **동기화 계산**(동작 Y1·Y4): 제안의 조상 목록(체크포인트 0·1·여럿, 1,000 너머), 머리가 같음, 머리 교차, 꼬리 교차, 교차 없음, 반복 한도.
10. **NKS**(동작 S): direct, rotation 1·15겹(통과)과 16겹, credential 혼자(거절), credential → rotation, 중간 `WrappingPubkey` 생략, 회전 키 없음, 다른 node 키, 신뢰 키가 아닌 KeyID, 지워진 키, `Nested`가 붙은 direct, 31바이트 신뢰 키, `np` 형식이 아닌 안쪽 `Pubkey`, 내력의 `previousNodeKeys` 순서. ZIP-215에서만 통과하는 서명(R에 위수 2인 점을 더한 것)이 direct에서는 통과하고 rotation의 바깥에서는 거절됨(노트 8.1).
11. **피어 집합**(동작 P2~P5): 서명 없음, 낡은 키, 같은 `WrappingPubkey` 묶음에서 내력이 긴 것만 남음, 길이가 같으면 모두 빠짐, credential 사슬은 묶이지 않음.
12. **끄기 비밀**(동작 X): 기준값, 틀린 비밀, 빈 비밀, 끄기 값 여럿 가운데 하나와 맞음.
13. **서명 만들기**(동작 R3·R5·R7): Go 시험의 감싼 인증 키 문자열(노트 7.1)의 해석. 거절: `-` 없음, 패딩 붙은 base64, URL 알파벳, credential이 아닌 A, 63·65바이트 B, 뒤 32바이트가 다른 B, `WrappingPubkey`가 다른 A, 한도 초과. 만든 서명이 `authorize`를 통과함. 재서명: 같은 키면 그대로, 회전 키가 NL 키인 direct는 통과, credential 사슬과 `WrappingPubkey` 없는 direct는 만들어지되 검증되지 않음, 16번째에서 줄어듦.
14. **한도와 비밀**: 동작 M의 Swiftail 한도 경계. `WrappedAuthKey`의 `description`·`dump`에 키 바이트가 없음.

`Tests/SwiftailControlTests`:

15. **신원**: NL 키의 왕복, `NLKey` 없는 옛 파일(새 키가 생기고 저장됨), 뒤 32바이트가 틀린 `nlpriv:`, `dump`에 NL 개인 키가 없음.
16. **등록 요청**(동작 R): `NLKey`가 0이 아님, 감싼 키로 만든 요청의 `Auth.AuthKey`가 앞부분뿐이고 **요청 바이트 어디에도 감싼 개인 키의 base64·16진이 없음**, `NodeKeySignature`가 base64인 NKS, 서명 없는 요청은 null, 잘못된 `--TL`은 요청이 나가기 전에 `invalidConfiguration`.
17. **`MapSession`의 `serverLock`**(동작 N1·O1): 첫 응답에 `TKAInfo` 없음(꺼짐), 있음, 도중에 빠짐(유지), `Disabled`, 읽히지 않는 `Head`(꺼짐), 빈 `Head`(켜짐·머리 없음), netmap은 그대로인데 `Head`만 바뀜.
18. **`TailnetLockPlan`**(동작 N2): 표의 여섯 줄과 머리의 바이트 비교.
19. **TKA RPC의 JSON**(동작 Y7): 요청 셋의 키 이름과 `"Head":""`·`"MissingAUMs":[]`, 응답의 base64 해독, 한도를 넘는 본문, 200이 아닌 응답. 메서드가 `GET`이고 `Content-Type`이 없음.
20. **저장**(동작 T): 쓰고 읽기, 0600, 끝 해시가 틀림, 잘린 파일, 모르는 형식 버전, 17MiB 초과, 쓰기 실패 뒤에도 메모리의 상태로 거름, 지우기.
21. **거르기와 상태**(동작 P·N6): `.disabled`·`.enforcing`·`.unverified`의 `peers`와 `filteredPeerCount`, `UnsignedPeerAPIOnly` 피어가 남음, 자기 서명이 없을 때의 `signingRequest`(`nodekey:`·`tlpub:` 텍스트).

`Tests/SwiftailTests`:

22. **노드**: `status.tailnetLock`이 netmap을 따라감, `tailnetLockChanged`가 바뀔 때만 나옴, 잠긴 노드의 상태가 `.running`까지 감.

### Go 기준값 대조

`Tools/interop/cmd/tkafixtures`(새 도구). `Tools/interop/README.md`의 기존 기준값 도구와 같은 규약이다: `sh Scripts/build-interop-tools.sh tkafixtures`로 빌드하고, 폴더 인자가 있으면 `Tests/SwiftailTKATests/Fixtures/tka-fixtures.json`을 쓰고 없으면 같은 JSON을 표준 출력에 쓴다. `reference`에 `go`·`tailscale` 버전을 적고 버전이 다르면 거절한다. Swift 소스는 읽거나 실행하지 않는다. 네트워크·현재 시각·외부 난수를 쓰지 않는다. 키는 `SHA-256("swiftail-fixtures/tka/<역할>/<번호>")`를 Ed25519 시드와 node 키 입력으로 쓴다(공개된 시험 전용 값). Go의 Ed25519 서명은 결정적이라 다시 만들면 같은 바이트가 나온다. 판정은 모두 Go `tka` 패키지의 공개 함수가 낸다(노트 7.2). 대조 시험(`GoComparisonTests.swift`)은 구현한 세션과 **다른 세션**이 쓴다.

| 배열 | 뽑는 것 | Swift가 견주는 것 |
| --- | --- | --- |
| `cbor` | 입력 hex마다 종류(AUM·NKS), `Unserialize`의 성공 여부, `StaticValidate`의 성공 여부, 성공하면 다시 인코딩한 바이트·`Hash`·`SigHash` | 정적 검사까지 통과한 입력은 바이트와 해시가 같다. 그 밖은 거절이라는 판정만(동작 E6·D8) |
| `chains` | 시나리오마다 부트스트랩 AUM과 단계(`Inform`에 넣는 AUM hex 목록, 성공 여부, 뒤의 머리, 뒤의 상태: 키의 KeyID·`Votes`·`Meta`, 끄기 값, StateID) | 단계마다 성공 여부와 머리·상태 |
| `sync` | 양쪽 저장소의 AUM 목록, 각자의 `SyncOffer`, 상대 제안에 대한 `MissingAUMs`(해시 목록 또는 오류), 받은 뒤의 머리 | 제안, 목록, 오류 여부, 머리 |
| `signatures` | (사슬의 어느 단계, node 키, NKS hex)마다 `NodeKeyAuthorizedWithDetails`의 판정과 내력(`PrevNodeKeys`, 처음 서명의 종류와 `WrappingPubkey`) | 판정과 내력 |
| `peerSets` | 피어 목록(node 키, NKS)과 남는 피어. `rotationTracker`는 내보내지 않은 타입이라 `mapfixtures`처럼 실행할 때 임시 사본에 파일 하나를 얹어 부른다. 그것이 되지 않으면 `TestRotationTracker`(`ipn/ipnlocal/tailnet-lock_test.go:1088`)의 표를 출처와 함께 옮겨 적는다 | 남는 피어 |
| `disablement` | 비밀과 `DisablementKDF`의 값, 상태에 대한 `ValidDisablement` | 값과 판정 |
| `authKeys` | 감싼 인증 키 문자열과 `DecodeWrappedAuthkey`의 결과(인증 키 부분, credential hex, 키 길이), 깨뜨린 변형마다 Go의 동작("원문 전체를 돌려줌", "panic") | 정상은 같은 부분들. 변형은 Swiftail이 모두 거절(동작 R3) |
| `resign` | 옛 서명·NL 시드·새 node 키와 `ResignNKS`의 결과, 그것의 판정 | 만든 서명의 `signatureHash`가 Go 것과 같고, Go의 서명을 Swift가 같은 판정으로 검증 |

뽑을 시나리오:

1. 직선 사슬: genesis 체크포인트 → AddKey → UpdateKey(`Votes`, `Meta`) → RemoveKey → NoOp → Checkpoint → 그 뒤의 AddKey. 체크포인트를 51개째에 두는 긴 사슬 하나(조상 목록).
2. 갈래: 가중치 차이, 같은 가중치의 RemoveKey 대 AddKey, 해시 비교로 갈리는 것, 진 갈래의 자손, 오래된 지점에서 갈라져 이기는 갈래(복구 AUM의 모양).
3. 거절: 서명 없음, 모르는 키 서명 섞임, 틀린 서명, 마지막 키 제거, 중복 AddKey, StateID가 다른 체크포인트, 부모 없는 AUM, 부모를 모르는 AUM, 33바이트 `PrevAUMHash`, 틀린 AUM이 든 묶음 전체.
4. 받아들여지는 이상한 것: 종류 0과 9, 필드를 더 실은 NoOp, `Public`이 null·길이 0·31바이트·33바이트인 AddKey와 그 뒤의 사슬, 모르는 필드와 비최단 정수가 든 AUM(해시는 정준 바이트의 것).
5. ZIP-215에서만 통과하는 서명: 그 서명의 AUM(받아들임), direct NKS(통과), rotation의 바깥(거절). 비정준 공개 키의 신뢰 키.
6. NKS: direct, rotation 1~15겹과 16겹, credential → rotation, 줄인 사슬, 키가 제거된 뒤의 판정, 같은 서명의 다른 node 키.
7. 디코더: 노트 8.1의 입력 전부와, 노트에 없는 것(예약된 추가 정보, 두 바이트로 쓴 32 미만의 단순값, 비최단으로 쓴 같은 키의 중복, 정수 아닌 필드의 null, `Signatures`의 null 원소, 음수 키의 끝값).
8. 동기화: 뒤처진 노드, 앞선 노드(서버가 모르는 AUM), 갈라진 양쪽, 교차 없음.

검증 명령(표준 입력으로 JSON 객체 하나, 출력은 JSON 한 줄, 실패는 종료 코드 1): `tkafixtures verify-nks`는 사슬의 AUM들·node 키·NKS를 받아 Go의 판정과 내력을 돌려준다. Swift가 만든 서명(`SignByCredential`·재서명)은 바이트가 매번 다르므로 이것으로 확인한다.

### 관문 (가): 계정 없이

`Tools/interop`의 `tailnet`(testcontrol + DERP + STUN + Go tsnet 피어)을 상대로 한다. 시험은 `Tests/SwiftailInteropTests/TailnetLockTests.swift`에 두고 `SWIFTAIL_TAILNET`이 없으면 건너뛴다.

testcontrol이 하는 것과 못 하는 것(노트 7.3): lock 켜기(`init/begin`·`finish`), `bootstrap`(genesis만), `sync/offer`, `sign`, 맵 응답의 `TKAInfo{Head}`, `tailnet-lock` capability(`DefaultNodeCapabilities`)는 있다. **`sync/send`, `disable`, 끄기 비밀을 주는 `bootstrap`, `TKAInfo.Disabled`, 등록 요청의 `NodeKeySignature` 저장은 없다.**

도구에 더할 것(결정 L15의 (가)):

- testcontrol 사본에: `sync/send`(`tkatest.HandleTKASyncSend`), `disable`(저장소를 비우고 받은 비밀을 기억), 끄기 뒤의 `bootstrap`이 `DisablementSecret`을 줌(맞는 것 또는 일부러 틀린 것), 맵 응답의 `TKAInfo{Disabled: true}`, 등록 요청의 `NodeKeySignature`를 Go `NodeKeyAuthorized`로 검증해 통과하면 그 노드의 `KeySignature`로 둠.
- `tailnet` 명령: `setLockCapability`(첫 등록 전에. 기존 capability에 `tailnet-lock`을 더한다), `lockInit`(Go 피어들을 서명 기기로 lock을 켠다), `lockStatus`(그 Go 피어의 `NetworkLockStatus`: 켜짐, 머리, 자기 서명 여부, 남은 피어와 거른 피어의 node 키), `lockSign`(node 키와 회전 키에 서명), `lockWrapAuthKey`(인증 키를 감싼다. 시험 전용 값이다), `lockModify`(서명 키를 더하거나 뺀다), `lockDisable`(끈다. `wrongSecret`이면 서버가 틀린 비밀을 준다), `lockRegistrations`(testcontrol이 받은 등록 요청의 `NLKey`·`NodeKeySignature` 유무와 Go의 판정, 그리고 요청 본문에서 찾은 감싼 키 흔적의 유무).

| # | 확인할 것 | 통과 기준 |
| --- | --- | --- |
| 1 | 부트스트랩 | lock이 켜진 시험 tailnet에 Swift 노드가 등록하면 `mode`가 `.enforcing`이고 `head`가 Go 서명 기기의 `lockStatus` 머리와 같다. 등록 요청의 `NLKey`가 0이 아니다 |
| 2 | 서명 전의 잠김 | `signingRequest`가 있고 그 `nodeKey`·`lockKey`가 등록한 값과 같다. `tailnetLockChanged`가 나왔다. Go 피어들의 `lockStatus`에서 Swift 노드가 거른 피어다. Swift 노드의 netmap에는 서명된 Go 피어가 남아 있다 |
| 3 | 서명 뒤 | `lockSign`에 2의 두 값을 넣으면 `signingRequest`가 nil이 되고, Go 피어의 netmap에 Swift 노드가 나타나고, 양쪽의 UDP 에코와 TCP가 된다 |
| 4 | 서명된 인증 키 | `lockWrapAuthKey`로 만든 키로 새 Swift 노드를 등록하면 처음부터 잠기지 않는다. `lockRegistrations`: 요청의 서명을 Go가 통과시켰고, 요청 본문에 감싼 개인 키의 흔적이 없다 |
| 5 | 서명 없는 Go 피어 | 서명하지 않은 Go 피어를 더하면 Swift 노드의 `peers`에 없고 `filteredPeerCount`가 는다. 같은 시점의 Go 서명 기기가 남긴 피어·거른 피어와 Swift 노드의 것이 node 키로 같다(Swift 노드 자신과 `UnsignedPeerAPIOnly` 피어는 견주지 않는다). 그 피어가 보낸 패킷에 Swift 노드가 답하지 않는다 |
| 6 | 사슬이 자란 뒤 | `lockModify`로 키를 더하고 빼면 Swift 노드의 `head`가 Go의 머리를 따라온다. 뺀 키로만 서명된 피어가 Swift 노드와 Go 노드에서 함께 빠진다 |
| 7 | lock 꺼짐 | `lockDisable` 뒤 `mode`가 `.disabled`이고 서명 없는 피어가 다시 보이며 `tailnet-lock.cbor`가 없다. `wrongSecret`이면 `.enforcing`에 머물고 파일이 남는다. 도중에 주입한 `TKAInfo` 없는 응답으로는 바뀌지 않고, 다시 이은 스트림의 첫 응답에 `TKAInfo`가 없으면 끄기 절차로 간다 |
| 8 | 다시 시작 | 같은 상태 디렉터리로 다시 띄우면 부트스트랩 RPC 없이 같은 `head`로 거른다(testcontrol이 받은 요청으로 확인). 그사이 사슬이 자랐으면 동기화로 따라온다. 같은 NL 키다 |
| 9 | node 키 교체 | 서명된 Swift 노드가 새 로그인으로 node 키를 바꾼 뒤 testcontrol이 재서명을 요청하면, 재서명한 요청의 서명을 Go가 통과시키고 옛 키는 Go 피어에서 낡은 키로 빠진다(testcontrol이 재서명을 요청하게 하는 보탬이 필요하다. 넣기 어려우면 이 항목은 `tkafixtures verify-nks`의 대조로 대신하고 그렇게 적는다) |
| 10 | 닫힌 쪽(U1이 (나)일 때) | 부트스트랩 응답을 깨뜨리면 `mode`가 `.unverified`이고 `peers`가 비어 있다. 되돌리면 다음 재시도에 `.enforcing`이 된다. 저장 파일을 깨뜨리고 다시 띄우면 `.unverified`다 |
| 11 | lock 없는 tailnet | 기존 관문(M2~M7)이 그대로 통과한다. `mode`는 `.disabled`이고 TKA RPC가 나가지 않는다 |
| 12 | 전체 | `eyebuild swift <용도> -- test` 전체 통과, 경고 0 |

### 관문 (나): 실제 tailnet

로컬에서는 볼 수 없는 것만 본다. 매번 사용자에게 먼저 알린다(plan 4절(b)).

| # | 확인할 것 | 통과 기준 |
| --- | --- | --- |
| 1 | 서명된 인증 키로 등록 | lock이 켜진 실제 tailnet에 임시 노드로 등록하면 `mode`가 `.enforcing`이고 잠기지 않는다. 서명된 다른 기기가 이 노드를 보고(그 기기의 `tailscale status`·`tailscale lock status`) ping이 된다 |
| 2 | 서명 기기가 뒤에 서명 | 서명 없는 인증 키(또는 로그인)로 등록하면 `signingRequest`가 나온다. 서명 기기에서 `tailscale lock sign`에 그 두 값을 넣으면 풀리고 통신된다 |
| 3 | 운영 서버의 동작 기록 | 이 노드가 `tailnet-lock` capability를 받는지(U2), 부트스트랩이 genesis를 주는지 나중 체크포인트를 주는지, `MissingAUMs`의 수와 응답 크기, 서명 없는 등록에 서버가 무엇을 답하는지, sync/send의 응답을 기록한다 |
| 4 | 다시 시작과 동기화 | 다시 띄우면 저장된 상태로 이어 가고, 그사이 서명 기기에서 키를 하나 더하면(사용자가 허락할 때만) 머리가 따라온다 |
| 5 | iPhone 터널 | M5 터널 빌드의 노드가 같은 tailnet에서 잠기지 않고 Mac의 tailnet HTTPS에 닿는다. 끄기 비밀 검증은 돌리지 않으므로 메모리는 평소 값을 기록한다 |

사용자에게 받을 것:

- lock이 켜진 tailnet과, 그 tailnet의 서명 기기 한 대(사용자가 직접 명령을 돌린다).
- 서명 기기에서 `tailscale lock sign <인증 키>`로 만든 **서명된 인증 키**(임시 노드용). 채팅이 아닌 비밀 입력으로 받는다. 호스트 이름은 가짜 값(`rd-mac-1a2b3c4d` 꼴)으로 정한다.
- 2를 위한 서명 없는 인증 키 하나와, 서명 기기에서 `tailscale lock sign <node 키> <lock 키>`를 한 번 돌려 주는 것.
- lock을 끄는 것은 실제 tailnet에서 하지 않는다(관문 (가) 7로만 본다).

## 8. 구현 단위

소유 파일이 겹치지 않게 나눈다. 단위 사이의 접점은 2절의 선언이 정하고 TL-0이 확정한다.

| 단위 | 내용 | 소유 파일 | 선후 | 추정 크기(라이브러리 / 시험) |
| --- | --- | --- | --- | --- |
| TL-0 | 총괄: 이 계약 확정(L·U·F의 답), `Package.swift`에 `SwiftailTKA`·`SwiftailTKATests`와 `SwiftailControl`의 의존, 2절 `package` 선언의 빈 껍데기, plan·`SwiftailControl.md`·`SwiftailHost.md`의 해당 줄 | `docs/`, `Package.swift` | 먼저 | — |
| TL-P1 | (선행, 진행 중) Ed25519 검증 | `Sources/SwiftailCrypto/Ed25519Verification.swift`와 시험 | 다른 세션 | — |
| TL-P2 | (선행, 진행 중) BLAKE2b, Argon2i | `Sources/SwiftailCrypto/BLAKE2b.swift`·`Argon2i.swift`와 시험 | 다른 세션 | — |
| TL-1 | CBOR 읽기·쓰기(동작 E1·D1·D2·D9, 시험 1·2의 항목 수준) | `Sources/SwiftailTKA/CBOR/*`, `Tests/SwiftailTKATests/CBOR/*` | **병렬** | 350 / 500 |
| TL-2 | 자료 형식: `AUMHash`와 base32, `TrustedKey`·`AUMSignature`·`AUM`·`AuthorityState`·`NodeKeySignature`의 읽기·정준 쓰기·해시·정적 검사(동작 E2~E6·D3~D8·A1, 시험 2~4) | `Sources/SwiftailTKA/Model/*`, `Tests/SwiftailTKATests/Model/*` | TL-1의 선언 뒤. TL-3·4와 **병렬**(선언을 먼저 맞춘다) | 550 / 700 |
| TL-3 | `Authority`: 검증·적용·갈래·들이기·부트스트랩·다시 열기·동기화 계산·끄기 비밀(동작 A2~A7·F·X·Y1·Y4, 시험 5~9·12) | `Sources/SwiftailTKA/Authority/*`, `Tests/SwiftailTKATests/Authority/*` | TL-2 뒤. TL-P1이 있어야 서명 시험이 돈다. 끄기 비밀만 TL-P2 | 650 / 900 |
| TL-4 | 서명: `authorize`·내력·피어 집합, `WrappedAuthKey`, 재서명(동작 S·P2~P5·R3·R5·R7, 시험 10·11·13·14) | `Sources/SwiftailTKA/Signatures/*`, `Tests/SwiftailTKATests/Signatures/*` | TL-2 뒤. TL-3과 **병렬** | 450 / 700 |
| TL-5 | Go 기준값 도구와 자료, 대조 시험 | `Tools/interop/cmd/tkafixtures/*`, `Scripts/build-interop-tools.sh`의 도구 이름 한 줄, `Tools/interop/README.md`의 새 절, `Tests/SwiftailTKATests/Fixtures/*`, `Tests/SwiftailTKATests/GoComparisonTests.swift` | 도구는 **병렬**(TL-1과 함께 시작). 대조 시험은 TL-2~4 뒤, 그것을 쓴 세션과 **다른 세션** | Go 900 / 500 |
| TL-6 | 제어의 등록 쪽: NL 키와 신원 파일, 인증 키 해석의 연결, 요청의 서명, 재서명 요청(동작 R, 시험 15·16) | `Sources/SwiftailControl/Client/NodeIdentity.swift`·`NodeIdentityStore.swift`·`AuthKey.swift`·`ControlClient+Registration.swift`, `Sources/SwiftailControl/Tailcfg/NLPublicKey.swift`, 해당 시험 | TL-4의 선언 뒤. TL-7과 **병렬** | 220 / 350 |
| TL-7 | 제어의 맵 쪽: `serverLock`, `TailnetLockPlan`, TKA RPC와 tailcfg, `TailnetLockStore`, 절차·거르기·`TailnetLockStatus`, `MapRequest.tkaHead`, `Netmap.tailnetLock`(동작 N·Y·P·O·T·K, 시험 17~21) | `Sources/SwiftailControl/Client/ControlClient+TailnetLock.swift`·`TailnetLockStore.swift`·`TailnetLockStatus.swift`·`ControlClient+MapPoll.swift`·`ControlClient.swift`, `Sources/SwiftailControl/Tailcfg/TKA*.swift`·`MapRequest.swift`, `Sources/SwiftailControl/Netmap/*`, 해당 시험 | TL-3·4 뒤. 가장 크다 | 600 / 900 |
| TL-8 | 노드와 마무리: `NodeStatus.tailnetLock`, `NodeEvent.tailnetLockChanged`, `ControlError.tailnetLockEnabled`와 그것을 가리키는 갈래 지우기(시험 22) | `Sources/Swiftail/NodeStatus.swift`·`NodeEvent.swift`·`NodeError.swift`·`TailnetNode.swift`·`TailnetNode+Control.swift`, `Sources/SwiftailControl/Client/ControlError.swift`, `Sources/SwiftailCertificates/CertificateManager.swift`의 그 한 줄, 해당 시험 | TL-6·7 뒤 | 120 / 200 |
| TL-9 | 관문 (가)의 도구: testcontrol 사본과 보탬, `tailnet`의 lock 명령 | `Tools/interop/internal/testcontrol/*`, `Tools/interop/cmd/tailnet/lock.go`·`lock_test.go`와 `main.go`의 분기, `Tools/interop/README.md`의 `tailnet` 절 | **병렬**(TL-5와 README의 절이 다르다) | Go 500(옮겨 적는 2,000줄은 따로) |
| TL-10 | 관문 (가)의 시험 | `Tests/SwiftailInteropTests/TailnetLockTests.swift` | TL-8·9 뒤 | — / 500 |
| TL-11 | 독립 검토: `SwiftailTKA` 전체와 제어의 절차(암호·프로토콜 코드. plan 10절) | — | TL-5의 대조가 통과한 뒤, 총괄이 관문 (가)를 다시 돌리기 전. 작성한 세션과 **다른 세션** | — |
| TL-12 | 관문 (나) | 사용자와 함께 | U3 뒤 | — |

순서: TL-0 → (TL-1, TL-5의 도구, TL-9) 병렬 → TL-2 → (TL-3, TL-4) 병렬 → (TL-5의 대조 시험, TL-6, TL-7) → TL-8 → TL-10 → TL-11 → 총괄이 관문 (가)를 다시 돌림 → TL-12. TL-P1·P2는 TL-3·4의 시험이 돌기 전에 끝나 있어야 한다.

### 예상 규모

라이브러리 약 2,900줄(`SwiftailTKA` 2,000, `SwiftailControl` 820, `Swiftail` 120. 선행 단위의 암호는 빼고), Swift 시험 약 5,250줄, Go 약 1,400줄(옮겨 적는 testcontrol 약 2,000줄은 따로). M7(라이브러리 약 3,200줄)과 비슷하다. 어려움은 양이 아니라 "받아들이되 해시는 정준 바이트로"라는 디코더의 정확성에 있다.

### 가장 큰 위험

1. **디코더가 Go와 한 바이트라도 다르게 다시 인코딩하면 보호가 약해진다.** 해시가 달라져 서명이 검증되지 않고, 그 AUM이 든 묶음 전체가 거절되어 상태가 그 앞에서 멈춘다. 그 뒤의 키 제거를 따라가지 못하면 Go 노드가 더는 믿지 않는 키를 Swiftail만 믿는다(노트 6.1의 실패 모양). null과 빈 값, `Meta`의 바이트, 모르는 필드의 처리가 모두 여기에 걸린다. 대응: 기준값 도구의 `cbor`·`chains`를 다른 세션이 대조하고, 받아들여지는 이상한 입력(시나리오 4·5)을 사슬 안에 넣어 "그 뒤의 AUM까지 따라간다"를 본다. 노트가 열거하지 못한 입력(9절)이 남는다.
2. **운영 제어 서버의 TKA 동작은 소스에 없다.** capability를 누가 받는지, 부트스트랩이 무엇을 주는지, 서명 없는 등록과 검증되지 않는 서명을 어떻게 다루는지, sync/send를 어떻게 검사하는지 모른다(노트 8.2). testcontrol은 시험용이고 그 보탬은 우리가 쓴다. 대응: 관문 (나) 3에서 기록하고, U1·U2를 그 기록으로 다시 본다. U1이 (나)면 서버의 일시 오류가 곧 "피어 없음"이 되므로 재시도(동작 N6)의 값이 중요하다.
3. **끄기 비밀 검증의 16MiB.** iOS 확장의 유휴 상주가 약 8.7MiB이고 한도가 50MiB다. 큰 맵 프레임의 해독(최고 약 14MB)과 겹치면 약 39MiB가 된다. 순수 Swift Argon2i의 실기기 속도도 재지 않았다. 대응: 한 번에 하나만 돌고, 같은 비밀은 다시 계산하지 않고(동작 O6), 맵 해독과 겹치지 않게 절차를 차례로 돈다. 실기기에서 한 번 잰다(관문 (가) 7을 터널 시험 앱으로).
4. **직접 구현한 Ed25519 검증과 Argon2i**(선행 단위). 판정이 Go와 다르면 1과 같은 결과다. 대응: 그 단위의 벡터(ZIP-215 196개, RFC 9106)와 다른 세션의 검토, 그리고 이 계약의 시나리오 5.

그 밖: 한 상태 디렉터리로 tailnet을 바꾸면 옛 상태가 남는다(동작 T6). 압축하지 않아 오래된 갈래에 대한 판정이 압축한 Go 노드와 다르다(결정 L7).

### `shortcut:`으로 남길 것

| 남기는 것 | 필요해지는 시점 |
| --- | --- |
| 압축(L7) | 저장이 한도에 닿는 tailnet이 보고될 때 |
| 감싼 인증 키로 다시 서명(L9의 (다)) | `--TL`로 등록한 노드의 키 교체가 잠김을 일으킬 때 |
| 상태 디렉터리 하나에서 tailnet 바꾸기(동작 T6) | 그런 사용처가 생길 때 |
| `UnsignedPeerAPIOnly` 피어 올리기 | Funnel 진입 같은 기능을 넣을 때 |
| 변화마다 저장 파일 전체를 다시 씀 | 사슬이 길어 쓰기가 눈에 띌 때 |
| 열지 못한 저장소를 앱이 파일을 지워서만 푼다 | 그 일이 실제로 보고될 때(초기화 API를 검토한다) |

## 9. 확인하지 못한 것

노트 8.2에서 이 계약에 걸리는 것:

- **운영 제어 서버의 동작**: `tailnet-lock` capability를 어느 노드에 주는지, 부트스트랩이 genesis와 나중 체크포인트 가운데 무엇을 주는지, `RegisterResponse.NodeKeySignature`를 언제 보내는지, 서명된 인증 키로 등록한 노드의 서명을 어떻게 저장·배포하는지, 서명 없는 등록에 무엇을 답하는지, 관리 콘솔의 서명이 회전 키로 등록 요청의 `NLKey`를 쓰는지, `UnsignedPeerAPIOnly`를 언제 주는지, sync/send의 `Interactive=false` 요청을 어떻게 검사하는지, TKA RPC에 429·503을 쓰는지, 응답 크기의 분포. 관문 (나) 3이 일부를 기록한다.
- **부트스트랩 실패가 운영에서 실제로 일어나는지**(U1의 가용성 영향의 크기).
- **CBOR 디코더가 받아들이는 입력 전체**는 열거되지 않았다. 노트의 표는 시험한 입력에 대한 것이다. 이 계약이 더한 것 가운데 Go의 판정을 실행으로 확인하지 않은 것: 예약된 추가 정보와 두 바이트로 쓴 32 미만 단순값의 거절(동작 D1), 비최단으로 쓴 같은 키의 중복이 중복으로 잡히는지(D4), 정수가 아닌 알려진 필드의 null(D5), `Signatures`의 null 원소, `Public`이 null이거나 길이가 32가 아닌 AddKey가 받아들여지고 그 KeyID가 무엇으로 견줘지는지(동작 E6. `StaticValidate`가 길이를 보지 않는다는 노트 3.2에서 끌어낸 것이다). 모두 `tkafixtures`의 시나리오 4·7로 확정하고, 다르면 이 계약을 고친다.
- **압축이 판정에 영향이 없다는 것**은 노트도 확인하지 못했다. 결정 L7은 압축을 하지 않으므로 그 미확인에 기대지 않지만, "받은 지 14일이 안 된 Go 노드와 같다"는 설명은 노트 4.11의 요약에서 끌어낸 것이고 Go의 `Compact`를 돌려 견주지 않았다.
- **`computeActiveAncestor`의 결정성**(노트 8.2): 뿌리 하나로 좁혀 닿지 않게 했다(동작 F6). Go 노드의 저장소에 뿌리가 여럿일 때의 머리와 Swiftail의 머리가 같은지는 견주지 않는다.
- **읽은 소스는 v1.104.7, 실행은 v1.104.6**이고 Go의 `tka`·`ipnlocal` 시험은 돌리지 않았다(노트 8.2). 이 계약이 직접 읽은 Go 줄(`direct.go:534-545`·`:704-747`, `auto.go:706-714`, `tailnet-lock.go:340-437`, testcontrol)도 v1.104.7의 것이다.

설계에서 새로 생긴 것:

- **두 번째 재서명 요청 뒤의 Go 상태**(동작 R6): `doLoginOrRegen`이 두 번째 응답의 재서명 요청을 버린다는 것만 읽었다. 그 뒤 Go가 등록된 것으로 보는지는 따라가지 않았다.
- **Go의 첫 맵 요청이 `TKAHead`를 싣는지**(동작 N4): 머리를 정하는 곳(`SetTKAHead`)만 읽었고, 시작할 때 저장된 머리가 첫 요청 전에 정해지는지는 확인하지 않았다.
- **이미 등록된 Swiftail 노드가 0이던 `NLKey`를 새 키로 바꿔 다시 붙을 때의 서버 동작**(동작 R1). M2~M7의 노드는 0을 보냈다.
- **등록된 키로 다시 붙을 때(인증 키 없이) 서명을 싣지 않아도 서버가 예전 서명을 유지하는지**(동작 R5 ③).
- **testcontrol 사본의 보탬이 실제로 서는지**: `tkatest.HandleTKASyncSend`와 사본의 맵 응답·등록 처리기를 읽었을 뿐 빌드해 보지 않았다. 끄기와 재서명 요청은 testcontrol에 본이 없어 운영 서버의 동작을 짐작해 쓰는 것이다(관문 (가) 7·9는 "Swiftail과 Go 클라이언트가 같은 서버 동작에 같이 반응한다"까지만 보인다).
- **`rotationTracker`를 기준값 도구에서 부를 수 있는지**(7절 `peerSets`): `mapfixtures`의 방식이 `ipn/ipnlocal`에도 통하는지 해 보지 않았다.
- **순수 Swift Argon2i의 시간과 최고 메모리**, 맵 해독과 겹칠 때의 `phys_footprint`.
- **`MapSession`이 응답마다 전체 netmap을 내는 것에 기댄 결정 L11**: `Sources/SwiftailControl/Netmap/MapSession.swift`와 `ControlClient+MapPoll.swift:81-96`을 읽어 확인했다. 증분만 노드로 넘기는 경로가 생기면 다시 본다.
- **첫 사용처의 Swift 코드**는 `tailnetLockEnabled`를 쓰는 한 줄과 Go 코어의 진단 로그만 찾아 읽었다. 상태 화면이 새 사건을 어떻게 받을지는 F2의 답에 달려 있다.
- 이 계약의 선언은 컴파일해 보지 않았다(코드를 쓰지 않는 세션이다). 빌드와 시험은 돌리지 않았다.
