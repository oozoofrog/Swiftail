# Swiftail netstack 계약 (M6, 초안)

M6의 목표는 **OS의 TCP 스택 없이 프로세스 안에서 tailnet 주소로 TCP를 듣고 거는 것**이다(`docs/plan.md` 7절 M6). M5까지 노드는 IP 패킷을 주고받았다. M6는 그 위에 Swift로 쓴 TCP를 얹어, tsnet의 `Listen("tcp", ":443")`과 `Dial`에 대응하는 공개 API를 낸다. 첫 사용처는 Mac 호스트(tailnet 위의 HTTPS 서버)이고, 지금 그 자리의 Go 코어(`tsnet.Server.Listen` + `tls.NewListener` + `http.Server`)를 걷어내는 것(M7)이 이 계약에 기댄다. 라이브러리는 전부 Swift이고 C·외부 패키지를 쓰지 않는다(plan 4절(a)).

이 문서는 **초안**이다. "총괄 확인 필요"를 정하고 "첫 사용처 확인 필요"의 답을 받은 뒤 확정한다.

프로토콜 세부는 [tcp-netstack.md](../protocol-notes/tcp-netstack.md)(아래에서 "TCP 노트". **아직 검증 전**이다)를 따른다. 이 문서는 범위, 구조, 공개 API, 한도, 시험과 관문만 정한다.

기존 계약과의 관계: [SwiftailTunnel.md](SwiftailTunnel.md)(M5)와 [SwiftailEngine.md](SwiftailEngine.md)의 내용은 그대로 두고, 이 문서가 M6의 변경을 덧붙인다. 어긋나면 이 문서가 앞선다.

## 타깃

| 타깃 | M6에서 더하는 것 | 근거 |
| --- | --- | --- |
| `SwiftailNetstack`(새 타깃, 제품으로 내보내지 않음) | TCP 세그먼트 코덱, 연결 하나의 상태 기계(`TCPConnection`), 여러 연결과 리스너를 묶는 `TCPStack`. 모두 소켓·시계·난수 없는 값 타입이고 접근 수준은 `package`다 | plan 5절 코드 기준. `SwiftailIO`처럼 패키지 안에서만 쓴다 |
| `SwiftailBase` | 인터넷 체크섬(RFC 1071)을 `package`로 옮겨 온다 | 엔진의 서비스 IP 응답과 netstack이 같은 계산을 쓴다(결정 D10) |
| `SwiftailEngine` | `ServiceIPReply+Checksum.swift`가 옮긴 체크섬을 부른다. 동작은 바뀌지 않는다 | 같은 곳 |
| `Swiftail` | `TunnelDevice.inProcess`, 공개 API(`listen`·`connect`, `TailnetListener`, `TailnetConnection`, `ConnectionError`), 노드와 스택 잇기, 기다리는 읽기·쓰기 깨우기 | 공개 API는 `Swiftail`에만 둔다(기존 구조) |

의존 방향: `SwiftailBase ◄─ SwiftailNetstack ◄─ Swiftail`. plan 5절 그림(`Swiftail ◄─ SwiftailNetstack`)과 반대다(총괄 확인 필요 N1). `SwiftailNetstack`은 `SwiftailBase`와 CryptoKit(ISN의 해시)만 쓴다. 엔진·제어·WireGuard를 모른다.

## M6에서 지원하는 범위

범위는 첫 사용처가 실제로 쓰는 것에서 정했다(TCP 노트 8절): 리스너 하나(포트 443 또는 시험 포트)와 그 위의 HTTPS, 진단용 프록시의 다이얼, 페어링한 기기 몇 대가 여는 동시 연결 수십 개, 서버 → 클라이언트 방향 수백 MB에서 4GiB까지의 전송, 클라이언트 → 서버 방향 4MB까지. 상대의 TCP 스택은 iPhone 커널과 gVisor다.

| 넣는다 | 근거 |
| --- | --- |
| IPv4·IPv6 tailnet 주소 | 노드가 두 계열 주소를 다 갖는다. 차이는 IP 머리와 의사 머리뿐이다 |
| 수동 열기(듣기)와 능동 열기(걸기), 반닫힘, RST | TCP 노트 8절 1·5 |
| 체크섬 만들기와 검사, MSS 옵션 | 빼면 연결이 서지 않는다(TCP 노트 4.8) |
| 창 확장 | 빼면 창이 64KiB로 묶인다. RTT 50ms에서 약 10Mbit/s가 한도가 된다 |
| RFC 6298 재전송 타이머(Karn), SYN·데이터 재전송 한도 | 필수(MUST-18, MUST-20) |
| slow start, congestion avoidance, fast retransmit·fast recovery, NewReno | 필수(MUST-19)와 plan 4절(a) |
| 0 창 탐침, 보내는 쪽·받는 쪽 SWS 회피 | 필수(MUST-36, MUST-38, MUST-39) |
| 지연 ACK | plan 4절(a). ACK 하나마다 WireGuard 암호화와 UDP 송신이 든다 |
| keep-alive(고정 값, 늘 켬) | Go 호스트가 죽은 상대의 연결을 이것으로 거둔다(총괄 확인 필요 N5) |
| RFC 5961의 RST·SYN·ACK 검사와 challenge ACK 속도 제한 | 동작 X |
| 순서가 어긋난 세그먼트 보관(받는 창 안, 구간 수 상한) | 손실 뒤 창 전체를 다시 받지 않는다 |
| TIME-WAIT | MUST-13 |

빼는 것은 아래 "제외" 표에 근거와 필요해지는 시점을 적는다. 빠진 기능은 닫힌 쪽이다: 협상하지 않는 옵션은 보내지 않고, 받은 것은 무시한다.

## 구조

```
앱 Task ── await connection.read/write ──┐
                                         ▼
TailnetNode (actor, 가장자리)   기다리는 읽기·쓰기·accept·connect를 쥐고 깨운다. 시각을 만든다
   │   stack: TCPStack (값)  ◄── .ipPacket ── engine.receive ◄── Magicsock ◄── 소켓·DERP
   │        └ 내보낼 IP 패킷 ──► engine.send ──► Magicsock ──► 소켓·DERP
   ▼
TCPStack (값)        리스너 표, 4-튜플 → 연결, 맺는 중인 연결과 accept 대기열, ISN·포트, 한도, 연결 없는 곳의 RST
   └ TCPConnection (값)   연결 하나: 상태, 보내는·받는 버퍼, 재전송 타이머, 혼잡 제어
        └ TCPSegment (값)  검증을 마친 세그먼트. IP 패킷 바이트와 서로 바뀐다
```

1. **연결 하나는 값 타입 상태 기계다.** 입력은 세그먼트, 응용의 호출(쓰기·읽기·닫기·중단), 시각이다. 출력은 보낼 세그먼트와 사건(맺어짐, 읽을 것이 생김, 쓸 자리가 생김, 상대가 쓰기를 닫음, 끝남과 그 까닭)이다. 소켓·시계·난수를 갖지 않는다. ISN은 인자로 받는다. WireGuard·엔진과 같은 모양이다(`advance(to:)`, `nextDeadline`).
2. **스택도 값 타입이다.** ISN을 만들 비밀(32바이트)은 만들 때 인자로 받는다. 시스템 난수는 노드가 뽑는다.
3. **가장자리는 `TailnetNode` actor 하나다.** 스택은 노드의 저장 프로퍼티이고, 엔진·`Magicsock`과 같은 actor 안에서 `await` 없이 주고받는다. 그래서 노드와 스택 사이에 버퍼도, 버림도, 따로 도는 타이머도 없다. 타이머는 노드의 것 하나가 엔진·`Magicsock`·스택의 가장 이른 기한에 깬다.
4. **분리된 Task가 없다.** 스택을 움직이는 일은 모두 `run()` 안에서 일어난다. 앱의 읽기·쓰기는 앱의 Task가 노드 actor로 건너와 하고, 기다려야 하면 그 Task가 멈춘다.

```swift
// SwiftailNetstack (package). 모양만 적는다. 이름과 인자는 구현 단위가 확정한다.
package struct TCPSegment: Sendable, Equatable {
    package init(parsingIPPacket bytes: [UInt8]) throws(ParseError)   // 동작 W
    package func ipPacket(hopLimit: UInt8 = 64) -> [UInt8]?   // nil: 주소 계열이 다르거나 IP 패킷 하나에 들어가지 않음
}

package struct TCPConnection: Sendable {
    package enum Output: Sendable, Equatable { case segment(TCPSegment), event(Event) }
    package enum Event: Sendable, Equatable { case established, readable, writable, endOfStream, closed(CloseReason) }
    package mutating func receive(_ segment: TCPSegment, at now: ContinuousClock.Instant) -> [Output]
    package mutating func write(_ bytes: ArraySlice<UInt8>, at now: ContinuousClock.Instant) -> (accepted: Int, outputs: [Output])
    package mutating func read(upTo maximumLength: Int, at now: ContinuousClock.Instant) -> (bytes: [UInt8], outputs: [Output])
    package mutating func finishWriting(at now: ContinuousClock.Instant) -> [Output]
    package mutating func abort() -> [Output]
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    package var nextDeadline: ContinuousClock.Instant? { get }
}

package struct TCPStack: Sendable {
    package enum Output: Sendable, Equatable { case ipPacket([UInt8]), event(Event), dropped(Drop) }
    package init(isnSecret: [UInt8], now: ContinuousClock.Instant)
    package mutating func receive(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output]
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    package var nextDeadline: ContinuousClock.Instant? { get }
    // listen·stopListening·accept·connect와, 연결 ID로 부르는 write·read·finishWriting·close·abort
}
```

## 공개 API (`Swiftail`, M6에서 더하는 것)

```swift
import SwiftailBase

public enum TunnelDevice: Sendable {
    case utun(fileDescriptor: Int32, mtu: Int = 1280)   // M5 그대로
    case memory(mtu: Int = 1280)                         // M5 그대로
    /// 프로세스 안의 TCP 스택. 피어가 이 노드의 주소로 보낸 패킷을 스택이 받고, 스택이 만든 패킷이 tailnet으로 나간다.
    /// `listen(port:)`과 `connect(to:port:)`는 이 장치에서만 쓸 수 있다. MTU는 1280으로 고정이다.
    case inProcess
}

extension TailnetNode {
    /// 이 노드의 tailnet 주소(IPv4·IPv6)에서 TCP 포트 하나를 듣는다. tsnet `Listen("tcp", ":<port>")`.
    /// `run()` 전에 불러도 된다. `run()`이 끝나면 리스너도 끝난다.
    public func listen(port: UInt16) throws(ConnectionError) -> TailnetListener

    /// tailnet의 피어에게 TCP 연결을 건다. tsnet `Dial(ctx, "tcp", "<host>:<port>")`.
    /// `host`는 IP 주소이거나 netmap에 있는 이름(MagicDNS FQDN, 짧은 이름)이다. 연결이 맺어질 때까지 기다린다.
    /// 호출한 Task를 취소하면 시도를 버리고 `.cancelled`를 던진다.
    public func connect(to host: String, port: UInt16) async throws(ConnectionError) -> TailnetConnection
}

/// 듣는 포트 하나. 맺어진 연결을 차례로 낸다. 리스너를 닫거나 `run()`이 끝나면 흐름이 끝난다.
/// 한 번에 한 Task만 돌 수 있다. 버려지면(`deinit`) 닫힌다.
///
///     let listener = try await node.listen(port: 443)
///     for await connection in listener { … }
public final class TailnetListener: AsyncSequence, Sendable {
    public typealias Element = TailnetConnection
    public typealias Failure = Never
    public let port: UInt16
    /// 듣기를 그만둔다. 아직 받아 가지 않은 연결은 RST로 끊는다. 이미 받아 간 연결은 그대로다.
    public func close() async
}

/// 맺어진 TCP 연결 하나. 읽기 하나와 쓰기 하나를 서로 다른 Task에서 동시에 해도 된다.
/// 닫지 않고 버려지면(`deinit`) RST로 끊는다.
public final class TailnetConnection: Sendable {
    /// 이 노드 쪽 주소와 포트.
    public let localEndpoint: IPEndpoint
    /// 상대의 tailnet 주소와 포트. 주소는 WireGuard가 인증한 피어의 것이다(엔진 계약 M3 동작 2·5의 AllowedIPs 출발지 검사).
    public let remoteEndpoint: IPEndpoint

    /// 받은 바이트를 순서대로 돌려준다. 버퍼에 있는 만큼(1바이트 이상, `maximumLength` 이하) 곧바로, 없으면 올 때까지 기다린다.
    /// 상대가 쓰기를 닫았고 남은 것이 없으면 nil. 읽어 간 만큼 받는 창이 열린다.
    public func read(upTo maximumLength: Int = 65_536) async throws(ConnectionError) -> [UInt8]?

    /// 바이트를 모두 보내는 버퍼에 넣을 때까지 기다린다. 상대가 받았다는 뜻이 아니다. 버퍼가 차면 자리가 날 때까지 멈춘다.
    /// 취소되면 연결을 RST로 끊고 `.cancelled`를 던진다(얼마나 들어갔는지 알 수 없기 때문이다).
    public func write(_ bytes: [UInt8]) async throws(ConnectionError)

    /// 보내기를 끝낸다(FIN). 버퍼에 남은 것을 다 보낸 뒤에 나간다. 읽기는 계속할 수 있다. tsnet `CloseWrite`.
    public func finishWriting() async throws(ConnectionError)

    /// 연결을 닫는다. 버퍼에 남은 것을 보내고 FIN으로 끝낸다. 곧바로 돌아오고, 마무리는 노드가 `run()` 안에서 한다.
    /// 읽지 않은 데이터가 있거나 닫은 뒤에 데이터가 오면 RST로 끊는다. tsnet `Close`.
    public func close() async

    /// 연결을 곧바로 끊는다(RST). 버퍼의 것은 버린다.
    public func abort() async
}

/// 듣기·걸기·연결의 실패.
public enum ConnectionError: Error, Sendable, Equatable {
    /// 장치가 `.inProcess`가 아니거나, 포트가 0이거나, 호스트가 비었다. 메시지는 무엇이 잘못됐는지만 담는다.
    case invalidConfiguration(String)
    /// 노드가 돌고 있지 않다(`run()`이 끝났다). `connect`는 상태가 `.running`이 아닐 때도 이것이다.
    case notRunning
    /// 이름이 netmap에 없거나, 그 주소를 가진 피어가 없다.
    case unknownHost
    /// 그 포트에 이미 리스너가 있다.
    case addressInUse
    /// 연결 수나 리스너 수가 상한에 닿았다.
    case limitReached
    /// 건 연결을 상대가 거절했다(SYN에 RST).
    case refused
    /// 상대가 답하지 않는다(재전송 한도, keep-alive 무응답, 닫는 중의 기한).
    case timedOut
    /// 상대가 연결을 끊었다(RST).
    case reset
    /// 상대가 netmap에서 빠졌거나 그 주소의 주인이 바뀌었다. 또는 이 노드의 주소가 바뀌었다.
    case peerRemoved
    /// 이미 닫거나 끊은 연결·리스너다.
    case closed
    /// 호출한 Task가 취소되었다.
    case cancelled
    /// 같은 방향의 호출이 이미 기다리고 있다(읽기 둘, 쓰기 둘).
    case concurrentUse
}
```

tsnet과의 대응:

| tsnet(Go) | Swiftail | 다른 점 |
| --- | --- | --- |
| `Server.Listen("tcp", ":443")` | `node.listen(port: 443)` | 주소 지정, `tcp4`·`tcp6`, 포트 0이 없다(제외 표) |
| `Listener.Accept()` | `for await connection in listener` | 받아 가지 않은 연결을 1초 뒤에 닫지 않는다. 대기열 상한으로 묶는다(동작 S5) |
| `Listener.Close()` | `listener.close()`, 또는 버림 | |
| `Server.Dial(ctx, "tcp", "host:443")` | `node.connect(to: "host", port: 443)` | `Running`을 기다리지 않는다. tailnet 밖의 주소로 걸지 않는다(동작 A2) |
| `net.Conn.Read`·`Write` | `read(upTo:)`·`write(_:)` | 시간 제한(deadline)이 없다. Task 취소로 끊는다 |
| `CloseWrite()` | `finishWriting()` | |
| `Close()` | `close()` | |
| `SetLinger(0)` + `Close()` | `abort()` | |
| `RemoteAddr()`·`LocalAddr()` | `remoteEndpoint`·`localEndpoint` | 문자열이 아니라 `IPEndpoint`다 |

`docs/plan.md` 6절 초안과 다른 점: `dial(host:port:)` → `connect(to:port:)`(총괄 확인 필요 N2), `listen`이 `async`가 아니다(actor 메서드라 밖에서는 `await`로 부르지만 안에서 기다리는 것이 없다), `TunnelDevice.inProcess`에 인자가 없다.

## 동작

번호는 시험과 검토에서 가리키는 이름이다. 값은 따로 적지 않으면 이 계약의 제안값이고 관문의 기록으로 조정한다.

### W. 세그먼트 코덱 (`TCPSegment`)

1. **해석**: 입력은 IP 패킷 바이트다. IPv4(옵션 포함)와 IPv6(확장 헤더 없음)의 머리에서 주소와 길이를 읽고, 프로토콜이 6이 아니면 `notTCP`, TCP 머리가 20바이트보다 짧거나 data offset이 5 미만이거나 세그먼트 밖을 가리키면 `malformed`, 체크섬이 틀리면 `badChecksum`이다. 엔진이 이미 IP 머리를 검사했지만(`IPPacket`), 스택은 자기 경계에서 다시 본다(스택만 따로 시험할 수 있고, 패킷 캡처를 그대로 넣을 수 있다).
2. **옵션**(TCP 노트 3.2): EOL에서 멈추고 NOP는 건너뛴다. MSS(kind 2, 길이 4)와 Window Scale(kind 3, 길이 3)만 읽고, SYN이 아닌 세그먼트의 둘은 무시한다. 모르는 옵션은 길이로 건너뛴다. 길이가 2보다 작거나 머리 밖으로 나가면 세그먼트를 `malformed`로 버린다(MUST-7의 대비. 연결을 끊지 않는다). MSS 0은 536(IPv4)·1220(IPv6)으로, shift가 14를 넘으면 14로 읽는다(RFC 7323 2.3).
3. **만들기**: 머리 20바이트 + 옵션(SYN에만 MSS, 협상 중이면 Window Scale, NOP로 4바이트 경계) + 데이터. 체크섬을 채운다. IP 머리는 IPv4면 IHL 5, DF 켬, 식별자 0, TTL 64. IPv6면 hop limit 64, flow label 0. 64는 Go·gVisor의 기본값이다(터널 계약 동작 L2).
4. urgent pointer와 CWR·ECE는 보낼 때 0, 받을 때 무시한다.
구현에서 정해진 것(M6-1, 2026-11-15):

- 검사 순서는 IP 머리의 구조 → 프로토콜(`notTCP`) → 조각 → IPv4 머리 체크섬 → TCP 머리 → TCP 체크섬 → 옵션이다. IPv4 머리 체크섬도 본다(틀리면 `badChecksum`). IPv4 조각(MF나 오프셋)은 `malformed`, IPv6 확장 헤더·조각 헤더(next header가 6이 아님)는 `notTCP`다.
- 길이가 규격과 다른 MSS(4가 아님)·Window Scale(3이 아님)은 값을 읽지 않고 길이로 건너뛴다. 같은 옵션이 여럿이면 뒤의 것이 남는다(gVisor와 같다). SYN이 아닌 세그먼트도 옵션의 길이는 검사한다.
- 선언: `TCPSegment`의 필드는 `source`·`destination`(`IPEndpoint`), `sequenceNumber`·`acknowledgmentNumber`(`SequenceNumber`), `flags`(`fin`·`syn`·`rst`·`psh`·`ack`), `window`(머리의 16비트 그대로), `maximumSegmentSize`·`windowScale`(SYN에만), `payload`, 그리고 `sequenceLength`(SEG.LEN)다. 체크섬은 `SwiftailBase`의 `InternetChecksum`(`add`, `addPseudoHeader`, `value`)이다.

5. 시퀀스 번호는 2^32 순환 타입(`SequenceNumber`)으로만 다룬다. 비교와 차이는 부호 있는 32비트 차이로 한다. `UInt32`를 직접 견주는 코드가 없어야 한다.

### T. 연결 상태 기계 (`TCPConnection`)

1. 상태는 SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT, CLOSED다(RFC 9293 3.3.2). LISTEN은 스택이 맡는다(동작 S).
2. **세그먼트 처리 순서**는 RFC 9293 3.10.7.4(TCP 노트 4.2) 그대로다: 시퀀스 검사 → RST → SYN → ACK → 데이터 → FIN. 순서를 바꾸지 않는다. SYN-SENT는 이 순서가 아니라 RFC 9293 3.10.7.3의 절차를 따로 따른다(ACK 검사 → RST → SYN). gVisor의 처리 순서는 RFC와 다르므로(받은 데이터를 먼저, ACK를 나중에) 순서의 근거로 쓰지 않는다. FIN은 그 앞의 데이터가 빈 곳 없이 도착한 뒤에만 소비한다.
3. **능동 열기**: SYN(MSS, Window Scale)을 보내고 SYN-SENT. SYN-ACK를 받으면 ACK를 보내고 ESTABLISHED, `.established`. RST(ACK가 맞는 것)를 받으면 `.closed(.refused)`. ACK 없는 SYN(동시 열기)은 버린다(제외 표).
4. **수동 열기**: 스택이 SYN을 넘겨 연결을 만든다. SYN-ACK를 보내고 SYN-RECEIVED. 맞는 ACK를 받으면 ESTABLISHED, `.established`. 틀린 ACK에는 `<SEQ=SEG.ACK><CTL=RST>`. RST는 동작 X3의 규칙으로 본다: `SEG.SEQ = RCV.NXT`일 때만 조용히 사라지고, 창 안의 다른 값이면 challenge ACK다(`.closed`를 내되 앱에는 알려지지 않는다. 아직 accept되지 않았다).
5. **MSS**: 광고하는 값은 1280 − IP 머리 − 20이다(IPv4 1240, IPv6 1220. TCP 노트 7절). 보내는 세그먼트의 데이터는 `min(상대가 광고한 MSS, 광고하는 값과 같은 식)`에서 그 세그먼트의 TCP 옵션 길이를 뺀 것 이하다(RFC 9293 3.7.1. 데이터 세그먼트에는 옵션을 싣지 않으므로 지금은 0이다). 상대의 SYN에 MSS 옵션이 없으면 IPv4 536, IPv6 1220으로 본다(같은 절). MSS를 지킨다고 경로에서 단편화되지 않는 것은 아니다. tailnet 경로는 WireGuard가 1280을 보장한다.
6. **닫기**(TCP 노트 4.4):
   - `finishWriting`: 보내는 버퍼가 비면 FIN을 보낸다. ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK.
   - `close`: `finishWriting`에 더해 읽기를 끝낸다. 받는 버퍼에 읽지 않은 데이터가 있으면 곧바로 RST를 보내고 끝난다. 닫은 뒤에 데이터가 오면 RST를 보내고 끝난다(SHLD-3).
   - FIN-WAIT-2에서 `close`를 부른 연결은 60초 안에 상대의 FIN이 오지 않으면 사라진다(gVisor의 linger 기본값). `finishWriting`만 부른 연결(읽는 쪽이 살아 있다)은 기한이 없고 keep-alive가 지킨다.
   - TIME-WAIT는 60초다(gVisor의 값이다. RFC 9293 3.6.1의 2MSL은 4분이다). 이 상태에서 FIN이 든 세그먼트가 오면, 시퀀스 검사로는 받지 않는 세그먼트(이미 소비한 FIN의 재전송)여도 ACK로 답하고 60초를 다시 잰다(RFC 9293 3.10.7.4의 TIME-WAIT 예외). 일반 시퀀스 검사에서 먼저 버리면 여기에 닿지 못하므로 따로 본다.
   - `abort`: SYN-SENT면 아무것도 보내지 않고, 그 밖에는 `<SEQ=SND.NXT><CTL=RST>`를 보내고 CLOSED.
7. **상대가 닫음**: FIN을 받으면 `.endOfStream`. 그 전에 받은 데이터는 모두 읽을 수 있다. RST를 받으면 버퍼를 비우고 `.closed(.reset)`. 둘은 다른 사건이다(MUST-12).
8. **keep-alive**: ESTABLISHED·CLOSE-WAIT·FIN-WAIT-2에서 받은 것도 보낼 것도 없이 2시간이 지나면 `<SEQ=SND.NXT-1><CTL=ACK>`(데이터 없음)를 75초마다 보낸다. 9번 보내도록 아무것도 받지 못하면 `.closed(.timedOut)`. 무엇이든 받으면 다시 2시간을 잰다. 값은 gVisor 기본값이다(TCP 노트 5절). 끄는 길은 없다(총괄 확인 필요 N5).
9. 받은 keep-alive 탐침(`SEG.SEQ = RCV.NXT-1`, 길이 0 또는 1)에는 시퀀스 검사의 "받지 않는 세그먼트에 ACK" 규칙으로 답하게 된다. 따로 처리하지 않는다.

구현에서 정해진 것(M6-4, 2026-11-15. `Sources/SwiftailNetstack/Connection/`):

- **생성**: `TCPConnection.connect(from:to:initialSequenceNumber:at:)`와, 스택이 ACK·RST 없는 SYN을 넘기는 `accept(_:initialSequenceNumber:at:) throws(AcceptError)`다. 상대 MSS가 64보다 작으면 그 SYN에 답할 RST를 오류에 담아 던진다. SYN·SYN-ACK에 실린 데이터와 FIN은 받지 않는다(상대가 다시 보낸다).
- **`receive`는 순수 ACK를 내지 않는다.** 곧바로 보낼 ACK(어긋난 데이터, 빈 곳을 메운 데이터, FIN, 창 밖 세그먼트, challenge ACK, 창 갱신)도 "지금"이 기한인 타이머로 둔다. 스택과 노드는 패킷 묶음을 넣은 뒤 **같은 시각으로 `advance(to:)`를 불러** ACK를 받는다(동작 F5·N4의 묶음 ACK). 응용 호출(`write`·`read`·`close` 등)은 끝에서 바로 낸다.
- **닫힌 까닭**은 `finished`·`reset`·`refused`·`timedOut`·`aborted`다. `finished`만 받는 버퍼를 남긴다. `close(at:)`가 선언에 더해졌다. `peerRemoved`는 연결이 아니라 스택이 낸다(아무것도 보내지 않고 연결을 버린다).
- **타이머**는 일곱 개(TIME-WAIT, FIN-WAIT-2 linger, 재전송, 0 창 탐침, SWS override, keep-alive, ACK)이고 `nextDeadline`은 그중 가장 이른 것이다. 끝난 연결은 nil이다. 같은 시각이면 데이터를 내는 타이머가 ACK보다 먼저다.
- **go-back-N**은 SND.NXT를 되돌리지 않고 "다음에 보낼 번호"를 따로 둔다(gVisor와 같다). ACK의 범위 검사는 지금까지 보낸 가장 높은 번호가 기준이다.
- **0 창 탐침**은 `<SEQ=SND.UNA−1>`에 0 한 바이트를 실은 ACK다(gVisor의 형식. RFC 9293 3.8.6.1의 "새 데이터 한 바이트"와 다르다. 탐침이 재전송 횟수에 섞이지 않는다). 창이 0일 때 RCV.NXT에서 시작하는 데이터 세그먼트는 데이터만 버리고 ACK·RST를 처리한 뒤 곧바로 ACK한다(RFC 9293 3.10.7.4).
- SYN-RECEIVED의 틀린 ACK는 RFC 5961 5.2의 범위 검사보다 먼저 보고 늘 RST로 답한다(T4, Linux·gVisor와 같다). challenge ACK의 속도 제한(5초에 10개)은 동작 X2·X3의 ACK에도 함께 쓴다.
- TIME-WAIT의 FIN 예외는 번호가 RCV.NXT−1인 FIN에만 적용한다(이미 소비한 FIN의 재전송. gVisor와 같다). `abort`는 CLOSING·LAST-ACK·TIME-WAIT에서 RST를 보내지 않는다(RFC 9293 3.10.5). SYN-SENT의 `close`는 아무것도 보내지 않고 `aborted`로 끝난다.
- 지연 ACK의 2×MSS는 이 쪽이 광고한 MSS가 기준이다. SYN을 다시 보내지 않았으면 핸드셰이크 왕복이 RTT의 첫 표본이다. PSH는 버퍼의 마지막 바이트를 싣는 세그먼트에 켠다.
- 빈 곳 너머에 먼저 온 FIN은 번호를 적어 두었다가 그 앞의 데이터가 다 도착하면 소비한다(RFC 9293 3.10.7.4 SHLD-31. 처음에는 `shortcut:`이었으나 독립 시험 M6-6이 짚어 넣었다).
- 손실이 심한 경로에서는 닫기가 `finished`가 아니라 `timedOut`으로 끝날 수 있다: TIME-WAIT 60초가 지난 뒤에야 상대의 FIN 재전송(RTO가 120초까지 자란다)이 닿으면 그 연결은 이미 없다. 데이터는 그 전에 모두 전달된 뒤다(M6-6의 손실 20% 조합에서 관찰).

### R. 재전송과 혼잡 제어

1. **RTO**(TCP 노트 4.5): 처음 1초. 측정이 생기면 RFC 6298 2.2·2.3의 식. 하한 200ms, 상한 120초(gVisor와 같다. RFC 6298 2.4의 1초 하한은 SHOULD다. 총괄 확인 필요 N4). G는 0으로 본다(시계가 나노초 단위다).
2. **RTT 재기**: 한 번에 세그먼트 하나의 왕복만 잰다. 그 세그먼트가 재전송되면 그 측정을 버린다(Karn). 타임스탬프 옵션은 쓰지 않는다.
3. **타이머 관리**는 RFC 6298 5.1~5.6 그대로다. SYN의 재전송 타이머가 만료된 적이 있고 맺어진 뒤의 RTO가 3초보다 작으면 3초로 올린다(5.7. 이미 더 큰 값을 낮추지 않는다).
4. **한도**: 데이터는 같은 세그먼트를 15번 다시 보내도록 확인이 없으면 `.closed(.timedOut)`(gVisor와 같다). SYN과 SYN-ACK는 7번 다시 보낸다(보낸 뒤 1·3·7·15·31·63·127초). 일곱 번째 재전송의 타이머(128초가 상한 120초에서 잘린다)가 만료되는 247초에 버린다. 횟수는 연결이 세고, 간격은 `RTOEstimator`의 두 배 규칙과 상한 그대로다. RFC 9293 3.8.3(MUST-23)이 SYN의 R2를 3분 이상으로 요구한다. gVisor는 127초에 그만두지만(6번) 따르지 않는다. SYN-ACK를 일찍 버리면 상대의 마지막 ACK가 사라졌을 때 맺어진 줄 아는 상대의 연결이 끊긴다.
5. **보낼 수 있는 양**: `min(cwnd, SND.WND) − (SND.NXT − SND.UNA)`.
6. **혼잡 제어**(TCP 노트 4.7): 초기 창 `min(10*MSS, max(2*MSS, 14600))`(RFC 6928, gVisor도 10 세그먼트). slow start와 congestion avoidance는 RFC 5681 식 2·3(식 3의 정수 나눗셈이 0이면 1바이트를 올린다), 손실 때 ssthresh는 식 4. 다만 **같은 세그먼트의 재전송 타이머가 되풀이해 만료될 때는 ssthresh를 다시 줄이지 않는다**(RFC 5681 3.1. 처음 만료 때만 식 4). RTO 만료면 cwnd를 1 세그먼트로 하고 slow start. 중복 ACK 3개면 RFC 5681 3.2의 단계 2~6에 RFC 6582 3.2의 `recover`와 partial ACK 처리를 더한다. 중복 ACK의 정의는 RFC 5681 2절이다.
   - 구현에서 정해진 것(M6-3, 2026-11-15. `RTOEstimator`, `NewRenoCongestionControl`): Karn(재전송된 세그먼트의 표본을 버림)은 보내는 버퍼를 쥔 연결이 지키고, 추정기는 재전송되지 않은 세그먼트의 표본만 받는다. `recover`는 RFC 6582의 "보낸 가장 높은 번호"를 한 칸 뒤(그때의 SND.NXT)로 적어 두고 `ACK > recover`로 견준다(같은 식이지만, 초기값 ISS에서도 첫 창의 손실이 fast retransmit에 걸린다. 문자 그대로의 `ACK − 1 > recover`는 SYN만 확인된 상태에서 거짓이 된다). 새 ACK가 `recover`를 넘으면 ACK − 1로 끌어올린다(손실 없이 2³¹바이트를 넘게 보낸 뒤 비교가 뒤집혀 fast retransmit이 막히는 것을 막는다. RFC에 없는 보완이다). full ACK의 cwnd는 `min(ssthresh, max(FlightSize, SMSS) + SMSS)`다. `cwnd == ssthresh`는 congestion avoidance로 본다. cwnd의 상한은 2³⁰이다. 같은 세그먼트의 반복 RTO 만료는 `SND.UNA`로 가린다. `shortcut:` fast recovery 중 부풀리기를 날아가는 세그먼트 수로 묶는 것(RFC 5681 3.2 단계 4의 MAY)은 없다.
7. 재전송은 늘 SND.UNA부터의 한 세그먼트다(SACK이 없다). RTO 만료 뒤에는 slow start가 창을 다시 열며 순서대로 다시 보낸다(go-back-N).
8. 유휴가 RTO보다 길었으면 보내기 전에 cwnd를 `min(초기 창, cwnd)`로 줄인다(RFC 5681 4.1).

### F. 흐름 제어와 버퍼

1. **받는 버퍼**는 연결마다 256KiB다. 광고하는 창은 버퍼의 남은 자리이고, 창의 오른쪽 끝을 왼쪽으로 옮기지 않는다(SHLD-14). 창 확장의 shift로 내림한 탓에 방금 광고한 값이 전보다 작아져도, 전에 허용한 오른쪽 끝까지는 받아들인다(RFC 7323 2.4).
2. **창 확장**(RFC 7323 2.2~2.4): 능동 열기의 SYN에는 늘 옵션을 싣고, 수동 열기의 SYN-ACK에는 상대의 SYN에 옵션이 있을 때만 싣는다. **양쪽 SYN에 모두 있을 때만** 켜지고, 방향마다 shift가 따로다(보내는 창은 상대의 shift로, 광고하는 창은 자기 shift로). SYN과 SYN-ACK 세그먼트의 창 필드는 확장하지 않는다. 상대의 shift가 14를 넘으면 14로 본다. 자기 shift는 3이다(`65535 << 3 >= 262144`가 되는 가장 작은 값. gVisor `FindWndScale`의 규칙). 꺼지면 창은 65,535까지다.
3. **받는 쪽 SWS 회피**: 창의 오른쪽 끝은 늘릴 수 있는 양이 `min(버퍼/2, MSS)` 이상일 때만 올린다(RFC 9293 3.8.6.2.2). 앱이 읽어 그만큼 열리면 창 갱신 ACK를 보낸다.
4. **순서가 어긋난 데이터**는 받는 창 안의 것만 받는 버퍼의 제자리에 둔다. 구간(빈 곳으로 갈린 덩어리)은 32개까지다. 넘으면 그 세그먼트를 버린다(상대가 다시 보낸다). 겹치는 바이트는 먼저 받은 것을 둔다. 창의 왼쪽이나 오른쪽으로 걸친 세그먼트는 창 안의 부분만 받는다.
   - 구현에서 정해진 것(M6-2, `ReceiveBuffer`): 구간은 `RCV.NXT`에서의 거리로 둔다. 새 구간이 필요한 세그먼트만 32개 상한을 받고, 기존 구간을 늘리거나 잇거나 `RCV.NXT`에 닿는 세그먼트는 32개에서도 받는다. 33번째 구간이 필요한 세그먼트는 창 안의 부분도 받지 않는다. 저장소는 연결당 원형 하나이고 쓰는 만큼만(4KiB부터 두 배씩) 자란다. `shortcut:` 한 번 자란 저장소는 줄이지 않는다. `ReceiveBuffer.windowEnd`는 앱이 읽을 때만 나아가고, 연결은 거기서 SWS 회피와 shift 내림을 거친 오른쪽 끝을 따로 기억한다. 버퍼는 물리 한계까지만 자르므로, 광고한 오른쪽 끝을 넘는 바이트는 **연결이 `insert` 전에 잘라 버린다**.
5. **ACK 보내기**: 순서가 어긋난 세그먼트, 빈 곳을 메우는 세그먼트, FIN, 창 밖 세그먼트에는 곧바로 ACK한다. 순서대로 온 데이터는 확인하지 않은 양이 2×MSS 이상이면 곧바로, 아니면 40ms 안에 ACK한다(RFC의 한도는 500ms 미만). 나가는 데이터 세그먼트가 있으면 거기에 실어 보낸다. 노드가 한 번에 처리하는 패킷 묶음 안에서는 ACK를 모아 연결마다 한 번 낸다(MUST-58·59. 동작 N4).
6. **보내는 버퍼**는 연결마다 256KiB다(아직 확인받지 못한 것과 아직 보내지 않은 것의 합). `write`는 자리가 있는 만큼만 받아들인다.
   - 구현에서 정해진 것(M6-2, `SendBuffer`): SYN·FIN은 버퍼 밖의 번호라 연결이 센다. `startSequence`는 데이터 쪽 `SND.UNA`이고, 범위 밖 ACK는 버퍼를 바꾸지 않는다. `shortcut:` 꺼낼 때마다 새 배열에 복사한다(`Span`은 지원 하한 macOS 15·iOS 18에 없다).
7. **보내는 쪽 SWS 회피**: 보낼 데이터 D, 쓸 수 있는 창 U에 대해 `min(D, U) >= MSS`이거나 `D <= U`이거나 `min(D, U) >= 지금까지 본 가장 큰 SND.WND / 2`일 때 보낸다. 아니면 창이 열리기를 기다린다. 창이 0이 아닌 작은 값에 머물면 끝없이 기다리게 되므로, 보낼 것이 있는데 위 조건이 **200ms** 동안 채워지지 않으면 창이 허락하는 만큼 보낸다(RFC 9293 3.8.6.2.1의 override 시간. 권고는 0.1~1초). 창이 0이면 아래 탐침이 맡는다. Nagle은 없다(제외 표).
8. **0 창 탐침**: 보낼 것이 있는데 SND.WND가 0이면 RTO 뒤에 1바이트를 보내고, 간격을 두 배씩(상한 60초) 늘려 계속한다. 상대가 ACK하는 한 끊지 않는다(MUST-37). 탐침 15번에 아무 ACK도 없으면 `.closed(.timedOut)`(gVisor `snd.go:597`).
9. 창 갱신은 `SND.UNA =< SEG.ACK =< SND.NXT`인 세그먼트에서만, RFC 9293 3.10.7.4의 SND.WL1·WL2 규칙으로 받는다. 동작 X3이 받아 주는 오래된 ACK(`SND.UNA`보다 앞)는 창을 바꾸지 않는다.

### S. 스택 (`TCPStack`)

1. **찾기**: 들어온 세그먼트는 (자기 주소, 자기 포트, 상대 주소, 상대 포트)로 연결을 찾고, 없으면 자기 포트로 리스너를 찾는다. 목적지가 자기 tailnet 주소가 아니면 `.dropped(.notForUs)`다(필터가 이미 걸렀지만 스택도 본다).
2. **연결도 리스너도 없으면** RFC 9293 3.10.7.1대로 RST로 답한다(RST에는 답하지 않는다). 리스너 없는 포트로 온 SYN도 여기다. tsnet도 RST다(TCP 노트 6.2 4).
3. **리스너**: 포트 하나에 하나, 16개까지. 자기 노드의 모든 tailnet 주소(IPv4·IPv6)를 듣는다. 리스너에 온 세그먼트는 TCP 노트 4.2의 LISTEN 규칙: RST는 무시, ACK가 있으면 RST로 답, SYN이면 연결을 만든다.
4. **맺는 중인 연결(SYN-RECEIVED)의 상한**: 스택 전체 64개, 상대 주소 하나에 16개. 넘는 SYN은 응답 없이 버린다(gVisor forwarder와 같다, TCP 노트 5절). 상대는 SYN을 다시 보낸다. 이 상태의 연결은 버퍼를 갖지 않는다.
5. **accept 대기열**: 맺어졌지만 앱이 아직 받아 가지 않은 연결은 리스너마다 32개까지다. 차 있으면 새 SYN을 응답 없이 버린다. 기다리는 동안에도 연결은 데이터를 받는다(받는 창까지). 리스너를 닫으면 대기열의 연결을 RST로 끊고 맺는 중인 연결을 버린다.
6. **연결 수의 상한**: 맺는 중·맺어진·닫는 중인 연결을 합쳐 256개. 닿으면 새 SYN은 응답 없이 버리고 `connect`는 `limitReached`다. TIME-WAIT의 기록은 따로 1,024개까지 두고 **기한 전에 버리지 않는다**(버리면 상대의 FIN 재전송에 RST로 답하게 되고, 앞 연결의 늦은 세그먼트가 같은 4-튜플의 새 연결에 섞일 수 있다). 1,024개에 닿으면 기록이 빠질 때까지 새 SYN을 응답 없이 버리고 `connect`는 `limitReached`다(닫힌 쪽). 기록 하나는 4-튜플과 시퀀스 번호 둘, 기한뿐이다.
7. **ISN**(RFC 6528 3): `ISN = M + F`. M은 스택을 만든 시각부터 4마이크로초마다 1씩 느는 값, F는 `HMAC-SHA256(비밀, 자기 주소 ‖ 자기 포트 ‖ 상대 주소 ‖ 상대 포트)`의 앞 32비트다. 비밀은 노드가 `run()`마다 시스템 난수로 32바이트를 뽑아 넘긴다.
8. **나가는 연결의 포트**: 49152…65535에서 차례로 고르고, 같은 4-튜플이 쓰이고 있으면(TIME-WAIT 포함) 건너뛴다. 출발 주소는 목적지와 같은 계열의 자기 주소다(tsnet과 같다). 그 계열의 자기 주소가 없으면 `unknownHost`.
9. **주소 바뀜**: 노드가 netmap을 적용할 때마다 자기 주소 목록을 넘긴다. 자기 주소가 아니게 된 주소를 쓰는 연결은 `.closed(.peerRemoved)`로 끝난다(아무것도 보내지 않는다).
10. **출력의 순서**: `receive`·`advance`·응용 호출의 출력 목록은 낸 순서대로 처리해야 한다. 한 연결의 세그먼트는 시퀀스 순서로 나온다.

구현에서 정해진 것(M6-5, 2026-11-15. `Sources/SwiftailNetstack/Stack/`):

- **ID**: `TCPStack.ConnectionID`·`ListenerID`는 스택 안에서 다시 쓰지 않는 `UInt64`다. 옛 ID로 부른 호출은 새 연결에 닿지 않고, 응용이 쥐지 않은 ID(없는 것, `close`·`abort`로 놓은 것, 대기열에 있는 것)는 아무 일도 하지 않는다.
- **선언**: `init(isnSecret:now:)`, 입력 `receive(_:at:)`·`advance(to:)`·`setLocalAddresses(_:)`·`removeConnections(toRemoteAddress:)`, 응용 호출 `listen(on:) throws(ListenError)`·`stopListening(_:)`·`accept(from:)`·`connect(to:at:) throws(ConnectError)`와 ID로 부르는 `write`·`read`·`finishWriting`·`close`·`abort`, 읽는 값 `connection(_:)`(복사본)·`nextDeadline`·`localAddresses`. 출력은 `.ipPacket`·`.event`·`.dropped`이고 사건은 `.established(id)`·`.acceptable(listener)`·`.readable(id)`·`.writable(id)`·`.endOfStream(id)`·`.closed(id, 까닭)`이다. 까닭에 `peerRemoved`가 더해진다.
- **사건은 응용이 쥔 연결에만 나온다.** 맺는 중이거나 대기열에 있거나 `close`한 뒤의 연결은 알리지 않는다. 대기열에 있는 동안 받은 데이터와 FIN은 `accept` 뒤에 `connection(_:)`으로 본다. `.closed(.finished)`는 TIME-WAIT에 들 때 알리고, 남은 데이터는 응용이 `close`할 때까지 읽힌다.
- **노드가 부르는 순서**: 스택을 만들고 `setLocalAddresses` → 패킷 묶음을 하나씩 `receive`에 넣은 뒤 같은 시각으로 `advance(to:)`(미뤄 둔 ACK가 나온다) → `nextDeadline`에 타이머를 맞춘다 → 출력은 낸 순서대로 처리한다. netmap을 적용할 때마다 `setLocalAddresses`를 다시 부르고, 주인이 바뀌거나 없어진 상대 주소마다 `removeConnections(toRemoteAddress:)`를 부른다(동작 X10에서 스택이 맡는 부분).
- **한도**: accept 대기열 32개에는 맺는 중인 연결도 센다(대기열이 32개를 넘지 않게). 연결 256개에는 맺는 중·대기열·응용이 쥔 것·놓았지만 닫는 중인 것이 모두 든다. 넘친 것은 `.dropped(.limitReached(종류))`로 알린다. TIME-WAIT 기록이 1,024개면 그 뒤 TIME-WAIT에 든 연결은 기록으로 옮기지 않고 연결인 채로 마친다.
- **TIME-WAIT 기록**: RST는 무시한다(RFC 9293 3.10.7.4는 CLOSED로 가라고 하지만 기한 전에 버리지 않기로 한 S6과 gVisor를 따른다). SYN과 데이터에는 ACK로 답하고 같은 4-튜플의 새 연결을 다시 열지 않는다. FIN의 재전송에는 ACK하고 기한을 다시 잰다. 데이터 없는 ACK에는 답하지 않는다. 주소가 바뀌어도 기록은 기한까지 둔다.
- 나가는 포트는 차례로 고른다(RFC 6056의 무작위 고르기가 아니다. 상대는 인증된 tailnet 피어다). 포트 0은 노드가 거른다. `stopListening`은 맺는 중인 연결을 아무것도 보내지 않고 버린다.
- 비용(연결 256개·기록 1,024개, 디버그 빌드): `receive` 하나 약 7µs, `nextDeadline` 약 5µs, 기한 없는 `advance` 약 27µs. `shortcut:` 기한은 힙 없이 훑는다.

### X. 신뢰할 수 없는 입력

tailnet 피어는 WireGuard로 인증되고 출발 주소는 그 피어의 AllowedIPs로 검사된다(엔진 계약 M3 동작 2·5, M-E2). 그래서 어떤 피어도 **다른 피어의 연결**에 세그먼트를 끼워 넣지 못한다. 남는 위협은 피어 자신이 보내는 틀린 세그먼트와 자원 고갈이다. 수신 필터는 TCP에서 SYN만 규칙에 견주므로(`PacketFilter`), **SYN이 아닌 세그먼트는 ACL이 막은 피어의 것도 스택까지 온다.**

1. 어떤 바이트열을 넣어도 죽지 않는다. 범위를 넘는 인덱스, 정수 넘침(길이 합, 창 계산, `SEG.SEQ + SEG.LEN`), 끝없는 옵션 순회가 없어야 한다.
2. **창 밖의 시퀀스**: 받지 않고 ACK로만 답한다(TCP 노트 4.2 1). 데이터 없는 창 밖 세그먼트에 대한 ACK는 4의 속도 제한을 받는다(ACK 고리를 막는다).
3. **RST**(RFC 5961 3.2): 창 밖이면 조용히 버리고, `SEG.SEQ = RCV.NXT`일 때만 끊고, 창 안의 다른 값이면 challenge ACK를 보낸다. **SYN**(4.2): 동기화된 상태에서는 늘 challenge ACK를 보내고 버린다. **ACK**(5.2): `SND.UNA − MAX.SND.WND =< SEG.ACK =< SND.NXT` 밖이면 버리고 ACK를 보낸다.
4. challenge ACK는 연결마다 5초에 10개까지다(RFC 5961 7의 예). 넘으면 보내지 않는다.
5. **창 0**: 상대가 창을 0으로 두어도 연결은 탐침으로 유지된다(동작 F8). 보내는 버퍼는 256KiB에서 멈추고 `write`가 기다린다. 그 연결이 쥐는 메모리는 상한 그대로다.
6. **작게 쪼갠 세그먼트**: 1바이트짜리 세그먼트를 띄엄띄엄 보내도 순서가 어긋난 구간은 32개까지이고(동작 F4), 데이터는 받는 버퍼 한 덩어리 안에 놓이므로 세그먼트마다 따로 쥐는 메모리가 없다.
7. **SYN 홍수**: 동작 S4·S5·S6의 상한. 맺는 중인 연결은 버퍼가 없고 247초 안에 사라진다(동작 R4). 상대 주소 하나가 쥘 수 있는 것은 16개다.
8. **연결 없는 곳으로 오는 세그먼트**: 하나에 RST 하나로 답한다. 답이 받은 것보다 크지 않으므로 증폭이 없다. 따로 속도를 제한하지 않는다.
9. **상대가 광고하는 값**: MSS는 그대로 믿지 않고 자기 MTU로 다시 묶는다(동작 T5). 상대가 광고한 MSS가 64보다 작으면 **연결을 맺지 않는다**: 수동 열기면 그 SYN에 RST로 답하고, 능동 열기면 RST를 보내고 `.closed(.refused)`다. 작은 값을 올려 잡아 보내면 상대의 받는 한도를 넘기게 되고(RFC 9293 3.7.1 MUST-16), 그대로 따르면 1바이트 세그먼트를 끝없이 만들게 된다. 64는 이 계약의 값이다(gVisor는 광고받은 값이 0이 아니면 48로 올려 잡는다, `gvisor/header/tcp.go:439`. RFC가 허용하는 근거는 없다). 창이 줄어드는 것을 견딘다(MUST-34): 쓸 수 있는 창이 음수면 새 데이터를 보내지 않는다.
10. **주소의 주인이 바뀜**: 연결을 맺을 때 상대 주소를 가진 피어의 node 키를 노드가 적어 둔다. netmap이 바뀌어 그 주소의 주인이 없어지거나 다른 키가 되면 그 연결을 `.closed(.peerRemoved)`로 끝낸다. 주소를 물려받은 다른 노드가 앞 노드의 연결을 이어 쓰는 것을 막는다(N8). Go의 netstack에는 이런 처리가 없다: 피어가 빠지거나 주소의 주인이 바뀌어도 열린 연결을 끊지 않고 재전송·keep-alive·응용의 종료에 맡긴다(`wgengine/netstack/netstack.go:729` 부근, TCP 노트). Swiftail이 더 엄격하다.

### N. 노드와의 접점 (`Swiftail`)

1. **장치**: `.inProcess`면 노드는 utun도 메모리 흐름도 쓰지 않는다. `inboundPackets`는 아무것도 내지 않고 `send(_:)`는 버린다. `networkSettings`는 M5와 같이 나온다(앱은 읽지 않아도 된다). `.utun`·`.memory`에서 `listen`·`connect`는 `invalidConfiguration`이다.
2. **들어오는 길**: 엔진이 장치로 쓰라고 낸 `.ipPacket`(피어가 보냈고 필터를 통과한 것, 자기 주소로 되돌린 것)을 `stack.receive(_:at:)`에 넣는다. TCP가 아닌 패킷은 스택이 `.dropped(.notTCP)`로 버린다(제외 표의 ICMP·UDP).
3. **나가는 길**: 스택의 `.ipPacket`을 `engine.send(_:at:)`에 넣는다. M5의 로컬 처리(동작 L)를 그대로 거친다: 자기 주소로 건 연결은 엔진이 되돌려 스택에 다시 들어오고, 서비스 IP로 건 연결은 엔진의 RST로 거절된다.
4. **한 사건을 끝까지**: 패킷 하나(또는 앱 호출·타이머 하나)에서 비롯된 스택과 엔진 사이의 주고받기는 `await` 없이 끝까지 돈다. 재귀가 아니라 대기열로 돈다(자기 주소로 건 연결의 큰 전송에서 호출 깊이가 자라지 않게 한다). 대기열이 빈 뒤에 미뤄 둔 ACK를 낸다(동작 F5).
5. **사건**: 스택의 사건으로 기다리던 호출을 깨운다. `readable` → 그 연결의 `read`, `writable` → `write`, `established` → `connect` 또는 리스너의 대기열, `closed(까닭)` → 그 연결의 모든 대기와 이후 호출이 그 까닭의 오류를 받는다.
6. **타이머**: 노드의 타이머가 엔진·`Magicsock`·스택의 `nextDeadline` 가운데 이른 것에 깨어 셋 다 `advance`한다.
7. **netmap**: 적용할 때마다 자기 주소를 스택에 넘기고(동작 S9), 연결마다 적어 둔 상대 키를 견준다(동작 X10).
8. **노드가 멈출 때**: `run()`이 끝나며 열린 연결마다 RST를 한 번 낸다(직접 경로면 나간다. DERP 통로에 있던 것은 사라질 수 있다). 기다리던 호출은 `notRunning`으로 깨어나고 리스너의 흐름은 끝난다. 그 뒤의 `listen`·`connect`는 `notRunning`이다.
9. **버려진 핸들**: `TailnetConnection`·`TailnetListener`의 `deinit`은 기다리지 않는 통로에 "끊기" 요청을 넣고, `run()`의 자식 하나가 그것을 처리한다(M5의 `startInteractiveLogin`과 같은 방식). 분리된 Task를 만들지 않는다.
10. **손실에서 오는 역압**: 스택이 낸 패킷이 UDP 송신 실패나 DERP 통로의 넘침(256개·1MiB, 터널 계약 동작 M)으로 사라지는 것은 TCP에게 보통의 손실이다. 혼잡 제어가 줄인다. 통로에서 스택으로 가는 신호는 따로 없다.
11. 시험 전용(공개 API 아님): `package func setInProcessLoss(rate: Double, seed: UInt64)`. 스택과 엔진 사이의 패킷을 양방향으로 `rate`의 확률로 버린다. 난수는 `seed`에서 만든다. 기본은 0이다.

### A. 가장자리: 듣기·걸기·읽기·쓰기

1. **`listen`**: 장치와 포트를 검사하고 리스너를 스택에 올린다. `run()` 전이면 적어 두었다가 `run()`이 시작할 때 올린다(`run()`을 띄운 직후에 불러도 실패하지 않게 한다). netmap 전에 들어도 된다(SYN은 netmap과 필터가 선 뒤에만 온다).
2. **`connect`**: ① 상태가 `.running`이 아니면 `notRunning`. ② `host`가 IP 주소면 그대로. 아니면 소문자로 바꾸고 끝 점을 뗀 이름을 netmap에서 찾는다: 피어와 자기 노드의 FQDN, MagicDNS 접미사를 뗀 짧은 이름. IPv4 주소를 먼저 고르고 없으면 IPv6다(Go `resolve.go:54-75`, `:115-140`). ③ 그 주소가 데이터면 피어의 주소나 자기 주소가 아니면 `unknownHost`. ④ SYN을 보내고 맺어질 때까지 기다린다. 결과는 연결, `refused`, `timedOut`(247초), `cancelled`다. tailnet 밖의 이름을 시스템 DNS로 찾거나 OS 소켓으로 걸지 않는다(tsnet과 다르다).
3. **`read`**: 받는 버퍼에 있으면 곧바로, 없으면 `readable`까지 기다린다. 상대의 FIN 뒤 버퍼가 비면 nil. 취소되면 `.cancelled`를 던지고 연결은 그대로다(버퍼의 데이터는 남는다).
4. **`write`**: 자리가 있는 만큼 넣고, 남으면 `writable`까지 기다렸다가 이어 넣는다. 사이사이 actor를 놓으므로 큰 쓰기가 노드를 붙잡지 않는다. `finishWriting`이나 `close` 뒤의 `write`는 `closed`.
5. **역압**: 받는 쪽은 앱이 읽어 간 만큼만 창이 열린다(읽지 않으면 상대가 256KiB에서 멈춘다). 보내는 쪽은 `write`가 버퍼 256KiB에서 멈춘다. 가장자리에 따로 쌓는 버퍼가 없다.
6. **동시 사용**: 연결 하나에 `read` 하나와 `write` 하나가 동시에 기다릴 수 있다. 같은 방향의 둘째 호출은 `concurrentUse`. 리스너를 도는 Task는 하나다.
7. **끝난 연결**: `closed(까닭)` 뒤의 `read`·`write`·`finishWriting`은 그 까닭의 오류를 던진다(`reset`, `timedOut`, `peerRemoved`). 앱이 `close`·`abort`한 뒤에는 `closed`.
8. **시간 제한**: API에 없다. 앱은 Task 취소로 건다(첫 사용처 확인 필요 F6).

### M. 메모리

| 버퍼 | 상한 | 넘으면 |
| --- | --- | --- |
| 연결의 받는 버퍼(순서가 어긋난 데이터 포함) | 256KiB | 창 밖은 받지 않는다 |
| 연결의 보내는 버퍼 | 256KiB | `write`가 기다린다 |
| 순서가 어긋난 구간 | 연결마다 32개 | 그 세그먼트를 버린다 |
| 연결(맺는 중·맺어짐·닫는 중) | 256개 | SYN을 버린다, `connect`는 `limitReached` |
| 맺는 중인 연결 | 64개, 상대 주소 하나에 16개 | SYN을 버린다 |
| accept 대기열 | 리스너마다 32개 | SYN을 버린다 |
| 리스너 | 16개 | `limitReached` |
| TIME-WAIT 기록 | 1,024개(버퍼 없음) | 기한 전에 버리지 않는다. 닿으면 새 SYN을 버리고 `connect`는 `limitReached`(동작 S6) |

- 버퍼는 쓰는 만큼만 잡고 상한까지 자란다. 유휴 연결은 버퍼를 쥐지 않는다.
- 최악은 256 × 512KiB = 128MiB다. 첫 사용처의 Mac 호스트를 기준으로 잡은 값이다. iOS 확장 안에서 `.inProcess`를 쓰게 되면 이 값으로는 50MiB 한도를 지킬 수 없다(첫 사용처 확인 필요 F6).
- Go와의 비교: gVisor의 버퍼 기본값은 방향마다 1MiB, 맺는 중인 연결의 상한은 macOS 2,048개다(TCP 노트 5절).

### K. 비밀과 로그

1. ISN의 비밀은 사건·오류·`description`·`dump`에 나오지 않는다.
2. 로그는 노드가 `os.Logger(subsystem: "Swiftail")`로 남긴다(M5와 같은 규칙): 리스너 열림·닫힘(포트), 연결의 맺어짐과 끝난 까닭, 상한에 닿아 버린 횟수. 주소 전체와 실린 데이터는 남기지 않는다.

## 결정

| # | 결정 | 정한 것 | 근거 |
| --- | --- | --- | --- |
| D1 | 혼잡 제어 | NewReno(RFC 5681 + 6582) | plan 4절(a). 규격이 짧고 결정적 시험으로 덮기 쉽다. gVisor의 CUBIC은 넣지 않는다 |
| D2 | 초기 창 | RFC 6928(10 세그먼트) | gVisor·Linux와 같다. 작은 HTTP 응답이 한 왕복에 끝난다 |
| D3 | 타임스탬프 | 쓰지 않는다 | 선택 기능이다. Karn만으로 RTO를 잴 수 있다. 세그먼트마다 12바이트가 준다 |
| D4 | 지연 ACK | 2×MSS 또는 40ms | RFC의 SHOULD. gVisor는 미루지 않는 것으로 보인다(TCP 노트 11절 1) |
| D5 | Nagle | 없음 | `write`가 준 바이트는 창이 허락하는 대로 나간다. 작은 쓰기를 묶는 일은 앱이 한다 |
| D6 | 받아 가지 않은 연결 | 대기열 상한(32)까지 둔다 | tsnet의 "1초 뒤 닫기"는 통로에 버퍼가 없어서 생긴 규칙이다(`tsnet.go:2406-2418`의 TODO) |
| D7 | 연결 없는 곳의 세그먼트 | RST | RFC와 gVisor가 같다 |
| D8 | 체크섬 검사 | 받을 때 검사한다 | Tailscale도 netstack 앞에서 검사한다. 자기 구현의 잘못을 관문에서 잡는다 |
| D9 | MTU | 1280 고정 | Tailscale TUN의 기본값. 인자를 두지 않는다 |
| D10 | 체크섬 코드의 자리 | `SwiftailBase`(`package`) | RFC 1071 계산을 두 벌 두지 않는다. 엔진 쪽은 호출만 바뀐다 |
| D11 | `SwiftailNetstack`의 접근 수준 | `package`, 제품 아님 | 앱이 쓰는 타입은 `Swiftail`의 것뿐이다. 공개 표면을 늘리지 않는다 |

## 총괄 확인 필요

| # | 무엇 | 선택지 | 권고 |
| --- | --- | --- | --- |
| N1 | 타깃의 의존 방향 | (가) `Swiftail`이 `SwiftailNetstack`에 의존한다. 스택은 노드 actor 안의 값이다 / (나) plan 5절대로 `SwiftailNetstack`이 `Swiftail`에 의존한다. 스택은 `.memory` 장치의 `inboundPackets`·`send` 위에 선 별도 actor다 | (가). (나)는 노드와 스택 사이에 256개에서 버리는 흐름과 actor 건너뛰기가 패킷마다 두 번 끼고, 타이머가 둘이 되고, `extension TailnetNode`에 저장 상태를 둘 수 없어 API가 다른 타입으로 간다. 대가: TCP를 쓰지 않는 앱(iOS 터널 확장)의 바이너리에도 스택 코드가 들어간다(상태는 `.inProcess`일 때만 생긴다). 코드 크기는 구현 뒤에 잰다 |
| N2 | 공개 API의 모양 | (가) 핸들(`TailnetListener`·`TailnetConnection`은 `final class`, 버려지면 끊음), 이름은 `listen(port:)`·`connect(to:port:)` / (나) 범위 함수(`withConnection(to:port:) { … }`, `acceptConnections(port:) { connection in … }`)만 / (다) plan 6절의 이름 `dial(host:port:)` | (가). tsnet과 일대일로 놓이고 첫 사용처의 HTTP 서버가 연결을 자기 Task 묶음에 넣기 쉽다. `deinit`의 끊기는 안전망이다. (나)는 수명이 구조로 보장되지만 연결을 다른 곳에 넘기지 못한다. "dial"은 Go의 말이고 Swift에서는 `connect`가 읽힌다(Network 프레임워크, POSIX) |
| N3 | SACK | (가) M6 최소 범위에서 빼고 관문의 손실 1%·5% 기록을 보고 정한다 / (나) 받는 쪽만(SACK 블록을 낸다) / (다) 양쪽(RFC 6675 회복) | (가). plan 4절(a)가 "측정 뒤에 판단"으로 적었다. 첫 사용처의 큰 전송은 Swift가 보내는 쪽이라 (나)는 도움이 작고, (다)는 상태 기계에서 가장 큰 덩어리다. 기준을 미리 둔다: 손실 1%에서 처리량이 손실 0%의 1/10 아래로 떨어지면 구현 단위 M6-10을 연다. 손실 5%는 기록만 한다 |
| N4 | RTO 하한 | (가) 200ms(gVisor, Linux) / (나) 1초(RFC 6298 2.4의 SHOULD) | (가). 하한 1초면 창 끝의 손실마다 1초씩 멈춘다. 상대인 두 스택이 모두 200ms 근처를 쓴다(커널 쪽은 확인하지 못함) |
| N5 | keep-alive | (가) 늘 켬(2시간·75초·9번), 설정 없음 / (나) 없음 / (다) 연결마다 켜고 끄는 API | (가). RFC는 기본 꺼짐과 응용의 선택을 요구하지만(MUST-24·25), tsnet은 받는 연결에 늘 켠다. Mac 호스트는 며칠씩 돌고 iPhone은 말없이 사라진다. (나)면 본문을 읽다 멈춘 연결이 상한 256을 갉아먹는다. (다)는 요청이 없다 |
| N6 | 메모리 상한의 값 | 동작 M의 표(연결 256, 버퍼 256KiB씩) / 더 크게(gVisor처럼 1MiB) / 더 작게 | 표의 값으로 시작하고 관문의 처리량 기록으로 조정한다. 창 256KiB는 RTT 20ms에서 약 100Mbit/s다 |
| N7 | macOS 커널 스택을 상대로 한 관문 | (가) 관리자 권한 한 번: Go 도구가 utun을 만들고 tsnet을 그 위에 띄운다(`addKernelPeer`). 반복해 돌릴 수 있다 / (나) 실기기: M5의 터널 확장을 켠 iPhone이 Mac의 Swift 리스너에서 받는다(첫 사용처 세션) / (다) 공식 Tailscale 앱을 켠 Mac과 실제 tailnet | (가)를 기본 관문으로, (나)를 마무리로. utun 없이 커널 TCP와 IP 패킷을 주고받는 길을 찾지 못했다(아래 "관문" (나)). (가)는 사용자가 sudo를 한 번 허락해야 한다 |
| N8 | 주소의 주인이 바뀐 연결 | (가) 끊는다(동작 X10) / (나) 그대로 둔다 | (가). 첫 사용처는 요청마다 원격 주소로 WhoIs를 하므로 (나)여도 다음 요청에서 걸리지만, 이미 시작한 전송은 이어진다. Go가 어떻게 하는지는 확인하지 못했다. 대가: 노드가 연결마다 상대 키를 적어 두고 netmap마다 견준다 |
| N9 | 연결 위의 TLS(M7의 일이지만 M6의 API를 가른다) | (가) 루프백 다리: Swiftail 연결을 `127.0.0.1`의 `NWListener`(TLS)로 이어 준다. 원격 주소는 따로 넘긴다 / (나) Swift로 쓴 TLS 1.3 서버 / (다) SecureTransport(`SSLSetIOFuncs`. macOS 10.15·iOS 13부터 폐기 표시, SDK 머리 파일에서 확인) | 지금 정하지 않는다. M6의 API는 바이트 흐름(`read`·`write`)만 내고, 어느 쪽이든 그 위에 설 수 있다. Network 프레임워크의 TLS를 사용자 바이트 흐름 위에 올리는 공개 API는 찾지 못했다(확인하지 못함). M7 계약 전에 따로 조사한다 |
| N10 | 체크섬을 `SwiftailBase`로 옮기기 | (가) 옮긴다(엔진 파일 하나의 호출이 바뀐다) / (나) netstack에 한 벌 더 둔다 | (가)(결정 D10). 엔진의 기존 시험이 그대로 지킨다 |
| N11 | `.inProcess`에서 ICMP echo에 답하기 | (가) 답하지 않는다 / (나) 답한다(tsnet은 답한다) | (가)로 시작한다. disco ping은 스택 없이 된다. 첫 사용처의 답(F12)에 따라 (나) |

### 총괄 확정 (2026-11-15, 초안 단계)

첫 사용처의 검토(아래 F1~F13) 전의 결정이다. 답에 따라 바뀔 수 있는 것은 그렇게 적는다.

| # | 결정 | 덧붙임 |
| --- | --- | --- |
| N1 | (가) `Swiftail`이 `SwiftailNetstack`에 의존한다 | iOS 터널 확장의 바이너리 크기 증가를 구현 뒤에 재어 기록한다. plan 5절 그림과 모듈 표는 검토가 끝난 뒤 함께 고친다 |
| N2 | (가) 핸들과 `listen(port:)`·`connect(to:port:)` | plan 6절 초안의 `dial`은 쓰지 않는다 |
| N3 | (가) SACK 없이 시작하고 관문 기록으로 정한다 | 기준: 손실 1%의 처리량이 손실 0%의 1/10 아래면 M6-10을 연다 |
| N4 | (가) RTO 하한 200ms | — |
| N5 | (가) keep-alive를 늘 켠다 | RFC의 "기본 꺼짐"과 다르다는 것을 문서 주석에 적는다. F5의 답에 따라 다시 본다 |
| N6 | 표의 값(연결 256개, 버퍼 256KiB씩)으로 시작 | Mac 호스트 기준이다. iOS 확장에서 `.inProcess`를 쓰게 되면(F6) 낮춘 값을 따로 정한다 |
| N7 | (나) 실기기를 기본 마무리로 두고, (가) `addKernelPeer`는 **사용자가 sudo를 허락할 때만** 쓴다 | 관리자 권한은 사용자만 줄 수 있다. 허락 전에는 Go 피어(gVisor) 관문 (가)와 실기기로 간다 |
| N8 | (가) 주소의 주인이 바뀐 연결은 끊는다 | — |
| N9 | 정하지 않는다. M6의 API는 바이트 흐름만 낸다 | **M7의 가장 큰 위험이다**: 사용자 바이트 흐름 위에 TLS를 올릴 공개 API가 Apple 플랫폼에 마땅치 않다. M7 계약 전에 따로 조사하고, F1의 답을 먼저 받는다 |
| N10 | (가) 체크섬을 `SwiftailBase`로 옮긴다 | — |
| N11 | (가) `.inProcess`는 ICMP echo에 답하지 않는 것으로 시작 | F12의 답에 따라 다시 본다 |

TCP 노트(`docs/protocol-notes/tcp-netstack.md`)는 다른 세션이 RFC 12개와 고정된 Go 소스에 대조해 고쳤다(2026-11-15). 그 대조에서 나온 계약의 정정을 동작 T2·T4·T5·T6, R3·R4·R6, F1·F2·F7·F9, S6, X7·X9·X10에 반영했다: 처리 순서의 근거는 RFC(gVisor는 다르다), RST는 X3 한 가지 규칙, 작은 창에서 멈추지 않게 하는 override 시간, SYN·SYN-ACK의 재전송은 247초까지(RFC의 3분 이상), TIME-WAIT 기록은 기한 전에 버리지 않음, 작은 MSS는 거절, 창 확장의 협상 규칙. 대조하지 못한 것: 커널 TCP(XNU)의 기본값, 실행으로 본 gVisor의 동작.

## 첫 사용처 확인 필요

이 절은 첫 사용처의 커밋된 코드(`core/internal/node/node.go`·`tls.go`, `core/internal/proxy/proxy.go`, `core/internal/host/`, `docs/protocol.md`, `docs/protocol-addenda.md`, `docs/tunnel.md`)를 읽고 세운 가정과 질문이다. 답에 따라 바뀌는 조항을 함께 적는다.

대응(Mac 호스트):

```swift
let node = try TailnetNode(configuration: configuration, device: .inProcess)
let listener = try await node.listen(port: 443)
try await withThrowingDiscardingTaskGroup { group in
    group.addTask { try await node.run() }
    for await connection in listener {
        group.addTask {
            // connection.remoteEndpoint.address → (M7) node.whoIs(…)
            // TLS와 HTTP는 이 위에 선다(F1)
            await serve(connection)
        }
    }
}
```

| # | 질문 | 가정한 것 | 답에 따라 바뀌는 곳 |
| --- | --- | --- | --- |
| F1 | Mac 호스트를 바꿀 때 TLS와 HTTP 서버는 누가 맡는가? Go의 `tls.NewListener` + `http.Server`에 해당하는 것을 첫 사용처가 Swift로 쓰는가, Swiftail이 무엇을 내야 하는가? | Swiftail은 바이트 흐름까지만 낸다 | N9. Swiftail이 맡아야 한다면 M7의 범위가 커진다 |
| F2 | 리스너는 하나인가(443 또는 시험 포트)? 한 노드에서 여러 포트를 동시에 듣는 일이 있는가? | 하나 | 동작 S3의 상한 16 |
| F3 | 동시에 열리는 연결은 많아야 몇 개인가(페어링한 기기 수 × 기기 하나의 연결 수)? | 수십 개 | 동작 M의 256, S4·S5의 상한 |
| F4 | 가장 큰 전송은 서버 → 클라이언트 4GiB(파일 하나의 상한), 클라이언트 → 서버 4MB가 맞는가? 4GiB를 넘는 것이 있는가? | 맞다 | 4GiB면 시퀀스 번호가 한 바퀴 돈다(시험 6). 넘는 전송이 흔하면 타임스탬프·PAWS(제외 표)를 다시 본다 |
| F5 | Swift HTTP 서버에도 `ReadHeaderTimeout` 10초·`IdleTimeout` 60초를 두는가? Go에는 요청 본문 읽기의 시간 제한이 없어, 사라진 클라이언트의 연결은 tsnet의 keep-alive(2시간)가 거둔다 | keep-alive가 필요하다 | N5. 서버가 모든 읽기에 시간 제한을 둔다면 keep-alive를 뺄 수 있다 |
| F6 | 프록시 모드(진단용)도 Swiftail로 옮기는가? 옮긴다면 iOS 확장 안에서 `.inProcess`를 쓰게 된다 | 옮기지 않는다. `connect`는 시험과 `rdtestenv`가 쓴다 | 옮긴다면: 동작 M의 상한을 iOS에서 낮춰야 한다(50MiB), `connect`에 시간 제한 인자가 필요한지(Go는 15초), `finishWriting`이 `CloseWrite` 자리에 맞는지 |
| F7 | 연결의 원격 주소는 `IPEndpoint`(주소와 포트)면 충분한가? `r.RemoteAddr` 문자열을 WhoIs 밖에서 쓰는 곳이 있는가? | 충분하다 | 공개 API의 `remoteEndpoint` |
| F8 | 지금은 `Running`이 된 뒤에 듣고, 듣기가 3번 실패하면 `Error`로 본다. Swiftail의 `listen`은 포트 중복과 상한 밖에는 실패하지 않고 `run()` 전에도 부를 수 있다. 그 재시도 로직을 없애도 되는가? | 된다 | 동작 A1 |
| F9 | 노드가 멈출 때(앱 종료, 다시 시작) 열린 연결은 RST 한 번으로 끊는다(직접 경로가 아니면 닿지 않을 수 있다). 진행 중인 전송을 마저 보내고 멈춰야 하는가? | RST로 충분하다 | 동작 N8 |
| F10 | 손실이 있는 경로(셀룰러, DERP)에서의 전송 속도에 기준이 있는가? Go 호스트로 잰 IPA 전송 속도 기록이 있으면 비교 기준으로 쓴다 | 없다 | N3(SACK), 관문 (가) 8·9의 기록 |
| F11 | 가짜 tailnet e2e(`listenTLS=false`)가 Swift 노드의 리스너를 그대로 상대해야 하는가? | M7에서 다룬다 | 관문 (가)의 범위 |
| F12 | Mac 호스트의 tailnet 주소로 ICMP ping을 보내 진단하는 절차가 있는가? | 없다 | N11 |
| F13 | 리스너가 받아 가지 않은 연결을 32개까지 두는 것(Go는 1초 뒤 닫음)이 지금의 동작에 기대는 곳과 어긋나는가? | 어긋나지 않는다 | 결정 D6 |

## 첫 사용처 검토 결과 (2026-11-15)

RemoteDebug 세션이 F1~F13에 답했다(그쪽 `2814b2c`의 Go 코드에서 확인한 것과 제안). 가정은 모두 맞았고, 계약의 조항은 다음과 같이 굳는다.

1. **TLS와 HTTP(F1)**: HTTP 서버는 첫 사용처가 Swift로 쓴다. 지금 Go 호스트는 `tls.NewListener` + `http.Server.Serve`라서 **HTTP/1.1만** 쓴다. TLS는 **루프백 다리**로 한다: Swiftail 연결을 `127.0.0.1`의 `NWListener`(TLS, ALPN `http/1.1`, 최소 TLS 1.2)로 이어 준다. 첫 사용처에는 tailnet과 무관한 OS TCP 리스너(같은 Wi-Fi 직접 연결)가 이미 있어, HTTP 서버 하나가 두 입구를 같은 방식으로 받게 된다. Swift로 쓴 TLS 서버는 하지 않는다. **M6의 API는 바이트 흐름 그대로다**(N9는 M7에서 닫는다). M7 계약이 정할 것:
   - 다리를 Swiftail이 선택 제품으로 낼지(역압과 반닫힘을 정확히 잇는 일이다), 첫 사용처가 쓸지. 어느 쪽이든 루프백 연결의 출발 포트 → tailnet `IPEndpoint` 대응을 HTTP 서버가 요청마다 물을 수 있어야 한다(WhoIs).
   - ts.net 인증서 API의 모양: 인증서 사슬(DER 또는 PEM)과 개인 키(`SecKey`로 만들 수 있는 형식. P-256이면 X9.63 원시 표현), 갱신을 알리는 사건. 첫 사용처가 키체인에 넣어 `SecIdentity`를 만든다.
2. **범위(F2·F3·F4·F6·F12)**: 리스너는 하나(기본 443), 동시 연결은 기기당 10개 안팎(상한 256이면 충분), 가장 큰 전송은 서버 → 클라이언트 4GiB·반대 방향 4MiB다. 프록시 모드는 Go와 함께 없어진다(호출하는 곳이 없다). 그래서 **iOS 확장에서 `.inProcess`를 쓸 일이 없고**, 동작 M의 상한은 Mac 호스트 기준 그대로다. `connect`는 시험과 진단이 쓴다. ICMP echo에는 답하지 않는다(N11 확정).
3. **시간 제한과 keep-alive(F5)**: 첫 사용처의 Swift 서버가 머리 10초, 본문 읽기 무응답 30초, 유휴 60초, 쓰기 무진행 60초를 둔다. 그래도 keep-alive는 켠 채로 둔다(N5 그대로. 다른 사용처는 시간 제한이 없을 수 있다). 쓰기 시간 제한은 `write`를 부른 Task의 취소로 건다: 취소된 `write`는 연결을 RST로 끊고 `.cancelled`를 던진다(동작 A4, 공개 API의 `write` 주석 그대로).
4. **그 밖(F7·F8·F9·F13)**: 원격 주소는 `IPEndpoint`면 충분하다. 듣기 재시도 로직은 없앤다(`listen`은 `run()` 전에도 된다). 노드가 멈출 때 RST 한 번이면 된다(받는 쪽이 Range로 이어받는다). 받아 가지 않은 연결 32개는 어긋나지 않는다.
5. **속도 기준(F10)**: 기록이 없다. 첫 사용처가 관문 (나)에서 Go 터널 + Go 호스트로 100MB 받는 시간을 재서 준다(Wi-Fi 직접 경로, 가능하면 셀룰러·DERP). 그 값이 N3(SACK)와 관문 기록의 비교 기준이다.
6. **통합 시험의 발판(F11)**: 가짜 tailnet e2e는 M7에서 다룬다. 그 전에, 계정 없이 프로세스 안에서 Swiftail 노드 둘(하나는 `listen`, 하나는 `connect`)을 `Tools/interop`의 시험 제어 서버에 붙여 돌리는 방법을 `Tools/interop/README.md`에 적는다(M6-9b의 몫으로 더한다). 첫 사용처가 호스트 이식의 통합 시험을 그 위에 올린다.
7. **큰 전송의 복사 횟수(제안)**: `write(_: [UInt8])`의 복사가 4GiB 전송에서 Mac의 CPU에 주는 영향은 관문 (가)의 100MB 전송에서 잰다. 문제가 보이면 복사를 줄인 쓰기(`Span` 계열이나 `some Collection<UInt8>`)를 더한다. 안전하지 않은 포인터를 공개 API에 내지 않는다(plan 5절 코드 기준). `shortcut:`으로 남긴다.
8. **커널 스택 관문**: "M5 터널을 켠 iPhone이 Mac의 Swift 리스너에서 큰 파일을 받는" 확인은 첫 사용처 세션이 맡는다. 그 시점에 맞춰 Swift 리스너 위의 최소 HTTPS 서버(파일 하나를 Range로 내보냄)를 그쪽이 만든다.

## 제외 (`shortcut:` 주석으로 남긴다)

| 제외 | 근거 | 필요해지는 시점 |
| --- | --- | --- |
| SACK(보내기·받기) | N3 | 관문에서 손실 1%의 처리량이 기준 아래일 때 |
| 타임스탬프, PAWS | D3 | 재전송이 잦은 경로에서 RTO가 맞지 않을 때, 한 연결이 4GiB를 여러 번 넘겨 옛 세그먼트와 헷갈릴 수 있을 때 |
| CUBIC, RACK, limited transmit(RFC 3042) | D1 | 대역·지연이 큰 경로에서 NewReno의 처리량이 문제일 때 |
| Nagle | D5 | 작은 쓰기를 많이 하는 앱이 생길 때 |
| 동시 열기(SYN-SENT에서 ACK 없는 SYN) | 받는 쪽과 거는 쪽이 정해진 사용처뿐이다. 그 SYN은 버린다 | 양쪽이 동시에 거는 프로토콜을 쓸 때 |
| urgent 데이터 | URG를 무시하고 보통 데이터로 읽는다(MUST-30과 다르다) | urgent를 쓰는 상대를 만날 때 |
| ECN | 선택 | |
| IP 단편화 재조립, 경로 MTU 탐색, ICMP 오류 처리 | 엔진이 조각을 받지 않는다. MSS가 MTU 1280 안에 있다 | 터널 MTU보다 작은 경로를 만날 때(WireGuard 바깥의 일이라 안쪽 TCP에는 보이지 않는다) |
| 받는 버퍼 자동 조정 | 고정 256KiB | 처리량 기록에서 창이 병목일 때 |
| 주소를 정한 듣기, `tcp4`·`tcp6`, 포트 0 | 첫 사용처는 포트만 정한다 | 그런 사용처가 생길 때 |
| tailnet 밖으로 걸기(시스템 DNS, OS 소켓) | tsnet만의 편의다 | |
| `connect`가 `Running`을 기다리기 | 앱이 `events`로 기다린다 | 상태를 볼 수 없는 호출자가 생길 때 |
| 읽기·쓰기·걸기의 시간 제한 인자 | Task 취소로 한다 | F6의 답에 따라 |
| UDP 소켓(`ListenPacket`), ICMP echo 응답 | 첫 사용처가 쓰지 않는다. N11 | F12의 답에 따라 |
| 서비스 IP의 TCP 53(DNS over TCP) | `.inProcess`에는 서비스 IP로 질의할 OS 리졸버가 없고, utun 장치에는 스택을 붙이지 않는다. M5의 RST 그대로다 | 터널 모드에서 512바이트를 넘는 MagicDNS 응답이 실제로 생길 때(utun 장치에 스택을 붙이는 일이 된다) |
| TLS, HTTP | N9, F1 | M7 |
| 바이트 `AsyncSequence`(`for try await chunk in connection`) | `read`를 도는 한 줄이다 | |
| 스택의 기한 찾기: 연결을 모두 훑는다 | 연결이 256개까지다 | 상한을 크게 올릴 때 |
| 패킷마다의 `[UInt8]` 할당과 복사 | M5까지와 같은 구조다 | 관문의 처리량 기록에서 병목일 때 |

## 시험

### 단위 시험 (소켓 없음, 시각을 넘겨 결정적으로)

`Tests/SwiftailNetstackTests/`(새 시험 타깃):

1. **코덱**: IPv4·IPv6 세그먼트의 해석과 만들기가 서로 되돌아온다. 체크섬(홀수 길이, 올림이 여러 번, IPv6 의사 머리). 옵션: MSS·Window Scale, NOP로 어긋난 정렬, EOL 뒤의 바이트, 모르는 옵션, 길이 0·1·머리 밖, shift 15, SYN이 아닌 세그먼트의 MSS. data offset 4·16(머리 밖). IPv4 옵션이 있는 패킷. 임의 바이트(고정 씨앗 1만 개)로 죽지 않는다.
2. **시퀀스 번호**: 2^32 경계를 넘는 비교·차이·창 포함 판정.
3. **상태 기계의 길**(연결 둘을 메모리에서 맞붙인다): 수동·능동 열기, 양방향 데이터, 닫기의 모든 순서(한쪽 먼저, 동시에, 반닫힘 뒤 반대 방향 데이터), `close`에 읽지 않은 데이터가 있을 때의 RST, 닫은 뒤 온 데이터에 RST, `abort`, 거절(SYN에 RST), SYN·SYN-ACK·데이터의 재전송 한도와 걸리는 시간, FIN-WAIT-2 기한, TIME-WAIT의 FIN 재전송, keep-alive(2시간 뒤 탐침, 답이 오면 다시, 9번 무응답이면 끝).
4. **세그먼트 처리 순서**(TCP 노트 4.2의 줄마다 하나): 받아들일 조건 표의 네 칸, 창 밖 세그먼트에 ACK, 창에 걸친 세그먼트의 자르기, SYN-SENT의 틀린 ACK에 RST, SYN-RECEIVED의 틀린 ACK에 RST, 창 갱신의 WL1·WL2 규칙, `SEG.ACK > SND.NXT`.
5. **RFC 5961**: RST가 창 밖(버림)·정확히 RCV.NXT(끊음)·창 안의 다른 값(challenge ACK), 동기화 상태의 SYN(challenge ACK), ACK 범위 밖, challenge ACK 11번째가 5초 안이면 나가지 않음.
6. **시퀀스 순환**: ISS가 `0xFFFF_F000`인 연결로 1MiB를 보낸다. 4GiB를 넘기는 전송은 가짜 데이터(길이만)로 시퀀스가 한 바퀴 도는 것을 본다.
7. **재전송 타이머**: RFC 6298 2.2·2.3의 식을 손으로 계산한 표와 견준다. 하한·상한, 물러나기, Karn(재전송된 세그먼트의 측정을 버림), 5.7.
8. **혼잡 제어**: 초기 창, slow start에서 congestion avoidance로 넘어가는 점, 중복 ACK 3개의 fast retransmit과 cwnd, partial ACK와 full ACK, RTO 뒤의 cwnd·ssthresh, 유휴 뒤 줄이기. 값은 RFC의 식으로 계산한 표다.
9. **흐름 제어**: 받는 쪽이 읽지 않으면 보내는 쪽이 창에서 멈춘다. 0 창 탐침의 간격과 창이 열린 뒤의 재개. 받는 쪽·보내는 쪽 SWS 회피. 줄어드는 창. 지연 ACK(둘째 세그먼트에서 곧바로, 하나뿐이면 40ms, 순서가 어긋나면 곧바로).
10. **순서가 어긋난 데이터**: 뒤집힌 순서, 겹침(앞·뒤·가운데·완전히 덮음), 33번째 구간 버림, 1바이트 세그먼트 1만 개에서 메모리가 상한 안.
11. **스택**: 연결·리스너 찾기, 연결 없는 곳의 RST 두 형식, RST에 답하지 않음, 리스너의 ACK에 RST, 상한(맺는 중 64·주소당 16·대기열 32·연결 256·리스너 16)과 넘친 SYN의 무응답, ISN이 같은 4-튜플에서 시간에 따라 늘고 다른 4-튜플에서 다름, 포트 고르기와 TIME-WAIT의 4-튜플 건너뛰기, 주소 바뀜에 `peerRemoved`.
12. **손실 주입(속성 시험)**: 스택 둘 사이에 가짜 링크(`LinkSimulator`: 씨앗 있는 난수로 손실·재정렬·중복·지연)를 두고 가짜 시계로 돌린다. 손실 {0, 1, 5, 20}% × 재정렬 {없음, 있음} × 중복 {없음, 있음} × 지연 {1ms, 50ms, 500ms} × 씨앗 여럿에서 양방향 1MiB를 보내: ① 받은 바이트의 해시가 같고 ② 정한 가짜 시간 안에 끝나고 ③ 모든 단계에서 버퍼가 상한 안이고 ④ 끝난 뒤 두 연결이 CLOSED로 사라진다. 실패하면 씨앗을 출력한다.

`Tests/SwiftailTests`(노드, 소켓 없음):

13. **이름 해석**(동작 A2): IP 주소, FQDN, 짧은 이름, 대소문자·끝 점, IPv4 먼저, 모르는 이름, 피어 아닌 주소, 자기 이름.
14. **기다림과 취소**: 데이터 없는 `read`가 기다리다 깨어남, 취소된 `read` 뒤에도 데이터가 남음, 취소된 `write`가 연결을 끊음, 취소된 `connect`, 같은 방향 둘째 호출의 `concurrentUse`, `run()`이 끝날 때 기다리던 호출이 `notRunning`, 버려진 연결이 RST로 끊김.
15. **주인이 바뀐 주소**(동작 X10): 피어가 netmap에서 빠짐, 같은 주소가 다른 키로 바뀜, 자기 주소가 바뀜.
16. **장치**: `.utun`·`.memory`에서 `listen`·`connect`가 `invalidConfiguration`. `.inProcess`에서 `inboundPackets`가 비어 있음. 자기 주소로 건 연결이 자기 리스너에 닿아 1MiB가 오감(동작 N3·N4의 대기열).

### Go 기준값 대조

`Tools/interop/cmd/tcpfixtures`(새 도구): gVisor의 `header` 패키지(`gvisor/pkg/tcpip/header`)로 세그먼트를 만들어 바이트와 기대하는 해석 결과(포트, 번호, 플래그, 창, 옵션, 체크섬)를 JSON으로 낸다. 사례는 단위 시험 1의 것이다. 자료: `Tests/SwiftailNetstackTests/Fixtures/tcp-segments.json`. 대조 시험은 코덱을 쓴 세션과 다른 세션이 쓴다. 상태 기계의 기준은 자료가 아니라 관문 (가)의 실제 gVisor 피어다.

## M6 관문

### (가) Go 피어(gVisor)

`Tools/interop`의 `tailnet`(testcontrol + DERP + STUN + Go tsnet 피어)을 상대로 Swift 노드를 `.inProcess`로 띄운다. 시험은 `Tests/SwiftailInteropTests/NetstackTests.swift`에 두고 `SWIFTAIL_TAILNET`이 없으면 건너뛴다.

`tailnet` 도구에 더할 명령(모두 곧바로 답하고, 전송은 뒤에서 돈다. 도구가 명령을 차례로 처리하기 때문이다):

- `peerServe`: `{"cmd":"peerServe","name":"go-peer-a","port":9100}`. 그 피어의 tsnet 리스너를 연다. 받은 연결마다 아래 "전송"을 한다.
- `peerDial`: `{"cmd":"peerDial","name":"go-peer-a","to":"100.64.0.2","port":9100,"send":104857600,"seed":1,"timeoutSec":15}`. 그 피어가 Swift 노드로 건다.
- 구현에서 정해진 것(M6-9a, 2026-11-15. 정확한 규약은 `Tools/interop/README.md`): `peerDial`은 곧바로 `transferID`를 돌려주고 전송은 뒤에서 돈다. 거는 쪽이 먼저 보내는 16바이트 머리는 **받는 쪽이 보낼 길이(UInt64 BE) + 씨앗(UInt64 BE)**이고 바이트 수와 SHA-256에 들지 않는다. 데이터는 LCG64(`x₀ = seed`, `xₙ₊₁ = 6364136223846793005 × xₙ + 1442695040888963407 mod 2⁶⁴`)의 갱신한 상태를 little endian 8바이트씩 이어 붙이고 마지막 낱말은 길이에서 자른다. 두 방향이 동시에 흐르고, 다 보내면 `CloseWrite`, 받는 쪽은 EOF까지 읽는다. `peerClose`는 리스너만 닫는다. 손실·지연 주입은 Go 쪽에 없다(Swift 노드의 손실 훅으로 한다). `addKernelPeer`는 만들지 않았다(N7). Go 피어 둘 사이의 100MB 양방향 전송은 약 1.8초였다(루프백).
- `transfers`: 끝났거나 도는 전송의 목록. 항목은 `{"name","remote","sent","sentSHA256","received","receivedSHA256","elapsedMs","error","state"}`.
- `peerClose`: 리스너를 닫는다.
- "전송": 한쪽 Task가 `send`바이트의 가짜 난수 흐름(씨앗에서 만든다. Swift와 Go가 같은 생성식을 쓴다)을 쓰고 `CloseWrite`, 다른 쪽이 EOF까지 읽으며 SHA-256과 바이트 수를 센다. `peerServe`가 보낼 양은 연결의 첫 16바이트(보낼 바이트 수와 씨앗)로 정한다.

| # | 확인할 것 | 통과 기준 |
| --- | --- | --- |
| 1 | Swift가 듣고 Go가 건다 | 3-way handshake 뒤 양방향 100MB씩을 동시에 보내, 양쪽이 센 SHA-256과 바이트 수가 서로 같다. 걸린 시간과 처리량을 기록한다 |
| 2 | Swift가 걸고 Go가 듣는다 | 1과 같다. 이름(FQDN, 짧은 이름)과 IP 주소로 각각 건다 |
| 3 | IPv6 | 1·2를 피어의 IPv6 tailnet 주소로 10MB씩 |
| 4 | DERP만으로 | 직접 경로를 막고(M4 관문의 방법) 1을 100MB로. DERP 통로의 넘침이 실제 손실을 만든다. 해시가 같고 멈추지 않는다 |
| 5 | 거절 | 리스너 없는 Swift 포트로 Go가 걸면 제한 시간 전에 "connection refused"로 끝난다. Go 리스너 없는 포트로 Swift가 걸면 `refused` |
| 6 | 닫기와 끊기 | 반닫힘(한쪽이 먼저 끝내도 반대 방향이 끝까지 간다), Swift의 `abort`를 Go가 reset 오류로 읽는다, Go가 끊으면 Swift가 `reset`을 받는다, 정상으로 닫으면 양쪽 모두 EOF |
| 7 | 동시 연결 | 32개를 동시에 열어 4MB씩 양방향. 모두 해시가 같다. 그동안 프로세스의 `phys_footprint` 최고치를 기록한다 |
| 8 | 손실 1% | `setInProcessLoss(rate: 0.01, seed:)`로 1을 20MB로. 해시가 같고, 받은 바이트 수가 30초 넘게 멈춘 구간이 없다. 처리량을 기록한다(N3의 판단 자료) |
| 9 | 손실 5% | 8과 같되 `rate: 0.05`. 기준도 같다. 처리량을 기록한다 |
| 10 | 상한 | 257번째 연결과 33번째 받아 가지 않은 연결의 SYN에 응답이 없고, 자리가 나면 다시 맺어진다. 노드는 죽지 않는다 |
| 11 | 회귀 | M3·M4·M5 관문 (가)가 `.memory` 장치에서 그대로 통과한다 |

"멈추지 않는다"의 뜻: 전송이 끝나고, 받은 바이트 수가 늘지 않은 가장 긴 구간이 30초 아래다.

### (나) macOS·iOS 커널 스택

**utun 없이 되는 길은 찾지 못했다.** 커널의 TCP가 사용자 프로세스와 IP 패킷을 주고받으려면 터널 인터페이스(utun), raw 소켓, BPF 가운데 하나가 있어야 하고, 저장소가 아는 범위에서는 모두 관리자 권한이나 Network Extension 권한이 든다(터널 계약 시험 9. XNU 소스로 확인하지는 못했다). 그래서 길은 셋이다(총괄 확인 필요 N7).

1. **관리자 권한으로 띄우는 Go 피어**(권고하는 기본 관문). `tailnet`에 `addKernelPeer`를 더한다: wireguard-go의 `tun.CreateTUN("utun", 1280)`으로 utun을 만들고 `tsnet.Server.Tun`에 넣어 띄운다. TUN을 받은 tsnet은 자기 주소의 패킷을 netstack이 아니라 TUN으로 흘린다(`tsnet.go:332-335`, `:921-931`). 도구가 utun에 그 피어의 tailnet 주소를 붙이고 Swift 노드의 주소로 가는 경로를 넣은 뒤(`ifconfig`, `route`), **OS 소켓**(`net.Listen`, `net.Dial`)으로 (가)의 "전송"을 한다. 그러면 Swift 스택의 상대는 macOS 커널의 TCP다. 이 명령만 `sudo`로 띄운 별도 프로세스에서 돈다. 확인하지 못한 것: tsnet이 TUN 모드에서 testcontrol과 문제없이 도는지, utun 주소·경로 설정에 더 필요한 것이 있는지. 단위 M6-9가 먼저 손으로 한 번 돌려 본다.
2. **실기기**(마무리). M5의 터널 확장(Swiftail 빌드 변형)을 켠 iPhone에서 Mac의 Swift 리스너로 접속한다. iPhone 커널의 TCP ↔ utun ↔ Swiftail 터널 ↔ tailnet ↔ Mac의 Swift TCP. 첫 사용처의 실제 경로와 같다. 첫 사용처 세션이 맡는다.
3. **공식 Tailscale 앱**. 공식 앱을 켠 Mac에서 OS 소켓으로 Swift 노드에 건다. 실제 tailnet과 계정이 필요하다(plan 4절(b)의 마무리 관문과 같은 절차).

| # | 확인할 것 | 통과 기준 |
| --- | --- | --- |
| 1 | 커널이 걸고 Swift가 듣는다 | 양방향 100MB의 해시가 같다. 처리량을 기록한다 |
| 2 | Swift가 걸고 커널이 듣는다 | 1과 같다 |
| 3 | 손실 1%·5% | (가) 8·9와 같은 기준 |
| 4 | 닫기와 끊기 | (가) 6과 같다 |
| 5 | 커널이 고른 옵션 | SYN·SYN-ACK를 잡아 MSS, Window Scale, SACK-Permitted, Timestamps를 기록한다(TCP 노트 11절 4를 채운다). Swift가 협상하지 않은 옵션을 커널이 쓰지 않는다 |
| 6 | (실기기) iPhone이 Mac의 Swift 리스너에서 100MB를 받는다 | 해시가 같다. Wi-Fi와 셀룰러 각각의 처리량을 기록한다 |

## 구현 단위

소유 파일이 겹치지 않게 나눈다. 단위 사이의 접점(타입의 모양)은 이 문서의 "구조" 절과 각 동작이 정하고, M6-0이 확정한다.

| 단위 | 내용 | 소유 파일 | 선후 |
| --- | --- | --- | --- |
| M6-0 | 총괄: 이 계약 확정(N1~N11, F의 답), TCP 노트 검증(다른 세션), `Package.swift`에 타깃 `SwiftailNetstack`·`SwiftailNetstackTests` 추가, plan 갱신 | `docs/contracts/SwiftailNetstack.md`, `docs/plan.md`, `Package.swift`, `docs/protocol-notes/` | 먼저 |
| M6-1 | 체크섬 옮기기, `TCPSegment` 코덱(동작 W). `SequenceNumber`는 M6-0에서 총괄이 만들었다(`Sources/SwiftailNetstack/Wire/SequenceNumber.swift`. 병렬 단위가 함께 쓰는 타입이다) | `Sources/SwiftailBase/InternetChecksum.swift`, `Sources/SwiftailEngine/Tunnel/ServiceIPReply+Checksum.swift`(호출만), `Sources/SwiftailNetstack/Wire/*`, `Tests/SwiftailNetstackTests/Wire/*`, `Tests/SwiftailBaseTests/InternetChecksumTests.swift` | M6-0 뒤. **2·3·7·9a와 병렬** |
| M6-2 | 보내는 버퍼와 받는 버퍼(순서가 어긋난 구간 포함. 동작 F1·F4·F6) | `Sources/SwiftailNetstack/Buffers/*`, `Tests/SwiftailNetstackTests/Buffers/*` | **병렬**(`SequenceNumber`의 모양만 M6-1과 맞춘다) |
| M6-3 | RTO 추정기와 NewReno(동작 R1~R3·R6·R8). 입력과 출력이 수뿐인 값 타입 | `Sources/SwiftailNetstack/Recovery/*`, `Tests/SwiftailNetstackTests/Recovery/*` | **병렬** |
| M6-4 | 연결 상태 기계(동작 T, R4·R5·R7, F2·F3·F5·F7~F9, X2~X5·X9) | `Sources/SwiftailNetstack/Connection/*`, `Tests/SwiftailNetstackTests/Connection/*`(시험 3·4·5·9의 기본 길) | M6-1·2·3 뒤. 가장 크다 |
| M6-5 | 스택(동작 S, X7·X8) | `Sources/SwiftailNetstack/Stack/*`, `Tests/SwiftailNetstackTests/Stack/*` | M6-4 뒤 |
| M6-6 | 독립 시험: `LinkSimulator`와 속성 시험(시험 12), 시험 4·5·6·10의 사례. 계약과 TCP 노트만 보고 쓴다 | `Tests/SwiftailNetstackTests/Support/*`, `Tests/SwiftailNetstackTests/Scenarios/*` | M6-4를 쓴 세션과 **다른 세션**. 하네스는 M6-4와 병렬로 쓰고, 시험은 M6-5 뒤에 돌린다 |
| M6-7 | Go 기준값 도구와 자료, 대조 시험 | `Tools/interop/cmd/tcpfixtures/`, `Tests/SwiftailNetstackTests/Fixtures/tcp-segments.json`, `Tests/SwiftailNetstackTests/Wire/GoSegmentComparisonTests.swift`, `Tools/interop/README.md`의 새 절 | 도구는 **병렬**. 대조 시험은 M6-1 뒤 다른 세션이 |
| M6-8 | 노드 통합(동작 N·A·K, X10): `TunnelDevice.inProcess`, 스택 잇기와 대기열, 공개 API, 이름 해석, 기다리는 호출, 버려진 핸들, 손실 훅 | `Sources/Swiftail/**`, `Tests/SwiftailTests/Netstack*`(시험 13~16) | M6-5 뒤 |
| M6-9 | 관문: (9a) `tailnet` 도구의 `peerServe`·`peerDial`·`transfers`·`peerClose`·`addKernelPeer`와 README, (9b) `NetstackTests.swift`와, 시험 제어 서버에 Swiftail 노드 둘을 붙여 `listen`·`connect`를 돌리는 방법의 문서(첫 사용처 검토 결과 6) | `Tools/interop/cmd/tailnet/*`, `Tools/interop/README.md`의 `tailnet` 절, `Tests/SwiftailInteropTests/NetstackTests.swift` | 9a는 **병렬**(M6-7과 README의 절이 다르다). 9b는 M6-8 뒤 |
| M6-10 | (조건부) SACK | `Sources/SwiftailNetstack/Recovery/SACK*`와 M6-4의 파일 | 관문 (가) 8의 기록이 N3의 기준 아래일 때만 |

순서: M6-0 → (M6-1, 2, 3, 6의 하네스, 7의 도구, 9a) 병렬 → M6-4 → M6-5 → M6-6의 시험 → M6-8 → M6-9b → 다른 세션의 검토 → 총괄이 관문 (가)를 다시 돌림 → 관문 (나) → (필요하면) M6-10.
