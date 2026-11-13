# SwiftailHTTP2 계약 (M2)

제어 서버와 말하는 데 필요한 만큼의 HTTP/2 **클라이언트 연결**을 입출력 없는 상태 기계로 구현한다. 연결 하나에 스트림 몇 개(등록 요청, 맵 스트림, 상태 갱신)를 다중화한다. 범용 HTTP 클라이언트가 아니다.

규격: RFC 9113(HTTP/2), RFC 7541(HPACK). 상대가 무엇을 보내는지는 [protocol-notes/control-transport.md](../protocol-notes/control-transport.md) 6.3절(Go 서버의 실제 동작을 확인한 것)에 있다.

Tailscale을 모른다. 아래 바이트 스트림은 TLS일 수도, 제어 프로토콜의 Noise 레코드일 수도 있다.

## 공개 API

```swift
public struct HeaderField: Sendable, Equatable {
    public var name: String      // 소문자
    public var value: String
    public init(_ name: String, _ value: String)
}

public struct HTTP2StreamID: Hashable, Sendable {
    public let rawValue: UInt32
}

public enum HTTP2Error: Error, Sendable, Equatable {
    /// 상대가 규격을 어겼다. 연결은 끝났다. code는 RFC 9113 §7의 오류 코드.
    /// 상대가 보낸 GOAWAY는 오류 코드가 있어도 던지지 않고 `goAway` 사건으로 알린다(같은 호출에서 모은 사건을 잃지 않기 위해서다).
    case connectionFailed(code: UInt32)
    /// 연결이 끝났거나 GOAWAY를 받아 새 요청을 시작할 수 없다.
    case connectionClosed
    /// 상대가 허용한 동시 스트림 수를 넘는다.
    case tooManyStreams
    /// 요청이 잘못됐다(빈 method·path, 대문자 헤더 이름 등).
    case invalidRequest
}

/// HTTP/2 클라이언트 연결 하나.
public struct HTTP2ClientConnection: Sendable {
    public struct Request: Sendable {
        public var method: String
        public var path: String
        public var authority: String
        public var headers: [HeaderField]      // 의사 헤더를 뺀 나머지
        public init(method: String, path: String, authority: String, headers: [HeaderField] = [])
    }

    public enum Event: Sendable, Equatable {
        case responseHead(HTTP2StreamID, status: Int, headers: [HeaderField])
        case responseData(HTTP2StreamID, [UInt8])
        /// 스트림이 끝났다. resetCode가 nil이면 정상 종료(END_STREAM), 아니면 RST_STREAM의 오류 코드.
        case streamClosed(HTTP2StreamID, resetCode: UInt32?)
        /// 상대가 GOAWAY를 보냈다. lastStreamID보다 큰 스트림은 처리되지 않았다.
        case goAway(lastStreamID: HTTP2StreamID, code: UInt32)
    }

    /// 연결을 시작한다. 프리페이스와 SETTINGS가 보낼 바이트로 준비된다.
    public init()

    /// 요청을 시작한다. `:scheme`은 늘 https다. body가 nil이면 HEADERS에서 요청이 끝난다.
    /// 본문은 흐름 제어 창이 허락하는 만큼씩 나간다.
    public mutating func startRequest(_ request: Request, body: [UInt8]?) throws(HTTP2Error) -> HTTP2StreamID

    /// 스트림을 버린다(RST_STREAM CANCEL). 이미 끝난 스트림이면 아무 일도 하지 않는다.
    public mutating func cancel(_ stream: HTTP2StreamID)

    /// 상대에게서 받은 바이트를 넣는다. 프레임 경계와 무관하게 임의의 조각이어도 된다.
    /// 오류를 던지면 연결은 끝난 것이다. 그때도 `takeOutboundBytes()`에 GOAWAY가 남아 있을 수 있다.
    public mutating func receive(_ bytes: [UInt8]) throws(HTTP2Error) -> [Event]

    /// 상대에게 보낼 바이트를 꺼낸다. 없으면 빈 배열. `init`, `startRequest`, `cancel`, `receive` 뒤에 부른다.
    public mutating func takeOutboundBytes() -> [UInt8]
}
```

## 동작 범위

포함:

- 프리페이스, SETTINGS 교환과 ACK, 모르는 SETTINGS와 모르는 프레임 type 무시
- HEADERS + CONTINUATION, DATA, RST_STREAM, PING(ACK로 답), GOAWAY, WINDOW_UPDATE. PRIORITY는 읽고 버린다. PUSH_PROMISE는 연결 오류다(ENABLE_PUSH=0을 알린다)
- HPACK 해제: 정적·동적 표, 모든 표현 형식, 표 크기 갱신, 허프만 문자열
- HPACK 압축: 색인 없는 리터럴만, 허프만 없이(가장 단순하고 규격상 유효하다)
- 흐름 제어: 보내는 쪽은 연결·스트림 창을 지키고 WINDOW_UPDATE와 SETTINGS_INITIAL_WINDOW_SIZE 변경을 반영한다. 받는 쪽은 받은 DATA만큼 곧바로 창을 돌려준다
- 상대의 MAX_FRAME_SIZE에 맞춘 프레임 분할, MAX_CONCURRENT_STREAMS 준수

한도(신뢰할 수 없는 입력): 받는 프레임 16,384바이트(알린 MAX_FRAME_SIZE), 헤더 블록 합계 64KiB, HPACK 동적 표 4,096바이트. 넘으면 연결 오류다. 어떤 바이트열로도 프로세스가 죽지 않는다.

제외(`shortcut:` 주석으로 남긴다):

- 받는 쪽 역압(backpressure). 받은 만큼 바로 창을 돌려주므로 소비가 느려도 서버를 늦추지 못한다. 필요해지는 시점: 큰 응답을 스트리밍으로 소비해야 할 때
- 요청 본문의 점진적 공급, 트레일러, 서버 푸시, 우선순위, 압축 표 재사용(보내는 쪽)
- 유휴 PING과 타임아웃. 연결을 가진 쪽(actor)이 시계를 갖고 판단한다

## 시험

단위 시험(`Tests/SwiftailHTTP2Tests`):

1. HPACK: RFC 7541 부록 C의 예제 전부(C.1 정수, C.2 헤더 표현, C.3·C.4 요청, C.5·C.6 응답. 허프만과 동적 표 축출 포함).
2. 프레임: 각 type의 해석, 한 바이트씩 쪼개 넣어도 같은 사건, CONTINUATION 결합, 패딩.
3. 흐름 제어: 창보다 큰 본문이 WINDOW_UPDATE를 기다린다. SETTINGS_INITIAL_WINDOW_SIZE가 열린 스트림의 창을 바꾼다. 받은 DATA만큼 WINDOW_UPDATE를 낸다.
4. 수명: SETTINGS ACK, PING 응답, GOAWAY 뒤 새 요청 거절, RST_STREAM, 스트림 ID가 홀수로 증가.
5. 한도와 임의 입력: 한도를 넘는 입력은 연결 오류, 무작위 바이트로 죽지 않는다.

상호 운용(`Tools/interop`의 Go HTTP/2 서버 상대, TCP 루프백): 작은 GET, 큰 본문의 POST 왕복(양방향 흐름 제어), 끝나지 않는 응답 스트림과 다른 요청의 동시 진행, 서버의 PING·GOAWAY.
