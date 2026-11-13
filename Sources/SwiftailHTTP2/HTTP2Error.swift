/// `HTTP2ClientConnection`이 던지는 오류.
public enum HTTP2Error: Error, Sendable, Equatable {
    /// 상대가 규격을 어겼거나 상대가 연결 오류를 알렸다. 연결은 끝났다. code는 RFC 9113 §7의 오류 코드.
    case connectionFailed(code: UInt32)
    /// 연결이 끝났거나 GOAWAY를 받아 새 요청을 시작할 수 없다.
    case connectionClosed
    /// 상대가 허용한 동시 스트림 수를 넘는다.
    case tooManyStreams
    /// 요청이 잘못됐다(빈 method·path, 대문자 헤더 이름 등).
    case invalidRequest
}

/// RFC 9113 §7의 오류 코드. 연결 오류(GOAWAY)와 스트림 오류(RST_STREAM)가 같은 코드를 쓴다.
enum HTTP2ErrorCode: UInt32 {
    case noError = 0x0
    case protocolError = 0x1
    case flowControlError = 0x3
    case streamClosed = 0x5
    case frameSizeError = 0x6
    case cancel = 0x8
    case compressionError = 0x9
    case enhanceYourCalm = 0xb
}

extension HTTP2Error {
    /// 이 코드로 연결을 끝내야 하는 오류.
    static func connection(_ code: HTTP2ErrorCode) -> HTTP2Error {
        .connectionFailed(code: code.rawValue)
    }
}
