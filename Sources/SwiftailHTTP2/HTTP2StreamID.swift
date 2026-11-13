/// 스트림 식별자(RFC 9113 §5.1.1).
///
/// 클라이언트가 시작하는 스트림은 1부터 홀수로 늘어난다. 0은 연결 전체를 가리키며 스트림이 아니다.
public struct HTTP2StreamID: Hashable, Sendable {
    public let rawValue: UInt32

    /// 연결 전체를 가리키는 0. 연결 흐름 제어 창이 이 식별자의 WINDOW_UPDATE로 갱신된다.
    static let connection = HTTP2StreamID(0)

    init(_ rawValue: UInt32) {
        self.rawValue = rawValue
    }
}
