/// 보내는 쪽 흐름 제어 창(RFC 9113 §5.2, §6.9).
///
/// 상대가 받아 줄 수 있다고 허락한 DATA 바이트 수다. DATA를 보낼 때마다 줄고, 상대의 WINDOW_UPDATE로
/// 늘어난다. 연결 전체의 창과 스트림마다의 창이 따로 있고, DATA는 둘 다 허락해야 나갈 수 있다.
/// 상대가 SETTINGS_INITIAL_WINDOW_SIZE를 줄이면 창이 음수가 될 수 있다(§6.9.2).
struct FlowControlWindow: Equatable {
    /// 창은 2^31-1을 넘을 수 없다(§6.9.1).
    static let maximum = Int(Int32.max)
    /// 연결과 스트림 창의 초깃값(§6.9.2).
    static let defaultInitialSize = 65_535

    /// 창을 2^31-1 넘게 키우려 했다. 연결 창이면 연결 오류, 스트림 창이면 스트림 오류다.
    struct Overflow: Error {}

    private(set) var available: Int

    init(_ available: Int = defaultInitialSize) {
        self.available = available
    }

    /// 보낸 만큼 줄인다. 부르는 쪽이 `available` 이하만 요청한다.
    mutating func consume(_ count: Int) {
        available -= count
    }

    /// WINDOW_UPDATE나 INITIAL_WINDOW_SIZE 변화로 `delta`만큼 바꾼다. `delta`는 음수일 수 있다.
    mutating func adjust(by delta: Int) throws(Overflow) {
        guard available + delta <= Self.maximum else { throw Overflow() }
        available += delta
    }
}
