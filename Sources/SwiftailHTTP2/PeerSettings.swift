/// 상대가 알린 SETTINGS 값(RFC 9113 §6.5.2).
///
/// 이 연결이 보내는 쪽으로서 지켜야 하는 값만 담는다. 상대의 HEADER_TABLE_SIZE는 동적 표를 쓰지 않는
/// 압축기에 상관이 없고, ENABLE_PUSH는 서버가 1로 알릴 수 없다는 것만 확인한다.
struct PeerSettings: Equatable {
    private enum Identifier: UInt16 {
        case enablePush = 0x2
        case maxConcurrentStreams = 0x3
        case initialWindowSize = 0x4
        case maxFrameSize = 0x5
    }

    /// 상대가 허용한 동시 스트림 수. 알리지 않으면 제한이 없다.
    var maxConcurrentStreams = Int.max
    var initialWindowSize = FlowControlWindow.defaultInitialSize
    /// 상대가 받아 줄 프레임 payload의 최대 길이.
    var maxFrameSize = 16_384
    // shortcut: 상대의 MAX_HEADER_LIST_SIZE는 지키지 않는다(요청 헤더는 작다), 큰 헤더를 보내게 되면 확인한다.

    /// SETTINGS를 반영한다. 값이 규격 범위 밖이면 연결 오류이고, 모르는 식별자는 무시한다.
    /// 성공하면 INITIAL_WINDOW_SIZE가 바뀐 만큼(열린 스트림의 창에 더할 값)을 돌려준다.
    mutating func apply(_ settings: [Frame.Setting]) throws(HTTP2Error) -> Int {
        let previousInitialWindowSize = initialWindowSize
        for setting in settings {
            let value = Int(setting.value)
            switch Identifier(rawValue: setting.identifier) {
            case .enablePush:
                // 서버가 1을 알리는 것도, 0과 1 말고 다른 값도 PROTOCOL_ERROR다.
                guard setting.value == 0 else { throw .connection(.protocolError) }
            case .maxConcurrentStreams:
                maxConcurrentStreams = value
            case .initialWindowSize:
                guard value <= FlowControlWindow.maximum else { throw .connection(.flowControlError) }
                initialWindowSize = value
            case .maxFrameSize:
                guard (16_384...16_777_215).contains(value) else { throw .connection(.protocolError) }
                maxFrameSize = value
            case nil:
                continue
            }
        }
        return initialWindowSize - previousInitialWindowSize
    }
}
