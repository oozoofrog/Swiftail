/// 연결이 기억하는 열린 스트림 하나(RFC 9113 §5.1).
///
/// 요청과 응답은 서로 독립으로 끝난다. 요청 쪽은 `unsentBody`가 `nil`이 되면(END_STREAM을 보내면),
/// 응답 쪽은 `receiving`이 `ended`가 되면(END_STREAM을 받으면) 끝난다. 둘 다 끝났거나 RST_STREAM으로
/// 끊기면 연결이 스트림을 잊는다. 그 뒤에 오는 프레임은 "닫힌 스트림"의 프레임으로 다룬다.
struct StreamState {
    enum Receiving: Equatable {
        /// 응답 머리를 기다린다.
        case awaitingHead
        /// 머리를 받았고 본문을 받는 중이다.
        case receivingBody
        /// END_STREAM까지 받았다.
        case ended
    }

    var receiving = Receiving.awaitingHead
    var sendWindow: FlowControlWindow
    /// 아직 내보내지 못한 요청 본문. `nil`이면 요청 쪽이 끝났다.
    var unsentBody: ArraySlice<UInt8>?

    init(sendWindowSize: Int, body: [UInt8]?) {
        sendWindow = FlowControlWindow(sendWindowSize)
        unsentBody = body?[...]
    }
}
