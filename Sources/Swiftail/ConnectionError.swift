/// 듣기·걸기·연결의 실패(`TailnetNode.listen(port:)`, `TailnetNode.connect(to:port:)`, `TailnetListener`,
/// `TailnetConnection`). 계약 `docs/contracts/SwiftailNetstack.md` "공개 API"와 동작 A.
///
/// 메시지에는 무엇이 잘못됐는지만 담는다. 주소·이름·실린 데이터는 담지 않는다(동작 K).
public enum ConnectionError: Error, Sendable, Equatable {
    /// 장치가 `.inProcess`가 아니거나, 포트가 0이거나, 호스트가 비었거나, 읽을 길이가 1보다 작다.
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
    /// 이미 닫거나 끊은 연결·리스너다. 쓰기를 끝낸(`finishWriting`) 뒤의 `write`도 이것이다.
    case closed
    /// 호출한 Task가 취소되었다.
    case cancelled
    /// 같은 방향의 호출이 이미 기다리고 있다(읽기 둘, 쓰기 둘).
    case concurrentUse
}
