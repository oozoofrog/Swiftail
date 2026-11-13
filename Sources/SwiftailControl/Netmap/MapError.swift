/// 맵 스트림을 더 읽을 수 없는 이유. 어느 경우든 이 스트림을 버리고 새 스트림으로 전체 맵부터 다시 받는다
/// (`docs/protocol-notes/control-map.md` 3.5, 4.2의 4).
public enum MapError: Error, Sendable, Equatable {
    /// 프레임의 길이 접두가 한도(`MapResponseFramer.maximumFrameSize`)를 넘는다.
    case frameTooLarge
    /// 프레임의 내용이 맵 응답 JSON이 아니다.
    case malformed
    /// 스트림의 첫 일반(KeepAlive가 아닌) 응답에 자기 노드(`Node`)가 없다.
    case missingSelfNode
}
