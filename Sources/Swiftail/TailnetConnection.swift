import SwiftailBase
import SwiftailNetstack

/// 맺어진 TCP 연결 하나. `TailnetNode.connect(to:port:)`이나 `TailnetListener`가 낸다. tsnet의 `net.Conn`에 해당한다.
///
/// 읽기 하나와 쓰기 하나를 서로 다른 Task에서 동시에 해도 된다. 같은 방향의 둘째 호출은 `ConnectionError.concurrentUse`다.
/// 시간 제한 인자는 없다: 호출한 Task를 취소해서 건다. 닫지 않고 버려지면(`deinit`) RST로 끊는다.
///
/// 상대가 연결을 끝내면 그 뒤의 `read`·`write`·`finishWriting`은 까닭의 오류(`reset`, `timedOut`, `peerRemoved`)를
/// 던진다. 앱이 `close`·`abort`한 뒤에는 `closed`다. 노드의 `run()`이 끝나면 `notRunning`이다.
/// 계약 `docs/contracts/SwiftailNetstack.md` "공개 API"와 동작 A.
public final class TailnetConnection: Sendable {
    /// 이 노드 쪽 주소와 포트.
    public let localEndpoint: IPEndpoint
    /// 상대의 tailnet 주소와 포트. 주소는 WireGuard가 인증한 피어의 것이다(피어의 AllowedIPs로 출발지를 검사한다).
    public let remoteEndpoint: IPEndpoint
    let node: TailnetNode
    let id: TCPStack.ConnectionID

    init(node: TailnetNode, id: TCPStack.ConnectionID, localEndpoint: IPEndpoint, remoteEndpoint: IPEndpoint) {
        self.node = node
        self.id = id
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
    }

    deinit {
        node.handleReleases.yield(.connection(id))
    }

    /// 받은 바이트를 순서대로 돌려준다. 버퍼에 있는 만큼(1바이트 이상, `maximumLength` 이하) 곧바로, 없으면 올 때까지 기다린다.
    /// 읽어 간 만큼 받는 창이 열린다(읽지 않으면 상대가 256KiB에서 멈춘다).
    ///
    /// - Returns: 상대가 쓰기를 닫았고 남은 것이 없으면 nil.
    /// - Throws: `maximumLength`가 0 이하면 `invalidConfiguration`, 다른 `read`가 기다리고 있으면 `concurrentUse`, 노드의
    ///   `run()`이 끝났으면 `notRunning`, 앱이 `close`·`abort`했으면(기다리던 `read`도) `closed`, 상대 쪽 일로 끝났으면 그
    ///   까닭(`reset`, `timedOut`, `peerRemoved`), 호출한 Task가 취소되면 `cancelled`(연결과 버퍼의 데이터는 그대로 남는다).
    public func read(upTo maximumLength: Int = 65_536) async throws(ConnectionError) -> [UInt8]? {
        try await node.readConnection(id, upTo: maximumLength)
    }

    /// 바이트를 모두 보내는 버퍼에 넣을 때까지 기다린다. 상대가 받았다는 뜻이 아니다. 버퍼(256KiB)가 차면 자리가 날 때까지
    /// 멈추고, 그 사이 노드를 붙잡지 않는다.
    ///
    /// - Throws: 다른 `write`가 기다리고 있으면 `concurrentUse`, 노드의 `run()`이 끝났으면 `notRunning`, `finishWriting`·
    ///   `close`·`abort` 뒤에는(기다리던 `write`도) `closed`, 상대 쪽 일로 끝났으면 그 까닭(`reset`, `timedOut`,
    ///   `peerRemoved`), 호출한 Task가 취소되면 연결을 RST로 끊고 `cancelled`(얼마나 들어갔는지 알 수 없기 때문이다).
    ///   `finishWriting`이 기다리던 `write`를 깨울 때 이미 버퍼에 들어간 만큼은 FIN 앞에 나간다.
    public func write(_ bytes: [UInt8]) async throws(ConnectionError) {
        try await node.writeConnection(id, bytes)
    }

    /// 보내기를 끝낸다(FIN). 버퍼에 남은 것을 다 보낸 뒤에 나간다. 읽기는 계속할 수 있다. tsnet `CloseWrite`.
    /// 두 번 불러도 된다. 기다리던 `write`는 `closed`로 깨어난다.
    ///
    /// - Throws: 노드의 `run()`이 끝났으면 `notRunning`, `close`·`abort`한 연결이면 `closed`, 상대 쪽 일로 끝난 연결이면 그
    ///   까닭(`reset`, `timedOut`, `peerRemoved`).
    public func finishWriting() async throws(ConnectionError) {
        try await node.finishWritingConnection(id)
    }

    /// 연결을 닫는다. 버퍼에 남은 것을 보내고 FIN으로 끝낸다. 곧바로 돌아오고, 마무리는 노드가 `run()` 안에서 한다.
    /// 읽지 않은 데이터가 있거나 닫은 뒤에 데이터가 오면 RST로 끊는다. 기다리던 `read`·`write`는 `closed`로 깨어난다.
    /// 던지지 않는다. 이미 닫은 연결이면 아무 일도 하지 않는다. tsnet `Close`.
    public func close() async {
        await node.closeConnection(id)
    }

    /// 연결을 곧바로 끊는다(RST). 버퍼의 것은 버린다. 던지지 않는다. 기다리던 `read`·`write`는 `closed`로 깨어난다.
    /// tsnet의 `SetLinger(0)` 뒤 `Close`.
    public func abort() async {
        await node.abortConnection(id)
    }
}
