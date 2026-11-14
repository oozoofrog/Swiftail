/// 이 노드의 tailnet 주소(IPv4·IPv6)에서 듣는 TCP 포트 하나. 맺어진 연결을 들어온 차례로 낸다.
/// `TailnetNode.listen(port:)`이 만든다. tsnet `Listener`(`Accept`, `Close`)에 해당한다.
///
/// 리스너를 닫거나 노드의 `run()`이 끝나면 흐름이 끝난다. 흐름을 기다리던 Task를 취소하면 그 Task의 흐름만 끝나고
/// 리스너는 그대로다. 한 번에 한 Task만 돌 수 있다: 다른 Task가 이미 기다리고 있으면 나중 Task의 흐름은 곧바로 끝난다.
/// 버려지면(`deinit`) 닫힌다. 받아 가지 않은 연결은 리스너마다 32개까지 맺어 둔다(계약 동작 S5, 결정 D6).
///
/// ```swift
/// let listener = try await node.listen(port: 443)
/// for await connection in listener {
///     group.addTask { await serve(connection) }
/// }
/// ```
public final class TailnetListener: AsyncSequence, Sendable {
    public typealias Element = TailnetConnection
    public typealias Failure = Never

    /// 듣는 포트.
    public let port: UInt16
    let node: TailnetNode
    /// 노드 안에서 이 리스너를 가리키는 번호. 같은 포트를 다시 열어도 새 번호다(옛 핸들의 `deinit`이 새 리스너를 닫지 않게).
    let token: UInt64

    init(node: TailnetNode, token: UInt64, port: UInt16) {
        self.node = node
        self.token = token
        self.port = port
    }

    deinit {
        node.handleReleases.yield(.listener(token))
    }

    /// 듣기를 그만둔다. 아직 받아 가지 않은 연결은 RST로 끊는다. 이미 받아 간 연결은 그대로다. 두 번 불러도 된다.
    public func close() async {
        await node.closeListener(token)
    }

    public func makeAsyncIterator() -> Iterator {
        Iterator(listener: self)
    }

    /// 리스너의 흐름. 다음 연결이 맺어질 때까지 기다린다.
    public struct Iterator: AsyncIteratorProtocol {
        let listener: TailnetListener

        /// 다음 연결. 리스너가 닫혔거나, `run()`이 끝났거나, 호출한 Task가 취소되었거나, 다른 Task가 이미 기다리고 있으면 nil.
        public mutating func next() async -> TailnetConnection? {
            await listener.node.nextConnection(from: listener.token)
        }
    }
}
