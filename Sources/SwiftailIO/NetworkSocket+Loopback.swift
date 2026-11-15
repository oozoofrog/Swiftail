import Foundation
import Network

/// 루프백 다리(`SwiftailLoopback.LoopbackBridge`)가 쓰는 보탬. 계약 `docs/contracts/SwiftailHost.md` 동작 B와 8절.
///
/// 다리는 tailnet 연결을 같은 기기의 `127.0.0.1` 리스너에 잇는다. 그러려면 셋이 더 필요하다: 리스너가 받은 연결의
/// 출발 포트와 견줄 자기 쪽 포트, 반닫힘을 옮길 쓰기 끝내기(FIN), 오류를 정상 닫기와 구별되게 옮길 끊기(RST).
extension NetworkSocket {
    /// `127.0.0.1:<port>`에 평문 TCP로 걸고 준비될 때까지 기다린다.
    ///
    /// 기한은 부르는 쪽이 건다(`withTimeout`). 듣는 쪽이 없으면 곧바로 실패한다(`connect`와 같이 `waiting`을 실패로 본다).
    /// IPv4 루프백만 쓴다: 다리의 표는 출발 포트로만 찾으므로 주소 계열이 하나여야 서버가 본 포트와 어긋나지 않는다.
    ///
    /// 이 소켓은 기다리던 `receive`·`write`의 Task가 취소되어도 **연결을 닫지 않는다**. 다리는 표에서 그 포트를 지운 뒤에
    /// 닫아야 하고(동작 B6 ②), 정상 끝이면 FIN(`close()`), 오류면 RST(`abort()`)로 닫기를 골라야 하기 때문이다.
    /// 그래서 주인이 반드시 `close()`나 `abort()`를 부른다(버리면 `deinit`이 `close()`처럼 닫는다).
    ///
    /// - Throws: `port`가 0이거나, 걸지 못했거나, 기다리던 Task가 취소되면 `connectFailed`.
    package static func connectLoopback(port: UInt16) async throws(SocketError) -> NetworkSocket {
        guard port != 0, let nwPort = NWEndpoint.Port(rawValue: port) else {
            throw .connectFailed("포트가 잘못되었다")
        }
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let connection = NWConnection(host: .ipv4(.loopback), port: nwPort, using: NWParameters(tls: nil, tcp: tcp))
        return try await open(connection, closesOnCancel: false)
    }

    /// 준비된 연결의 자기 쪽 포트. 루프백 리스너가 받은 연결에서는 상대(이 소켓)의 출발 포트로 보인다.
    /// 연결이 준비되기 전이거나 경로가 없으면 nil이다.
    package var localPort: UInt16? {
        guard case .hostPort(_, let port)? = connection.currentPath?.localEndpoint else { return nil }
        return port.rawValue
    }

    /// 쓰기 방향만 닫는다(TCP FIN). 앞서 부른 `send`·`write`의 바이트가 먼저 나간다. 읽기는 계속할 수 있다.
    ///
    /// 내용 없이 `finalMessage` 문맥으로 끝을 알린다. 그 뒤의 `send`·`write`는 보내지지 않는다.
    package func finishWriting() {
        connection.send(content: nil, contentContext: .finalMessage, isComplete: true, completion: .idempotent)
    }

    /// 연결을 곧바로 끊는다. 상대에게는 정상 닫기(FIN)가 아니라 오류로 보인다(RST). 보내지 못한 바이트는 버린다.
    /// 걸려 있던 `receive()`는 오류로 끝난다. 여러 번 불러도 된다.
    ///
    /// `NWConnection.forceCancel()`이다. `cancel()`(`close()`)은 FIN으로 닫으므로 상대가 끝까지 받은 것으로 읽는다.
    package func abort() {
        connection.forceCancel()
    }
}
