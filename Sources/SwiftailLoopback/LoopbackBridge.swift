import Swiftail
import SwiftailBase
import SwiftailIO
import Synchronization

/// tailnet에서 받은 TCP 연결을 이 기기의 루프백(`127.0.0.1`) TCP 리스너로 이어 준다.
///
/// TLS와 HTTP를 OS의 스택(`NWListener`)으로 끝내려는 앱이 쓴다. 다리는 바이트를 해석하지 않는다. 루프백 연결의 저쪽에서는
/// 상대가 `127.0.0.1`로 보이므로, 서버는 받은 연결의 **출발 포트**로 `origin(forLoopbackSourcePort:)`를 물어 tailnet의
/// 상대를 안다. 표에 없는 포트는 다리가 이은 연결이 아니다(같은 기기의 다른 프로세스다). 서버는 그런 연결을 끊어야 한다.
///
/// 서버가 지킬 것(계약 `docs/contracts/SwiftailHost.md` 동작 B7):
/// - 리스너를 `127.0.0.1`에만 묶고 포트는 시스템이 고르게 한다.
/// - 받은 연결마다 **TLS 핸드셰이크가 끝난 뒤(`.ready`), 요청을 읽기 전에** `origin(forLoopbackSourcePort:)`를 묻고, nil이면
///   그 연결을 끊는다. 평문 리스너라면 첫 바이트를 받은 뒤에 묻는다. 그보다 먼저 물으면 다리가 아직 적지 못한 정당한
///   연결을 끊을 수 있다(리스너가 연결을 알리는 때와 다리가 표에 적는 때 사이에는 순서가 없다).
/// - 신원은 요청마다 `whoIs`로 다시 찾지 않고 `Origin.peer`를 쓴다. 연결을 맺을 때 확인한 신원이다(동작 B2).
///
/// 다리는 포트마다가 아니라 연결마다 동작한다. 서버가 리스너를 새 포트로 바꿔도 옛 포트로 잇던 연결은 그대로 간다.
public final class LoopbackBridge: Sendable {
    /// 루프백 연결 하나의 tailnet 쪽 상대.
    public struct Origin: Sendable, Equatable {
        /// 상대의 tailnet 주소와 포트.
        public var remoteEndpoint: IPEndpoint
        /// 잇기 시작할 때 확인한 상대의 신원. 연결이 사는 동안 바뀌지 않는다.
        public var peer: PeerIdentity
    }

    private struct State {
        /// `forward`에 들어와 아직 돌아가지 않은 호출의 수. 상한과 견준다.
        var forwarding = 0
        /// 루프백 연결의 출발 포트 → tailnet 쪽 상대.
        var origins: [UInt16: Origin] = [:]
    }

    /// 한 방향이 한 번에 쥐는 바이트(계약 한도 표: 방향당 64KiB).
    private static let chunkSize = 65_536
    /// 루프백 연결을 맺는 기한(계약 한도 표).
    private static let connectTimeout = Duration.seconds(5)

    private let node: TailnetNode
    let connectionLimit: Int
    private let state = Mutex(State())

    /// `node`가 받은 연결을 잇는 다리. 신원은 `node.whoIs(_:)`로 찾는다. 잇는 연결은 256개까지다(노드의 연결 상한과 같다).
    public convenience init(node: TailnetNode) {
        self.init(node: node, connectionLimit: 256)
    }

    /// 상한을 바꾼 다리. 시험이 상한에 닿는 경우를 연결 몇 개로 만든다(노드 하나의 자기 연결로는 다리에 256개를 올릴 수 없다).
    init(node: TailnetNode, connectionLimit: Int) {
        self.node = node
        self.connectionLimit = connectionLimit
    }

    /// 연결 하나를 `127.0.0.1:<port>`로 잇고, 두 방향이 다 끝날 때까지 바이트를 나른다. 끝나면 두 연결을 닫고 돌아온다.
    ///
    /// 차례(동작 B1): 상한을 보고, 상대의 신원을 확인하고, 루프백으로 걸고(5초), 그 연결의 출발 포트를 표에 적은 **뒤에**
    /// 복사를 시작한다. 끝나면 표에서 **지운 뒤에** 루프백 연결을 닫는다(동작 B6).
    ///
    /// 나르기(동작 B3·B4): 방향마다 덩어리 하나(64KiB 이하)만 쥐고, 받는 쪽이 받아 갈 때까지 다음을 읽지 않는다. 한쪽이
    /// 쓰기를 닫으면(FIN) 다른 쪽의 쓰기를 닫고 반대 방향은 계속 나른다.
    ///
    /// 끊김(동작 B5): 어느 쪽이든 오류로 끝나거나(`reset`, `timedOut`, `peerRemoved`, 노드가 멈춤, 루프백의 실패) 부른 Task가
    /// 취소되면 두 연결을 RST로 끊는다. 루프백의 서버에게도 정상 닫기(FIN)로 보이지 않으므로, 반쯤 받은 것을 끝까지 받은
    /// 것으로 읽지 않는다. 잇기 시작한 뒤의 끊김은 던지지 않는다(취소만 `cancelled`로 던진다).
    ///
    /// - Throws: 상한이면 `limitReached`, 신원이 없으면 `unknownPeer`, 루프백에 걸지 못하면 `loopbackUnavailable`, 부른 Task가
    ///   취소되면 `cancelled`. 던질 때는 `connection`을 RST로 끊은 뒤다.
    public func forward(_ connection: TailnetConnection, toLoopbackPort port: UInt16) async throws(LoopbackBridgeError) {
        guard reserveSlot() else {
            await connection.abort()
            throw .limitReached
        }
        defer { releaseSlot() }

        guard let peer = await node.whoIs(connection.remoteEndpoint.address) else {
            await connection.abort()
            throw .unknownPeer
        }

        let socket: NetworkSocket
        do {
            socket = try await withTimeout(Self.connectTimeout) { try await NetworkSocket.connectLoopback(port: port) }
        } catch {
            await connection.abort()
            if Task.isCancelled { throw .cancelled }
            switch error {
            case SocketError.connectFailed(let message): throw .loopbackUnavailable(message)
            case is TimeoutError: throw .loopbackUnavailable("5초 안에 연결하지 못했다")
            default: throw .loopbackUnavailable("연결하지 못했다")
            }
        }

        let origin = Origin(remoteEndpoint: connection.remoteEndpoint, peer: peer)
        guard let sourcePort = socket.localPort, record(origin, at: sourcePort) else {
            socket.abort()
            await connection.abort()
            throw .loopbackUnavailable("출발 포트를 표에 적지 못했다")
        }

        if await relay(connection, socket, sourcePort: sourcePort) {
            forget(sourcePort)
            socket.close()
            await connection.close()
        } else if Task.isCancelled {
            throw .cancelled
        }
    }

    /// 다리가 이은 루프백 연결의 출발 포트로 tailnet 쪽 상대를 찾는다. 기다리지 않는다.
    ///
    /// 다리는 표에 적기 전에는 그 연결로 한 바이트도 보내지 않는다. 그러므로 서버가 그 연결에서 무엇이든 받은 뒤
    /// (TLS 핸드셰이크가 끝난 뒤)에 물으면, 다리가 이은 연결은 반드시 표에 있다. 연결이 끝나면 닫기 전에 지운다.
    public func origin(forLoopbackSourcePort port: UInt16) -> Origin? {
        state.withLock { $0.origins[port] }
    }

    // MARK: 나르기

    /// 두 방향을 나른다. 두 방향이 다 정상으로 끝나면 true.
    ///
    /// 한 방향이 실패하면 곧바로 표에서 지우고 두 연결을 RST로 끊는다. 그래야 다른 방향의 기다림이 풀린다. 부른 Task가
    /// 취소되면 두 방향의 기다림이 실패로 풀려 같은 길로 온다. 루프백 소켓은 취소로 닫히지 않으므로(`connectLoopback`)
    /// 지우기가 늘 닫기보다 먼저다.
    private func relay(_ connection: TailnetConnection, _ socket: NetworkSocket, sourcePort: UInt16) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask { await Self.copyToLoopback(from: connection, to: socket) }
            group.addTask { await Self.copyToTailnet(from: socket, to: connection) }
            var finishedCleanly = true
            for await finished in group where !finished && finishedCleanly {
                finishedCleanly = false
                forget(sourcePort)
                socket.abort()
                await connection.abort()
            }
            return finishedCleanly
        }
    }

    /// tailnet → 루프백. 상대가 쓰기를 닫으면 루프백에 FIN을 보내고 true.
    private static func copyToLoopback(from connection: TailnetConnection, to socket: NetworkSocket) async -> Bool {
        while true {
            let chunk: [UInt8]?
            do {
                chunk = try await connection.read(upTo: chunkSize)
            } catch {
                return false
            }
            guard let chunk else {
                socket.finishWriting()
                return true
            }
            guard await socket.writeAccepted(chunk) else { return false }
        }
    }

    /// 루프백 → tailnet. 루프백 쪽이 쓰기를 닫으면 tailnet에 FIN을 보내고 true.
    private static func copyToTailnet(from socket: NetworkSocket, to connection: TailnetConnection) async -> Bool {
        while true {
            let chunk: [UInt8]?
            do {
                chunk = try await socket.receive()
            } catch {
                return false
            }
            do {
                guard let chunk else {
                    try await connection.finishWriting()
                    return true
                }
                if !chunk.isEmpty { try await connection.write(chunk) }
            } catch {
                return false
            }
        }
    }

    // MARK: 표

    private func reserveSlot() -> Bool {
        state.withLock { state in
            guard state.forwarding < connectionLimit else { return false }
            state.forwarding += 1
            return true
        }
    }

    private func releaseSlot() {
        state.withLock { $0.forwarding -= 1 }
    }

    /// 표에 적는다. 그 포트가 이미 있으면 적지 않고 false다: 어느 연결의 상대인지 가를 수 없으므로 잇지 않는다.
    /// 커널은 같은 리스너로 가는 연결의 출발 포트를 겹치게 주지 않지만, 다리는 서로 다른 리스너 포트로도 잇는다.
    private func record(_ origin: Origin, at port: UInt16) -> Bool {
        state.withLock { state in
            guard state.origins[port] == nil else { return false }
            state.origins[port] = origin
            return true
        }
    }

    private func forget(_ port: UInt16) {
        state.withLock { _ = $0.origins.removeValue(forKey: port) }
    }
}
