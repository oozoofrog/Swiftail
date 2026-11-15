import Network
import Swiftail
import SwiftailBase
import SwiftailIO
import Synchronization

/// tailnet에서 받은 TCP 연결을 이 기기의 루프백(`127.0.0.1`) TCP 리스너로 이어 준다.
///
/// TLS와 HTTP를 OS의 스택(`NWListener`)으로 끝내려는 앱이 쓴다. 다리는 바이트를 해석하지 않는다. 루프백 연결의 저쪽에서는
/// 상대가 `127.0.0.1`로 보이므로, 서버는 다리가 준 프로토콜을 리스너에 넣고 받은 연결로 `origin(of:)`을 물어 tailnet의
/// 상대를 안다.
///
/// 다리는 루프백 연결마다 일회용 토큰을 TLS 바이트보다 먼저 보낸다. 리스너의 그 프로토콜이 토큰을 확인한 연결만 위(TLS)로
/// 올리므로, 같은 기기의 다른 프로세스가 연 연결은 서버에게 `.ready`가 되지 않고 실패한다. 출발 포트를 다시 쓰거나
/// 다른 리스너로 같은 출발 포트를 써도 마찬가지다(계약 `docs/contracts/SwiftailHost.md` 동작 B6).
///
/// 서버가 지킬 것(동작 B7):
/// - 리스너를 `127.0.0.1`에만 묶고 포트는 시스템이 고르게 한다.
/// - 리스너의 `NWParameters`에 `makeListenerProtocolOptions()`를 **`applicationProtocols`의 끝에** 더한다(TLS 아래,
///   TCP 바로 위). 앞에 넣으면 TLS 위에 놓여 핸드셰이크가 깨진다.
/// - 받은 연결마다 **`.ready`가 된 뒤, 요청을 읽기 전에** `origin(of:)`을 한 번 묻고, nil이면 그 연결을 끊는다. 답은 한 번만
///   나온다(두 번째는 nil).
/// - 신원은 요청마다 `whoIs`로 다시 찾지 않고 `Origin.peer`를 쓴다. 연결을 맺을 때 확인한 신원이다(동작 B2).
/// - 끝난 연결은 `cancel()`하고 그 `NWConnection`의 참조를 놓는다. 준비되지 않고 끝난 연결(토큰 없는 연결이 그렇다)의 소켓은
///   `cancel()`만으로는 닫히지 않고 객체가 풀릴 때 닫힌다. 붙잡고 있으면 그런 연결마다 파일 서술자가 남는다.
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

    /// 루프백 연결을 끝내는 방법.
    private enum LoopbackEnding {
        /// 정상 닫기(FIN).
        case close
        /// 오류로 끊기(RST).
        case reset
    }

    /// `forward`에 들어와 아직 돌아가지 않은 호출의 수. 상한과 견준다.
    private let forwarding = Mutex(0)

    /// 한 방향이 한 번에 쥐는 바이트(계약 한도 표: 방향당 64KiB).
    private static let chunkSize = 65_536
    /// 루프백 연결을 한 번 맺는 기한(계약 한도 표).
    private static let connectTimeout = Duration.seconds(5)
    /// 루프백으로 거는 횟수. 뽑힌 출발 포트의 열쇠에 허가가 남아 있으면 다른 포트로 다시 건다(계약 한도 표).
    private static let connectAttempts = 3

    private let node: TailnetNode
    let connectionLimit: Int
    let admission = LoopbackAdmissionTable()
    /// 루프백 연결을 닫기 직전에 그 연결의 열쇠와 표의 모양을 받는다. 시험만 쓴다.
    private let willEndLoopback: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable.Snapshot) -> Void)?
    /// 루프백으로 건 연결의 열쇠를 표에 적기 직전에 그 열쇠와 표를 받는다. 시험만 쓴다(뽑힌 출발 포트에 허가가 남은 경우를 만든다).
    private let willExpect: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable) -> Void)?

    /// `node`가 받은 연결을 잇는 다리. 신원은 `node.whoIs(_:)`로 찾는다. 잇는 연결은 256개까지다(노드의 연결 상한과 같다).
    public convenience init(node: TailnetNode) {
        self.init(node: node, connectionLimit: 256)
    }

    /// 상한을 바꾼 다리. 시험이 상한에 닿는 경우를 연결 몇 개로 만들고(노드 하나의 자기 연결로는 다리에 256개를 올릴 수
    /// 없다), 루프백 연결을 닫는 순간의 표를 본다.
    init(
        node: TailnetNode, connectionLimit: Int,
        willEndLoopback: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable.Snapshot) -> Void)? = nil,
        willExpect: (@Sendable (LoopbackAdmissionTable.Key, LoopbackAdmissionTable) -> Void)? = nil
    ) {
        self.node = node
        self.connectionLimit = connectionLimit
        self.willEndLoopback = willEndLoopback
        self.willExpect = willExpect
    }

    /// 서버의 루프백 리스너에 넣을 프로토콜. 다리가 보낸 토큰을 확인한 연결만 위로 올린다.
    ///
    /// `NWParameters.defaultProtocolStack.applicationProtocols`의 **끝에** 더한다(`append`). 그 자리가 TLS 아래, TCP 바로
    /// 위다. 평문 리스너에서도 같다. 이 다리의 토큰만 받으므로 리스너 하나에는 다리 하나를 쓴다.
    public func makeListenerProtocolOptions() -> NWProtocolFramer.Options {
        let options = NWProtocolFramer.Options(definition: LoopbackAdmissionFramer.definition)
        options[LoopbackAdmissionFramer.tableOption] = admission
        return options
    }

    /// 연결 하나를 `127.0.0.1:<port>`로 잇고, 두 방향이 다 끝날 때까지 바이트를 나른다. 끝나면 두 연결을 닫고 돌아온다.
    ///
    /// 차례(동작 B1): 상한을 보고, 상대의 신원을 확인하고, 루프백으로 건다(5초). 그 연결의 `(출발 포트, 리스너 포트)`와
    /// 새 토큰을 표에 적은 **뒤에** 토큰을 보내고, 그 뒤에 복사를 시작한다. 그 열쇠에 앞선 연결의 허가가 남아 표가 받지
    /// 않으면 다른 출발 포트로 다시 건다(3번까지). 끝나면 소비되지 않은 토큰을 거둔 **뒤에** 루프백 연결을 닫는다.
    ///
    /// 나르기(동작 B3·B4): 방향마다 덩어리 하나(64KiB 이하)만 쥐고, 받는 쪽이 받아 갈 때까지 다음을 읽지 않는다. 한쪽이
    /// 쓰기를 닫으면(FIN) 다른 쪽의 쓰기를 닫고 반대 방향은 계속 나른다.
    ///
    /// 끊김(동작 B5): 어느 쪽이든 오류로 끝나거나(`reset`, `timedOut`, `peerRemoved`, 노드가 멈춤, 루프백의 실패) 부른 Task가
    /// 취소되면 두 연결을 RST로 끊는다. 루프백의 서버에게도 정상 닫기(FIN)로 보이지 않으므로, 반쯤 받은 것을 끝까지 받은
    /// 것으로 읽지 않는다. 잇기 시작한 뒤의 끊김은 던지지 않는다(취소만 `cancelled`로 던진다).
    ///
    /// - Throws: 상한이면 `limitReached`, 신원이 없으면 `unknownPeer`, 루프백에 걸지 못하거나 토큰을 적거나 보내지 못하면
    ///   `loopbackUnavailable`, 부른 Task가 취소되면 `cancelled`. 던질 때는 `connection`을 RST로 끊은 뒤다.
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

        let token = LoopbackAdmissionTable.makeToken()
        let socket: NetworkSocket
        let key: LoopbackAdmissionTable.Key
        do {
            (socket, key) = try await openLoopback(
                port: port, token: token, origin: Origin(remoteEndpoint: connection.remoteEndpoint, peer: peer))
        } catch {
            await connection.abort()
            throw error
        }
        guard await socket.writeAccepted(token) else {
            endLoopback(socket, key, .reset)
            await connection.abort()
            if Task.isCancelled { throw .cancelled }
            throw .loopbackUnavailable("토큰을 보내지 못했다")
        }

        if await relay(connection, socket, key: key) {
            endLoopback(socket, key, .close)
            await connection.close()
        } else if Task.isCancelled {
            throw .cancelled
        }
    }

    /// 서버가 받은 루프백 연결의 tailnet 쪽 상대. 기다리지 않는다. 한 연결에 한 번만 답한다(두 번째는 nil).
    ///
    /// `connection`이 `.ready`이고, 리스너의 `makeListenerProtocolOptions()`가 그 연결에서 이 다리의 토큰을 확인했을 때만
    /// 답한다. 토큰은 TLS 바이트보다 먼저 오고 확인되기 전에는 연결이 준비되지 않으므로, `.ready`가 된 뒤에 물으면 다리가 이은
    /// 연결은 반드시 답을 얻는다. nil이면 다리가 이은 연결이 아니거나 이미 물었다. 서버는 그 연결을 끊는다.
    public func origin(of connection: NWConnection) -> Origin? {
        guard case .ready = connection.state,
              case .hostPort(.ipv4(let remoteHost), let remotePort) = connection.endpoint, remoteHost == .loopback,
              case .hostPort(_, let localPort)? = connection.currentPath?.localEndpoint
        else { return nil }
        return admission.take(LoopbackAdmissionTable.Key(sourcePort: remotePort.rawValue, listenerPort: localPort.rawValue))
    }

    // MARK: 루프백 연결

    /// `127.0.0.1:<port>`로 걸고, 그 연결의 열쇠에 `token`을 적는다. 아직 한 바이트도 보내지 않았다.
    ///
    /// 뽑힌 출발 포트의 열쇠에 허가가 남아 있으면 표가 받지 않는다(서버가 가져가지 않은 채 끝난 연결의 것이다. TLS
    /// 핸드셰이크 전에 끝난 연결이 그렇게 남는다). 그때는 그 소켓을 쥔 채 다시 건다. 쥐고 있어야 커널이 같은 포트를 다시
    /// 주지 않는다. 쥔 소켓은 돌아갈 때 RST로 끊는다(토큰을 보내지 않았으므로 서버에게는 준비되지 않고 끝난 연결이다).
    private func openLoopback(
        port: UInt16, token: [UInt8], origin: Origin
    ) async throws(LoopbackBridgeError) -> (NetworkSocket, LoopbackAdmissionTable.Key) {
        var refused: [NetworkSocket] = []
        defer { for socket in refused { socket.abort() } }
        for _ in 0..<Self.connectAttempts {
            let socket: NetworkSocket
            do {
                socket = try await withTimeout(Self.connectTimeout) { try await NetworkSocket.connectLoopback(port: port) }
            } catch {
                if Task.isCancelled { throw .cancelled }
                switch error {
                case SocketError.connectFailed(let message): throw .loopbackUnavailable(message)
                case is TimeoutError: throw .loopbackUnavailable("5초 안에 연결하지 못했다")
                default: throw .loopbackUnavailable("연결하지 못했다")
                }
            }
            guard let sourcePort = socket.localPort else {
                socket.abort()
                throw .loopbackUnavailable("출발 포트를 읽지 못했다")
            }
            let key = LoopbackAdmissionTable.Key(sourcePort: sourcePort, listenerPort: port)
            willExpect?(key, admission)
            if admission.expect(token, for: key, origin: origin) { return (socket, key) }
            refused.append(socket)
        }
        throw .loopbackUnavailable("토큰을 표에 적지 못했다")
    }

    // MARK: 나르기

    /// 두 방향을 나른다. 두 방향이 다 정상으로 끝나면 true.
    ///
    /// 한 방향이 실패하면 곧바로 두 연결을 RST로 끊는다. 그래야 다른 방향의 기다림이 풀린다. 부른 Task가 취소되면 두 방향의
    /// 기다림이 실패로 풀려 같은 길로 온다. 루프백 소켓은 취소로 닫히지 않으므로(`connectLoopback`) 닫기는 늘
    /// `endLoopback`을 지난다.
    private func relay(_ connection: TailnetConnection, _ socket: NetworkSocket, key: LoopbackAdmissionTable.Key) async -> Bool {
        await withTaskGroup(of: Bool.self) { group in
            group.addTask { await Self.copyToLoopback(from: connection, to: socket) }
            group.addTask { await Self.copyToTailnet(from: socket, to: connection) }
            var finishedCleanly = true
            for await finished in group where !finished && finishedCleanly {
                finishedCleanly = false
                endLoopback(socket, key, .reset)
                await connection.abort()
            }
            return finishedCleanly
        }
    }

    /// 토큰을 적은 뒤 루프백 연결을 끝내는 유일한 길. 소비되지 않은 토큰을 거둔 뒤에 닫는다.
    ///
    /// 허가(서버가 아직 가져가지 않은 상대)는 지우지 않고 끝났다고만 적는다(`withdraw`). 그것은 이 연결이 실제로 나른
    /// 바이트의 상대이고, 서버가 그 연결에 대해 아직 물을 수 있다. 지우면 같은 4-튜플을 다시 쓰는 다리의 새 연결이 그 자리에
    /// 들어가, 늦게 온 조회가 다른 상대를 얻을 수 있다.
    private func endLoopback(_ socket: NetworkSocket, _ key: LoopbackAdmissionTable.Key, _ ending: LoopbackEnding) {
        admission.withdraw(key)
        willEndLoopback?(key, admission.snapshot)
        switch ending {
        case .close: socket.close()
        case .reset: socket.abort()
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

    // MARK: 상한

    private func reserveSlot() -> Bool {
        forwarding.withLock { forwarding in
            guard forwarding < connectionLimit else { return false }
            forwarding += 1
            return true
        }
    }

    private func releaseSlot() {
        forwarding.withLock { $0 -= 1 }
    }
}
