import Foundation
import Network
import Swiftail
import SwiftailBase

/// 들어오는 쪽이 짝 맺기 메시지를 주고받는 연결. 프로세스 안 노드의 연결과 OS 소켓, 두 가지가 있다.
///
/// 실패를 가르지 않는다. 절차에는 "연결이 끝났다"만 뜻이 있고, 그 뜻은 상태 기계가 단계에 따라 정한다.
protocol PairingTransport: Sendable {
    /// 받은 바이트. 상대가 닫았거나, 연결이 실패했거나, 기다리던 Task가 취소되면 nil.
    func receive() async -> [UInt8]?
    /// 바이트를 보낸다. 실패는 다음 `receive()`가 알린다.
    func send(_ bytes: [UInt8]) async
    /// 연결을 닫는다. 보낸 것은 먼저 나간다.
    func close() async
}

/// 프로세스 안 노드의 tailnet 연결.
struct TailnetPairingTransport: PairingTransport {
    let connection: TailnetConnection

    func receive() async -> [UInt8]? {
        try? await connection.read()
    }

    func send(_ bytes: [UInt8]) async {
        try? await connection.write(bytes)
    }

    func close() async {
        await connection.close()
    }
}

/// OS 소켓(`NWConnection`)의 TCP 연결. 노드가 터널 확장에 있는 앱이 쓴다. 터널이 바이트를 tailnet으로 나른다.
///
/// `NWConnection`은 콜백으로 알린다. 콜백마다 값 하나짜리 흐름으로 바꿔 기다린다. 기다리던 Task가 취소되면 흐름이 끝나
/// 기다림이 풀리고, 늦게 온 콜백의 값은 버려진다(취소된 절차는 연결을 닫으므로 잃는 것이 없다). 버려지면 연결을 닫는다.
final class SocketPairingTransport: PairingTransport {
    /// 한 번에 읽는 양. 절차의 메시지는 모두 이보다 작다.
    private static let maximumReadLength = 4096

    private let connection: NWConnection

    init(_ connection: NWConnection) {
        self.connection = connection
    }

    /// `host:port`로 거는 평문 TCP 연결. 이름은 OS가 푼다(터널이 연결돼 있으면 MagicDNS).
    ///
    /// - Parameters:
    ///   - isIPv4: 쓸 IP 판. 이 기기의 tailnet 주소와 같은 판으로만 건다(로컬 끝을 그 주소와 견줄 수 있게).
    ///   - tunnelOnly: Wi-Fi·셀룰러·유선·루프백 인터페이스로 나가지 못하게 한다. 남는 것은 터널(utun) 같은 그 밖의
    ///     인터페이스다. 터널이 꺼져 있으면 연결이 서지 않는다. 루프백으로 도는 시험만 끈다.
    convenience init(host: String, port: NWEndpoint.Port, isIPv4: Bool, tunnelOnly: Bool) {
        let tcp = NWProtocolTCP.Options()
        tcp.noDelay = true
        let parameters = NWParameters(tls: nil, tcp: tcp)
        if let ip = parameters.defaultProtocolStack.internetProtocol as? NWProtocolIP.Options {
            ip.version = isIPv4 ? .v4 : .v6
        }
        if tunnelOnly {
            parameters.prohibitedInterfaceTypes = [.wifi, .cellular, .wiredEthernet, .loopback]
        }
        self.init(NWConnection(host: NWEndpoint.Host(host), port: port, using: parameters))
    }

    deinit {
        connection.cancel()
    }

    /// 연결을 시작하고 준비될 때까지 기다린다. 준비됐으면 true.
    ///
    /// 거절이나 이름 풀이 실패에서 `NWConnection`은 `waiting`으로 머물며 스스로 다시 시도한다. 다시 걸기는 부르는 쪽이
    /// 하므로(계약 동작 J1) 여기서는 실패로 본다.
    func open() async -> Bool {
        let (states, continuation) = AsyncStream.makeStream(of: Bool.self)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: continuation.yield(true)
            case .waiting, .failed, .cancelled: continuation.yield(false)
            default: break
            }
        }
        connection.start(queue: DispatchQueue(label: "Swiftail.Pairing"))
        var isReady = false
        for await state in states {
            isReady = state
            break
        }
        connection.stateUpdateHandler = nil
        return isReady
    }

    /// 준비된 연결의 두 끝(이쪽, 상대). IP 주소가 아니면 nil.
    var endpoints: (local: IPEndpoint, remote: IPEndpoint)? {
        guard let path = connection.currentPath, let local = path.localEndpoint.flatMap(Self.endpoint),
              let remote = path.remoteEndpoint.flatMap(Self.endpoint)
        else { return nil }
        return (local, remote)
    }

    func receive() async -> [UInt8]? {
        let (chunks, continuation) = AsyncStream.makeStream(of: [UInt8].self)
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maximumReadLength) {
            data, _, isComplete, error in
            if let data, !data.isEmpty {
                continuation.yield(Array(data))
            } else if error == nil, !isComplete {
                continuation.yield([])
            }
            continuation.finish()
        }
        for await chunk in chunks { return chunk }
        return nil
    }

    func send(_ bytes: [UInt8]) async {
        let (processed, continuation) = AsyncStream.makeStream(of: Void.self)
        connection.send(content: Data(bytes), completion: .contentProcessed { _ in continuation.finish() })
        for await _ in processed {}
    }

    func close() async {
        connection.cancel()
    }

    private static func endpoint(_ endpoint: NWEndpoint) -> IPEndpoint? {
        guard case .hostPort(let host, let port) = endpoint else { return nil }
        let address: SwiftailBase.IPAddress?
        switch host {
        case .ipv4(let ipv4): address = SwiftailBase.IPAddress(bytes: ipv4.rawValue)
        case .ipv6(let ipv6): address = SwiftailBase.IPAddress(bytes: ipv6.rawValue)
        default: address = nil
        }
        return address.map { IPEndpoint(address: $0, port: port.rawValue) }
    }
}
