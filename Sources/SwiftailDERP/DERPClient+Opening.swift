import CryptoKit
import Network
import SwiftailBase
import SwiftailIO

/// 핸드셰이크를 마친 연결: 소켓, 준비된 상태 기계, 준비와 함께 온 사건.
struct OpenedConnection: Sendable {
    let socket: NetworkSocket
    let connection: DERPConnection
    /// 서버가 ServerKey와 같은 조각에 붙여 보낸 패킷 같은 것. `ready`를 포함한다.
    let events: [DERPConnection.Event]
}

extension DERPClient {
    /// 서버에 닿아 TLS를 맺고, 업그레이드와 핸드셰이크를 마쳐 `ready`가 될 때까지 진행한다.
    ///
    /// 서버 목록은 앞에서부터 TCP로 시도해(서버당 `tcpTimeout`) 처음 붙는 곳에 TLS를 맺는다. TLS 실패는 다음 서버로
    /// 넘어가지 않고 이번 시도의 실패다(노트 4.1절 1). 서버 하나 안에서는 `targets`를 함께 건다(`dial`).
    static func open(
        servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, plaintextForTests: Bool,
        interface: NWInterface?
    ) async throws -> OpenedConnection {
        let (socket, server) = try await connect(to: servers, plaintextForTests: plaintextForTests, interface: interface)
        do {
            var connection = try DERPConnection(
                privateKey: privateKey, host: hostHeader(for: server), isPreferred: isPreferred, clientInfoNonce: randomNonce()
            )
            socket.send(connection.takeOutboundBytes())
            while true {
                guard let bytes = try await socket.receive() else { throw Disconnection.closedByServer }
                let events = try connection.receive(bytes)
                socket.send(connection.takeOutboundBytes())
                if events.contains(.ready) { return OpenedConnection(socket: socket, connection: connection, events: events) }
            }
        } catch {
            socket.close()
            throw error
        }
    }

    /// 서버 목록에서 처음 닿는 곳에 TLS 소켓을 연다. `plaintextForTests`면 TLS 없이 연다(시험의 가짜 서버용).
    ///
    /// 마지막 서버는 어느 쪽 실패든 이번 시도의 실패이므로 곧바로 TLS를 맺는다. `interface`가 있으면 모든 연결이 그
    /// 인터페이스로만 나간다(대상이 루프백이면 묶지 않는다).
    // shortcut: `NetworkSocket.connect`는 TCP와 TLS를 한 번에 맺으므로, TCP 실패와 TLS 실패를 가르려고 마지막이 아닌
    // 서버는 평문 TCP로 먼저 닿는지만 보고(맺자마자 닫는다) 먼저 붙은 대상에 TLS로 다시 맺는다. 서버마다 TCP 연결이
    // 하나 더 생긴다. 마지막 서버는 대상마다 TCP와 TLS를 함께 맺어 먼저 끝나는 쪽을 쓰므로, Go(먼저 붙은 TCP에만 TLS)와
    // 달리 한 대상의 TLS가 실패해도 다른 대상이 붙으면 쓴다. TCP 연결을 맺은 뒤 그 위에 TLS를 얹는 길이 `SwiftailIO`에
    // 생기면 한 번만 맺는다.
    private static func connect(
        to servers: [DERPServer], plaintextForTests: Bool, interface: NWInterface?
    ) async throws -> (NetworkSocket, DERPServer) {
        for (index, server) in servers.enumerated() {
            try Task.checkCancellation()
            var targets = server.targets
            if index < servers.count - 1 {
                do {
                    let (probe, target) = try await withTimeout(tcpTimeout) { [targets] in
                        try await dial(targets, of: server, tls: .none, interface: interface)
                    }
                    probe.close()
                    targets = [target]
                } catch {
                    continue
                }
            }
            let security = plaintextForTests ? NetworkSocket.TLS.none : tls(for: server)
            return (try await dial(targets, of: server, tls: security, interface: interface).socket, server)
        }
        throw Disconnection.noServers
    }

    /// `targets`를 함께 걸어 먼저 붙는 연결과 그 대상을 돌려준다(Go `dialNode`). 진 쪽 연결은 닫는다. 모두 실패하면
    /// 가장 먼저 온 실패를 던지고, 대상이 없으면 `Disconnection.noServers`다.
    ///
    /// 연결마다 TaskGroup의 자식이므로 부른 Task가 취소되면 열던 연결이 모두 닫힌다(`NetworkSocket.connect`).
    // shortcut: Go는 IPv6를 선호하는 망에서 IPv4를 200ms 늦게 건다(`preferIPv6`). Swiftail에는 주소 체계 선호 판단이
    // 없으므로 모두 곧바로 건다. 필요해지는 시점: IPv6가 되는 망에서 IPv4 쪽이 먼저 붙어 생기는 문제가 보일 때.
    private static func dial(
        _ targets: [DERPServer.Target], of server: DERPServer, tls: NetworkSocket.TLS, interface: NWInterface?
    ) async throws -> (socket: NetworkSocket, target: DERPServer.Target) {
        try await withThrowingTaskGroup(of: (socket: NetworkSocket, target: DERPServer.Target).self) { group in
            for target in targets {
                let host = switch target {
                case .hostName: server.hostName
                case .address(let address): address.description
                }
                let bound = NetworkSocket.bindableInterface(interface, forHost: host)
                group.addTask {
                    (try await NetworkSocket.connect(host: host, port: server.port, tls: tls, interface: bound), target)
                }
            }
            var firstFailure: (any Error)?
            while let result = await group.nextResult() {
                switch result {
                case .success(let winner):
                    group.cancelAll()
                    // 취소가 닿기 전에 붙은 진 쪽 연결을 닫는다.
                    while let late = await group.nextResult() {
                        if case .success(let loser) = late { loser.socket.close() }
                    }
                    return winner
                case .failure(let failure):
                    if firstFailure == nil { firstFailure = failure }
                }
            }
            throw firstFailure ?? Disconnection.noServers
        }
    }

    private static func tls(for server: DERPServer) -> NetworkSocket.TLS {
        switch server.verification {
        case .system: .system(serverName: server.hostName)
        case .noneForTests: .insecureForTests(serverName: server.hostName)
        }
    }

    /// `Host` 값. 포트가 443이 아니면 붙인다(Go와 같다).
    private static func hostHeader(for server: DERPServer) -> String {
        server.port == 443 ? server.hostName : "\(server.hostName):\(server.port)"
    }

    /// ClientInfo를 봉할 nonce. 시스템 난수는 상태 기계 바깥인 여기서만 뽑는다.
    private static func randomNonce() -> [UInt8] {
        (0..<DERPHandshake.nonceSize).map { _ in UInt8.random(in: .min ... .max) }
    }
}
