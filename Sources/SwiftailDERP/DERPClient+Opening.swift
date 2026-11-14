import CryptoKit
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
    /// 넘어가지 않고 이번 시도의 실패다(노트 4.1절 1).
    ///
    /// shortcut: IPv4·IPv6 동시 시도는 없다. `address`가 있으면 그 주소 하나만, 없으면 `NWConnection`이 `hostName`을
    /// 해석해 고른다.
    static func open(
        servers: [DERPServer], privateKey: Curve25519.KeyAgreement.PrivateKey, isPreferred: Bool, plaintextForTests: Bool
    ) async throws -> OpenedConnection {
        let (socket, server) = try await connect(to: servers, plaintextForTests: plaintextForTests)
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
    /// 마지막 서버는 어느 쪽 실패든 이번 시도의 실패이므로 곧바로 TLS를 맺는다.
    // shortcut: `NetworkSocket.connect`는 TCP와 TLS를 한 번에 맺으므로, TCP 실패와 TLS 실패를 가르려고 마지막이 아닌
    // 서버는 평문 TCP로 먼저 닿는지만 보고(맺자마자 닫는다) TLS로 다시 맺는다. 서버마다 TCP 연결이 하나 더 생긴다.
    // TCP 연결을 맺은 뒤 그 위에 TLS를 얹는 길이 `SwiftailIO`에 생기면 한 번만 맺는다.
    private static func connect(to servers: [DERPServer], plaintextForTests: Bool) async throws -> (NetworkSocket, DERPServer) {
        for (index, server) in servers.enumerated() {
            try Task.checkCancellation()
            let host = server.address?.description ?? server.hostName
            if index < servers.count - 1 {
                do {
                    let probe = try await withTimeout(tcpTimeout) {
                        try await NetworkSocket.connect(host: host, port: server.port, tls: .none)
                    }
                    probe.close()
                } catch {
                    continue
                }
            }
            let security = plaintextForTests ? NetworkSocket.TLS.none : tls(for: server)
            return (try await NetworkSocket.connect(host: host, port: server.port, tls: security), server)
        }
        throw Disconnection.noServers
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
