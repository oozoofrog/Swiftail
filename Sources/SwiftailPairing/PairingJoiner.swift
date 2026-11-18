import Foundation
import Network
import Swiftail
import SwiftailBase
import SwiftailIO

/// 짝 맺기의 들어오는 쪽. 받은 제안(`PairingOffer`)의 여는 쪽에 걸어 절차를 돌리고 짝(`PairedHost`)을 돌려준다.
///
/// 가장자리다. 절차의 판단은 입출력 없는 `PairingJoinerSession`이 하고, 여기서는 연결을 걸고(안 되면 다시 걸고), 기한을
/// 재고, 취소를 본다. 분리된 Task는 없다: 호출한 Task를 취소하면 연결을 끊고 `cancelled`로 돌아온다(계약 동작 J7).
///
/// 방금 tailnet에 들어온 노드는 이름 풀이와 경로, 그리고 여는 쪽의 netmap에 자기가 오르는 데 시간이 걸린다. 그동안
/// 여는 쪽은 모르는 상대의 연결을 읽지 않고 닫는다. 그래서 첫 `challenge`를 받을 때까지 60초 동안 1초 간격으로 다시
/// 건다(J1). `challenge`를 받은 뒤에는 다시 걸지 않는다.
///
/// ```swift
/// let offer = try PairingOffer(link: scannedText)
/// let host = try await PairingJoiner.pair(with: offer, deviceName: "거실 iPad", node: node) { code in
///     Task { @MainActor in screen.show(confirmationCode: code) }   // 여는 쪽 화면의 숫자와 견준다
/// }
/// ```
///
/// 계약 `docs/contracts/SwiftailPairing.md` 5절.
public enum PairingJoiner {
    /// 첫 `challenge`를 받아야 하는 기한(J1).
    static let challengeWindow = Duration.seconds(60)
    /// 다시 거는 간격(J1).
    static let redialInterval = Duration.seconds(1)

    /// 프로세스 안 노드로 들어온다.
    ///
    /// 승인되면 `decision`이 알려 준 `StableID`가 연결 상대의 `whoIs`와 같은지도 본다(J6).
    ///
    /// - Parameters:
    ///   - offer: 링크나 QR에서 읽은 제안.
    ///   - deviceName: 여는 쪽의 승인 화면에 보일 이 기기의 이름. 1~64바이트이고 제어·서식 문자가 없어야 한다.
    ///   - node: 돌고 있는 `.inProcess` 노드. 제안에 인증 키가 있었으면 그 키로 띄운 노드다.
    ///   - awaitingApproval: 여는 쪽이 확인된 뒤 한 번 불린다. 받은 확인 숫자를 화면에 보인다.
    /// - Throws: `PairingError`. 기기 이름이나 노드의 장치가 맞지 않으면 `invalidConfiguration`, 60초 안에 닿지 못하면
    ///   `unreachable`, 제안이 없거나 만료됐거나 비밀이 틀리면 `rejected`, 여는 쪽을 확인하지 못하면
    ///   `hostNotVerified`, 거절이면 `denied`, 승인이 130초 안에 오지 않으면 `timedOut`, 절차와 다른 바이트면
    ///   `protocolViolation`, 호출한 Task가 취소되면 `cancelled`.
    public static func pair(
        with offer: PairingOffer, deviceName: String, node: TailnetNode,
        awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in }
    ) async throws(PairingError) -> PairedHost {
        try await join(offer, deviceName: deviceName, awaitingApproval: awaitingApproval) {
            do throws(ConnectionError) {
                let connection = try await node.connect(to: offer.host, port: offer.port)
                return .connected(
                    TailnetPairingTransport(connection: connection),
                    PairingEndpoints(joiner: connection.localEndpoint, host: connection.remoteEndpoint))
            } catch {
                // 노드가 아직 돌지 않거나 여는 쪽이 netmap에 없는 것은 기다리면 풀린다. 설정이 틀린 것은 풀리지 않는다.
                if case .invalidConfiguration = error {
                    return .failed(.invalidConfiguration("노드로 걸 수 없다(.inProcess 장치와 0이 아닌 포트가 필요하다)"))
                }
                return .unreachable
            }
        } verifyHost: { stableID, endpoints in
            await node.whoIs(endpoints.host.address)?.stableID == stableID
        }
    }

    /// OS 소켓으로 들어온다. 노드가 터널 확장에 있는 앱이 터널이 연결된 뒤에 부른다.
    ///
    /// 이름은 OS가 푼다(터널의 MagicDNS). 라이브러리는 이 연결이 터널로 나갔는지 직접 볼 수 없으므로, 앱이 넘긴 이 기기의
    /// tailnet 주소와 견준다: 연결은 그 주소와 같은 IP 판으로, Wi-Fi·셀룰러·유선·루프백이 아닌 인터페이스로만 걸고,
    /// 준비된 연결의 로컬 끝이 그 주소가 아니거나 원격 끝이 tailnet 대역 밖이면 아무것도 보내지 않고 `notOnTailnet`으로
    /// 끝난다(J2). 이 길에서는 짝이 된 뒤의 연결에서 상대가 그 짝인지 라이브러리로 확인할 수 없다.
    ///
    /// - Parameter localAddress: 이 기기의 tailnet 주소(`100.64.0.1`). 터널 확장이 노드의 `status.addresses`에서 읽어
    ///   앱에 넘긴 값이어야 한다. IPv4-mapped IPv6는 IPv4로 바꿔 쓴다. OS의 인터페이스 목록에서 짐작한 값을 넣으면
    ///   이 검사가 뜻을 잃는다.
    /// - Throws: 위 `pair(with:deviceName:node:awaitingApproval:)`의 것과, `localAddress`가 tailnet 대역 밖이면
    ///   `invalidConfiguration`, 연결이 터널을 거친 것이 아니면 `notOnTailnet`.
    public static func pair(
        with offer: PairingOffer, deviceName: String, localAddress: SwiftailBase.IPAddress,
        awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void = { _ in }
    ) async throws(PairingError) -> PairedHost {
        try await pair(
            with: offer, deviceName: deviceName, localAddress: localAddress, requiringTunnel: true,
            awaitingApproval: awaitingApproval)
    }

    /// OS 소켓으로 들어온다. `requiringTunnel`은 루프백으로 도는 시험만 끈다(공개하지 않는다): 끄면 대역 검사와
    /// 인터페이스 금지를 하지 않는다. 로컬 끝이 `localAddress`인지는 꺼도 본다.
    static func pair(
        with offer: PairingOffer, deviceName: String, localAddress suppliedAddress: SwiftailBase.IPAddress,
        requiringTunnel: Bool,
        awaitingApproval: @escaping @Sendable (_ confirmationCode: String) -> Void
    ) async throws(PairingError) -> PairedHost {
        let localAddress = suppliedAddress.unmappedIPv4
        guard !requiringTunnel || localAddress.isTailscaleAddress else {
            throw .invalidConfiguration("localAddress는 이 기기의 tailnet 주소여야 한다")
        }
        return try await join(offer, deviceName: deviceName, awaitingApproval: awaitingApproval) {
            guard let port = NWEndpoint.Port(rawValue: offer.port), port.rawValue != 0 else {
                return .failed(.invalidConfiguration("포트는 0이 아니어야 한다"))
            }
            let transport = SocketPairingTransport(
                host: offer.host, port: port, isIPv4: localAddress.isIPv4, tunnelOnly: requiringTunnel)
            guard await transport.open(), let ends = transport.endpoints else {
                await transport.close()
                return .unreachable
            }
            let endpoints = PairingEndpoints(joiner: ends.local, host: ends.remote)
            guard requiringTunnel ? endpoints.isOnTailnet(localAddress: localAddress) : endpoints.isLocal(localAddress)
            else {
                await transport.close()
                return .failed(.notOnTailnet)
            }
            return .connected(transport, endpoints)
        }
    }

    // MARK: 절차

    /// 한 번 걸어 본 결과.
    enum Dialed: Sendable {
        case connected(any PairingTransport, PairingEndpoints)
        /// 이번에는 닿지 못했다. 기한이 남았으면 다시 건다.
        case unreachable
        /// 다시 걸어도 소용없다.
        case failed(PairingError)
    }

    /// 걸고, 닿지 못하면 기한 안에서 다시 걸고, 닿은 연결에서 절차를 끝까지 돌린다.
    ///
    /// - Parameters:
    ///   - dial: 연결 하나를 건다.
    ///   - verifyHost: 승인된 `StableID`가 그 연결의 상대 것인지 본다(J6).
    static func join(
        _ offer: PairingOffer, deviceName: String,
        awaitingApproval: @escaping @Sendable (String) -> Void,
        dial: @escaping @Sendable () async -> Dialed,
        verifyHost: @escaping @Sendable (_ stableID: String, PairingEndpoints) async -> Bool = { _, _ in true }
    ) async throws(PairingError) -> PairedHost {
        guard let deviceName = DeviceName(deviceName) else {
            throw .invalidConfiguration("기기 이름은 1~64바이트이고 제어·서식 문자가 없어야 한다")
        }
        let challengeDeadline = ContinuousClock.now + challengeWindow
        while true {
            do throws(PairingError) {
                let approval = try await attempt(
                    offer, deviceName: deviceName, challengeDeadline: challengeDeadline,
                    awaitingApproval: awaitingApproval, dial: dial, verifyHost: verifyHost)
                return PairedHost(host: offer.host, stableID: approval.stableID, name: approval.name, pairedAt: Date())
            } catch {
                guard error == .unreachable, ContinuousClock.now + redialInterval < challengeDeadline else {
                    throw error
                }
            }
            try? await Task.sleep(for: redialInterval)
            if Task.isCancelled { throw .cancelled }
        }
    }

    /// 연결 하나로 해 본다. `challenge`를 받기 전에 끝나면 `unreachable`이다.
    private static func attempt(
        _ offer: PairingOffer, deviceName: DeviceName, challengeDeadline: ContinuousClock.Instant,
        awaitingApproval: @Sendable (String) -> Void,
        dial: @escaping @Sendable () async -> Dialed,
        verifyHost: @Sendable (String, PairingEndpoints) async -> Bool
    ) async throws(PairingError) -> PairingJoinerSession.Approval {
        // 걸기도 기한 안에서만 기다린다(답 없는 SYN은 247초까지 간다).
        let dialed = try? await withTimeout(ContinuousClock.now.duration(to: challengeDeadline), dial)
        guard case .connected(let transport, let endpoints) = dialed else {
            if Task.isCancelled { throw .cancelled }
            if case .failed(let error) = dialed { throw error }
            throw .unreachable
        }

        var session = PairingJoinerSession(
            offer: offer, deviceName: deviceName, nonce: PairingRandom.bytes(PairingMessage.nonceLength),
            endpoints: endpoints, challengeDeadline: challengeDeadline)
        var actions: [PairingJoinerSession.Action] = [.send(session.hello)]
        while true {
            for action in actions {
                switch action {
                case .send(let bytes):
                    await transport.send(bytes)
                case .awaitingApproval(let confirmationCode):
                    awaitingApproval(confirmationCode)
                case .finish(.success(let approval)):
                    let isVerified = await verifyHost(approval.stableID, endpoints)
                    await transport.close()
                    guard isVerified else { throw .hostNotVerified }
                    return approval
                case .finish(.failure(let error)):
                    await transport.close()
                    throw error
                }
            }
            // 끝나지 않은 절차에는 늘 기한이 있다.
            guard !Task.isCancelled, let deadline = session.deadline else {
                await transport.close()
                throw .cancelled
            }
            do {
                let received = try await withTimeout(ContinuousClock.now.duration(to: deadline)) {
                    await transport.receive()
                }
                // 취소로 풀린 읽기는 끊김이 아니다. 위에서 `cancelled`로 끝낸다.
                actions = Task.isCancelled ? [] : received.map { session.receive($0, at: .now) }
                    ?? session.connectionEnded()
            } catch {
                actions = Task.isCancelled ? [] : session.advance(to: max(.now, deadline))
            }
        }
    }
}
