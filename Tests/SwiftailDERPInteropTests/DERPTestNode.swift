import CryptoKit
import SwiftailBase
import SwiftailDERP

/// 시험용 노드: 키 하나와 `DERPClient` 하나.
struct DERPTestNode: Sendable {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let publicKey: NodePublicKey
    let client: DERPClient

    /// 키를 주지 않으면 새로 만든다. 같은 키로 다시 만들면 "같은 노드가 다시 뜬" 것이다.
    init(server: DERPServer, privateKey: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()) {
        self.privateKey = privateKey
        publicKey = NodePublicKey(privateKey.publicKey)
        client = DERPClient(servers: [server], privateKey: privateKey, isPreferred: true)
    }
}

/// `client.run()`을 자식 Task로 돌리며 `body`를 실행한다. `body`가 끝나거나 던지면 `run()`을 취소하고 끝나기를 기다린다.
func running<Result: Sendable>(
    _ node: DERPTestNode, _ body: () async throws -> Result
) async throws -> Result {
    try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask { await node.client.run() }
        defer { group.cancelAll() }
        return try await body()
    }
}

struct WaitTimeout: Error, CustomStringConvertible {
    let description: String
}

/// 한 클라이언트의 사건을 차례로 읽는다. 기다린 사건 말고 지나간 것도 세어 둔다(연결이 끊기지 않았는지 확인하려고).
struct DERPWatcher {
    private let stream: AsyncStream<DERPClient.Event>
    private(set) var connectedCount = 0
    private(set) var disconnectedCount = 0

    init(_ node: DERPTestNode) {
        stream = node.client.events
    }

    mutating func waitForConnected(timeout: Duration = .seconds(20)) async throws {
        _ = try await wait("connected", timeout: timeout) { event in
            if case .connected = event { true } else { nil }
        }
    }

    /// `expected`와 같은 패킷이 올 때까지 기다리고 보낸 쪽 키를 돌려준다. 다른 패킷은 건너뛴다.
    mutating func waitForPacket(_ expected: [UInt8], timeout: Duration = .seconds(20)) async throws -> NodePublicKey {
        try await wait("패킷 \(expected.count)바이트", timeout: timeout) { event in
            if case let .packet(bytes, from: sender) = event, bytes == expected { sender } else { nil }
        }
    }

    mutating func waitForPeerGone(_ peer: NodePublicKey, timeout: Duration = .seconds(20)) async throws {
        _ = try await wait("peerGone", timeout: timeout) { event in
            if case let .peerGone(gone) = event, gone == peer { true } else { nil }
        }
    }

    private mutating func wait<Value: Sendable>(
        _ description: String, timeout: Duration, _ match: (DERPClient.Event) -> Value?
    ) async throws -> Value {
        let deadline = ContinuousClock.now.advanced(by: timeout)
        while true {
            let remaining = deadline - ContinuousClock.now
            guard remaining > .zero else { throw WaitTimeout(description: "\(description) 제한 시간 초과 (\(timeout))") }
            let event = try await Self.next(from: stream, waitingFor: description, timeout: remaining)
            switch event {
            case .connected: connectedCount += 1
            case .disconnected: disconnectedCount += 1
            case .attemptFailed, .packet, .peerGone: break
            }
            if let value = match(event) { return value }
        }
    }

    /// 사건 하나와 마감을 경쟁시킨다. 시간 초과는 시험을 끝내므로 취소로 닫힌 흐름을 다시 쓰지 않는다.
    private static func next(
        from stream: AsyncStream<DERPClient.Event>, waitingFor description: String, timeout: Duration
    ) async throws -> DERPClient.Event {
        try await withThrowingTaskGroup(of: DERPClient.Event.self) { group in
            defer { group.cancelAll() }
            group.addTask {
                for await event in stream { return event }
                throw WaitTimeout(description: "\(description)를 기다리는 중 사건 흐름이 끝났다")
            }
            group.addTask {
                try await Task.sleep(for: timeout, clock: .continuous)
                throw WaitTimeout(description: "\(description) 제한 시간 초과 (\(timeout))")
            }
            guard let event = try await group.next() else { throw WaitTimeout(description: "\(description) 사건 없음") }
            return event
        }
    }
}

/// 서버가 `receiver`를 등록하기 전에 보낸 패킷은 버려진다(`connected`는 ClientInfo를 보낸 시점이다). 첫 패킷이 닿을 때까지
/// 조금씩 다시 보내고, 닿으면 양쪽이 서버에 등록된 것이다. 닿은 뒤에도 이미 보낸 탐지 패킷이 더 올 수 있으므로 이후 기다림은
/// 내용으로 걸러 낸다.
func establishPath(
    from sender: DERPTestNode, to receiver: DERPTestNode, receiverWatcher: inout DERPWatcher
) async throws {
    let probe = Array("probe".utf8)
    try await withThrowingTaskGroup(of: Void.self) { group in
        group.addTask {
            while true {
                await sender.client.send(probe, to: receiver.publicKey)
                try await Task.sleep(for: .milliseconds(200), clock: .continuous)
            }
        }
        defer { group.cancelAll() }
        _ = try await receiverWatcher.waitForPacket(probe)
    }
}

/// 내용을 알아볼 수 있는 패킷. 바이트 i는 `i % 251`이다.
func samplePacket(size: Int) -> [UInt8] {
    (0..<size).map { UInt8($0 % 251) }
}
