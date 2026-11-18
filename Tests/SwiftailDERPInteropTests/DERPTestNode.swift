import CryptoKit
import SwiftailBase
import SwiftailDERP

/// A test node with one key and one `DERPClient`.
struct DERPTestNode: Sendable {
    let privateKey: Curve25519.KeyAgreement.PrivateKey
    let publicKey: NodePublicKey
    let client: DERPClient

    /// Generates a new key if none is provided. Re-creating it with the same key represents restarting the same node.
    init(server: DERPServer, privateKey: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey()) {
        self.privateKey = privateKey
        publicKey = NodePublicKey(privateKey.publicKey)
        client = DERPClient(servers: [server], privateKey: privateKey, isPreferred: true)
    }
}

/// Runs `client.run()` as a child Task while executing `body`. When `body` returns or throws, cancels `run()` and waits for it to finish.
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

/// Reads a client's events in order. Also counts events other than the one being awaited to check that the connection stayed open.
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

    /// Waits for a packet matching `expected` and returns the sender's key. Skips other packets.
    mutating func waitForPacket(_ expected: [UInt8], timeout: Duration = .seconds(20)) async throws -> NodePublicKey {
        try await wait("\(expected.count)-byte packet", timeout: timeout) { event in
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
            guard remaining > .zero else { throw WaitTimeout(description: "Timed out waiting for \(description) (\(timeout))") }
            let event = try await Self.next(from: stream, waitingFor: description, timeout: remaining)
            switch event {
            case .connected: connectedCount += 1
            case .disconnected: disconnectedCount += 1
            case .attemptFailed, .packet, .peerGone: break
            }
            if let value = match(event) { return value }
        }
    }

    /// Races one event against a deadline. A timeout ends the test, so the stream closed by cancellation is not reused.
    private static func next(
        from stream: AsyncStream<DERPClient.Event>, waitingFor description: String, timeout: Duration
    ) async throws -> DERPClient.Event {
        try await withThrowingTaskGroup(of: DERPClient.Event.self) { group in
            defer { group.cancelAll() }
            group.addTask {
                for await event in stream { return event }
                throw WaitTimeout(description: "Event stream ended while waiting for \(description)")
            }
            group.addTask {
                try await Task.sleep(for: timeout, clock: .continuous)
                throw WaitTimeout(description: "Timed out waiting for \(description) (\(timeout))")
            }
            guard let event = try await group.next() else { throw WaitTimeout(description: "No event for \(description)") }
            return event
        }
    }
}

/// Packets sent before the server registers `receiver` are discarded (`connected` marks the point when ClientInfo was sent). Resend periodically
/// until the first packet arrives, at which point both sides are registered. Previously sent probe packets may still arrive afterward, so subsequent waits
/// filter by content.
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

/// A packet with recognizable content. Byte i is `i % 251`.
func samplePacket(size: Int) -> [UInt8] {
    (0..<size).map { UInt8($0 % 251) }
}
