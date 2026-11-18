// Fake control server for `set-dns` tests. Simulates `GET /key`, the `POST /ts2021` upgrade, a Noise IK responder, and a minimal
// HTTP/2 server over loopback TCP. Accepts registration (`/machine/register`) and state uploads immediately, and sends only headers for the map stream
// before leaving it open (long poll). The test sets the `set-dns` response.
//
// The Noise responder mirrors `NoiseIK` (initiator): `<- s ... -> e, es, s, ss <- e, ee, se`
// (`docs/protocol-notes/control-transport.md` §4.5). Does not update flow-control windows. The test requests and responses are much smaller than the default window
// (65,535 bytes).

import CryptoKit
import Foundation
import Network
import Synchronization
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailHTTP2

final class SetDNSFakeControlServer: Sendable {
    /// The response to send for `set-dns`.
    enum SetDNSReply: Sendable {
        /// Responds with this status and body.
        case respond(status: Int, body: [UInt8])
        /// Leaves the stream open without responding.
        case never
    }

    /// A single HTTP/2 request received by the server.
    struct Request: Sendable {
        var connection: Int
        var stream: UInt32
        var method: String
        var path: String
        var headers: [HeaderField]
        var body: [UInt8]

        func header(_ name: String) -> String? { headers.first { $0.name == name }?.value }
    }

    private struct State {
        var keyRequests = 0
        /// If false, answers `/key` with 500 (the client backs off and retries).
        var acceptsConnections = true
        var setDNSReply = SetDNSReply.respond(status: 200, body: Array("{}".utf8))
        /// Bodies for registration requests in order. Accepts immediately (`MachineAuthorized`) when the list is empty.
        var registerReplies: [[UInt8]] = []
        /// If true, leaves registration requests unanswered (leaves the stream open). Used by the logout deadline test.
        var registerNeverAnswers = false
        var requests: [Request] = []
        /// Open map streams (connection number and stream ID). Removed when the client closes them with RST_STREAM.
        var openMapStreams: Set<[UInt32]> = []
        var connections: [NWConnection] = []
        var nextConnection = 0
    }

    private let listener: NWListener
    private let state = Mutex(State())
    /// The server's static Noise key. Test-only and generated fresh for each run.
    private let serverKey = Curve25519.KeyAgreement.PrivateKey()

    init() throws {
        let parameters = NWParameters.tcp
        parameters.requiredLocalEndpoint = NWEndpoint.hostPort(host: "127.0.0.1", port: .any)
        listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [weak self] connection in
            guard let self else { connection.cancel(); return }
            let number = self.state.withLock { state in
                state.connections.append(connection)
                state.nextConnection += 1
                return state.nextConnection
            }
            connection.start(queue: .global())
            Task { await self.serve(connection, number: number) }
        }
    }

    // MARK: Test interface

    var keyRequests: Int { state.withLock { $0.keyRequests } }
    var requests: [Request] { state.withLock { $0.requests } }
    var setDNSRequests: [Request] { requests.filter { $0.path == "/machine/set-dns" } }
    var openMapStreams: Set<[UInt32]> { state.withLock { $0.openMapStreams } }

    func setAcceptsConnections(_ accepts: Bool) { state.withLock { $0.acceptsConnections = accepts } }
    func setSetDNSReply(_ reply: SetDNSReply) { state.withLock { $0.setDNSReply = reply } }
    func enqueueRegisterReply(_ body: String) { state.withLock { $0.registerReplies.append(Array(body.utf8)) } }
    func setRegisterNeverAnswers(_ never: Bool) { state.withLock { $0.registerNeverAnswers = never } }

    func start() async throws -> URL {
        let listener = listener
        let port = try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<UInt16, any Error>) in
            let once = Mutex<CheckedContinuation<UInt16, any Error>?>(continuation)
            listener.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    if let port = listener.port?.rawValue { once.withLock { $0.take() }?.resume(returning: port) }
                case .failed(let error):
                    once.withLock { $0.take() }?.resume(throwing: error)
                default:
                    break
                }
            }
            listener.start(queue: .global())
        }
        return try #require(URL(string: "http://127.0.0.1:\(port)"))
    }

    func close() {
        listener.cancel()
        for connection in state.withLock({ $0.connections }) { connection.cancel() }
    }

    /// Waits for `condition` to become true. Records a test failure and throws when the deadline expires.
    func wait(
        _ what: String, within duration: Duration = .seconds(20), until condition: (SetDNSFakeControlServer) -> Bool
    ) async throws {
        let deadline = ContinuousClock.now + duration
        while !condition(self) {
            guard ContinuousClock.now < deadline else {
                Issue.record("\(what) within \(duration)")
                throw CancellationError()
            }
            try await Task.sleep(for: .milliseconds(10))
        }
    }

    // MARK: Single connection

    private func serve(_ connection: NWConnection, number: Int) async {
        var received: [UInt8] = []
        guard let (head, remainder) = await readHead(connection, buffer: &received) else { return }
        let requestLine = head.first ?? ""
        if requestLine.hasPrefix("GET /key") {
            await answerKey(connection)
        } else if requestLine.hasPrefix("POST /ts2021 "), let session = upgrade(connection, head: head) {
            await serveHTTP2(connection, number: number, session: session, initial: remainder)
        } else {
            connection.cancel()
        }
    }

    private func answerKey(_ connection: NWConnection) async {
        let accepts = state.withLock { state in
            state.keyRequests += 1
            return state.acceptsConnections
        }
        let body = #"{"publicKey":"\#(MachinePublicKey(serverKey.publicKey))"}"#
        let response = accepts
            ? "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            : "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
    }

    /// Runs the Noise responder with the initiation from the upgrade header and sends 101 and response. Closes the connection on failure.
    private func upgrade(_ connection: NWConnection, head: [String]) -> ControlSession? {
        let prefix = "x-tailscale-handshake:"
        guard let line = head.first(where: { $0.lowercased().hasPrefix(prefix) }),
              let initiation = Data(base64Encoded: line.dropFirst(prefix.count).trimmingCharacters(in: .whitespaces)).map(Array.init),
              initiation.count == 5 + HandshakeInitiation.payloadSize,
              initiation[2] == NoiseMessageType.initiation
        else {
            connection.cancel()
            return nil
        }
        let version = UInt16(initiation[0]) << 8 | UInt16(initiation[1])
        let clientEphemeral = Array(initiation[5..<37])
        let encryptedMachineKey = Array(initiation[37..<85])
        let initiationTag = Array(initiation[85..<101])

        var symmetric = SymmetricState(protocolName: NoiseIK.protocolName)
        symmetric.mixHash(NoiseIK.prologue(protocolVersion: version))
        symmetric.mixHash(Array(serverKey.publicKey.rawRepresentation))
        symmetric.mixHash(clientEphemeral)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        guard let esKey = symmetric.mixDH(serverKey, clientEphemeral),
              let machineKey = symmetric.decryptAndHash(encryptedMachineKey, key: esKey),
              let ssKey = symmetric.mixDH(serverKey, machineKey),
              symmetric.decryptAndHash(initiationTag, key: ssKey) != nil
        else {
            connection.cancel()
            return nil
        }
        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        symmetric.mixHash(ephemeralPublic)
        guard symmetric.mixDH(ephemeral, clientEphemeral) != nil, let seKey = symmetric.mixDH(ephemeral, machineKey) else {
            connection.cancel()
            return nil
        }
        let responseTag = symmetric.encryptAndHash([], key: seKey)
        let (clientToServer, serverToClient) = symmetric.split()

        let upgradeHead = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n"
        let response = [NoiseMessageType.response] + UInt16(HandshakeResponse.payloadSize).bigEndianBytes + ephemeralPublic + responseTag
        connection.send(content: Data(Array(upgradeHead.utf8) + response), completion: .contentProcessed { _ in })
        return ControlSession(keys: TransportKeys(send: serverToClient, receive: clientToServer))
    }

    /// A stream collecting the headers and body of one request.
    private struct PendingRequest {
        var headers: [HeaderField]
        var body: [UInt8] = []
    }

    private func serveHTTP2(_ connection: NWConnection, number: Int, session established: ControlSession, initial bytes: [UInt8]) async {
        var session = established
        var frames = FrameBuffer()
        var decoder = HPACKDecoder()
        var pending: [UInt32: PendingRequest] = [:]
        var prefaceRemaining = HTTP2ClientConnection.preface.count

        func send(_ plaintext: [UInt8]) {
            guard let sealed = try? session.seal(plaintext) else { return }
            connection.send(content: Data(sealed), completion: .contentProcessed { _ in })
        }

        send(FrameEncoder.settings([]))
        var incoming = bytes
        while true {
            guard var plaintext = try? session.receive(incoming) else { break }
            if prefaceRemaining > 0 {
                let skipped = min(prefaceRemaining, plaintext.count)
                plaintext.removeFirst(skipped)
                prefaceRemaining -= skipped
            }
            frames.append(plaintext)
            do {
                while let frame = try frames.nextFrame() {
                    switch frame {
                    case .settings:
                        send(FrameEncoder.settingsAcknowledgement())
                    case let .ping(ack, data) where !ack:
                        send(FrameEncoder.pingAcknowledgement(data))
                    case let .headers(id, block, endStream, _):
                        pending[id.rawValue] = PendingRequest(headers: try decoder.decode(block))
                        if endStream, let request = pending.removeValue(forKey: id.rawValue) {
                            respond(to: request, stream: id, connection: number, send: send)
                        }
                    case let .data(id, payload, endStream, _):
                        pending[id.rawValue]?.body += payload
                        if endStream, let request = pending.removeValue(forKey: id.rawValue) {
                            respond(to: request, stream: id, connection: number, send: send)
                        }
                    case let .rstStream(id, _):
                        _ = state.withLock { $0.openMapStreams.remove([UInt32(number), id.rawValue]) }
                    default:
                        break
                    }
                }
                frames.discardConsumedBytes()
            } catch {
                break
            }
            guard let next = await receive(connection) else { break }
            incoming = next
        }
        state.withLock { state in
            state.openMapStreams = state.openMapStreams.filter { $0[0] != UInt32(number) }
        }
        connection.cancel()
    }

    private func respond(to pending: PendingRequest, stream: HTTP2StreamID, connection: Int, send: ([UInt8]) -> Void) {
        let field = { (name: String) in pending.headers.first { $0.name == name }?.value ?? "" }
        let request = Request(
            connection: connection, stream: stream.rawValue, method: field(":method"), path: field(":path"),
            headers: pending.headers.filter { !$0.name.hasPrefix(":") }, body: pending.body
        )
        let reply: SetDNSReply? = state.withLock { state in
            state.requests.append(request)
            switch request.path {
            case "/machine/register":
                if state.registerNeverAnswers { return .never }
                guard state.registerReplies.isEmpty else { return .respond(status: 200, body: state.registerReplies.removeFirst()) }
                return .respond(status: 200, body: Array(#"{"MachineAuthorized":true}"#.utf8))
            case "/machine/map":
                let streaming = (try? JSONSerialization.jsonObject(with: Data(request.body)) as? [String: Any])?["Stream"] as? Bool == true
                guard streaming else { return .respond(status: 200, body: []) }
                state.openMapStreams.insert([UInt32(connection), stream.rawValue])
                return nil
            case "/machine/set-dns":
                return state.setDNSReply
            default:
                return .respond(status: 404, body: [])
            }
        }
        let block = { (status: Int) in HPACKEncoder.encode([HeaderField(":status", "\(status)")]) }
        switch reply {
        case nil:
            // Map stream: Send headers only and leave it open.
            send(FrameEncoder.headers(stream, block: block(200), endStream: false, maximumPayloadLength: FrameBuffer.defaultMaximumPayloadLength))
        case .never?:
            break
        case let .respond(status, body)?:
            send(FrameEncoder.headers(stream, block: block(status), endStream: body.isEmpty, maximumPayloadLength: FrameBuffer.defaultMaximumPayloadLength))
            if !body.isEmpty { send(FrameEncoder.data(stream, body[...], endStream: true)) }
        }
    }

    // MARK: Sockets

    private func receive(_ connection: NWConnection) async -> [UInt8]? {
        await withCheckedContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 1 << 16) { data, _, _, _ in
                if let data, !data.isEmpty {
                    continuation.resume(returning: [UInt8](data))
                } else {
                    continuation.resume(returning: nil)
                }
            }
        }
    }

    /// Reads HTTP/1.1 headers through the blank line and splits them into lines. Also returns bytes already received after the headers.
    private func readHead(_ connection: NWConnection, buffer: inout [UInt8]) async -> ([String], [UInt8])? {
        let terminator = Array("\r\n\r\n".utf8)
        while true {
            if let range = buffer.firstRange(of: terminator) {
                let head = String(decoding: buffer[..<range.lowerBound], as: UTF8.self)
                return (head.components(separatedBy: "\r\n"), Array(buffer[range.upperBound...]))
            }
            guard buffer.count < 1 << 16, let next = await receive(connection) else {
                connection.cancel()
                return nil
            }
            buffer += next
        }
    }
}
