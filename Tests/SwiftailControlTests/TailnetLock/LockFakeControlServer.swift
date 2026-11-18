// Fake control server for tailnet lock tests. Simulates `GET /key`, the `POST /ts2021` upgrade, a Noise IK responder, and a minimal
// HTTP/2 server over loopback TCP (same structure as `SetDNSFakeControlServer`). Adds two features.
//
// - Sends test-defined responses on the map stream: the first response when the stream opens and responses pushed onto the open stream.
// - Answers the three TKA RPCs. The server uses a real `Authority` for its authority state, so the sync response (`MissingAUMs`) is actually computed.
//   Each path can have a fixed response (`faults`) or a held response (`hold` and `release`). State uploads can be held too.
//
// Does not update flow-control windows (the client does not enforce the receive window).

import CryptoKit
import Foundation
import Network
import Synchronization
import Testing

import SwiftailBase
@testable import SwiftailControl
@testable import SwiftailHTTP2
import SwiftailTKA

final class LockFakeControlServer: Sendable {
    static let bootstrapPath = "/machine/tka/bootstrap"
    static let syncOfferPath = "/machine/tka/sync/offer"
    static let syncSendPath = "/machine/tka/sync/send"
    /// The paths for state uploads and the map stream. Setting `hold` in `faults` holds only state uploads (non-streaming requests).
    static let mapPath = "/machine/map"

    /// A single HTTP/2 request received by the server.
    struct Request: Sendable {
        var connection: Int
        var method: String
        var path: String
        var headers: [HeaderField]
        var body: [UInt8]

        func header(_ name: String) -> String? { headers.first { $0.name == name }?.value }
        /// The body's JSON object. Empty if the body is not an object.
        var object: [String: Any] { (try? JSONSerialization.jsonObject(with: Data(body))) as? [String: Any] ?? [:] }
    }

    enum Reply: Sendable {
        case respond(status: Int, body: [UInt8])
        /// Holds the request without responding. `release(_:)` responds with the server state at that time.
        case hold

        static func json(_ text: String) -> Reply { .respond(status: 200, body: Array(text.utf8)) }
    }

    /// Server-side tailnet lock.
    struct Lock: Sendable {
        /// The server's authority state. nil means tailnet lock is disabled.
        var authority: Authority?
        /// The disablement secret returned by bootstrap after lock is disabled.
        var disablementSecret: [UInt8] = []
        /// Path → fixed response. If present, send it instead of a response based on server state.
        var faults: [String: Reply] = [:]
    }

    /// The send side of a single connection. Request handling and test pushes share it, so sealing and sending use one lock
    /// (record nonce order must match send order).
    private final class Link: Sendable {
        let connection: NWConnection
        private let session: Mutex<ControlSession>

        init(connection: NWConnection, session: ControlSession) {
            self.connection = connection
            self.session = Mutex(session)
        }

        func send(_ plaintext: [UInt8]) {
            session.withLock { session in
                guard let sealed = try? session.seal(plaintext) else { return }
                connection.send(content: Data(sealed), completion: .contentProcessed { _ in })
            }
        }

        func open(_ bytes: [UInt8]) -> [UInt8]? {
            session.withLock { try? $0.receive(bytes) }
        }
    }

    private struct State {
        var lock = Lock()
        var requests: [Request] = []
        /// The first response (JSON) on a new map stream. If nil, sends only headers and leaves the stream open.
        var mapResponse: String?
        var mapStreams: [(link: Link, stream: HTTP2StreamID)] = []
        var held: [(request: Request, link: Link, stream: HTTP2StreamID)] = []
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

    var requests: [Request] { state.withLock { $0.requests } }
    func requests(to path: String) -> [Request] { requests.filter { $0.path == path } }
    /// TKA RPC paths in receipt order.
    var tkaPaths: [String] { requests.map(\.path).filter { $0.hasPrefix("/machine/tka/") } }
    var lock: Lock { state.withLock { $0.lock } }
    var openMapStreamCount: Int { state.withLock { $0.mapStreams.count } }

    func updateLock(_ body: (inout Lock) -> Void) { state.withLock { body(&$0.lock) } }
    func setMapResponse(_ json: String?) { state.withLock { $0.mapResponse = json } }

    /// Pushes one response onto an open map stream.
    func push(_ json: String) {
        let payload = frame(json)
        for (link, stream) in state.withLock({ $0.mapStreams }) {
            link.send(FrameEncoder.data(stream, payload[...], endStream: false))
        }
    }

    /// Answers the held request for `path` with the current server state. Also clears any fixed response for that path.
    func release(_ path: String) {
        let answers = state.withLock { state in
            state.lock.faults[path] = nil
            let matching = state.held.filter { $0.request.path == path }
            state.held.removeAll { $0.request.path == path }
            return matching.map { ($0.link, $0.stream, Self.tkaReply(to: $0.request, lock: &state.lock)) }
        }
        for (link, stream, reply) in answers {
            Self.send(reply, on: stream, over: link)
        }
    }

    /// Drops all connections. The client backs off and reconnects.
    func dropConnections() {
        let connections = state.withLock { state in
            state.mapStreams = []
            state.held = []
            defer { state.connections = [] }
            return state.connections
        }
        for connection in connections { connection.cancel() }
    }

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
        dropConnections()
    }

    // MARK: TKA RPC responses

    /// The response computed from server state. A fixed response takes precedence when set.
    private static func tkaReply(to request: Request, lock: inout Lock) -> Reply {
        if let fault = lock.faults[request.path] { return fault }
        let object = request.object
        let base64 = { (bytes: [UInt8]) in Data(bytes).base64EncodedString() }
        switch request.path {
        case mapPath:
            // Reached only when releasing a held state upload.
            return .respond(status: 200, body: [])
        case bootstrapPath:
            guard let authority = lock.authority, let checkpoint = authority.aums.first else {
                return .json(#"{"DisablementSecret":"\#(base64(lock.disablementSecret))"}"#)
            }
            return .json(#"{"GenesisAUM":"\#(base64(checkpoint.serialized()))"}"#)
        case syncOfferPath:
            guard let authority = lock.authority, let head = (object["Head"] as? String).flatMap(AUMHash.init(text:)) else {
                return .respond(status: 500, body: [])
            }
            let ancestors = (object["Ancestors"] as? [String] ?? []).compactMap(AUMHash.init(text:))
            let missing = (try? authority.missingAUMs(for: SyncOffer(head: head, ancestors: ancestors))) ?? []
            let offer = authority.syncOffer()
            let texts = { (values: [String]) in values.map { #""\#($0)""# }.joined(separator: ",") }
            return .json("""
                {"Head":"\(offer.head.text)","Ancestors":[\(texts(offer.ancestors.map(\.text)))],\
                "MissingAUMs":[\(texts(missing.map { base64($0.serialized()) }))]}
                """)
        case syncSendPath:
            guard var authority = lock.authority else { return .respond(status: 500, body: []) }
            let updates = (object["MissingAUMs"] as? [String] ?? [])
                .compactMap { Data(base64Encoded: $0) }.compactMap { try? AUM(decoding: [UInt8]($0)) }
            if !updates.isEmpty, (try? authority.inform(updates)) != nil { lock.authority = authority }
            return .json(#"{"Head":"\#(authority.head.text)"}"#)
        default:
            return .respond(status: 404, body: [])
        }
    }

    private static func send(_ reply: Reply, on stream: HTTP2StreamID, over link: Link) {
        guard case let .respond(status, body) = reply else { return }
        sendHead(status, on: stream, over: link, endStream: body.isEmpty)
        var offset = 0
        while offset < body.count {
            let end = min(offset + FrameBuffer.defaultMaximumPayloadLength, body.count)
            link.send(FrameEncoder.data(stream, body[offset..<end], endStream: end == body.count))
            offset = end
        }
    }

    private static func sendHead(_ status: Int, on stream: HTTP2StreamID, over link: Link, endStream: Bool) {
        link.send(FrameEncoder.headers(
            stream, block: HPACKEncoder.encode([HeaderField(":status", "\(status)")]), endStream: endStream,
            maximumPayloadLength: FrameBuffer.defaultMaximumPayloadLength
        ))
    }

    // MARK: Single connection

    private func serve(_ connection: NWConnection, number: Int) async {
        var received: [UInt8] = []
        guard let (head, remainder) = await readHead(connection, buffer: &received) else { return }
        let requestLine = head.first ?? ""
        if requestLine.hasPrefix("GET /key") {
            let body = #"{"publicKey":"\#(MachinePublicKey(serverKey.publicKey))"}"#
            let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            connection.send(content: Data(response.utf8), completion: .contentProcessed { _ in connection.cancel() })
        } else if requestLine.hasPrefix("POST /ts2021 "), let session = upgrade(connection, head: head) {
            await serveHTTP2(Link(connection: connection, session: session), number: number, initial: remainder)
        } else {
            connection.cancel()
        }
    }

    /// Runs the Noise responder with the initiation from the upgrade header and sends 101 and response. Closes the connection on failure.
    /// `<- s ... -> e, es, s, ss <- e, ee, se`(`docs/protocol-notes/control-transport.md` 4.5).
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

        var symmetric = SymmetricState(protocolName: NoiseIK.protocolName)
        symmetric.mixHash(NoiseIK.prologue(protocolVersion: version))
        symmetric.mixHash(Array(serverKey.publicKey.rawRepresentation))
        symmetric.mixHash(clientEphemeral)
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        guard let esKey = symmetric.mixDH(serverKey, clientEphemeral),
              let machineKey = symmetric.decryptAndHash(Array(initiation[37..<85]), key: esKey),
              let ssKey = symmetric.mixDH(serverKey, machineKey),
              symmetric.decryptAndHash(Array(initiation[85..<101]), key: ssKey) != nil
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

    private func serveHTTP2(_ link: Link, number: Int, initial bytes: [UInt8]) async {
        var frames = FrameBuffer()
        var decoder = HPACKDecoder()
        var pending: [UInt32: (headers: [HeaderField], body: [UInt8])] = [:]
        var prefaceRemaining = HTTP2ClientConnection.preface.count

        link.send(FrameEncoder.settings([]))
        var incoming = bytes
        while true {
            guard var plaintext = link.open(incoming) else { break }
            if prefaceRemaining > 0 {
                let skipped = min(prefaceRemaining, plaintext.count)
                plaintext.removeFirst(skipped)
                prefaceRemaining -= skipped
            }
            frames.append(plaintext)
            do {
                while let frame = try frames.nextFrame() {
                    var finished: HTTP2StreamID?
                    switch frame {
                    case .settings:
                        link.send(FrameEncoder.settingsAcknowledgement())
                    case let .ping(ack, data) where !ack:
                        link.send(FrameEncoder.pingAcknowledgement(data))
                    case let .headers(id, block, endStream, _):
                        pending[id.rawValue] = (try decoder.decode(block), [])
                        if endStream { finished = id }
                    case let .data(id, payload, endStream, _):
                        pending[id.rawValue]?.body += payload
                        if endStream { finished = id }
                    case let .rstStream(id, _):
                        state.withLock { $0.mapStreams.removeAll { $0.link === link && $0.stream == id } }
                    default:
                        break
                    }
                    if let finished, let request = pending.removeValue(forKey: finished.rawValue) {
                        respond(to: request, stream: finished, connection: number, link: link)
                    }
                }
                frames.discardConsumedBytes()
            } catch {
                break
            }
            guard let next = await receive(link.connection) else { break }
            incoming = next
        }
        state.withLock { state in
            state.mapStreams.removeAll { $0.link === link }
            state.held.removeAll { $0.link === link }
        }
        link.connection.cancel()
    }

    private func respond(to pending: (headers: [HeaderField], body: [UInt8]), stream: HTTP2StreamID, connection: Int, link: Link) {
        let field = { (name: String) in pending.headers.first { $0.name == name }?.value ?? "" }
        let request = Request(
            connection: connection, method: field(":method"), path: field(":path"),
            headers: pending.headers.filter { !$0.name.hasPrefix(":") }, body: pending.body
        )
        // Choose and send the response under the same lock so `push` cannot intervene
        // between registering the map stream and sending the first response, which would reverse their order.
        state.withLock { state in
            state.requests.append(request)
            switch request.path {
            case "/machine/register":
                Self.send(.json(#"{"MachineAuthorized":true}"#), on: stream, over: link)
            case "/machine/map":
                guard request.object["Stream"] as? Bool == true else {
                    // State upload. Hold it if the fixed response (`hold`) is set.
                    if case .hold = state.lock.faults[request.path] {
                        state.held.append((request, link, stream))
                    } else {
                        Self.sendHead(200, on: stream, over: link, endStream: true)
                    }
                    return
                }
                Self.sendHead(200, on: stream, over: link, endStream: false)
                if let first = state.mapResponse {
                    link.send(FrameEncoder.data(stream, frame(first)[...], endStream: false))
                }
                state.mapStreams.append((link, stream))
            default:
                let reply = Self.tkaReply(to: request, lock: &state.lock)
                if case .hold = reply {
                    state.held.append((request, link, stream))
                } else {
                    Self.send(reply, on: stream, over: link)
                }
            }
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
