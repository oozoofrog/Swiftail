// tailnet lock 시험용 가짜 제어 서버: 루프백 TCP 위에서 `GET /key`, `POST /ts2021` 업그레이드, Noise IK 응답자, 최소
// HTTP/2 서버를 흉내 낸다(`SetDNSFakeControlServer`와 같은 뼈대). 더한 것은 둘이다.
//
// - 맵 스트림에 시험이 정한 응답을 보낸다: 스트림이 열릴 때의 첫 응답과, 열린 스트림에 밀어 넣는 응답.
// - TKA RPC 셋에 답한다. 서버 쪽 서명 권한 상태는 실제 `Authority`라서 동기화의 답(`MissingAUMs`)이 진짜 계산이다.
//   경로마다 고정 답을 걸거나(`faults`) 답을 붙들어 둘 수 있다(`hold`·`release`).
//
// 흐름 제어 창은 갱신하지 않는다(클라이언트는 받는 창을 강제하지 않는다).

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

    /// 서버가 받은 HTTP/2 요청 하나.
    struct Request: Sendable {
        var connection: Int
        var method: String
        var path: String
        var headers: [HeaderField]
        var body: [UInt8]

        func header(_ name: String) -> String? { headers.first { $0.name == name }?.value }
        /// 본문의 JSON 객체. 객체가 아니면 비어 있다.
        var object: [String: Any] { (try? JSONSerialization.jsonObject(with: Data(body))) as? [String: Any] ?? [:] }
    }

    enum Reply: Sendable {
        case respond(status: Int, body: [UInt8])
        /// 답하지 않고 붙들어 둔다. `release(_:)`가 그때의 서버 상태로 답한다.
        case hold

        static func json(_ text: String) -> Reply { .respond(status: 200, body: Array(text.utf8)) }
    }

    /// 서버 쪽 tailnet lock.
    struct Lock: Sendable {
        /// 서버의 서명 권한 상태. nil이면 lock이 꺼진 tailnet이다.
        var authority: Authority?
        /// lock이 꺼진 뒤 bootstrap이 주는 끄기 비밀.
        var disablementSecret: [UInt8] = []
        /// 경로 → 고정 답. 있으면 서버 상태 대신 이것으로 답한다.
        var faults: [String: Reply] = [:]
    }

    /// 연결 하나의 보내는 쪽. 요청을 처리하는 흐름과 시험이 밀어 넣는 흐름이 함께 쓰므로 봉인과 송신을 한 잠금 안에서 한다
    /// (레코드의 nonce 순서가 송신 순서와 같아야 한다).
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
        /// 새 맵 스트림의 첫 응답(JSON). nil이면 머리만 보내고 열어 둔다.
        var mapResponse: String?
        var mapStreams: [(link: Link, stream: HTTP2StreamID)] = []
        var held: [(request: Request, link: Link, stream: HTTP2StreamID)] = []
        var connections: [NWConnection] = []
        var nextConnection = 0
    }

    private let listener: NWListener
    private let state = Mutex(State())
    /// 서버의 Noise 정적 키. 시험 전용이고 실행마다 새로 만든다.
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

    // MARK: 시험이 쓰는 것

    var requests: [Request] { state.withLock { $0.requests } }
    func requests(to path: String) -> [Request] { requests.filter { $0.path == path } }
    /// TKA RPC의 경로들. 받은 순서다.
    var tkaPaths: [String] { requests.map(\.path).filter { $0.hasPrefix("/machine/tka/") } }
    var lock: Lock { state.withLock { $0.lock } }
    var openMapStreamCount: Int { state.withLock { $0.mapStreams.count } }

    func updateLock(_ body: (inout Lock) -> Void) { state.withLock { body(&$0.lock) } }
    func setMapResponse(_ json: String?) { state.withLock { $0.mapResponse = json } }

    /// 열려 있는 맵 스트림에 응답 하나를 밀어 넣는다.
    func push(_ json: String) {
        let payload = frame(json)
        for (link, stream) in state.withLock({ $0.mapStreams }) {
            link.send(FrameEncoder.data(stream, payload[...], endStream: false))
        }
    }

    /// 붙들어 둔 `path`의 요청에 지금의 서버 상태로 답한다. 그 경로의 고정 답도 지운다.
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

    /// 모든 연결을 끊는다. 클라이언트는 물러났다가 다시 잇는다.
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

    // MARK: TKA RPC의 답

    /// 서버 상태로 계산한 답. 고정 답이 걸려 있으면 그것이다.
    private static func tkaReply(to request: Request, lock: inout Lock) -> Reply {
        if let fault = lock.faults[request.path] { return fault }
        let object = request.object
        let base64 = { (bytes: [UInt8]) in Data(bytes).base64EncodedString() }
        switch request.path {
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

    // MARK: 연결 하나

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

    /// 업그레이드 머리의 initiation으로 Noise 응답자를 돌리고 101과 response를 보낸다. 실패하면 연결을 끊는다.
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
        // 답은 잠금 안에서 정하고 보내기도 그 안에서 한다: 맵 스트림을 등록하는 것과 첫 응답을 보내는 것 사이에 `push`가
        // 끼어들어 순서가 뒤바뀌지 않게 한다.
        state.withLock { state in
            state.requests.append(request)
            switch request.path {
            case "/machine/register":
                Self.send(.json(#"{"MachineAuthorized":true}"#), on: stream, over: link)
            case "/machine/map":
                guard request.object["Stream"] as? Bool == true else {
                    Self.sendHead(200, on: stream, over: link, endStream: true)
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

    // MARK: 소켓

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

    /// HTTP/1.1 머리(빈 줄까지)를 읽어 줄로 나눈다. 머리 뒤에 이미 온 바이트도 돌려준다.
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
