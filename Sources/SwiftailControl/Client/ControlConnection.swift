import CryptoKit
import Foundation
import Network
import SwiftailBase
import SwiftailHTTP2
import SwiftailIO

/// One connection to the control server: HTTP/1.1 upgrade → Noise → (early payload) → HTTP/2 over a socket.
///
/// Each layer assembles its own units in its state machine. `ControlSession` assembles TCP chunks into Noise records, and
/// `HTTP2ClientConnection` assembles record plaintext into frames after it passes through `EarlyPayloadParser`. Above that,
/// `MapResponseFramer` assembles map frames from the response body (`ControlClient`). This actor only moves bytes.
///
/// Multiplexes several requests (registration, state reporting, and the map stream) over one connection. Streams each response through an
/// `AsyncThrowingStream`. The read loop (`readLoop`) receives from the socket and dispatches to streams.
/// The lifetime matches the scope of `withConnection`. Leaving scope cancels the read loop and closes the socket.
///
/// `docs/protocol-notes/control-transport.md` 4.2, 4.4, 4.7, 6.3.
actor ControlConnection {
    /// A part flowing through the response stream.
    enum ResponsePart: Sendable {
        case head(status: Int, headers: [HeaderField])
        case data([UInt8])
    }

    typealias ResponseParts = AsyncThrowingStream<ResponsePart, any Error>

    /// The deadline from the upgrade to the Noise response. Go uses 5 seconds for dialing and 5 seconds for the handshake.
    static let handshakeTimeout = Duration.seconds(10)

    nonisolated let authority: String
    private let socket: NetworkSocket
    private var session: ControlSession
    private var earlyPayload: EarlyPayloadParser? = EarlyPayloadParser()
    private var http2 = HTTP2ClientConnection()
    private var streams: [HTTP2StreamID: ResponseParts.Continuation] = [:]
    private var failure: ControlError?

    private init(socket: NetworkSocket, session: ControlSession, authority: String) {
        self.socket = socket
        self.session = session
        self.authority = authority
    }

    /// Establishes a connection and calls `body`. Closes the connection when `body` returns or throws or the connection drops.
    /// If `interface` is present, connects only through that interface.
    /// If the connection drops, ends all pending response streams with `ControlError.connection`.
    static func withConnection<Result: Sendable>(
        to endpoint: ControlEndpoint,
        interface: NWInterface? = nil,
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey,
        _ body: @escaping @Sendable (ControlConnection) async throws -> Result
    ) async throws -> Result {
        let connection = try await withControlTimeout(handshakeTimeout) {
            try await open(endpoint, interface: interface, machineKey: machineKey, serverKey: serverKey)
        }
        defer { connection.close() }
        return try await withThrowingTaskGroup(of: Outcome<Result>.self) { group in
            defer { group.cancelAll() }
            group.addTask {
                do throws(ControlError) {
                    try await connection.readLoop()
                    return .readEnded(.connection("Connection ended"))
                } catch {
                    return .readEnded(error)
                }
            }
            group.addTask { .finished(try await body(connection)) }

            // Give `body` time to finish before throwing a disconnect error. If the server closes immediately after sending a response, the connection error could beat
            // the conclusion `body` would reach from the response already received (such as a registration rejection that retrying cannot help) and cause a retry.
            // Dropping the connection ends all pending response streams, so `body` will finish soon. Allow only a grace period so a `body` sleeping for reasons unrelated to the connection
            // cannot make this wait indefinitely.
            var readFailure: ControlError?
            while let outcome = try await group.next() {
                switch outcome {
                case .finished(let result):
                    return result
                case .readEnded(let error):
                    readFailure = error
                    group.addTask {
                        try await Task.sleep(for: bodyGracePeriod, clock: .continuous)
                        return .graceExpired
                    }
                case .graceExpired:
                    throw readFailure ?? ControlError.connection("Connection ended")
                }
            }
            throw readFailure ?? ControlError.connection("Connection ended")
        }
    }

    /// How long to give `body` to finish on its own after the connection drops.
    private static var bodyGracePeriod: Duration { .seconds(1) }

    private enum Outcome<Result: Sendable>: Sendable {
        case finished(Result)
        case readEnded(ControlError)
        case graceExpired
    }

    /// Establishes a connection and completes the upgrade and Noise handshake. Sends the HTTP/2 preface immediately,
    /// without waiting for the early payload, as in Go.
    private static func open(
        _ endpoint: ControlEndpoint,
        interface: NWInterface?,
        machineKey: Curve25519.KeyAgreement.PrivateKey,
        serverKey: MachinePublicKey
    ) async throws(ControlError) -> ControlConnection {
        let socket = try await NetworkSocket.connect(to: endpoint, interface: interface)
        do throws(ControlError) {
            var handshake = try transport { () throws(ControlTransportError) in
                try ControlHandshake(machineKey: machineKey, serverKey: serverKey)
            }
            socket.send(UpgradeRequest.bytes(host: endpoint.hostHeader, initiation: handshake.initiation))

            var upgrade = UpgradeResponseParser()
            var afterHead: [UInt8]?
            while afterHead == nil {
                guard let bytes = try await socket.receiveBytes() else {
                    throw .connection("Server closed the connection before the upgrade response")
                }
                afterHead = try transport { () throws(ControlTransportError) in try upgrade.receive(bytes) }
            }
            var pending = afterHead ?? []
            while true {
                let bytes = pending
                if let (session, remainder) = try transport({ () throws(ControlTransportError) in try handshake.receive(bytes) }) {
                    let connection = ControlConnection(socket: socket, session: session, authority: endpoint.authority)
                    try await connection.start(with: remainder)
                    return connection
                }
                // The server closes the connection without an error message on handshake failure (notes §4.4, item 3.6).
                guard let next = try await socket.receiveBytes() else {
                    throw .connection("Server closed the connection during the Noise handshake")
                }
                pending = next
            }
        } catch {
            socket.close()
            throw error
        }
    }

    private func start(with remainder: [UInt8]) throws(ControlError) {
        try flush()
        if !remainder.isEmpty { try process(sealed: remainder) }
    }

    /// Closes the connection. The read loop and pending response streams end with an error.
    nonisolated func close() {
        socket.close()
    }

    // MARK: Requests

    /// Starts a request and returns the response stream. The first part of the stream is `head`.
    /// If the receiver drops the stream, cancels that request with RST_STREAM on the next receive.
    func send(_ request: HTTP2ClientConnection.Request, body: [UInt8]?) throws(ControlError) -> ResponseParts {
        if let failure { throw failure }
        let id: HTTP2StreamID
        do {
            id = try http2.startRequest(request, body: body)
        } catch {
            throw .connection("Could not start the HTTP/2 request: \(error)")
        }
        let (stream, continuation) = ResponseParts.makeStream()
        streams[id] = continuation
        try flush()
        return stream
    }

    // MARK: Reading

    /// Receives from the socket and dispatches to each response stream. On connection end, finishes all streams with that error and throws it.
    private func readLoop() async throws(ControlError) {
        do throws(ControlError) {
            while true {
                guard let bytes = try await socket.receiveBytes() else {
                    throw .connection("Server closed the connection")
                }
                try process(sealed: bytes)
            }
        } catch {
            fail(error)
            throw error
        }
    }

    private func process(sealed bytes: [UInt8]) throws(ControlError) {
        var plaintext = try transport { () throws(ControlTransportError) in try session.receive(bytes) }
        if var parser = earlyPayload {
            let input = plaintext
            guard let (_, remainder) = try transport({ () throws(ControlTransportError) in try parser.receive(input) }) else {
                earlyPayload = parser
                return
            }
            // M2 uses no nodeKeyChallenge. Only strips it from the stream.
            earlyPayload = nil
            plaintext = remainder
        }
        guard !plaintext.isEmpty else { return }

        let events: [HTTP2ClientConnection.Event]
        do {
            events = try http2.receive(plaintext)
        } catch {
            try? flush()   // Send any pending GOAWAY.
            throw .connection("HTTP/2 connection error: \(error)")
        }
        for event in events {
            dispatch(event)
        }
        try flush()
    }

    private func dispatch(_ event: HTTP2ClientConnection.Event) {
        switch event {
        case let .responseHead(id, status, headers):
            deliver(.head(status: status, headers: headers), to: id)
        case let .responseData(id, bytes):
            deliver(.data(bytes), to: id)
        case let .streamClosed(id, resetCode):
            if let resetCode {
                streams.removeValue(forKey: id)?.finish(throwing: ControlError.connection("Server reset the stream (RST_STREAM \(resetCode))"))
            } else {
                streams.removeValue(forKey: id)?.finish()
            }
        case let .goAway(lastStreamID, code):
            for id in streams.keys where id.rawValue > lastStreamID.rawValue {
                streams.removeValue(forKey: id)?.finish(throwing: ControlError.connection("Server rejected the request with GOAWAY (\(code))"))
            }
        }
    }

    private func deliver(_ part: ResponsePart, to id: HTTP2StreamID) {
        guard let continuation = streams[id] else { return }
        if case .terminated = continuation.yield(part) {
            // The receiver is gone. Cancel the stream to stop the server sending more.
            streams[id] = nil
            http2.cancel(id)
        }
    }

    /// Seals outbound HTTP/2 bytes into records and sends them.
    private func flush() throws(ControlError) {
        let outbound = http2.takeOutboundBytes()
        guard !outbound.isEmpty else { return }
        let sealed = try transport { () throws(ControlTransportError) in try session.seal(outbound) }
        socket.send(sealed)
    }

    private func fail(_ error: ControlError) {
        failure = failure ?? error
        for continuation in streams.values {
            continuation.finish(throwing: error)
        }
        streams = [:]
        socket.close()
    }
}

/// Maps a transport state machine error to a connection error. Exposes upgrade rejection as an HTTP status.
private func transport<T>(_ operation: () throws(ControlTransportError) -> T) throws(ControlError) -> T {
    do {
        return try operation()
    } catch .upgradeRejected(let status) {
        throw .http(status: status)
    } catch {
        throw .connection("Control transport error: \(error)")
    }
}
