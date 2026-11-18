import Foundation
import SwiftailBase
import SwiftailHTTP2

/// Two exchanges over the connection: sending one request and receiving the whole response, or streaming the response body.
/// Registration, state reporting, and the map stream use these exchange methods.
///
/// For the JSON exchange helpers, a request body uses `Content-Type: application/json`. When the node key is nonzero, these helpers add the load-balancing hint
/// `Ts-Lb: nodekey:…`. The response body is untrusted server input. Stop reading and discard the stream
/// if the limit is exceeded.
///
/// `docs/protocol-notes/control-transport.md` §4.7, items 3~5.
extension ControlConnection {
    /// A fully received response.
    struct Response: Sendable {
        var status: Int
        var headers: [HeaderField]
        var body: [UInt8]
    }

    /// A request carrying a JSON body.
    nonisolated func jsonRequest(_ method: String, path: String, nodeKey: NodePublicKey?) -> HTTP2ClientConnection.Request {
        var headers = [HeaderField("content-type", "application/json")]
        if let nodeKey, !nodeKey.isZero {
            headers.append(HeaderField("ts-lb", nodeKey.description))
        }
        return HTTP2ClientConnection.Request(method: method, path: path, authority: authority, headers: headers)
    }

    /// Sends a request and receives the entire response, including its body. Fails if the body exceeds `limit` bytes.
    nonisolated func response(
        to request: HTTP2ClientConnection.Request,
        body: [UInt8]?,
        limit: Int
    ) async throws(ControlError) -> Response {
        var reader = try await responseStream(to: request, body: body)
        var collected: [UInt8] = []
        while let chunk = try await reader.nextChunk() {
            guard collected.count + chunk.count <= limit else {
                throw .connection("Response body exceeds the limit of \(limit) bytes")
            }
            collected += chunk
        }
        return Response(status: reader.status, headers: reader.headers, body: collected)
    }

    /// Sends a request and waits for the response head. The returned reader streams the body.
    nonisolated func responseStream(
        to request: HTTP2ClientConnection.Request,
        body: [UInt8]?
    ) async throws(ControlError) -> ResponseReader {
        var iterator = try await send(request, body: body).makeAsyncIterator()
        guard case let .head(status, headers) = try await ResponseReader.next(&iterator) else {
            throw .connection("Stream ended without a response head")
        }
        return ResponseReader(status: status, headers: headers, iterator: iterator)
    }
}

/// Reads chunks of a response body after receiving its head. Chunk boundaries are HTTP/2 DATA boundaries and carry no meaning.
struct ResponseReader {
    let status: Int
    let headers: [HeaderField]
    fileprivate var iterator: ControlConnection.ResponseParts.AsyncIterator

    fileprivate init(status: Int, headers: [HeaderField], iterator: ControlConnection.ResponseParts.AsyncIterator) {
        self.status = status
        self.headers = headers
        self.iterator = iterator
    }

    /// The first value for the lowercase header name.
    func header(_ name: String) -> String? {
        headers.first { $0.name == name }?.value
    }

    /// The next body chunk, or nil at the end of the body.
    mutating func nextChunk() async throws(ControlError) -> [UInt8]? {
        switch try await Self.next(&iterator) {
        case .data(let bytes): bytes
        case .head: throw .connection("Received the response head twice")
        case nil: nil
        }
    }

    fileprivate static func next(
        _ iterator: inout ControlConnection.ResponseParts.AsyncIterator
    ) async throws(ControlError) -> ControlConnection.ResponsePart? {
        let part: ControlConnection.ResponsePart?
        do {
            part = try await iterator.next()
        } catch {
            throw error as? ControlError ?? .connection("Could not read the response")
        }
        // Canceling the waiting Task ends the stream without an error. Distinguish that from a normal end (END_STREAM) so a truncated body
        // is never accepted as a complete response.
        if part == nil, Task.isCancelled { throw .connection("Canceled") }
        return part
    }
}
