# SwiftailHTTP2 Contract (M2)

Implement an HTTP/2 **client connection** as an I/O-free state machine with the functionality needed to communicate with the control server. Multiplex a few streams (registration request, map stream, status update) on one connection. It is not a general-purpose HTTP client.

Specifications are RFC 9113 (HTTP/2) and RFC 7541 (HPACK). See [protocol-notes/control-transport.md](../protocol-notes/control-transport.md) §6.3 for what the peer sends, as verified against the Go server's actual behavior.

This module has no knowledge of Tailscale. The underlying byte stream can be TLS or the control protocol's Noise records.

## Public API

```swift
public struct HeaderField: Sendable, Equatable {
    public var name: String      // Lowercase
    public var value: String
    public init(_ name: String, _ value: String)
}

public struct HTTP2StreamID: Hashable, Sendable {
    public let rawValue: UInt32
}

public enum HTTP2Error: Error, Sendable, Equatable {
    /// The peer violated the specification, and the connection has ended. The code is an error code from RFC 9113 §7.
    /// Report received GOAWAY as a `goAway` event without throwing, even when it carries an error code. This preserves events collected in the same call.
    case connectionFailed(code: UInt32)
    /// The connection has ended or received GOAWAY, so new requests cannot start.
    case connectionClosed
    /// The request exceeds the concurrent stream count allowed by the peer.
    case tooManyStreams
    /// The request is invalid (for example, an empty method or path or an uppercase header name).
    case invalidRequest
}

/// A single HTTP/2 client connection.
public struct HTTP2ClientConnection: Sendable {
    public struct Request: Sendable {
        public var method: String
        public var path: String
        public var authority: String
        public var headers: [HeaderField]      // Headers other than pseudo-headers
        public init(method: String, path: String, authority: String, headers: [HeaderField] = [])
    }

    public enum Event: Sendable, Equatable {
        case responseHead(HTTP2StreamID, status: Int, headers: [HeaderField])
        case responseData(HTTP2StreamID, [UInt8])
        /// The stream has ended. A nil resetCode means a normal end (END_STREAM). Otherwise, it is the RST_STREAM error code.
        case streamClosed(HTTP2StreamID, resetCode: UInt32?)
        /// The peer sent GOAWAY. Streams with IDs greater than lastStreamID were not processed.
        case goAway(lastStreamID: HTTP2StreamID, code: UInt32)
    }

    /// Starts the connection. The preface and SETTINGS are ready to send.
    public init()

    /// Starts a request. The `:scheme` is always https. If body is nil, the request ends with HEADERS.
    /// Sends the body in chunks as the flow-control windows allow.
    public mutating func startRequest(_ request: Request, body: [UInt8]?) throws(HTTP2Error) -> HTTP2StreamID

    /// Cancels the stream (RST_STREAM CANCEL). Does nothing if the stream has already ended.
    /// The stream emits no further events, including `streamClosed`. The caller handles cleanup.
    public mutating func cancel(_ stream: HTTP2StreamID)

    /// Feeds bytes received from the peer. Chunks can be split at arbitrary positions, regardless of frame boundaries.
    /// A thrown error means the connection has ended. A GOAWAY may still be available from `takeOutboundBytes()`.
    public mutating func receive(_ bytes: [UInt8]) throws(HTTP2Error) -> [Event]

    /// Takes the bytes to send to the peer, or an empty array if none are available. Call after `init`, `startRequest`, `cancel`, and `receive`.
    public mutating func takeOutboundBytes() -> [UInt8]
}
```

## Scope of Behavior

Supported behavior includes the following.

- Preface, SETTINGS exchange and ACK, and ignoring unknown SETTINGS and frame types
- HEADERS + CONTINUATION, DATA, RST_STREAM, PING (reply with ACK), GOAWAY, and WINDOW_UPDATE. Read and discard PRIORITY. PUSH_PROMISE is a connection error (the client advertises ENABLE_PUSH=0)
- HPACK decompression, including static and dynamic tables, all representation formats, table size updates, and Huffman strings
- HPACK compression using only literals without indexing and without Huffman encoding (the simplest valid option)
- Flow control. The sender respects the connection and stream windows and applies changes from WINDOW_UPDATE and SETTINGS_INITIAL_WINDOW_SIZE. The receiver restores the window by the amount of DATA received. Emit WINDOW_UPDATE through `takeOutboundBytes()` instead of once per frame, with one for the connection and one per stream, so replies do not accumulate even with many small DATA frames
- Frame splitting based on the peer's MAX_FRAME_SIZE and compliance with MAX_CONCURRENT_STREAMS

Limits for untrusted input are 16,384 bytes per incoming frame (the advertised MAX_FRAME_SIZE), 64KiB per complete header block, 4,096 bytes for the HPACK dynamic table, and 64KiB of pending bytes for control frames prompted by the peer (PING ACK, SETTINGS ACK, RST_STREAM), drained by `takeOutboundBytes()`. Exceeding a limit is a connection error (ENHANCE_YOUR_CALM for the last limit, with GOAWAY appended regardless of the limit). No byte sequence can crash the process.

Response validation failures produce RST_STREAM PROTOCOL_ERROR and `streamClosed` for the affected stream only (RFC 9113 §8.1.1, §8.2, §8.3, §8.6). Header names must be nonempty lowercase tokens and cannot contain an interior `:`, spaces, or uppercase letters. Values cannot contain NUL, CR, or LF. Connection-specific fields are forbidden (`connection`, `keep-alive`, `proxy-connection`, `transfer-encoding`, `upgrade`, and `te` with a value other than `trailers`). Apply the same rules to request headers (`invalidRequest`) and trailers, and forbid pseudo-headers in trailers. A `content-length` field must occur only once and contain a decimal integer equal to the number of DATA bytes received (skip the comparison for HEAD responses, 204, and 304 because they have no body). Treat 101 as an error rather than forwarding it as an informational response.

Apply SETTINGS_INITIAL_WINDOW_SIZE to open stream windows in received order, even within one frame, and check for overflow (above 2^31-1) after each change. Intermediate overflow is a FLOW_CONTROL_ERROR connection error.

Record the following exclusions in `shortcut:` comments.

- Receive-side backpressure. The client restores the window as soon as it receives data, so slow consumption cannot slow the server. This becomes necessary when large responses must be consumed as a stream
- Incremental request body supply, outgoing trailers, server push, priorities, and reuse of the compression table when sending
- Idle PING and timeouts. The connection owner (actor) keeps the clock and decides

## Tests

Unit tests (`Tests/SwiftailHTTP2Tests`) cover the following.

1. HPACK. All examples from RFC 7541 Appendix C (C.1 integers, C.2 header representations, C.3 and C.4 requests, C.5 and C.6 responses, including Huffman encoding and dynamic table eviction).
2. Frames. Parsing each type, producing the same events when fed one byte at a time, combining CONTINUATION frames, and handling padding.
3. Flow control. A body larger than the window waits for WINDOW_UPDATE. SETTINGS_INITIAL_WINDOW_SIZE changes the windows of open streams. The client sends WINDOW_UPDATE for the amount of DATA received.
4. Lifecycle. SETTINGS ACK, PING replies, rejection of new requests after GOAWAY, RST_STREAM, and increasing odd stream IDs.
5. Limits and arbitrary input. Input that exceeds a limit causes a connection error, and random bytes do not cause a crash.

Interop tests against the Go HTTP/2 server in `Tools/interop` over TCP loopback cover a small GET, a POST round trip with a large body (bidirectional flow control), a response stream that never ends running concurrently with another request, and PING and GOAWAY from the server.
