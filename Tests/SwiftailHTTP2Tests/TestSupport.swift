// Shared test helpers for converting base-16 values, building frames for the server to send, and parsing the connection's output back into frames.

import Testing

@testable import SwiftailHTTP2

/// Converts a base-16 string into bytes, ignoring whitespace so RFC dumps can be pasted verbatim.
func hex(_ string: String) -> [UInt8] {
    let digits = string.filter { !$0.isWhitespace }
    var bytes: [UInt8] = []
    var index = digits.startIndex
    while index < digits.endIndex {
        let next = digits.index(index, offsetBy: 2)
        bytes.append(UInt8(digits[index..<next], radix: 16) ?? 0)
        index = next
    }
    return bytes
}

/// The bytes of a single frame. Used by tests acting as the server (peer).
func frameBytes(_ type: UInt8, flags: UInt8 = 0, stream: UInt32 = 0, payload: [UInt8] = []) -> [UInt8] {
    let length = payload.count
    return [UInt8(length >> 16 & 0xff), UInt8(length >> 8 & 0xff), UInt8(length & 0xff), type, flags] + stream.bigEndianBytes + payload
}

func settingsBytes(_ settings: [(UInt16, UInt32)] = []) -> [UInt8] {
    frameBytes(4, payload: settings.flatMap { [UInt8($0.0 >> 8), UInt8($0.0 & 0xff)] + $0.1.bigEndianBytes })
}

func windowUpdateBytes(stream: UInt32, increment: UInt32) -> [UInt8] {
    frameBytes(8, stream: stream, payload: increment.bigEndianBytes)
}

func rstStreamBytes(stream: UInt32, code: UInt32) -> [UInt8] {
    frameBytes(3, stream: stream, payload: code.bigEndianBytes)
}

func goAwayBytes(lastStream: UInt32, code: UInt32) -> [UInt8] {
    frameBytes(7, payload: lastStream.bigEndianBytes + code.bigEndianBytes)
}

/// The server's response HEADERS frame. This module's encoder creates the header block.
func responseHeadBytes(stream: UInt32, status: String = "200", headers: [HeaderField] = [], endStream: Bool = false) -> [UInt8] {
    let block = HPACKEncoder.encode([HeaderField(":status", status)] + headers)
    return frameBytes(1, flags: 0x4 | (endStream ? 0x1 : 0), stream: stream, payload: block)
}

func dataBytes(stream: UInt32, _ payload: [UInt8], endStream: Bool = false) -> [UInt8] {
    frameBytes(0, flags: endStream ? 0x1 : 0, stream: stream, payload: payload)
}

/// Parses a byte sequence back into frames. Use it to check the connection's output.
func parseFrames(_ bytes: [UInt8], maximumPayloadLength: Int = FrameBuffer.defaultMaximumPayloadLength) throws -> [Frame] {
    var buffer = FrameBuffer(maximumPayloadLength: maximumPayloadLength)
    buffer.append(bytes)
    var frames: [Frame] = []
    while let frame = try buffer.nextFrame() { frames.append(frame) }
    return frames
}

extension HTTP2ClientConnection {
    /// Parses the bytes queued for sending back into frames, skipping the initial preface.
    mutating func takeOutboundFrames() throws -> [Frame] {
        var bytes = takeOutboundBytes()
        if bytes.starts(with: HTTP2ClientConnection.preface) { bytes.removeFirst(HTTP2ClientConnection.preface.count) }
        // The peer's MAX_FRAME_SIZE (at most 2^24-1) determines the outbound frame size.
        return try parseFrames(bytes, maximumPayloadLength: 1 << 24)
    }

    /// A connection that has received the server's SETTINGS and completed the exchange. Leaves its outbound buffer empty.
    static func established(serverSettings: [(UInt16, UInt32)] = []) throws -> HTTP2ClientConnection {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(settingsBytes(serverSettings))
        _ = connection.takeOutboundBytes()
        return connection
    }
}

let getRequest = HTTP2ClientConnection.Request(method: "GET", path: "/key?v=148", authority: "tail0001")

/// A fixed-seed pseudorandom number generator (SplitMix64). Failures can be reproduced exactly.
struct SplitMix64 {
    var state: UInt64

    mutating func next() -> UInt64 {
        state &+= 0x9e37_79b9_7f4a_7c15
        var z = state
        z = (z ^ (z >> 30)) &* 0xbf58_476d_1ce4_e5b9
        z = (z ^ (z >> 27)) &* 0x94d0_49bb_1331_11eb
        return z ^ (z >> 31)
    }

    mutating func bytes(count: Int) -> [UInt8] {
        (0..<count).map { _ in UInt8(truncatingIfNeeded: next()) }
    }
}
