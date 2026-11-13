// 시험 공용 도구: 16진 변환, 서버가 보낼 프레임 만들기, 연결이 낸 바이트를 프레임으로 되읽기.

import Testing

@testable import SwiftailHTTP2

/// 공백을 무시하고 16진 문자열을 바이트로 바꾼다. RFC의 덤프를 그대로 붙이기 위한 것이다.
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

/// 프레임 하나의 바이트. 서버(상대) 역할의 시험이 쓴다.
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

/// 서버의 응답 머리 HEADERS 프레임. 헤더 블록은 이 모듈의 압축기로 만든다.
func responseHeadBytes(stream: UInt32, status: String = "200", headers: [HeaderField] = [], endStream: Bool = false) -> [UInt8] {
    let block = HPACKEncoder.encode([HeaderField(":status", status)] + headers)
    return frameBytes(1, flags: 0x4 | (endStream ? 0x1 : 0), stream: stream, payload: block)
}

func dataBytes(stream: UInt32, _ payload: [UInt8], endStream: Bool = false) -> [UInt8] {
    frameBytes(0, flags: endStream ? 0x1 : 0, stream: stream, payload: payload)
}

/// 바이트열을 프레임들로 되읽는다. 연결이 낸 바이트를 확인할 때 쓴다.
func parseFrames(_ bytes: [UInt8], maximumPayloadLength: Int = FrameBuffer.defaultMaximumPayloadLength) throws -> [Frame] {
    var buffer = FrameBuffer(maximumPayloadLength: maximumPayloadLength)
    buffer.append(bytes)
    var frames: [Frame] = []
    while let frame = try buffer.nextFrame() { frames.append(frame) }
    return frames
}

extension HTTP2ClientConnection {
    /// 지금까지 쌓인 보낼 바이트를 프레임으로 되읽는다. 맨 앞의 프리페이스는 건너뛴다.
    mutating func takeOutboundFrames() throws -> [Frame] {
        var bytes = takeOutboundBytes()
        if bytes.starts(with: HTTP2ClientConnection.preface) { bytes.removeFirst(HTTP2ClientConnection.preface.count) }
        // 보내는 프레임의 크기는 상대의 MAX_FRAME_SIZE(최대 2^24-1)가 정한다.
        return try parseFrames(bytes, maximumPayloadLength: 1 << 24)
    }

    /// 서버 SETTINGS를 받아 교환을 마친 연결. 보낼 바이트는 비워 둔다.
    static func established(serverSettings: [(UInt16, UInt32)] = []) throws -> HTTP2ClientConnection {
        var connection = HTTP2ClientConnection()
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(settingsBytes(serverSettings))
        _ = connection.takeOutboundBytes()
        return connection
    }
}

let getRequest = HTTP2ClientConnection.Request(method: "GET", path: "/key?v=148", authority: "tail0001")

/// 고정 시드 의사 난수(SplitMix64). 실패하면 그대로 재현된다.
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
