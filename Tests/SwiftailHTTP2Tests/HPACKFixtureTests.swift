import Foundation
import Testing

@testable import SwiftailHTTP2

@Suite("Go HPACK 자료의 독립 해독")
struct HPACKFixtureTests {
    private struct Connection: Decodable {
        let name: String
        let blocks: [Block]
    }

    private struct Block: Decodable {
        struct Header: Decodable {
            let name: String
            let value: String
            let sensitive: Bool
        }
        let hex: String
        let headers: [Header]
        var fields: [HeaderField] { headers.map { HeaderField($0.name, $0.value) } }
    }

    private func fixtures() throws -> [Connection] {
        let url = try #require(Bundle.module.url(forResource: "hpack", withExtension: "json", subdirectory: "Fixtures"))
        return try JSONDecoder().decode([Connection].self, from: Data(contentsOf: url))
    }

    private func bytes(_ value: String) throws -> [UInt8] {
        let digits = Array(value.utf8)
        try #require(digits.count.isMultiple(of: 2))
        return try stride(from: 0, to: digits.count, by: 2).map {
            try #require(UInt8(String(decoding: digits[$0..<$0 + 2], as: UTF8.self), radix: 16))
        }
    }

    @Test("연결마다 Go 블록 순서와 동적 표를 유지한다")
    func decodeFixtures() throws {
        for fixture in try fixtures() {
            var decoder = HPACKDecoder()
            for (index, block) in fixture.blocks.enumerated() {
                let decoded = try decoder.decode(bytes(block.hex))
                // 중계하지 않는 API는 sensitive를 노출하지 않는다. never indexed도 원본 바이트로 검증한다.
                #expect(decoded == block.fields, "\(fixture.name), 블록 \(index)")
            }
        }
    }

    @Test("Go 블록의 각 바이트를 HEADERS와 CONTINUATION으로 전달한다")
    func fragmentedFrames() throws {
        for fixture in try fixtures() {
            var connection = HTTP2ClientConnection()
            _ = connection.takeOutboundBytes()
            _ = try connection.receive(frameBytes(4))
            _ = connection.takeOutboundBytes()
            for (index, block) in fixture.blocks.enumerated() {
                var payload = try bytes(block.hex)
                let status = block.headers.first { $0.name == ":status" }
                if status == nil {
                    // 일반 필드만 있는 자료는 응답으로 만들기 위해 정적 :status=200을 보충한다.
                    // 표 크기 갱신은 반드시 맨 앞에 남겨 두며, 정적 색인은 동적 표를 바꾸지 않는다(7541 §4.2).
                    var prefix = 0
                    while prefix < payload.count, payload[prefix] & 0xe0 == 0x20 {
                        let extended = payload[prefix] & 0x1f == 0x1f
                        prefix += 1
                        if extended {
                            var more = true
                            while more {
                                try #require(prefix < payload.count)
                                more = payload[prefix] & 0x80 != 0
                                prefix += 1
                            }
                        }
                    }
                    payload.insert(0x88, at: prefix)
                }
                let id = try connection.startRequest(.init(method: "GET", path: "/fixture", authority: "tail0001.test"), body: nil)
                _ = connection.takeOutboundBytes()
                var events: [HTTP2ClientConnection.Event] = []
                for (offset, byte) in payload.enumerated() {
                    let last = offset == payload.count - 1
                    let flags: UInt8 = (offset == 0 ? 1 : 0) | (last ? 4 : 0)
                    events += try connection.receive(frameBytes(offset == 0 ? 1 : 9, flags: flags, stream: id.rawValue, payload: [byte]))
                    if !last { #expect(events.isEmpty, "END_HEADERS 전에는 응답 머리가 없어야 한다") }
                }
                let code = try #require(Int(status?.value ?? "200"))
                #expect(events == [
                    .responseHead(id, status: code, headers: block.fields.filter { $0.name != ":status" }),
                    .streamClosed(id, resetCode: nil),
                ], "\(fixture.name), 블록 \(index)")
            }
        }
    }
}
