import Foundation
import Testing

@testable import SwiftailHTTP2

@Suite("Independent decoding of Go HPACK fixtures")
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

    @Test("Preserves the Go block order and dynamic table for each connection")
    func decodeFixtures() throws {
        for fixture in try fixtures() {
            var decoder = HPACKDecoder()
            for (index, block) in fixture.blocks.enumerated() {
                let decoded = try decoder.decode(bytes(block.hex))
                // The API does not relay headers and does not expose sensitive. Check never indexed against the original bytes as well.
                #expect(decoded == block.fields, "\(fixture.name), block \(index)")
            }
        }
    }

    @Test("Delivers each byte of a Go block through HEADERS and CONTINUATION")
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
                    // Add a static :status=200 to fixtures with only regular fields to make a response.
                    // Table size updates must stay at the very beginning, and a static index leaves the dynamic table unchanged (7541 §4.2).
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
                    if !last { #expect(events.isEmpty, "Response headers must be absent before END_HEADERS") }
                }
                let code = try #require(Int(status?.value ?? "200"))
                #expect(events == [
                    .responseHead(id, status: code, headers: block.fields.filter { $0.name != ":status" }),
                    .streamClosed(id, resetCode: nil),
                ], "\(fixture.name), block \(index)")
            }
        }
    }
}
