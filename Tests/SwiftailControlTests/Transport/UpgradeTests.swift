// Contract unit test 2: Upgrade request format, validation of response status and `Upgrade` value, handoff of bytes after the headers, and limits.

import Foundation
import Testing

@testable import SwiftailControl

@Suite("HTTP upgrade")
struct UpgradeTests {
    private let initiation = Array(0..<101).map(UInt8.init)

    @Test("The request uses POST /ts2021, Host, Upgrade, Connection, and standard base64 initiation, with no body")
    func requestBytes() throws {
        let request = String(decoding: UpgradeRequest.bytes(host: "127.0.0.1:9911", initiation: initiation), as: UTF8.self)
        let encoded = Data(initiation).base64EncodedString()
        #expect(request == """
            POST /ts2021 HTTP/1.1\r
            Host: 127.0.0.1:9911\r
            Upgrade: tailscale-control-protocol\r
            Connection: upgrade\r
            X-Tailscale-Handshake: \(encoded)\r
            Content-Length: 0\r
            \r

            """)
        // 101 bytes is not a multiple of 3, so padding is present (standard base64).
        #expect(encoded.hasSuffix("="))
    }

    private let switching = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n".utf8)

    @Test("Passes bytes already received after the 101 headers to the Noise layer")
    func remainder() throws {
        var parser = UpgradeResponseParser()
        let noise: [UInt8] = [2, 0, 48, 0xAA]
        #expect(try parser.receive(switching + noise) == noise)
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("Headers end at the blank line even when received one byte at a time, with an empty array if nothing follows")
    func byteByByte() throws {
        var parser = UpgradeResponseParser()
        for byte in switching.dropLast() {
            #expect(try parser.receive([byte]) == nil)
        }
        #expect(try parser.receive([switching[switching.count - 1]]) == [])
    }

    @Test("Header names are case-insensitive, whitespace around values is trimmed, and the reason phrase is optional")
    func lenientForms() throws {
        var parser = UpgradeResponseParser()
        let head = "HTTP/1.1 101\r\nupgrade:\t tailscale-control-protocol  \r\n\r\n"
        #expect(try parser.receive(Array(head.utf8)) == [])
    }

    @Test("A status other than 101 yields upgradeRejected(status:)", arguments: [400, 200, 404, 500, 100])
    func rejected(_ status: Int) throws {
        var parser = UpgradeResponseParser()
        let head = "HTTP/1.1 \(status) Whatever\r\nContent-Length: 0\r\n\r\n"
        #expect(throws: ControlTransportError.upgradeRejected(status: status)) { try parser.receive(Array(head.utf8)) }
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("A missing or inexact Upgrade value yields malformed", arguments: [
        "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: Tailscale-Control-Protocol\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocolx\r\n\r\n",
    ])
    func wrongUpgrade(_ head: String) throws {
        var parser = UpgradeResponseParser()
        #expect(throws: ControlTransportError.malformed) { try parser.receive(Array(head.utf8)) }
    }

    @Test("An invalid status line or header line yields malformed", arguments: [
        "\r\n\r\n",
        "HTTP/2 101 x\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 1O1 x\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 1011 x\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1101\r\nUpgrade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101 x\r\nUpgrade tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101 x\r\nUp grade: tailscale-control-protocol\r\n\r\n",
        "HTTP/1.1 101 x\r\n: tailscale-control-protocol\r\n\r\n",
    ])
    func malformedHead(_ head: String) throws {
        var parser = UpgradeResponseParser()
        #expect(throws: ControlTransportError.malformed) { try parser.receive(Array(head.utf8)) }
    }

    @Test("A lone CR or LF or a control character in the status line or header value yields malformed", arguments: [
        "X-Test: x\ny", "X-Test: x\ry", "X-Test: x\0y", "X-Test: x\u{7F}y", "X-Test: \u{1B}",
    ])
    func controlCharacterInHeaderValue(_ line: String) throws {
        var parser = UpgradeResponseParser()
        let head = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\n\(line)\r\n\r\n"
        #expect(throws: ControlTransportError.malformed) { try parser.receive(Array(head.utf8)) }

        var statusParser = UpgradeResponseParser()
        let statusHead = "HTTP/1.1 101 Switching\u{1}Protocols\r\nUpgrade: tailscale-control-protocol\r\n\r\n"
        #expect(throws: ControlTransportError.malformed) { try statusParser.receive(Array(statusHead.utf8)) }
    }

    @Test("Accepts tabs and bytes of 0x80 or above inside header values")
    func tabAndObsTextInHeaderValue() throws {
        var parser = UpgradeResponseParser()
        let head = Array("HTTP/1.1 101 x\r\nUpgrade: tailscale-control-protocol\r\nX-Test: a\tb ".utf8)
            + [0xC3, 0xA9] + Array("\r\n\r\n".utf8)
        #expect(try parser.receive(head) == [])
    }

    @Test("Does not retain received bytes when exceeding the limit causes failure")
    func oversizedInputIsDropped() throws {
        var parser = UpgradeResponseParser()
        #expect(throws: ControlTransportError.messageTooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: 1_000_000))
        }
        #expect(parser.head.buffer.isEmpty)
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("Reaching 16KiB without a blank line yields messageTooLarge")
    func headTooLarge() throws {
        var parser = UpgradeResponseParser()
        let start = Array("HTTP/1.1 101 x\r\nX-Pad: ".utf8)
        #expect(try parser.receive(start) == nil)
        #expect(throws: ControlTransportError.messageTooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: 16 * 1024 - start.count))
        }
    }

    @Test("Accepts a blank line that ends within 16KiB")
    func headAtLimit() throws {
        var parser = UpgradeResponseParser()
        let prefix = Array("HTTP/1.1 101 x\r\nUpgrade: tailscale-control-protocol\r\nX-Pad: ".utf8)
        let padding = [UInt8](repeating: UInt8(ascii: "a"), count: 16 * 1024 - prefix.count - 4)
        #expect(try parser.receive(prefix + padding + Array("\r\n\r\n".utf8) + [7]) == [7])
    }
}
