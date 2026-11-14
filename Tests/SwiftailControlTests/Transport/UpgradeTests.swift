// 계약 단위 2 시험: 업그레이드 요청 형식, 응답의 상태·`Upgrade` 값 검증, 머리 뒤 바이트 인계, 한도.

import Foundation
import Testing

@testable import SwiftailControl

@Suite("HTTP 업그레이드")
struct UpgradeTests {
    private let initiation = Array(0..<101).map(UInt8.init)

    @Test("요청은 POST /ts2021, Host, Upgrade, Connection, 표준 base64 initiation이고 본문이 없다")
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
        // 101바이트는 3의 배수가 아니므로 패딩이 붙는다(표준 base64).
        #expect(encoded.hasSuffix("="))
    }

    private let switching = Array("HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocol\r\nConnection: upgrade\r\n\r\n".utf8)

    @Test("101 머리 뒤에 이미 온 바이트를 Noise 계층에 넘긴다")
    func remainder() throws {
        var parser = UpgradeResponseParser()
        let noise: [UInt8] = [2, 0, 48, 0xAA]
        #expect(try parser.receive(switching + noise) == noise)
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("머리가 한 바이트씩 와도 빈 줄에서 끝나고, 뒤가 없으면 빈 배열이다")
    func byteByByte() throws {
        var parser = UpgradeResponseParser()
        for byte in switching.dropLast() {
            #expect(try parser.receive([byte]) == nil)
        }
        #expect(try parser.receive([switching[switching.count - 1]]) == [])
    }

    @Test("헤더 이름은 대소문자를 가리지 않고, 값 앞뒤 공백을 걷어 내며, 이유 문구는 없어도 된다")
    func lenientForms() throws {
        var parser = UpgradeResponseParser()
        let head = "HTTP/1.1 101\r\nupgrade:\t tailscale-control-protocol  \r\n\r\n"
        #expect(try parser.receive(Array(head.utf8)) == [])
    }

    @Test("101이 아니면 upgradeRejected(status:)", arguments: [400, 200, 404, 500, 100])
    func rejected(_ status: Int) throws {
        var parser = UpgradeResponseParser()
        let head = "HTTP/1.1 \(status) Whatever\r\nContent-Length: 0\r\n\r\n"
        #expect(throws: ControlTransportError.upgradeRejected(status: status)) { try parser.receive(Array(head.utf8)) }
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("Upgrade 값이 없거나 정확히 같지 않으면 malformed", arguments: [
        "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrade\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: Tailscale-Control-Protocol\r\n\r\n",
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: tailscale-control-protocolx\r\n\r\n",
    ])
    func wrongUpgrade(_ head: String) throws {
        var parser = UpgradeResponseParser()
        #expect(throws: ControlTransportError.malformed) { try parser.receive(Array(head.utf8)) }
    }

    @Test("상태 줄이나 헤더 줄의 형식이 틀리면 malformed", arguments: [
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

    @Test("상태 줄이나 헤더 값에 홀로 있는 CR·LF나 제어 문자가 있으면 malformed", arguments: [
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

    @Test("헤더 값 안의 탭과 0x80 이상의 바이트는 받는다")
    func tabAndObsTextInHeaderValue() throws {
        var parser = UpgradeResponseParser()
        let head = Array("HTTP/1.1 101 x\r\nUpgrade: tailscale-control-protocol\r\nX-Test: a\tb ".utf8)
            + [0xC3, 0xA9] + Array("\r\n\r\n".utf8)
        #expect(try parser.receive(head) == [])
    }

    @Test("한도를 넘겨 실패하면 받은 바이트를 쥐고 있지 않는다")
    func oversizedInputIsDropped() throws {
        var parser = UpgradeResponseParser()
        #expect(throws: ControlTransportError.messageTooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: 1_000_000))
        }
        #expect(parser.head.buffer.isEmpty)
        #expect(throws: ControlTransportError.closed) { try parser.receive([]) }
    }

    @Test("빈 줄 없이 16KiB에 이르면 messageTooLarge")
    func headTooLarge() throws {
        var parser = UpgradeResponseParser()
        let start = Array("HTTP/1.1 101 x\r\nX-Pad: ".utf8)
        #expect(try parser.receive(start) == nil)
        #expect(throws: ControlTransportError.messageTooLarge) {
            try parser.receive([UInt8](repeating: UInt8(ascii: "a"), count: 16 * 1024 - start.count))
        }
    }

    @Test("빈 줄이 16KiB 안에 끝나면 받는다")
    func headAtLimit() throws {
        var parser = UpgradeResponseParser()
        let prefix = Array("HTTP/1.1 101 x\r\nUpgrade: tailscale-control-protocol\r\nX-Pad: ".utf8)
        let padding = [UInt8](repeating: UInt8(ascii: "a"), count: 16 * 1024 - prefix.count - 4)
        #expect(try parser.receive(prefix + padding + Array("\r\n\r\n".utf8) + [7]) == [7])
    }
}
