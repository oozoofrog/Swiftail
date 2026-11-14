import Foundation
import SwiftailBase
import SwiftailDERP
import Testing

@testable import SwiftailDERP

@Suite("DERP 핸드셰이크")
struct DERPHandshakeTests {
    @Test("만들자마자 업그레이드 요청이 나온다: GET /derp, Host, Connection, Upgrade뿐이다")
    func upgradeRequest() throws {
        var connection = try DERPFixtures.connection(host: "derp1.example.test")
        #expect(
            String(decoding: connection.takeOutboundBytes(), as: UTF8.self)
                == "GET /derp HTTP/1.1\r\nHost: derp1.example.test\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"
        )
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("ServerKey를 받으면 ClientInfo가 Go box.Seal의 출력과 같은 바이트로 나가고, 홈이면 NotePreferred가 이어진다")
    func clientInfoMatchesGoVector() throws {
        var connection = try DERPFixtures.connection(isPreferred: true)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame())
        #expect(events == [.ready])

        // 본문 104바이트 = 키 32 + nonce 24 + 태그 16 + JSON 32 (노트 3.4절).
        let clientInfo = try DERPFixtures.Server.frame(0x02, DERPFixtures.bytes(DERPFixtures.clientInfoBody))
        #expect(clientInfo.count == 109)
        let notePreferred: [UInt8] = [0x07, 0, 0, 0, 1, 0x01]
        #expect(connection.takeOutboundBytes() == clientInfo + notePreferred)
    }

    @Test("홈이 아니면 NotePreferred를 보내지 않는다")
    func notPreferred() throws {
        var connection = try DERPFixtures.connection(isPreferred: false)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame())
        let clientInfo = try DERPFixtures.Server.frame(0x02, DERPFixtures.bytes(DERPFixtures.clientInfoBody))
        #expect(connection.takeOutboundBytes() == clientInfo)
    }

    @Test("Go가 봉한 ServerInfo를 연다")
    func opensGoServerInfo() throws {
        var connection = try DERPFixtures.readyConnection()
        let frame = try DERPFixtures.Server.frame(0x03, DERPFixtures.bytes(DERPFixtures.serverInfoBody))
        #expect(try connection.receive(frame).isEmpty)
        #expect(connection.hasReceivedFrameAfterHandshake)
        // Swift로 봉한 것도 같은 키로 열린다(열린 뒤에도 연결은 살아 있다).
        #expect(try connection.receive(DERPFixtures.Server.serverInfoFrame()).isEmpty)
        #expect(try connection.receive(DERPFixtures.Server.recvPacket(from: DERPFixtures.nodeKey(7), [1])).count == 1)
    }

    @Test("ServerKey만 받은 연결은 핸드셰이크 뒤 프레임을 받은 것으로 치지 않는다")
    func serverKeyAloneIsNotProgress() throws {
        var connection = try DERPFixtures.connection()
        _ = try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame())
        #expect(!connection.hasReceivedFrameAfterHandshake)
    }

    @Test("101 머리와 ServerKey가 한 조각에 와도, 머리만 먼저 와도 같다")
    func headAndServerKeyInOneChunkOrTwo() throws {
        var together = try DERPFixtures.connection()
        let all = try DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame()
        #expect(try together.receive(all) == [.ready])

        var apart = try DERPFixtures.connection()
        #expect(try apart.receive(DERPFixtures.Server.upgradeResponse).isEmpty)
        #expect(try apart.receive(DERPFixtures.Server.serverKeyFrame()) == [.ready])
        #expect(together.takeOutboundBytes() == apart.takeOutboundBytes())
    }

    @Test("한 바이트씩 넣어도 같은 사건과 같은 출력이 나온다")
    func byteAtATime() throws {
        let peer = try DERPFixtures.nodeKey(3)
        let input = try DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame()
            + DERPFixtures.Server.serverInfoFrame()
            + DERPFixtures.Server.recvPacket(from: peer, [1, 2, 3])
            + DERPFixtures.Server.frame(0x08, peer.rawValue + [0x01])

        var whole = try DERPFixtures.connection()
        let expected = try whole.receive(input)
        #expect(expected == [.ready, .packet([1, 2, 3], from: peer), .peerGone(peer, reason: .notHere)])

        var pieces = try DERPFixtures.connection()
        var actual: [DERPConnection.Event] = []
        for byte in input { actual += try pieces.receive([byte]) }
        #expect(actual == expected)
        #expect(pieces.takeOutboundBytes() == whole.takeOutboundBytes())
    }

    @Test("ServerKey의 40바이트 뒤(향후 확장)는 버린다")
    func serverKeyTrailingBytes() throws {
        var connection = try DERPFixtures.connection()
        let input = try DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame(trailing: [UInt8](repeating: 9, count: 984))
        #expect(try connection.receive(input) == [.ready])
    }

    @Test("준비 뒤의 ServerKey는 모르는 프레임처럼 건너뛴다")
    func lateServerKeyIsSkipped() throws {
        var connection = try DERPFixtures.readyConnection()
        #expect(try connection.receive(DERPFixtures.Server.serverKeyFrame()).isEmpty)
    }

    @Test("생성 인자를 검증한다: nonce 길이, Host에 공백·CR·LF·빈 값")
    func constructorValidation() throws {
        let key = try DERPFixtures.privateKey(seed: DERPFixtures.clientSeed)
        let nonce = try DERPFixtures.bytes(DERPFixtures.nonce)
        #expect(throws: DERPError.malformed) {
            try DERPConnection(privateKey: key, host: "h", isPreferred: true, clientInfoNonce: Array(nonce.dropLast()))
        }
        for host in ["", "a b", "a\r\nX-Evil: 1", "a\nb", "a\u{7F}"] {
            #expect(throws: DERPError.malformed) {
                try DERPConnection(privateKey: key, host: host, isPreferred: true, clientInfoNonce: nonce)
            }
        }
    }
}
