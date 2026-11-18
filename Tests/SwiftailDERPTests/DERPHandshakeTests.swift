import Foundation
import SwiftailBase
import SwiftailDERP
import Testing

@testable import SwiftailDERP

@Suite("DERP handshake")
struct DERPHandshakeTests {
    @Test("Creating the handshake immediately emits an upgrade request with only GET /derp, Host, Connection, and Upgrade")
    func upgradeRequest() throws {
        var connection = try DERPFixtures.connection(host: "derp1.example.test")
        #expect(
            String(decoding: connection.takeOutboundBytes(), as: UTF8.self)
                == "GET /derp HTTP/1.1\r\nHost: derp1.example.test\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n"
        )
        #expect(connection.takeOutboundBytes().isEmpty)
    }

    @Test("Receiving ServerKey emits ClientInfo with the same bytes as Go box.Seal, followed by NotePreferred for the home server")
    func clientInfoMatchesGoVector() throws {
        var connection = try DERPFixtures.connection(isPreferred: true)
        _ = connection.takeOutboundBytes()
        let events = try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame())
        #expect(events == [.ready])

        // The 104-byte body is the 32-byte key + 24-byte nonce + 16-byte tag + 32-byte JSON (notes §3.4).
        let clientInfo = try DERPFixtures.Server.frame(0x02, DERPFixtures.bytes(DERPFixtures.clientInfoBody))
        #expect(clientInfo.count == 109)
        let notePreferred: [UInt8] = [0x07, 0, 0, 0, 1, 0x01]
        #expect(connection.takeOutboundBytes() == clientInfo + notePreferred)
    }

    @Test("Does not send NotePreferred if this is not the home server")
    func notPreferred() throws {
        var connection = try DERPFixtures.connection(isPreferred: false)
        _ = connection.takeOutboundBytes()
        _ = try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame())
        let clientInfo = try DERPFixtures.Server.frame(0x02, DERPFixtures.bytes(DERPFixtures.clientInfoBody))
        #expect(connection.takeOutboundBytes() == clientInfo)
    }

    @Test("Opens ServerInfo sealed by Go")
    func opensGoServerInfo() throws {
        var connection = try DERPFixtures.readyConnection()
        let frame = try DERPFixtures.Server.frame(0x03, DERPFixtures.bytes(DERPFixtures.serverInfoBody))
        #expect(try connection.receive(frame).isEmpty)
        #expect(connection.hasReceivedFrameAfterHandshake)
        // The same key opens the Swift-sealed version too (the connection remains open afterward).
        #expect(try connection.receive(DERPFixtures.Server.serverInfoFrame()).isEmpty)
        #expect(try connection.receive(DERPFixtures.Server.recvPacket(from: DERPFixtures.nodeKey(7), [1])).count == 1)
    }

    @Test("Receiving only ServerKey does not count as receiving a post-handshake frame")
    func serverKeyAloneIsNotProgress() throws {
        var connection = try DERPFixtures.connection()
        _ = try connection.receive(DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame())
        #expect(!connection.hasReceivedFrameAfterHandshake)
    }

    /// Before the fix, the flag was set before processing the frame, so the client reconnected without backoff to servers that sent only a ServerInfo that could not be opened and then disconnected.
    @Test("ServerInfo that cannot be opened or is not JSON does not count as a received post-handshake frame")
    func failedFrameIsNotProgress() throws {
        var tampered = try DERPFixtures.readyConnection()
        var frame = try DERPFixtures.Server.serverInfoFrame()
        frame[frame.count - 1] ^= 0x01
        #expect(throws: DERPError.handshakeFailed) { try tampered.receive(frame) }
        #expect(!tampered.hasReceivedFrameAfterHandshake)

        var notJSON = try DERPFixtures.readyConnection()
        #expect(throws: DERPError.malformed) { try notJSON.receive(DERPFixtures.Server.serverInfoFrame(Array("not json".utf8))) }
        #expect(!notJSON.hasReceivedFrameAfterHandshake)
    }

    @Test("The result is the same whether the 101 header and ServerKey arrive in one chunk or the header arrives by itself first")
    func headAndServerKeyInOneChunkOrTwo() throws {
        var together = try DERPFixtures.connection()
        let all = try DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame()
        #expect(try together.receive(all) == [.ready])

        var apart = try DERPFixtures.connection()
        #expect(try apart.receive(DERPFixtures.Server.upgradeResponse).isEmpty)
        #expect(try apart.receive(DERPFixtures.Server.serverKeyFrame()) == [.ready])
        #expect(together.takeOutboundBytes() == apart.takeOutboundBytes())
    }

    @Test("Feeding bytes one at a time produces the same events and output")
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

    @Test("Discards bytes after the first 40 bytes of ServerKey (future extensions)")
    func serverKeyTrailingBytes() throws {
        var connection = try DERPFixtures.connection()
        let input = try DERPFixtures.Server.upgradeResponse + DERPFixtures.Server.serverKeyFrame(trailing: [UInt8](repeating: 9, count: 984))
        #expect(try connection.receive(input) == [.ready])
    }

    @Test("Skips ServerKey after readiness as an unknown frame")
    func lateServerKeyIsSkipped() throws {
        var connection = try DERPFixtures.readyConnection()
        #expect(try connection.receive(DERPFixtures.Server.serverKeyFrame()).isEmpty)
    }

    @Test("Validates initializer arguments, including the nonce length and Host values with spaces, CR, LF, or an empty value")
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
