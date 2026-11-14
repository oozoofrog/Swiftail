import CryptoKit
import Foundation
import SwiftailBase
import SwiftailCrypto
import SwiftailDERP
import Testing

@Suite("DERP 임의 입력과 비밀")
struct DERPRobustnessTests {
    /// 어떤 바이트열이 어떤 조각으로 와도 죽지 않는다. 결과는 사건이거나 `DERPError`다.
    private func feed(_ connection: inout DERPConnection, _ input: [UInt8], using generator: inout SplitMix64) {
        var rest = input[...]
        while !rest.isEmpty {
            let size = Int.random(in: 1...max(1, min(rest.count, 70)), using: &generator)
            _ = try? connection.receive(Array(rest.prefix(size)))
            _ = connection.takeOutboundBytes()
            rest = rest.dropFirst(size)
        }
    }

    @Test("완전히 임의인 바이트를 처음부터 넣어도 죽지 않는다")
    func randomBytesFromStart() throws {
        var generator = SplitMix64(state: 1)
        for _ in 0..<200 {
            var connection = try DERPFixtures.connection()
            let input = (0..<Int.random(in: 0...600, using: &generator)).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
            feed(&connection, input, using: &generator)
        }
    }

    @Test("올바른 머리와 ServerKey 뒤에 임의 바이트·임의 프레임이 와도 죽지 않는다")
    func randomFramesAfterHandshake() throws {
        var generator = SplitMix64(state: 2)
        let types: [UInt8] = [0x01, 0x03, 0x05, 0x06, 0x08, 0x09, 0x12, 0x13, 0x14, 0x15, 0x00, 0xFF]
        for _ in 0..<300 {
            var connection = try DERPFixtures.readyConnection()
            var input: [UInt8] = []
            for _ in 0..<Int.random(in: 1...20, using: &generator) {
                let body = (0..<Int.random(in: 0...80, using: &generator)).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
                input += DERPFixtures.Server.frame(types.randomElement(using: &generator) ?? 0, body)
            }
            if Bool.random(using: &generator) { input.append(UInt8.random(in: .min ... .max, using: &generator)) }
            feed(&connection, input, using: &generator)
        }
    }

    @Test("임의 바이트에서 만든 send와 receive를 섞어도 죽지 않는다")
    func randomSendsAndFailures() throws {
        var generator = SplitMix64(state: 3)
        var connection = try DERPFixtures.readyConnection()
        for step in 0..<500 {
            let packet = [UInt8](repeating: UInt8(truncatingIfNeeded: step), count: Int.random(in: 0...3, using: &generator))
            _ = try? connection.send(packet, to: DERPFixtures.nodeKey(UInt8(truncatingIfNeeded: step)))
            _ = connection.takeOutboundBytes()
            _ = try? connection.receive([UInt8.random(in: .min ... .max, using: &generator)])
        }
    }

    @Test("dump와 description에 개인 키와 공유 키가 나오지 않는다")
    func secretsAreHidden() throws {
        let privateKey = try DERPFixtures.bytes(DERPFixtures.clientSeed)
        let sharedKey = try NaClBox.sharedKey(privateKey: privateKey, peerPublicKey: DERPFixtures.bytes(DERPFixtures.serverPublic))

        var ready = try DERPFixtures.readyConnection()
        _ = try ready.receive(DERPFixtures.Server.serverInfoFrame())
        let before = try DERPFixtures.connection()
        for connection in [before, ready] {
            var dumped = ""
            dump(connection, to: &dumped)
            let texts = [dumped, String(describing: connection), String(reflecting: connection)]
            for text in texts {
                for secret in [privateKey, sharedKey] {
                    #expect(!text.contains(secret.hex))
                    #expect(!text.lowercased().contains(secret.hex))
                    #expect(!text.contains(Data(secret).base64EncodedString()))
                    #expect(!text.contains(secret.map(String.init).joined(separator: ", ")))
                }
            }
        }
    }

    @Test("DERPClient의 dump와 description에도 개인 키가 나오지 않는다")
    func clientSecretsAreHidden() throws {
        let key = try DERPFixtures.privateKey(seed: DERPFixtures.clientSeed)
        let client = DERPClient(servers: [DERPServer(hostName: "derp.example.test")], privateKey: key, isPreferred: true)
        var dumped = ""
        dump(client, to: &dumped)
        for text in [dumped, String(describing: client)] {
            #expect(!text.contains(DERPFixtures.clientSeed))
            #expect(!text.contains(Array(key.rawRepresentation).map(String.init).joined(separator: ", ")))
        }
    }
}
