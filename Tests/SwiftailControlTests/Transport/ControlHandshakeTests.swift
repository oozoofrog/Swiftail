// 계약 단위 2 시험: 고정 벡터(initiation, response, 중간값, 방향별 키), 조각난 response, 서버 error 메시지,
// 101 뒤 EOF 처리에 필요한 상태.

import CryptoKit
import SwiftailBase
import Testing

@testable import SwiftailControl

@Suite("제어 Noise 핸드셰이크")
struct ControlHandshakeTests {
    private typealias V = TransportVectors

    @Test("initiation이 노트 7.3의 벡터와 바이트 단위로 같다")
    func initiationVector() throws {
        #expect(try V.handshake().initiation == V.bytes(V.initiation))
    }

    @Test("중간 hash·ck·AEAD 키가 노트 7.3의 표와 같다")
    func intermediateValues() throws {
        let machine = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: V.bytes(V.clientMachinePrivate))
        let ephemeral = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: V.bytes(V.clientEphemeralPrivate))
        let server = try V.bytes(V.serverStaticPublic)
        #expect(Array(machine.publicKey.rawRepresentation) == (try V.bytes(V.clientMachinePublic)))
        #expect(Array(ephemeral.publicKey.rawRepresentation) == (try V.bytes(V.clientEphemeralPublic)))

        var state = SymmetricState(protocolName: NoiseIK.protocolName)
        #expect(state.hash.hex == "bbea022b948cf3bc5857d70804229179e1116bc40cb8cc074835349c464bca36")
        #expect(state.chainingKey == state.hash)
        state.mixHash(NoiseIK.prologue(protocolVersion: 148))
        #expect(state.hash.hex == "fec1c32c3bfa98e7b8fe17ed6a11ca98010faf537dfe04facd365dcc7278c6e3")
        state.mixHash(server)
        #expect(state.hash.hex == "4ff25d533e57e80cde501455476df3c74d6105a0404fd2367b2fe2bb4bba0ac1")
        state.mixHash(Array(ephemeral.publicKey.rawRepresentation))
        #expect(state.hash.hex == "8f4d3fee07c8dca8b9193141d281d1a219a6020d14f310b55b11664105de1e99")

        let es = state.mixDH(ephemeral, server)
        let esKey = try #require(es)
        #expect(state.chainingKey.hex == "638c46b2fa99a1d28c6eb68e133c5d220eaf490852adf740ac083beb644259fa")
        #expect(try esKey == key("61d19a096c56c8c57f13d65d3d35f392b87fecc40b9be69c2431d14021761348"))
        _ = state.encryptAndHash(Array(machine.publicKey.rawRepresentation), key: esKey)
        #expect(state.hash.hex == "a46b7bce53ea6f082652cfbe415cbc3d09124ac9a1c5917c42c8a028b4df851c")

        let ss = state.mixDH(machine, server)
        let ssKey = try #require(ss)
        #expect(state.chainingKey.hex == "859ff0aa416be42ccff019b9b0a8c90127042d9022f1b7653360236214fabc5c")
        #expect(try ssKey == key("27d4bfb4f102b7b35e13f29013edb4f8297fd35051466874ee42f211a7a26251"))
        _ = state.encryptAndHash([], key: ssKey)
        #expect(state.hash.hex == "771e5e7a343ed7076b5956fa19a2ec6ac6179f4457291c0cf14cebf949988998")

        let serverEphemeral = try V.bytes(V.serverEphemeralPublic)
        state.mixHash(serverEphemeral)
        #expect(state.hash.hex == "0a4c2fc98dedfaed302eb21c6766a44475caeb9875fc68b16f77687547edf9d2")
        let ee = state.mixDH(ephemeral, serverEphemeral)
        #expect(ee != nil)
        #expect(state.chainingKey.hex == "4d7a28f286cc2ba50b46631421d591b895a65b320c6ecc06ae9257c3892ee374")
        let se = state.mixDH(machine, serverEphemeral)
        let seKey = try #require(se)
        #expect(state.chainingKey.hex == "6cbc50260668a0a00ce3581cf60c6b0917f53b1237ec69031af3e2564ece36b4")
        #expect(try seKey == key("3924ede1bd3140a5e6600880c30b3a717c8b726a300233b30e9684aadcf40ca9"))
        let responseTag = Array(try V.bytes(V.response)[35...])
        #expect(state.decryptAndHash(responseTag, key: seKey) != nil)
        #expect(state.hash.hex == "e1450d6bb0ab8e06a5cda35ff6c7ec232f7f2f6be0cc5f93433c43dc11abc66f")

        let (send, receive) = state.split()
        #expect(try send == key(V.clientToServerKey))
        #expect(try receive == key(V.serverToClientKey))
    }

    private func key(_ hex: String) throws -> SymmetricKey {
        SymmetricKey(data: try V.bytes(hex))
    }

    @Test("response를 받으면 세션이 생기고, 양방향 레코드가 벡터와 같다")
    func responseAndRecordVectors() throws {
        var session = try V.clientSession()
        for (plaintext, record) in V.clientRecords.prefix(3) {
            #expect(try session.seal(Array(plaintext.utf8)) == V.bytes(record))
        }
        for (plaintext, record) in V.serverRecords {
            #expect(try session.receive(V.bytes(record)) == Array(plaintext.utf8))
        }
    }

    @Test("response 뒤에 같이 온 바이트를 남은 바이트로 넘긴다")
    func remainderAfterResponse() throws {
        var handshake = try V.handshake()
        let record = try V.bytes(V.serverRecords[0].record)
        let received = try handshake.receive(V.bytes(V.response) + record)
        let result = try #require(received)
        #expect(result.remainder == record)
        var session = result.session
        #expect(try session.receive(result.remainder) == Array("server-0".utf8))
    }

    @Test("response가 한 바이트씩 와도 마지막 바이트에서 세션이 생긴다")
    func byteByByteResponse() throws {
        var handshake = try V.handshake()
        let response = try V.bytes(V.response)
        for byte in response.dropLast() {
            #expect(try handshake.receive([byte]) == nil)
        }
        let received = try handshake.receive([response[response.count - 1]])
        let result = try #require(received)
        #expect(result.remainder.isEmpty)
        // 세션을 돌려준 뒤에는 더 받지 않는다.
        #expect(throws: ControlTransportError.closed) { try handshake.receive([]) }
    }

    @Test("101 뒤 아무것도 오지 않았거나 response가 덜 왔으면 세션이 없다(이때의 EOF는 핸드셰이크 실패)")
    func noSessionBeforeFullResponse() throws {
        var handshake = try V.handshake()
        #expect(try handshake.receive([]) == nil)
        #expect(try handshake.receive(Array(V.bytes(V.response)[..<50])) == nil)
    }

    @Test("서버 error 메시지는 handshakeFailed이고, 그 뒤는 closed다")
    func serverError() throws {
        var handshake = try V.handshake()
        let message = Array("unexpected handshake message type".utf8)
        #expect(throws: ControlTransportError.handshakeFailed) {
            try handshake.receive([3] + UInt16(message.count).bigEndianBytes + message)
        }
        #expect(throws: ControlTransportError.closed) { try handshake.receive(V.bytes(V.response)) }
    }

    @Test("모르는 type이나 48이 아닌 길이는 malformed", arguments: [[0x04, 0x00, 0x30], [0x02, 0x00, 0x2F], [0x02, 0x01, 0x30]])
    func malformedResponse(_ header: [UInt8]) throws {
        var handshake = try V.handshake()
        #expect(throws: ControlTransportError.malformed) { try handshake.receive(header) }
    }

    @Test("response의 임시 키나 태그가 한 바이트라도 바뀌면 handshakeFailed")
    func tamperedResponse() throws {
        let response = try V.bytes(V.response)
        for index in 3..<response.count {
            var tampered = response
            tampered[index] ^= 0x01
            var handshake = try V.handshake()
            #expect(throws: ControlTransportError.handshakeFailed) { try handshake.receive(tampered) }
        }
    }

    @Test("버전은 initiation 머리와 프롤로그에 실린다. 다른 버전의 transcript로는 벡터 response가 열리지 않는다")
    func protocolVersion() throws {
        var handshake = try V.handshake(protocolVersion: 149)
        #expect(handshake.initiation.count == 101)
        #expect(Array(handshake.initiation[..<5]) == [0x00, 0x95, 0x01, 0x00, 0x60])
        // 임시 공개 키는 같고, 프롤로그가 섞인 암호문은 다르다.
        #expect(handshake.initiation[5..<37] == (try V.bytes(V.initiation))[5..<37])
        #expect(handshake.initiation[37...] != (try V.bytes(V.initiation))[37...])
        #expect(throws: ControlTransportError.handshakeFailed) { try handshake.receive(V.bytes(V.response)) }
    }

    @Test("서버 정적 키가 저차 점이면 initiation을 만들지 않고 handshakeFailed")
    func lowOrderServerKey() throws {
        let machine = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: V.bytes(V.clientMachinePrivate))
        #expect(throws: ControlTransportError.handshakeFailed) {
            try ControlHandshake(machineKey: machine, serverKey: .zero)
        }
    }

    @Test("서버 임시 키가 저차 점이면 handshakeFailed")
    func lowOrderServerEphemeral() throws {
        var handshake = try V.handshake()
        let response = [2, 0, 48] + [UInt8](repeating: 0, count: 48)
        #expect(throws: ControlTransportError.handshakeFailed) { try handshake.receive(response) }
    }

    @Test("시스템 난수 임시 키: 같은 장기 키로 만들어도 initiation이 매번 다르다")
    func freshEphemeral() throws {
        let machine = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: V.bytes(V.clientMachinePrivate))
        let server = try #require(MachinePublicKey(rawValue: V.bytes(V.serverStaticPublic)))
        let first = try ControlHandshake(machineKey: machine, serverKey: server)
        let second = try ControlHandshake(machineKey: machine, serverKey: server)
        #expect(first.initiation.count == 101)
        #expect(Array(first.initiation[..<5]) == [0x00, 0x94, 0x01, 0x00, 0x60])
        #expect(first.initiation != second.initiation)
    }
}
