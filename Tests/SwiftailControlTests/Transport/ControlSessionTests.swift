// 계약 단위 2 시험: 빈 레코드, 4,077바이트 경계 분할, 조각난 레코드, 변조된 레코드 뒤 closed, 한도.

import Testing

@testable import SwiftailControl

@Suite("제어 Noise 레코드")
struct ControlSessionTests {
    private typealias V = TransportVectors

    @Test("빈 평문 레코드는 건너뛰되 nonce를 소비한다(카운터 3의 빈 레코드 뒤 카운터 4)")
    func emptyRecordConsumesNonce() throws {
        var server = try V.serverSession()
        var received: [UInt8] = []
        for (_, record) in V.clientRecords {
            received += try server.receive(V.bytes(record))
        }
        #expect(received == Array("client-0client-1client-2after-empty".utf8))
    }

    @Test("빈 평문은 레코드를 만들지 않고 카운터도 쓰지 않는다")
    func sealEmpty() throws {
        var client = try V.clientSession()
        #expect(try client.seal([]).isEmpty)
        #expect(try client.seal(Array("client-0".utf8)) == V.bytes(V.clientRecords[0].record))
    }

    @Test("평문 4,077바이트는 레코드 하나(4,096바이트), 4,078바이트는 둘로 나뉜다")
    func splitAtMaximumPlaintext() throws {
        var client = try V.clientSession()
        var server = try V.serverSession()

        let exact = (0..<4077).map { UInt8(truncatingIfNeeded: $0) }
        let one = try client.seal(exact)
        #expect(one.count == 4096)
        #expect(Array(one[..<3]) == [0x04, 0x0F, 0xFD])
        #expect(try server.receive(one) == exact)

        let over = exact + [0xAB]
        let two = try client.seal(over)
        #expect(two.count == 4096 + 3 + 1 + 16)
        #expect(Array(two[4096..<4099]) == [0x04, 0x00, 0x11])
        #expect(try server.receive(two) == over)
    }

    @Test("레코드가 한 바이트씩 와도 완성된 것만 연다")
    func byteByByte() throws {
        var client = try V.clientSession()
        var received: [UInt8] = []
        let records = try V.serverRecords.flatMap { try V.bytes($0.record) }
        for byte in records {
            received += try client.receive([byte])
        }
        #expect(received == Array("server-0server-1server-2".utf8))
    }

    @Test("변조된 레코드는 authenticationFailed이고, 그 뒤 세션은 양방향 모두 closed다")
    func tamperedRecordCloses() throws {
        var record = try V.bytes(V.serverRecords[0].record)
        record[record.count - 1] ^= 0x01
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.authenticationFailed) { try client.receive(record) }
        #expect(throws: ControlTransportError.closed) { try client.receive(V.bytes(V.serverRecords[0].record)) }
        #expect(throws: ControlTransportError.closed) { try client.seal([1]) }
    }

    @Test("레코드는 카운터 순서대로만 열린다(카운터 1 레코드를 먼저 받으면 실패)")
    func outOfOrder() throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.authenticationFailed) { try client.receive(V.bytes(V.serverRecords[1].record)) }
    }

    @Test("태그보다 짧은 암호문은 authenticationFailed")
    func shorterThanTag() throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.authenticationFailed) { try client.receive([4, 0, 5, 1, 2, 3, 4, 5]) }
    }

    @Test("레코드가 아닌 type은 malformed", arguments: [UInt8(1), 2, 3, 0, 0xFF])
    func wrongType(_ type: UInt8) throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.malformed) { try client.receive([type, 0, 24]) }
        #expect(throws: ControlTransportError.closed) { try client.receive([]) }
    }

    @Test("머리를 포함해 4,096바이트를 넘는 길이는 본문을 기다리지 않고 messageTooLarge")
    func tooLarge() throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.messageTooLarge) { try client.receive([4, 0x0F, 0xFE]) }
    }

    @Test("완성된 레코드 뒤의 덜 온 레코드는 다음 receive까지 남겨 둔다")
    func partialTail() throws {
        var client = try V.clientSession()
        let first = try V.bytes(V.serverRecords[0].record)
        let second = try V.bytes(V.serverRecords[1].record)
        #expect(try client.receive(first + second[..<10]) == Array("server-0".utf8))
        #expect(try client.receive(Array(second[10...])) == Array("server-1".utf8))
    }
}
