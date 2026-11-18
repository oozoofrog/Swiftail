// Contract unit test 2: Empty records, splitting at the 4,077-byte boundary, fragmented records, closed after a tampered record, and limits.

import Testing

@testable import SwiftailControl

@Suite("Control Noise records")
struct ControlSessionTests {
    private typealias V = TransportVectors

    @Test("Skips empty plaintext records but consumes a nonce (counter 4 after the empty record at counter 3)")
    func emptyRecordConsumesNonce() throws {
        var server = try V.serverSession()
        var received: [UInt8] = []
        for (_, record) in V.clientRecords {
            received += try server.receive(V.bytes(record))
        }
        #expect(received == Array("client-0client-1client-2after-empty".utf8))
    }

    @Test("Empty plaintext creates no record and consumes no counter")
    func sealEmpty() throws {
        var client = try V.clientSession()
        #expect(try client.seal([]).isEmpty)
        #expect(try client.seal(Array("client-0".utf8)) == V.bytes(V.clientRecords[0].record))
    }

    @Test("4,077 plaintext bytes make one record (4,096 bytes), and 4,078 bytes split into two")
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

    @Test("Opens only complete records even when they arrive one byte at a time")
    func byteByByte() throws {
        var client = try V.clientSession()
        var received: [UInt8] = []
        let records = try V.serverRecords.flatMap { try V.bytes($0.record) }
        for byte in records {
            received += try client.receive([byte])
        }
        #expect(received == Array("server-0server-1server-2".utf8))
    }

    @Test("A tampered record yields authenticationFailed, after which the session is closed in both directions")
    func tamperedRecordCloses() throws {
        var record = try V.bytes(V.serverRecords[0].record)
        record[record.count - 1] ^= 0x01
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.authenticationFailed) { try client.receive(record) }
        #expect(throws: ControlTransportError.closed) { try client.receive(V.bytes(V.serverRecords[0].record)) }
        #expect(throws: ControlTransportError.closed) { try client.seal([1]) }
    }

    @Test("Opens records only in counter order (receiving counter 1 first fails)")
    func outOfOrder() throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.authenticationFailed) { try client.receive(V.bytes(V.serverRecords[1].record)) }
    }

    @Test("Ciphertext shorter than the tag yields authenticationFailed")
    func shorterThanTag() throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.authenticationFailed) { try client.receive([4, 0, 5, 1, 2, 3, 4, 5]) }
    }

    @Test("A non-record type yields malformed", arguments: [UInt8(1), 2, 3, 0, 0xFF])
    func wrongType(_ type: UInt8) throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.malformed) { try client.receive([type, 0, 24]) }
        #expect(throws: ControlTransportError.closed) { try client.receive([]) }
    }

    @Test("A length over 4,096 bytes including the header yields messageTooLarge without waiting for the body")
    func tooLarge() throws {
        var client = try V.clientSession()
        #expect(throws: ControlTransportError.messageTooLarge) { try client.receive([4, 0x0F, 0xFE]) }
    }

    @Test("Keeps the incomplete record after a complete record until the next receive")
    func partialTail() throws {
        var client = try V.clientSession()
        let first = try V.bytes(V.serverRecords[0].record)
        let second = try V.bytes(V.serverRecords[1].record)
        #expect(try client.receive(first + second[..<10]) == Array("server-0".utf8))
        #expect(try client.receive(Array(second[10...])) == Array("server-1".utf8))
    }
}
