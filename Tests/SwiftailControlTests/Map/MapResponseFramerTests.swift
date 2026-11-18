// Map stream frames (4-byte little-endian length + JSON) and arbitrary input. docs/protocol-notes/control-map.md §3.1, §3.5.
// Random input uses a fixed seed so failures can be reproduced exactly.

import Foundation
import Testing

@testable import SwiftailControl

@Suite("Map response framer")
struct MapResponseFramerTests {
    private let first = #"{"Node":{"ID":1},"Domain":"tail0001.ts.net"}"#
    private let second = #"{"KeepAlive":true}"#

    @Test("Emits one frame as soon as it is complete, even one byte at a time")
    func byteByByte() throws {
        var framer = MapResponseFramer()
        let stream = frame(first) + frame(second)
        var responses: [MapResponse] = []
        for (index, byte) in stream.enumerated() {
            let output = try framer.receive([byte])
            if index == frame(first).count - 1 || index == stream.count - 1 {
                #expect(output.count == 1, "Byte \(index)")
            } else {
                #expect(output.isEmpty, "Byte \(index)")
            }
            responses += output
        }
        #expect(responses.map(\.keepAlive) == [false, true])
        #expect(responses.first?.domain == "tail0001.ts.net")
    }

    @Test("One chunk can contain multiple frames and part of the next frame")
    func severalFramesInOneChunk() throws {
        var framer = MapResponseFramer()
        let third = frame(#"{"Domain":"x"}"#)
        let output = try framer.receive(frame(first) + frame(second) + third.prefix(6))
        #expect(output.count == 2)
        #expect(try framer.receive(Array(third.dropFirst(6))).map(\.domain) == ["x"])
        #expect(try framer.receive([]).isEmpty)
    }

    @Test("A length prefix over 8MiB fails without waiting for the payload")
    func frameTooLarge() throws {
        let limit = MapResponseFramer.maximumFrameSize
        #expect(limit == 8 << 20)
        var framer = MapResponseFramer()
        #expect(throws: MapError.frameTooLarge) { try framer.receive(frame(first) + Self.header(limit + 1)) }
        // Returns the same error after failure.
        #expect(throws: MapError.frameTooLarge) { try framer.receive([]) }

        var largest = MapResponseFramer()
        #expect(try largest.receive(Self.header(limit)).isEmpty)
        var maximum = MapResponseFramer()
        #expect(throws: MapError.frameTooLarge) { try maximum.receive([0xFF, 0xFF, 0xFF, 0xFF]) }
    }

    @Test("Non-JSON input or JSON that is not a map response yields malformed", arguments: ["", "{", "not json", "[]", "null", "1", #"{"Node":[]}"#])
    func malformed(_ payload: String) {
        var framer = MapResponseFramer()
        #expect(throws: MapError.malformed) { try framer.receive(frame(payload)) }
    }

    @Test("Applies one Go-generated map response frame to a session")
    func goMarshaledThroughSession() throws {
        var framer = MapResponseFramer()
        var session = MapSession()
        let responses = try framer.receive(frame(TailcfgJSONTests.goMarshaledMapResponse))
        let response = try #require(responses.first)
        let netmap = try #require(try session.apply(response, receivedAt: receivedAt).netmap)
        #expect(netmap.selfNode.capMap.keys.sorted() == ["cap/old", "cap/x", "cap/y"])
        #expect(netmap.peers.map(\.id) == [2])
        #expect(netmap.peers.first?.online == true)
        #expect(netmap.domain == "tail0001.ts.net")
        #expect(netmap.packetFilter.count == 1)
        #expect(netmap.userProfiles.keys.sorted() == [100])
        #expect(netmap.derpMap?.regions?.keys.sorted() == [1])
        #expect(netmap.tailnetLock == TailnetLockStatus())
    }

    @Test("Random bytes and corrupted JSON do not cause a crash")
    func randomInput() throws {
        var random = SeededRandom(seed: 0x5157_1F7A_0000_0002)
        let seeds = [Array(TailcfgJSONTests.goMarshaledMapResponse.utf8), Array(first.utf8), Array(second.utf8)]
        var decoded = 0
        for round in 0..<3000 {
            var payload: [UInt8]
            if round.isMultiple(of: 3) {
                payload = (0..<Int.random(in: 0...64, using: &random)).map { _ in UInt8.random(in: 0...255, using: &random) }
            } else {
                // Change, delete, or insert a few bytes in valid JSON.
                payload = seeds[round % seeds.count]
                for _ in 0..<Int.random(in: 1...4, using: &random) where !payload.isEmpty {
                    let index = Int.random(in: 0..<payload.count, using: &random)
                    let byte = Array(#"{}[]",:0-9.etrunlfa\"#.utf8).randomElement(using: &random) ?? 0
                    switch Int.random(in: 0...2, using: &random) {
                    case 0: payload[index] = byte
                    case 1: payload.remove(at: index)
                    default: payload.insert(byte, at: index)
                    }
                }
            }
            var framer = MapResponseFramer()
            var session = MapSession()
            do {
                for response in try framer.receive(frame(payload)) {
                    _ = try session.apply(response, receivedAt: receivedAt)
                    decoded += 1
                }
            } catch {
                // Only MapError is allowed (the compiler guarantees it through typed throws). The test checks only that there is no crash.
            }
        }
        #expect(decoded > 0)
    }

    private static func header(_ length: Int) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: length >> (8 * $0)) }
    }
}
