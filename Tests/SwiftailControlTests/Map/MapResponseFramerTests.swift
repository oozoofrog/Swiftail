// 맵 스트림 프레임(4바이트 리틀엔디언 길이 + JSON)과 임의 입력. docs/protocol-notes/control-map.md 3.1, 3.5.
// 무작위 입력은 고정 시드라 실패하면 그대로 재현된다.

import Foundation
import Testing

@testable import SwiftailControl

@Suite("맵 응답 프레이머")
struct MapResponseFramerTests {
    private let first = #"{"Node":{"ID":1},"Domain":"tail0001.ts.net"}"#
    private let second = #"{"KeepAlive":true}"#

    @Test("한 바이트씩 넣어도 프레임이 다 찬 순간에 하나씩 나온다")
    func byteByByte() throws {
        var framer = MapResponseFramer()
        let stream = frame(first) + frame(second)
        var responses: [MapResponse] = []
        for (index, byte) in stream.enumerated() {
            let output = try framer.receive([byte])
            if index == frame(first).count - 1 || index == stream.count - 1 {
                #expect(output.count == 1, "바이트 \(index)")
            } else {
                #expect(output.isEmpty, "바이트 \(index)")
            }
            responses += output
        }
        #expect(responses.map(\.keepAlive) == [false, true])
        #expect(responses.first?.domain == "tail0001.ts.net")
    }

    @Test("한 조각에 여러 프레임과 다음 프레임의 일부가 함께 와도 된다")
    func severalFramesInOneChunk() throws {
        var framer = MapResponseFramer()
        let third = frame(#"{"Domain":"x"}"#)
        let output = try framer.receive(frame(first) + frame(second) + third.prefix(6))
        #expect(output.count == 2)
        #expect(try framer.receive(Array(third.dropFirst(6))).map(\.domain) == ["x"])
        #expect(try framer.receive([]).isEmpty)
    }

    @Test("길이 접두가 8MiB를 넘으면 페이로드를 기다리지 않고 실패한다")
    func frameTooLarge() throws {
        let limit = MapResponseFramer.maximumFrameSize
        #expect(limit == 8 << 20)
        var framer = MapResponseFramer()
        #expect(throws: MapError.frameTooLarge) { try framer.receive(frame(first) + Self.header(limit + 1)) }
        // 오류 뒤에도 같은 오류다.
        #expect(throws: MapError.frameTooLarge) { try framer.receive([]) }

        var largest = MapResponseFramer()
        #expect(try largest.receive(Self.header(limit)).isEmpty)
        var maximum = MapResponseFramer()
        #expect(throws: MapError.frameTooLarge) { try maximum.receive([0xFF, 0xFF, 0xFF, 0xFF]) }
    }

    @Test("JSON이 아니거나 맵 응답이 아니면 malformed", arguments: ["", "{", "not json", "[]", "null", "1", #"{"Node":[]}"#])
    func malformed(_ payload: String) {
        var framer = MapResponseFramer()
        #expect(throws: MapError.malformed) { try framer.receive(frame(payload)) }
    }

    @Test("Go가 만든 맵 응답 한 프레임을 세션에 적용한다")
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
        #expect(netmap.tailnetLockEnabled == false)
    }

    @Test("무작위 바이트와 망가뜨린 JSON으로 죽지 않는다")
    func randomInput() throws {
        var random = SeededRandom(seed: 0x5157_1F7A_0000_0002)
        let seeds = [Array(TailcfgJSONTests.goMarshaledMapResponse.utf8), Array(first.utf8), Array(second.utf8)]
        var decoded = 0
        for round in 0..<3000 {
            var payload: [UInt8]
            if round.isMultiple(of: 3) {
                payload = (0..<Int.random(in: 0...64, using: &random)).map { _ in UInt8.random(in: 0...255, using: &random) }
            } else {
                // 올바른 JSON의 바이트를 몇 개 바꾸거나 지우거나 끼워 넣는다.
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
                // MapError만 나와야 한다(타입 있는 오류라 컴파일러가 보장한다). 죽지 않는 것이 이 시험의 전부다.
            }
        }
        #expect(decoded > 0)
    }

    private static func header(_ length: Int) -> [UInt8] {
        (0..<4).map { UInt8(truncatingIfNeeded: length >> (8 * $0)) }
    }
}
