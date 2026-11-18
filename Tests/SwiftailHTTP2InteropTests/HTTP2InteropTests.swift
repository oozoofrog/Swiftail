import Foundation
import Testing
import SwiftailHTTP2

private let downloadSizes = [0, 1, 16_383, 16_384, 16_385, 65_535, 65_536, 1_048_576, 5_000_000]

private func pattern(_ count: Int) -> [UInt8] { (0..<count).map { UInt8($0 % 251) } }

/// Reports the first mismatch instead of dumping entire large arrays into the failure message.
private func verify(_ response: H2Driver.Response, status: Int = 200, body: [UInt8]) throws {
    try #require(response.status == status)
    try #require(response.closed)
    try #require(response.resetCode == nil)
    guard response.body.count == body.count else {
        throw H2InteropFailure("Body length: actual \(response.body.count), expected \(body.count)")
    }
    if let offset = body.indices.first(where: { response.body[$0] != body[$0] }) {
        throw H2InteropFailure("Body byte at offset \(offset): actual \(response.body[offset]), expected \(body[offset])")
    }
}

private func download(_ driver: H2Driver, size: Int, timeout: Duration = .seconds(60)) async throws {
    let id = try await driver.request("/bytes?size=\(size)")
    let head = try await driver.head(id)
    try #require(head.status == 200)
    _ = try await driver.data(id, count: size, timeout: timeout)
    try verify(await driver.closed(id, timeout: timeout), body: pattern(size))
}

private func echo(_ driver: H2Driver, size: Int) async throws {
    let body = pattern(size)
    let id = try await driver.request("/echo", method: "POST", body: body)
    try verify(await driver.closed(id), body: body)
}

private func headerCases(_ driver: H2Driver) async throws {
    var smallIDs: [HTTP2StreamID] = []
    for (count, size) in [(4, 20), (4, 20), (96, 400)] {
        let id = try await driver.request("/headers?count=\(count)&size=\(size)")
        if count == 4 { smallIDs.append(id) }
        let response = try await driver.closed(id)
        try verify(response, body: [])
        let expectedValue = String(decoding: (0..<size).map { UInt8(97 + $0 % 26) }, as: UTF8.self)
        let testHeaders = response.headers.filter { $0.name.hasPrefix("x-test-") }
        try #require(testHeaders.count == count)
        for index in 0..<count {
            try #require(testHeaders.filter { $0.name == "x-test-\(index)" }.map(\.value) == [expectedValue])
        }
    }
    let frames = await driver.receivedFrames()
    try #require(frames.contains { $0.type == 9 }, "The large response must use CONTINUATION on the wire")
    let sizes = smallIDs.map { id in
        frames.filter { $0.stream == id.rawValue && ($0.type == 1 || $0.type == 9) }.reduce(0) { $0 + $1.length }
    }
    try #require(sizes.count == 2 && sizes[1] > 0 && sizes[1] < sizes[0], "Dynamic indexing must make the second response smaller on the wire")
}

@Suite("Go HTTP/2 TCP interop", .enabled(if: h2serverBinary != nil, "Skipping Go HTTP/2 interop tests because SWIFTAIL_H2SERVER is missing"), .timeLimit(.minutes(4)))
struct HTTP2InteropTests {
    @Test("Status, body, and clean closure of a small GET")
    func small() async throws {
        try await withH2Server { driver, _ in
            let id = try await driver.request("/small")
            try verify(await driver.closed(id), body: Array("ok".utf8))
        }
    }

    @Test("Final status code and empty body", arguments: [204, 404, 500])
    func status(code: Int) async throws {
        try await withH2Server { driver, _ in
            let id = try await driver.request("/status?code=\(code)")
            try verify(await driver.closed(id), status: code, body: [])
        }
    }

    @Test("Every byte at receive window and DATA boundaries", arguments: downloadSizes)
    func bytes(size: Int) async throws {
        try await withH2Server { driver, _ in try await download(driver, size: size) }
    }

    @Test("POST frame splitting and bidirectional flow control", arguments: [0, 1, 65_535, 65_536, 1_048_576, 4_000_000])
    func post(size: Int) async throws {
        try await withH2Server { driver, _ in try await echo(driver, size: size) }
    }

    @Test("Huffman coding, CONTINUATION, and dynamic index reuse on the same connection")
    func headers() async throws {
        try await withH2Server { driver, _ in try await headerCases(driver) }
    }

    @Test("Multiplexes an endless stream with another request and reuses the connection after cancellation")
    func multiplexAndCancel() async throws {
        try await withH2Server { driver, _ in
            let stream = try await driver.request("/stream?count=0&intervalMs=50")
            let head = try await driver.head(stream)
            try #require(head.status == 200)
            var streamed = try await driver.data(stream, count: 2)
            for round in 0..<3 {
                let previousCount = streamed.body.count
                let small = try await driver.request("/small")
                let bytes = try await driver.request("/bytes?size=\(65_536 + round)")
                let body = pattern(65_536 + round)
                let post = try await driver.request("/echo", method: "POST", body: body)
                try verify(await driver.closed(small), body: Array("ok".utf8))
                try verify(await driver.closed(bytes), body: body)
                try verify(await driver.closed(post), body: body)
                streamed = try await driver.data(stream, count: previousCount + 2)
                try #require(!streamed.closed)
                let expected = Array((0..<streamed.body.count).map { "\($0)\n" }.joined().utf8)
                try #require(Array(expected.prefix(streamed.body.count)) == streamed.body)
            }
            await driver.cancel(stream)
            let next = try await driver.request("/small")
            try verify(await driver.closed(next), body: Array("ok".utf8))
            let frames = await driver.receivedFrames()
            try #require(frames.contains { $0.stream == next.rawValue && $0.type == 1 })
        }
    }

    @Test("Runs 20 requests with different body sizes concurrently on one connection")
    func concurrentRequests() async throws {
        try await withH2Server { driver, _ in
            var requests: [(HTTP2StreamID, Int)] = []
            for index in 0..<20 {
                let size = index * 16_385
                requests.append((try await driver.request("/bytes?size=\(size)"), size))
            }
            // Start all 20 before awaiting responses. The actor continues receiving.
            for (id, size) in requests {
                try verify(await driver.closed(id), body: pattern(size))
            }
        }
    }

    @Test("GOAWAY blocks new requests and lets in-flight streams finish")
    func goAway() async throws {
        try await withH2Server { driver, server in
            let id = try await driver.request("/stream?count=12&intervalMs=50")
            _ = try await driver.data(id, count: 2)
            try await server.command("goaway")
            let event = try await driver.serverGoAway()
            try #require(event.code == 0)
            try #require(event.lastStreamID.rawValue >= id.rawValue)
            do {
                _ = try await driver.request("/small")
                throw H2InteropFailure("Accepted a new request after GOAWAY")
            } catch let error as HTTP2Error {
                try #require(error == .connectionClosed)
            }
            try verify(await driver.closed(id), body: Array((0..<12).map { "\($0)\n" }.joined().utf8))
        }
    }

    @Test("Preserves the body and headers when TCP is split into one-byte or seven-byte chunks", arguments: [1, 7])
    func fragmentedTCP(fragmentSize: Int) async throws {
        try await withH2Server(fragmentSize: fragmentSize) { driver, _ in
            for size in downloadSizes { try await download(driver, size: size, timeout: .seconds(180)) }
            try await headerCases(driver)
        }
    }
}
