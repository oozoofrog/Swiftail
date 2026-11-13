import Foundation
import SwiftailHTTP2

/// 연결 위의 두 가지 주고받기: "요청 하나를 보내 응답 전체를 받는다"와 "응답 본문을 흘려 받는다".
/// 등록·상태 올리기·맵 스트림은 모두 이 둘로 쓴다.
///
/// 본문이 있는 요청은 JSON이고 `Content-Type: application/json`을 붙인다. node 키가 있으면 부하 분산 힌트
/// `Ts-Lb: nodekey:…`를 붙인다. 응답 본문은 서버가 보낸 신뢰할 수 없는 입력이므로 한도를 넘으면 읽기를 멈추고
/// 스트림을 버린다.
///
/// `docs/protocol-notes/control-transport.md` 4.7의 3~5.
extension ControlConnection {
    /// 다 받은 응답.
    struct Response: Sendable {
        var status: Int
        var headers: [HeaderField]
        var body: [UInt8]
    }

    /// JSON 본문을 실은 요청.
    nonisolated func jsonRequest(_ method: String, path: String, nodeKey: NodePublicKey?) -> HTTP2ClientConnection.Request {
        var headers = [HeaderField("content-type", "application/json")]
        if let nodeKey, !nodeKey.isZero {
            headers.append(HeaderField("ts-lb", nodeKey.description))
        }
        return HTTP2ClientConnection.Request(method: method, path: path, authority: authority, headers: headers)
    }

    /// 요청을 보내고 본문까지 다 받는다. 본문이 `limit`바이트를 넘으면 실패한다.
    nonisolated func response(
        to request: HTTP2ClientConnection.Request,
        body: [UInt8]?,
        limit: Int
    ) async throws(ControlError) -> Response {
        var reader = try await responseStream(to: request, body: body)
        var collected: [UInt8] = []
        while let chunk = try await reader.nextChunk() {
            guard collected.count + chunk.count <= limit else {
                throw .connection("응답 본문이 한도(\(limit)바이트)를 넘는다")
            }
            collected += chunk
        }
        return Response(status: reader.status, headers: reader.headers, body: collected)
    }

    /// 요청을 보내고 응답 머리까지 기다린다. 본문은 돌려준 읽개로 흘려 받는다.
    nonisolated func responseStream(
        to request: HTTP2ClientConnection.Request,
        body: [UInt8]?
    ) async throws(ControlError) -> ResponseReader {
        var iterator = try await send(request, body: body).makeAsyncIterator()
        guard case let .head(status, headers) = try await ResponseReader.next(&iterator) else {
            throw .connection("응답 머리 없이 스트림이 끝났다")
        }
        return ResponseReader(status: status, headers: headers, iterator: iterator)
    }
}

/// 머리를 받은 응답의 본문을 조각으로 읽는다. 조각의 경계는 HTTP/2 DATA 경계이며 뜻이 없다.
struct ResponseReader {
    let status: Int
    let headers: [HeaderField]
    fileprivate var iterator: ControlConnection.ResponseParts.AsyncIterator

    fileprivate init(status: Int, headers: [HeaderField], iterator: ControlConnection.ResponseParts.AsyncIterator) {
        self.status = status
        self.headers = headers
        self.iterator = iterator
    }

    /// 머리 이름(소문자)의 첫 값.
    func header(_ name: String) -> String? {
        headers.first { $0.name == name }?.value
    }

    /// 다음 본문 조각. 본문이 끝나면 nil.
    mutating func nextChunk() async throws(ControlError) -> [UInt8]? {
        switch try await Self.next(&iterator) {
        case .data(let bytes): bytes
        case .head: throw .connection("응답 머리가 두 번 왔다")
        case nil: nil
        }
    }

    fileprivate static func next(
        _ iterator: inout ControlConnection.ResponseParts.AsyncIterator
    ) async throws(ControlError) -> ControlConnection.ResponsePart? {
        let part: ControlConnection.ResponsePart?
        do {
            part = try await iterator.next()
        } catch {
            throw error as? ControlError ?? .connection("응답을 읽지 못했다")
        }
        // 기다리던 Task가 취소되면 스트림은 오류 없이 끝난다. 정상 종료(END_STREAM)와 구별해 잘린 본문을
        // 온전한 응답으로 받아들이지 않는다.
        if part == nil, Task.isCancelled { throw .connection("취소되었다") }
        return part
    }
}
