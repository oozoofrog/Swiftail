import Foundation
import SwiftailIO

/// `POST /machine/set-dns`: ACME DNS-01의 TXT 레코드를 제어 서버에 올린다.
///
/// 맵 스트림과 같은 `ControlClient`가 `run()` 동안 쥔 연결 위의 새 HTTP/2 스트림으로 보낸다. 같은 Noise 클라이언트라는
/// 것은 Go와 같지만, 같은 물리 연결이라는 것은 Swiftail의 구현 선택이고 서버가 요구한다는 근거는 없다.
///
/// Go와 다른 Swiftail의 선택(계약 `docs/contracts/SwiftailHost.md` 동작 D2·D3):
/// - 연결이 없으면(다시 잇는 중) 설 때까지 기다린다. 기다림과 응답을 합쳐 60초다. Go는 `not connected`로 곧바로 실패한다.
/// - 200이 아니면 상태 코드만 싣고 본문은 읽지 않는다(로그에도 남기지 않는다). Go는 본문을 200 code point까지 싣는다.
/// - 200의 본문은 4KiB까지 읽고 JSON 객체여야 한다. Go는 1MiB까지 읽고 `null`도 받는다.
///
/// 이름과 값은 오류 문자열과 로그에 넣지 않는다(동작 K2·K3).
///
/// `docs/protocol-notes/whois-certs-state.md` 3.2 (출처: tailscale.com `control/controlclient/direct.go` `setDNSNoise`,
/// `ipn/ipnlocal/local.go` `SetDNS`, BSD-3-Clause).
extension ControlClient {
    /// 200 응답 본문의 한도(계약 한도 표).
    static let maximumSetDNSResponseSize = 4 << 10

    /// TXT 레코드 하나를 올려 달라고 요청하고 제어 서버의 답을 기다린다.
    ///
    /// 이름이 어떤 레코드여야 하는지(자기 cert 도메인의 `_acme-challenge.`)는 부르는 쪽(`TailnetNode.setDNS`)이 본다.
    ///
    /// - Throws: 이름이나 값이 비었으면 `invalidConfiguration`. 등록 전이면(node 키 없음) 곧바로 `connection`.
    ///   60초 안에 연결이 서지 않거나 답이 없거나, 연결이 끊기거나, 200 본문이 4KiB를 넘거나 JSON 객체가 아니면
    ///   `connection`. 200이 아니면 `http(status:)`.
    package func setDNS(name: String, value: String) async throws(ControlError) {
        guard !name.isEmpty, !value.isEmpty else { throw .invalidConfiguration("set-dns의 이름과 값은 비어 있으면 안 된다") }
        guard nodePublicKey?.isZero == false else { throw .connection("등록 전에는 set-dns를 보낼 수 없다") }
        let limit = timeouts.setDNS
        do {
            try await withTimeout(limit) { try await self.sendSetDNS(name: name, value: value) }
        } catch let error as ControlError {
            throw error
        } catch is TimeoutError {
            throw .connection("set-dns가 \(limit) 안에 끝나지 않았다")
        } catch {
            throw .connection("set-dns가 취소되었다")
        }
    }

    private func sendSetDNS(name: String, value: String) async throws(ControlError) {
        let connection = try await waitForConnection()
        // 기다리는 동안 키가 바뀌었을 수 있으므로 보낼 때의 키를 쓴다.
        guard let nodeKey = nodePublicKey, !nodeKey.isZero else { throw .connection("등록 전에는 set-dns를 보낼 수 없다") }
        let body: [UInt8]
        do {
            body = Array(try JSONEncoder().encode(SetDNSRequest(nodeKey: nodeKey, name: name, value: value)))
        } catch {
            throw .connection("set-dns 요청을 JSON으로 만들지 못했다")
        }
        var reader = try await connection.responseStream(
            to: connection.jsonRequest("POST", path: "/machine/set-dns", nodeKey: nodeKey),
            body: body
        )
        // 읽개를 버리면 스트림이 취소된다(RST_STREAM). 거절의 본문은 읽지 않는다.
        guard reader.status == 200 else { throw .http(status: reader.status) }
        var collected: [UInt8] = []
        while let chunk = try await reader.nextChunk() {
            guard collected.count + chunk.count <= Self.maximumSetDNSResponseSize else {
                throw .connection("set-dns 응답 본문이 한도(\(Self.maximumSetDNSResponseSize)바이트)를 넘는다")
            }
            collected += chunk
        }
        guard (try? JSONDecoder().decode(SetDNSResponse.self, from: Data(collected))) != nil else {
            throw .connection("set-dns 응답이 JSON 객체가 아니다")
        }
    }

    /// 등록을 마친 연결이 설 때까지 기다린다. 기다리는 Task가 취소되면 `connection`을 던진다.
    private func waitForConnection() async throws(ControlError) -> ControlConnection {
        while true {
            if let activeConnection { return activeConnection }
            let (wakeups, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            let id = nextConnectionWaiter
            nextConnectionWaiter += 1
            connectionWaiters[id] = continuation
            for await _ in wakeups { break }
            connectionWaiters[id] = nil
            guard !Task.isCancelled else { throw .connection("취소되었다") }
        }
    }
}
