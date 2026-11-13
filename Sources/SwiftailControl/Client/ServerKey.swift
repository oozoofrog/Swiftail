import Foundation

/// 제어 서버의 Noise 공개 키를 `GET <serverURL>/key?v=148`로 얻는다.
///
/// Noise가 아닌 평범한 HTTP(S) 요청이다. `https://`이면 URLSession의 기본 인증서 검증을 그대로 쓴다.
/// 응답은 `{"legacyPublicKey":"mkey:…","publicKey":"mkey:…"}`이고 `publicKey`만 쓴다. 0이면 Noise를 모르는
/// 옛 서버이므로 실패한다. 본문은 64KiB까지만 읽는다. testcontrol은 이 요청에서 Noise 키 쌍을 만들므로
/// `/ts2021`보다 먼저 불러야 한다.
///
/// `docs/protocol-notes/control-transport.md` 3.8, 4.1.
enum ServerKey {
    static let maximumBodySize = 64 << 10

    static func fetch(for endpoint: ControlEndpoint) async throws(ControlError) -> MachinePublicKey {
        guard let url = endpoint.url(path: "/key?v=148") else {
            throw .invalidConfiguration("서버 URL로 /key 주소를 만들지 못했다")
        }
        var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 10)
        request.httpMethod = "GET"
        var body: [UInt8] = []
        let response: URLResponse
        do {
            let (bytes, received) = try await URLSession.shared.bytes(for: request)
            response = received
            for try await byte in bytes {
                guard body.count < maximumBodySize else { throw ControlError.connection("/key 응답이 64KiB를 넘는다") }
                body.append(byte)
            }
        } catch let error as ControlError {
            throw error
        } catch {
            throw .connection("/key 요청 실패(코드 \((error as NSError).code))")
        }
        guard let status = (response as? HTTPURLResponse)?.statusCode else {
            throw .connection("/key 응답이 HTTP가 아니다")
        }
        guard status == 200 else { throw .http(status: status) }
        return try parse(body)
    }

    /// `/key` 응답 본문에서 Noise 키를 꺼낸다.
    static func parse(_ body: [UInt8]) throws(ControlError) -> MachinePublicKey {
        guard let response = try? JSONDecoder().decode(Response.self, from: Data(body)) else {
            throw .connection("/key 응답을 해석하지 못했다")
        }
        guard !response.publicKey.isZero else { throw .connection("제어 서버가 너무 오래되었다(Noise 키 없음)") }
        return response.publicKey
    }

    private struct Response: Decodable {
        var publicKey: MachinePublicKey
    }
}
