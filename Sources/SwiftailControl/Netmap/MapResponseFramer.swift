import Foundation

/// 맵 스트림의 HTTP 본문을 맵 응답으로 자른다.
///
/// 프레임은 4바이트 리틀엔디언 길이 N과 N바이트의 JSON이다. 한 본문에 프레임이 끝없이 이어지고,
/// 프레임 경계는 HTTP/2 DATA 프레임 경계와 무관하다. 그래서 받은 바이트를 모아 두었다가 다 찬 프레임만
/// 해독한다. 길이 접두가 한도를 넘으면 그 바이트를 모으기 전에 실패한다.
///
/// 요청의 `Compress`를 비워 두므로 페이로드는 비압축 JSON이다. `shortcut:` zstd 해제기는 없다. 운영 서버가
/// 비압축을 받아 주지 않으면 그때 추가한다(계약 "프레이밍과 증분 적용").
/// `docs/protocol-notes/control-map.md` 3.1, 3.5.
public struct MapResponseFramer: Sendable {
    /// 프레임 하나의 최대 페이로드 크기(64MiB). Go의 256MiB보다 낮다. iOS 확장의 메모리 한도 때문이다.
    static let maximumFrameSize = 64 << 20

    private static let headerSize = 4

    /// 아직 다 차지 않은 프레임의 바이트.
    private var buffer: [UInt8] = []

    public init() {}

    /// 받은 바이트를 넣고 완성된 응답들을 순서대로 돌려준다. 덜 온 프레임은 안에 둔다.
    /// 오류가 나면 스트림을 버려야 한다. 같은 호출에서 앞서 완성된 응답도 돌려주지 않지만, 새 스트림이
    /// 전체 맵부터 다시 보내므로 잃는 상태는 없다. 이 값을 다시 쓰면 같은 오류가 난다.
    public mutating func receive(_ bytes: [UInt8]) throws(MapError) -> [MapResponse] {
        buffer += bytes
        var responses: [MapResponse] = []
        var start = 0
        while buffer.count - start >= Self.headerSize {
            let length = buffer[start..<start + Self.headerSize].reversed().reduce(0) { $0 << 8 | Int($1) }
            guard length <= Self.maximumFrameSize else {
                buffer.removeFirst(start)
                throw .frameTooLarge
            }
            let payloadStart = start + Self.headerSize
            guard buffer.count - payloadStart >= length else { break }
            let payload = Data(buffer[payloadStart..<payloadStart + length])
            do {
                responses.append(try JSONDecoder().decode(MapResponse.self, from: payload))
            } catch {
                buffer.removeFirst(start)
                throw .malformed
            }
            start = payloadStart + length
        }
        buffer.removeFirst(start)
        return responses
    }
}
