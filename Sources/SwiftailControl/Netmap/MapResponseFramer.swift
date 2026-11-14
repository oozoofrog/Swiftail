import Foundation

/// 맵 스트림의 HTTP 본문을 맵 응답으로 자른다.
///
/// 프레임은 4바이트 리틀엔디언 길이 N과 N바이트의 JSON이다. 한 본문에 프레임이 끝없이 이어지고,
/// 프레임 경계는 HTTP/2 DATA 프레임 경계와 무관하다. 그래서 받은 바이트를 모아 두었다가 다 찬 프레임만
/// 해독한다. 길이 접두가 한도를 넘으면 그 바이트를 모으기 전에 실패한다.
///
/// 해독 전에 페이로드를 한 번 훑어 중첩 깊이(`maximumNestingDepth`)와 값의 수(`maximumValueCount`)를
/// 검사한다. 바이트 한도만으로는 재귀 해독의 스택과 해독 뒤의 메모리를 막지 못하기 때문이다.
///
/// 요청의 `Compress`를 비워 두므로 페이로드는 비압축 JSON이다. `shortcut:` zstd 해제기는 없다. 운영 서버가
/// 비압축을 받아 주지 않으면 그때 추가한다(계약 "프레이밍과 증분 적용").
/// `docs/protocol-notes/control-map.md` 3.1, 3.5.
public struct MapResponseFramer: Sendable {
    /// 프레임 하나의 최대 페이로드 크기(8MiB). Go의 256MiB보다 훨씬 낮다. iOS 패킷 터널 확장의 메모리 한도(약 50MiB,
    /// 첫 사용처의 보고치) 때문이다.
    ///
    /// 근거는 해독의 최고치다. 프레임을 다 모은 뒤 해독하므로, 바이트 버퍼와 해독한 값이 한꺼번에 메모리에 있다. 정상
    /// 자료로 한도를 채울 때 해독 결과는 64MiB 프레임에서 약 110MB(`maximumValueCount`의 잰 값)였고, 같은 비율로 8MiB는
    /// 약 14MB다. 한도 50MiB 안에 들면서 유휴 상주(20MiB 이하 목표)에 얹어도 넘치지 않는 크기다. 피어 1,000개
    /// tailnet의 비압축 전체 맵이 수 MB라는 것은 추정이며 확인하지 못했다. 이 한도를 넘는 tailnet은 맵을 받지 못하므로
    /// 실기기 측정에서 `frameTooLarge`가 보이면 조정한다(`docs/contracts/SwiftailTunnel.md` 동작 M, 총괄 확인 필요 T5).
    static let maximumFrameSize = 8 << 20

    /// 페이로드 JSON의 최대 중첩 깊이(최상위 객체가 1). 넘으면 `malformed`.
    ///
    /// `Decodable` 해독은 재귀라서 깊은 JSON은 스택을 다 쓰고 프로세스를 죽인다(오류로 잡을 수 없다).
    /// - 실제 tailcfg의 깊이: Go 자료(`map-sessions.json`) 73응답의 최대는 7이다. 가장 깊은 경로는
    ///   `PacketFilter[].CapGrant[].CapMap.<속성>[]`에 인자 JSON이 붙는 9 + 인자의 깊이다.
    /// - 스택: 보조 스레드의 기본 스택(512KiB)에서 Debug 빌드로 `CapMap` 인자 배열 중첩을 해독하면
    ///   깊이 210은 견디고 215에서 스택이 넘친다(1단계에 약 2.4KiB). 64단계는 약 155KiB로 그 스택의
    ///   3분의 1이 안 되어, 호출하는 쪽이 이미 스택을 쓰고 있어도 여유가 있다.
    static let maximumNestingDepth = 64

    /// 페이로드 하나에 든 값(배열 원소 + 객체 멤버)의 최대 수. 넘으면 `malformed`.
    ///
    /// 해독한 값의 메모리는 JSON 바이트와 비례하지 않는다. `{}` 3바이트가 `Node` 하나(stride 392바이트)가
    /// 되므로 프레임 한도 안에 수백만 개의 노드가 들어간다(8MiB ÷ 3 ≈ 280만). 그래서 값의 수로 해독 뒤 메모리를 묶는다.
    /// - 정상 크기: Go 자료의 노드 하나는 값 8~29개(바이트 223~729)다. 피어 10,000명의 전체 맵은
    ///   노드에 29 × 10,000 = 290,000, 프로필(값 약 6개)에 60,000으로 약 350,000이다. 1,000,000은
    ///   그 약 2.9배이고, 노드 하나에 값 100개를 써도 피어 10,000명이 들어간다.
    /// - 잰 메모리(Debug, 해독 전후 phys_footprint): Go 자료의 가장 큰 노드(값 29개) 100,000개는 노드당
    ///   약 3.2KB(값당 약 110바이트)이고, 값 하나로 가장 크게 부풀리는 빈 `Node` `{}`(stride 392바이트)
    ///   100,000개는 노드당 약 1.3KB다. 해독기의 중간 표현과 배열 확장이 포함된 수치다.
    /// - 최악의 메모리: 1,000,000 × 1.3KB ≈ 1.3GB(바이트 한도만 있을 때는 8MiB ÷ 3 × 1.3KB ≈ 3.6GB).
    ///   정상 자료로 64MiB를 채우면 약 110MB였고, 8MiB는 약 14MB다. 정상 자료는 50MB 확장 한도
    ///   안이지만 최악은 그보다 크므로, 이 한도는 해독을 끝까지 마칠 수 있는 크기로 묶을 뿐 확장의 메모리를 보장하지
    ///   않는다. 제어 서버는 Noise로 인증된 상대다.
    static let maximumValueCount = 1_000_000

    private static let headerSize = 4

    /// 아직 다 차지 않은 프레임의 바이트.
    private var buffer: [UInt8] = []
    /// 실패한 뒤의 오류. 있으면 바이트를 더 모으지 않고 같은 오류를 낸다.
    private var failure: MapError?

    public init() {}

    /// 받은 바이트를 넣고 완성된 응답들을 순서대로 돌려준다. 덜 온 프레임은 안에 둔다.
    /// 오류가 나면 스트림을 버려야 한다. 같은 호출에서 앞서 완성된 응답도 돌려주지 않지만, 새 스트림이
    /// 전체 맵부터 다시 보내므로 잃는 상태는 없다. 실패하면 모은 바이트를 버리고, 다시 부르면 같은 오류가 난다.
    public mutating func receive(_ bytes: [UInt8]) throws(MapError) -> [MapResponse] {
        if let failure { throw failure }
        do {
            return try decodeFrames(appending: bytes)
        } catch {
            failure = error
            buffer = []
            throw error
        }
    }

    private mutating func decodeFrames(appending bytes: [UInt8]) throws(MapError) -> [MapResponse] {
        buffer += bytes
        var responses: [MapResponse] = []
        var start = 0
        while buffer.count - start >= Self.headerSize {
            let length = buffer[start..<start + Self.headerSize].reversed().reduce(0) { $0 << 8 | Int($1) }
            guard length <= Self.maximumFrameSize else { throw .frameTooLarge }
            let payloadStart = start + Self.headerSize
            guard buffer.count - payloadStart >= length else { break }
            let payload = buffer[payloadStart..<payloadStart + length]
            try Self.checkShape(of: payload)
            do {
                responses.append(try JSONDecoder().decode(MapResponse.self, from: Data(payload)))
            } catch {
                throw .malformed
            }
            start = payloadStart + length
        }
        buffer.removeFirst(start)
        return responses
    }

    /// 해독 전에 JSON 바이트를 한 번 훑어 중첩 깊이와 값의 수가 한도 안인지 본다.
    ///
    /// 문법은 검사하지 않는다(해독기가 한다). 문자열 안의 괄호·쉼표는 세지 않으며, 이스케이프된 `\"`는
    /// 문자열을 끝내지 않는다. UTF-8의 여러 바이트 문자는 0x80 이상이라 ASCII 구분자와 섞이지 않는다.
    /// 값의 수는 컨테이너마다 "첫 값 + 쉼표 수"로 센다.
    ///
    /// 0 바이트가 있으면 거절한다. `JSONDecoder`는 UTF-16·UTF-32로 쓴 JSON도 받는데, 그 바이트를 UTF-8로
    /// 훑으면 따옴표와 괄호를 다르게 읽어 이 검사가 해독기와 어긋난다. UTF-16·UTF-32의 JSON은 구분자마다
    /// 0 바이트를 갖고, UTF-8의 JSON에는 0 바이트가 올 수 없으므로(제어 문자는 이스케이프해야 한다)
    /// 이것으로 UTF-8만 남는다.
    static func checkShape(of json: ArraySlice<UInt8>) throws(MapError) {
        var depth = 0
        var values = 0
        var inString = false
        var escaped = false
        var awaitingFirstValue = false
        for byte in json {
            guard byte != 0 else { throw .malformed }
            if inString {
                if escaped {
                    escaped = false
                } else if byte == UInt8(ascii: "\\") {
                    escaped = true
                } else if byte == UInt8(ascii: "\"") {
                    inString = false
                }
                continue
            }
            switch byte {
            case UInt8(ascii: " "), UInt8(ascii: "\t"), UInt8(ascii: "\n"), UInt8(ascii: "\r"):
                continue
            case UInt8(ascii: "]"), UInt8(ascii: "}"):
                awaitingFirstValue = false
                depth -= 1
                continue
            default:
                break
            }
            if awaitingFirstValue {
                awaitingFirstValue = false
                values += 1
            }
            switch byte {
            case UInt8(ascii: "\""):
                inString = true
            case UInt8(ascii: "["), UInt8(ascii: "{"):
                depth += 1
                guard depth <= maximumNestingDepth else { throw .malformed }
                awaitingFirstValue = true
            case UInt8(ascii: ","):
                values += 1
            default:
                break
            }
            guard values <= maximumValueCount else { throw .malformed }
        }
    }
}
