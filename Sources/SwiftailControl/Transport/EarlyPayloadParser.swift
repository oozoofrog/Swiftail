import Foundation

/// Noise 평문 스트림 맨 앞에 올 수 있는 서버의 선행 메시지(early payload)를 걸러 낸다.
///
/// 서버가 보내는 평문의 첫 9바이트는 HTTP/2 SETTINGS 프레임 머리이거나, 매직 `ff ff ff 54 53`과 JSON 길이
/// (uint32 BE)로 된 early payload 머리다. 매직이면 그 길이만큼의 `tailcfg.EarlyNoise` JSON을 읽어 내고,
/// 아니면 9바이트를 포함한 모든 바이트를 그대로 HTTP/2에 넘긴다. 매직을 걸러 내지 못하면 HTTP/2 해석이
/// 깨지므로 서버가 보내지 않더라도 이 단계를 거친다.
///
/// JSON 해석은 Go의 `json.Unmarshal`(포인터 대상)을 따른다: `null`은 payload 없음, 모르는 필드는 무시,
/// `nodeKeyChallenge`의 접두사·길이·16진이 틀리면 실패. 빈 JSON(길이 0)도 실패다.
///
/// `docs/protocol-notes/control-transport.md` 3.7절, 4.7절 8단계
/// (출처: tailscale.com `control/ts2021/conn.go`의 `readHeader`, `tailcfg/tailcfg.go`의 `EarlyNoise`).
public struct EarlyPayloadParser: Sendable {
    /// 서버가 연결마다 보내는 선행 정보.
    public struct EarlyPayload: Sendable, Equatable {
        /// 클라이언트가 node 개인 키를 가졌음을 증명할 때 쓰라고 주는 일회용 공개 키.
        /// 필드가 없거나 `null`이거나 0 키면 `nil`이다.
        public var nodeKeyChallenge: ChallengePublicKey?
    }

    static let magic: [UInt8] = [0xFF, 0xFF, 0xFF, 0x54, 0x53]
    /// HTTP/2 프레임 머리와 같은 크기다.
    static let headerSize = 9
    static let maximumPayloadSize = 10 << 20

    private var buffer: [UInt8] = []
    private var isDone = false

    public init() {}

    /// 판단하기에 바이트가 모자라면 nil. 판단이 끝나면 (있었다면) 선행 메시지와 그 뒤의 바이트(HTTP/2의 것).
    ///
    /// - Throws: JSON 길이가 10MiB를 넘으면 `messageTooLarge`, JSON이 틀리면 `malformed`,
    ///   판단을 이미 돌려줬거나 실패한 뒤면 `closed`.
    public mutating func receive(_ plaintext: [UInt8]) throws(ControlTransportError) -> (payload: EarlyPayload?, remainder: [UInt8])? {
        guard !isDone else { throw .closed }
        buffer += plaintext
        guard buffer.count >= Self.headerSize else { return nil }

        guard buffer.starts(with: Self.magic) else {
            return finish(payload: nil, consumed: 0)
        }
        let length = Int(UInt32(bigEndianBytes: buffer[Self.magic.count..<Self.headerSize]))
        guard length <= Self.maximumPayloadSize else { throw fail(.messageTooLarge) }
        let end = Self.headerSize + length
        guard buffer.count >= end else { return nil }

        // `try?`를 쓰면 JSON `null`과 해석 실패가 똑같이 nil로 합쳐진다.
        let decoded: EarlyNoise?
        do {
            decoded = try JSONDecoder().decode(EarlyNoise?.self, from: Data(buffer[Self.headerSize..<end]))
        } catch {
            throw fail(.malformed)
        }
        let payload = decoded.map { EarlyPayload(nodeKeyChallenge: $0.nodeKeyChallenge.flatMap { $0.isZero ? nil : $0 }) }
        return finish(payload: payload, consumed: end)
    }

    private mutating func finish(payload: EarlyPayload?, consumed: Int) -> (payload: EarlyPayload?, remainder: [UInt8]) {
        isDone = true
        let remainder = Array(buffer[consumed...])
        buffer = []
        return (payload, remainder)
    }

    private mutating func fail(_ error: ControlTransportError) -> ControlTransportError {
        isDone = true
        buffer = []
        return error
    }
}

/// `tailcfg.EarlyNoise`의 JSON 모양. 와이어 해석에만 쓴다.
private struct EarlyNoise: Decodable {
    var nodeKeyChallenge: ChallengePublicKey?
}
