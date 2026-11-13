/// 서버의 업그레이드 응답 머리를 읽고 검증한다.
///
/// 성공하면 `101 Switching Protocols`와 `Upgrade: tailscale-control-protocol`이 온다. 그 바로 뒤부터
/// Noise response가 이어지며, 한 번의 TCP 읽기에 HTTP 머리와 Noise 바이트가 함께 들어올 수 있다.
/// 그래서 머리 뒤에 이미 도착한 바이트를 돌려줘 `ControlHandshake`에 넘기게 한다.
///
/// 클라이언트는 상태와 `Upgrade` 값만 본다(`Connection`은 검사하지 않는다). `Upgrade` 값은 정확히
/// 같아야 한다. 머리의 줄 끝은 CRLF만 받는다(Go 서버가 그렇게 보낸다).
///
/// `docs/protocol-notes/control-transport.md` 3.6절, 4.4절 2단계 3~4
/// (출처: tailscale.com `control/controlhttp/client.go`).
public struct UpgradeResponseParser: Sendable {
    /// `Upgrade` 헤더 값.
    static let protocolName = "tailscale-control-protocol"
    /// 빈 줄까지 포함한 응답 머리의 한도.
    static let maximumHeadSize = 16 * 1024

    private var buffer: [UInt8] = []
    private var isDone = false

    public init() {}

    /// 머리가 아직 다 오지 않았으면 nil. 다 왔으면 남은 바이트(Noise 계층의 것).
    ///
    /// - Throws: 101이 아니면 `upgradeRejected`, 형식이 틀리거나 `Upgrade` 값이 다르면 `malformed`,
    ///   머리가 16KiB를 넘으면 `messageTooLarge`, 머리를 이미 돌려줬거나 실패한 뒤면 `closed`.
    public mutating func receive(_ bytes: [UInt8]) throws(ControlTransportError) -> [UInt8]? {
        guard !isDone else { throw .closed }
        // 앞서 받은 끝 3바이트와 이어서 빈 줄이 완성될 수 있다.
        let searchStart = max(0, buffer.count - 3)
        buffer += bytes

        let searchEnd = min(buffer.count, Self.maximumHeadSize)
        guard let headEnd = Self.endOfHead(in: buffer, from: searchStart, to: searchEnd) else {
            guard buffer.count < Self.maximumHeadSize else {
                isDone = true
                throw .messageTooLarge
            }
            return nil
        }

        isDone = true
        let head = buffer[..<(headEnd - 4)]
        let remainder = Array(buffer[headEnd...])
        buffer = []
        try Self.validate(head)
        return remainder
    }

    /// `\r\n\r\n` 바로 뒤의 인덱스. `searchEnd`를 넘는 곳은 보지 않는다.
    private static func endOfHead(in bytes: [UInt8], from searchStart: Int, to searchEnd: Int) -> Int? {
        let firstEnd = searchStart + 4
        guard firstEnd <= searchEnd else { return nil }
        for end in firstEnd...searchEnd where bytes[(end - 4)..<end].elementsEqual(crlfcrlf) {
            return end
        }
        return nil
    }

    /// 상태 줄과 헤더 줄들을 검증한다. 상태를 먼저 본다: 101이 아니면 나머지 형식과 무관하게 거절이다.
    private static func validate(_ head: ArraySlice<UInt8>) throws(ControlTransportError) {
        var lines = head.split(separator: crlf, omittingEmptySubsequences: false)
        let status = try statusCode(of: lines.removeFirst())
        guard status == 101 else { throw .upgradeRejected(status: status) }

        var upgrade: ArraySlice<UInt8>?
        for line in lines {
            let field = try HeaderField(parsing: line)
            // 같은 이름이 여럿이면 Go의 `Header.Get`처럼 첫 값을 쓴다.
            if upgrade == nil, field.hasName("upgrade") {
                upgrade = field.value
            }
        }
        guard let upgrade, upgrade.elementsEqual(protocolName.utf8) else { throw .malformed }
    }

    /// `HTTP/1.x SP 3DIGIT [SP reason]`의 상태 코드.
    private static func statusCode(of line: ArraySlice<UInt8>) throws(ControlTransportError) -> Int {
        let parts = line.split(separator: UInt8(ascii: " "), maxSplits: 2, omittingEmptySubsequences: false)
        guard parts.count >= 2,
              parts[0].count == 8,
              parts[0].starts(with: "HTTP/1.".utf8),
              let minor = parts[0].last, isDigit(minor),
              parts[1].count == 3,
              parts[1].allSatisfy(isDigit)
        else { throw .malformed }
        return parts[1].reduce(0) { $0 * 10 + Int($1 - UInt8(ascii: "0")) }
    }

    private static func isDigit(_ byte: UInt8) -> Bool {
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
    }

    private static let crlf: [UInt8] = [0x0D, 0x0A]
    private static let crlfcrlf: [UInt8] = [0x0D, 0x0A, 0x0D, 0x0A]
}

/// `name: value` 한 줄. 이름은 HTTP token 문자만, 값은 앞뒤 공백·탭을 걷어 낸다.
private struct HeaderField {
    let name: ArraySlice<UInt8>
    let value: ArraySlice<UInt8>

    init(parsing line: ArraySlice<UInt8>) throws(ControlTransportError) {
        guard let colon = line.firstIndex(of: UInt8(ascii: ":")) else { throw .malformed }
        name = line[..<colon]
        guard !name.isEmpty, name.allSatisfy(Self.isTokenCharacter) else { throw .malformed }

        var value = line[(colon + 1)...]
        while let first = value.first, Self.isWhitespace(first) { value = value.dropFirst() }
        while let last = value.last, Self.isWhitespace(last) { value = value.dropLast() }
        self.value = value
    }

    /// 이름은 대소문자를 가리지 않는다. `lowercased`는 소문자 ASCII여야 한다.
    func hasName(_ lowercased: String) -> Bool {
        name.count == lowercased.utf8.count
            && zip(name, lowercased.utf8).allSatisfy { a, b in a | 0x20 == b }
    }

    private static func isWhitespace(_ byte: UInt8) -> Bool {
        byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t")
    }

    /// RFC 9110 5.6.2 token.
    private static func isTokenCharacter(_ byte: UInt8) -> Bool {
        switch byte {
        case UInt8(ascii: "0")...UInt8(ascii: "9"), UInt8(ascii: "a")...UInt8(ascii: "z"), UInt8(ascii: "A")...UInt8(ascii: "Z"):
            true
        default:
            Array("!#$%&'*+-.^_`|~".utf8).contains(byte)
        }
    }
}
