import SwiftailBase

/// 양 끝을 포함하는 주소 범위. 필터 규칙의 주소 표현(`*`, CIDR, `a-b`, 단일 주소)을 모두 이 하나로 나타낸다.
///
/// Go는 `a-b` 범위를 접두 목록으로 풀지만, 여기서는 범위 그대로 견준다. 넓은 범위를 풀 때 생기는
/// 접두 수의 폭증이 없고, 포함 여부의 답은 같다.
///
/// `docs/protocol-notes/netmap-engine.md` 4.4의 주소 문자열 표.
struct AddressRange: Sendable, Equatable {
    /// 네트워크 바이트 순서의 아래 끝과 위 끝. 길이(4 또는 16)가 같고 `lower ≤ upper`다.
    private let lower: [UInt8]
    private let upper: [UInt8]

    private init(lower: [UInt8], upper: [UInt8]) {
        self.lower = lower
        self.upper = upper
    }

    /// 주소 하나.
    init(_ address: IPAddress) {
        lower = address.bytes
        upper = address.bytes
    }

    /// 접두가 덮는 범위: 호스트 비트를 모두 0으로 한 주소부터 모두 1로 한 주소까지.
    init(_ prefix: IPPrefix) {
        lower = prefix.address.bytes
        upper = prefix.address.bytes.enumerated().map { index, byte in
            let networkBits = min(max(prefix.length - index * 8, 0), 8)
            return byte | UInt8(truncatingIfNeeded: 0xFF >> networkBits)
        }
    }

    /// 두 주소 사이. 주소 종류가 다르거나 역순이면 `nil`.
    init?(from lower: IPAddress, through upper: IPAddress) {
        guard lower.bytes.count == upper.bytes.count,
              !upper.bytes.lexicographicallyPrecedes(lower.bytes)
        else { return nil }
        self.lower = lower.bytes
        self.upper = upper.bytes
    }

    /// 주소가 범위 안에 있는지. 주소 종류가 다르면 `false`.
    func contains(_ address: IPAddress) -> Bool {
        address.bytes.count == lower.count
            && !address.bytes.lexicographicallyPrecedes(lower)
            && !upper.lexicographicallyPrecedes(address.bytes)
    }
}

extension AddressRange {
    /// 필터 규칙의 주소 표현 하나를 해석한다. 해석할 수 없으면 빈 목록이다(그 항목만 버린다).
    ///
    /// Go `parseIPSet`과 같은 순서로 본다: `*` → `cap:` → `/`가 있으면 CIDR → `-`가 정확히 하나면 범위 →
    /// 단일 주소. CIDR의 호스트 비트가 남아 있으면 조용히 지우지 않고 버린다.
    static func ranges(parsing text: String) -> [AddressRange] {
        if text == "*" {
            return [everything(byteCount: 4), everything(byteCount: 16)]
        }
        // shortcut: `cap:` 출발지(노드 capability로 맞추기)는 M3에서 지원하지 않는다. 목적지의 `cap:`는 Go도 오류다.
        if text.hasPrefix("cap:") {
            return []
        }
        if text.contains("/") {
            guard let prefix = IPPrefix(text),
                  IPAddress(String(text.prefix { $0 != "/" })) == prefix.address
            else { return [] }
            return [AddressRange(prefix)]
        }
        let ends = text.split(separator: "-", omittingEmptySubsequences: false)
        if ends.count == 2 {
            guard let lower = IPAddress(String(ends[0])),
                  let upper = IPAddress(String(ends[1])),
                  let range = AddressRange(from: lower, through: upper)
            else { return [] }
            return [range]
        }
        guard let address = IPAddress(text) else { return [] }
        return [AddressRange(address)]
    }

    /// 한 주소 종류의 모든 주소. `*`의 절반이다.
    private static func everything(byteCount: Int) -> AddressRange {
        AddressRange(lower: [UInt8](repeating: 0, count: byteCount), upper: [UInt8](repeating: 0xFF, count: byteCount))
    }
}
