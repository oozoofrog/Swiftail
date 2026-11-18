import SwiftailBase

/// An inclusive address range. Represents every filter rule address expression (`*`, CIDR, `a-b`, and single addresses).
///
/// Go expands an `a-b` range into a list of prefixes. Here the range is compared directly, avoiding the explosion in
/// prefix count when expanding a wide range while giving the same membership result.
///
/// The address string table in `docs/protocol-notes/netmap-engine.md` 4.4.
struct AddressRange: Sendable, Equatable {
    /// The lower and upper endpoints in network byte order. They have the same length (4 or 16) and `lower ≤ upper`.
    private let lower: [UInt8]
    private let upper: [UInt8]

    private init(lower: [UInt8], upper: [UInt8]) {
        self.lower = lower
        self.upper = upper
    }

    /// A single address.
    init(_ address: IPAddress) {
        lower = address.bytes
        upper = address.bytes
    }

    /// The range covered by a prefix, from the address with all host bits set to 0 to the one with all host bits set to 1.
    init(_ prefix: IPPrefix) {
        lower = prefix.address.bytes
        upper = prefix.address.bytes.enumerated().map { index, byte in
            let networkBits = min(max(prefix.length - index * 8, 0), 8)
            return byte | UInt8(truncatingIfNeeded: 0xFF >> networkBits)
        }
    }

    /// The range between two addresses. Returns `nil` if they are from different families or reversed.
    init?(from lower: IPAddress, through upper: IPAddress) {
        guard lower.bytes.count == upper.bytes.count,
              !upper.bytes.lexicographicallyPrecedes(lower.bytes)
        else { return nil }
        self.lower = lower.bytes
        self.upper = upper.bytes
    }

    /// Whether the address is in the range. Returns `false` for a different address family.
    func contains(_ address: IPAddress) -> Bool {
        address.bytes.count == lower.count
            && !address.bytes.lexicographicallyPrecedes(lower)
            && !upper.lexicographicallyPrecedes(address.bytes)
    }
}

extension AddressRange {
    /// Parses one filter rule address expression. If it cannot be parsed, returns an empty list, dropping only that item.
    ///
    /// Uses the same order as Go `parseIPSet`. `*` → `cap:` → CIDR if `/` is present → range if exactly one `-` is present →
    /// single address. Rejects a CIDR with host bits set instead of silently clearing them.
    static func ranges(parsing text: String) -> [AddressRange] {
        if text == "*" {
            return [everything(byteCount: 4), everything(byteCount: 16)]
        }
        // shortcut: M3 does not support `cap:` sources (matching by node capability). A `cap:` destination is also an error in Go.
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

    /// All addresses in one address family. Half of `*`.
    private static func everything(byteCount: Int) -> AddressRange {
        AddressRange(lower: [UInt8](repeating: 0, count: byteCount), upper: [UInt8](repeating: 0xFF, count: byteCount))
    }
}
