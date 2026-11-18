import SwiftailBase
import SwiftailEngine

/// A table of node keys and names (FQDNs) for data plane peers. Attaches names to path events and looks up peer paths by name.
///
/// The name is netmap `Node.name` with one trailing dot removed (`rd-mac-1a2b3c4d.tail0001.ts.net`). Lookup removes one
/// trailing dot and compares ASCII case-insensitively. If two peers share a name, the lower node ID wins. The node
/// rebuilds it for each netmap. Contract `docs/contracts/SwiftailEngine.md`, “Changes in M4” N6.
struct PeerDirectory: Sendable, Equatable {
    struct Entry: Sendable, Equatable {
        var key: NodePublicKey
        /// The name with the trailing dot removed. May be empty.
        var name: String
    }

    /// Ascending node ID order.
    private(set) var entries: [Entry] = []

    init() {}

    /// - Parameter peers: Peers installed in the data plane (`EnginePeer.peers(in:at:)`, ascending node ID order).
    init(peers: [EnginePeer]) {
        entries = peers.map { peer in
            Entry(key: peer.key, name: peer.name.hasSuffix(".") ? String(peer.name.dropLast()) : peer.name)
        }
    }

    /// The peer's name. Returns nil if absent from the table or empty.
    func name(of key: NodePublicKey) -> String? {
        entries.first { $0.key == key }.map(\.name).flatMap { $0.isEmpty ? nil : $0 }
    }

    /// The key of the peer named `fqdn`. If two peers share the name, the lower node ID wins.
    func key(named fqdn: String) -> NodePublicKey? {
        let wanted = Self.comparable(fqdn)
        guard !wanted.isEmpty else { return nil }
        return entries.first { Self.comparable($0.name) == wanted }?.key
    }

    /// The table with peers present only in `other` appended. Used only to attach old names to path events for departing peers.
    func keepingNames(of other: PeerDirectory) -> PeerDirectory {
        let present = Set(entries.map(\.key))
        var merged = self
        merged.entries += other.entries.filter { !present.contains($0.key) }
        return merged
    }

    /// The name used for comparison, with one trailing dot removed and only uppercase ASCII converted to lowercase. DNS
    /// names are ASCII case-insensitive.
    private static func comparable(_ name: String) -> String {
        let trimmed = name.hasSuffix(".") ? name.dropLast() : Substring(name)
        let lowered = trimmed.unicodeScalars.map { scalar in
            ("A"..."Z").contains(scalar) ? Unicode.Scalar(scalar.value + 32) ?? scalar : scalar
        }
        return String(String.UnicodeScalarView(lowered))
    }
}
