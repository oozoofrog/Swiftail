import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// 데이터면 피어의 node 키와 이름(FQDN)의 표. 경로 사건에 이름을 붙이고, 이름으로 피어의 경로를 찾는다.
///
/// 이름은 netmap `Node.name`에서 끝의 점 하나를 뗀 것이다(`rd-mac-1a2b3c4d.tail0001.ts.net`). 찾을 때는 끝의 점 하나를
/// 떼고 ASCII 대소문자를 무시해 비교하며, 같은 이름이 둘이면 node ID가 작은 쪽이다. 노드가 netmap마다 새로 만든다.
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N6.
struct PeerDirectory: Sendable, Equatable {
    struct Entry: Sendable, Equatable {
        var key: NodePublicKey
        /// 끝의 점을 뗀 이름. 비어 있을 수 있다.
        var name: String
    }

    /// node ID 오름차순.
    private(set) var entries: [Entry] = []

    init() {}

    /// - Parameter peers: 데이터면에 올린 피어(`EnginePeer.peers(in:at:)`, node ID 오름차순).
    init(netmap: Netmap, peers: [EnginePeer]) {
        entries = peers.map { peer in
            let name = netmap.peers.first { $0.key == peer.key }?.name ?? ""
            return Entry(key: peer.key, name: name.hasSuffix(".") ? String(name.dropLast()) : name)
        }
    }

    /// 이 피어의 이름. 표에 없거나 이름이 비었으면 nil.
    func name(of key: NodePublicKey) -> String? {
        entries.first { $0.key == key }.map(\.name).flatMap { $0.isEmpty ? nil : $0 }
    }

    /// 이름이 `fqdn`인 피어의 키. 같은 이름이 둘이면 node ID가 작은 쪽이다.
    func key(named fqdn: String) -> NodePublicKey? {
        let wanted = Self.comparable(fqdn)
        guard !wanted.isEmpty else { return nil }
        return entries.first { Self.comparable($0.name) == wanted }?.key
    }

    /// `other`에만 있는 피어를 뒤에 덧붙인 표. 빠지는 피어의 경로 사건에 옛 이름을 붙이는 동안만 쓴다.
    func keepingNames(of other: PeerDirectory) -> PeerDirectory {
        var merged = self
        merged.entries += other.entries.filter { old in !entries.contains { $0.key == old.key } }
        return merged
    }

    /// 비교용 이름: 끝의 점 하나를 떼고 ASCII 대문자만 소문자로 바꾼다(DNS 이름은 ASCII 대소문자를 구분하지 않는다).
    private static func comparable(_ name: String) -> String {
        let trimmed = name.hasSuffix(".") ? name.dropLast() : Substring(name)
        let lowered = trimmed.unicodeScalars.map { scalar in
            ("A"..."Z").contains(scalar) ? Unicode.Scalar(scalar.value + 32) ?? scalar : scalar
        }
        return String(String.UnicodeScalarView(lowered))
    }
}
