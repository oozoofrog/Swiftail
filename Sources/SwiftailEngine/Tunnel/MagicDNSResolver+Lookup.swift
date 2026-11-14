// 이름 색인 규칙은 Tailscale의 `ipn/ipnlocal/node_backend.go`(`addNodeNameLocked`, `nodeByFQDNLocked`, `magicDNSAddrs`,
// `magicDNSPTR`, `dnsConfigForNetmap`의 `ExtraRecords`)와 `types/netmap/netmap.go` `MagicDNSSuffixOfNodeName`
// (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)을 따른다. 규칙만 옮겼고 코드는 Swift로 새로 썼다.

import SwiftailBase
import SwiftailControl

/// 이름 ↔ 주소 찾기: `ExtraRecords` 호스트 표가 먼저, 그다음 netmap의 노드(self와 피어). 노트 4.2.1.
extension MagicDNSResolver {
    /// `ExtraRecords`에서 온 이름 하나와 그 주소들.
    struct HostRecord: Sendable {
        /// 비교에 쓰는 소문자 이름.
        let key: DNSMessage.Name
        /// PTR 답에 쓰는 이름(받은 대소문자 그대로).
        let name: DNSMessage.Name
        /// 받은 순서의 주소. 같은 이름의 레코드는 이어 붙인다.
        var addresses: [IPAddress]
    }

    /// 노드가 IPv4를 가져도 피어의 AAAA에 답하게 하는 자기 노드 속성(Go `nodecap.MagicDNSPeerAAAA`).
    static let peerAAAACapability = "magicdns-aaaa"

    /// `Type`이 `""`·`A`·`AAAA`이고 값이 IP 주소인 레코드만 호스트 표에 넣는다. 이름이 될 수 없는 것은 버린다.
    static func hostRecords(from records: [DNSRecord]) -> [HostRecord] {
        var hosts: [HostRecord] = []
        for record in records where ["", "A", "AAAA"].contains(record.type) {
            guard let address = IPAddress(record.value), let name = DNSMessage.Name(record.name) else { continue }
            let key = name.lowercased()
            if let index = hosts.firstIndex(where: { $0.key == key }) {
                hosts[index].addresses.append(address)
            } else {
                hosts.append(HostRecord(key: key, name: name, addresses: [address]))
            }
        }
        return hosts
    }

    /// 소문자 이름의 주소들. nil이면 모르는 이름이고, 빈 배열이면 이름은 있으나 답할 주소가 없다.
    func addresses(for name: DNSMessage.Name) -> [IPAddress]? {
        if let host = hosts.first(where: { $0.key == name }) {
            return host.addresses
        }
        guard let netmap, let node = node(named: name, in: netmap), !node.addresses.isEmpty else { return nil }
        return Self.answerAddresses(of: node, in: netmap)
    }

    /// 주소의 이름(PTR 대상). 서비스 IP, 호스트 표, 노드의 자기 주소(한 주소짜리 접두) 순으로 찾는다.
    func name(for address: IPAddress) -> DNSMessage.Name? {
        if ServiceIP.contains(address) {
            return Self.symbolicName
        }
        if let host = hosts.first(where: { $0.addresses.contains(address) }) {
            return host.name
        }
        guard let netmap else { return nil }
        let owns = { (node: Node) in
            node.addresses.contains { $0.address == address && $0.length == $0.address.bytes.count * 8 }
        }
        // Go 색인은 self 다음 피어 순으로 채워 뒤의 것이 덮으므로 뒤에서부터 찾는다.
        guard let node = netmap.peers.last(where: owns) ?? (owns(netmap.selfNode) ? netmap.selfNode : nil) else { return nil }
        return DNSMessage.Name(node.name)
    }

    /// 이름이 가리키는 노드(Go `nodeByFQDNLocked`).
    ///
    /// 노드마다 두 키가 있다: 끝 점을 뗀 소문자 `Name`, 그리고 그것이 MagicDNS 접미사로 끝나면 접미사를 뗀 짧은 이름.
    /// `Proxied`(MagicDNS)가 꺼져 있으면 점 없는 이름은 찾지 않는다. 같은 키를 가진 노드가 여럿이면 Go 색인처럼
    /// 피어 목록의 뒤쪽이 이긴다.
    private func node(named name: DNSMessage.Name, in netmap: Netmap) -> Node? {
        guard netmap.dnsConfig?.proxied == true || name.labels.count > 1 else { return nil }
        let dot = UInt8(ascii: ".")
        let key = Array(name.labels.joined(separator: [dot]))
        let suffix = Self.magicDNSSuffix(of: netmap.selfNode.name)
        // 짧은 이름 키가 `key`인 노드는 정식 키가 `key.접미사`인 노드다.
        let qualifiedKey = suffix.isEmpty ? nil : key + [dot] + suffix
        let matches = { (node: Node) -> Bool in
            let canonical = Self.canonicalKey(of: node.name)
            if canonical.elementsEqual(key) { return true }
            guard let qualifiedKey else { return false }
            return canonical.elementsEqual(qualifiedKey)
        }
        return netmap.peers.last(where: matches) ?? (matches(netmap.selfNode) ? netmap.selfNode : nil)
    }

    /// 답할 주소(Go `magicDNSAddrs`, 결정 D7). 자기가 IPv6 전용이면 대상의 IPv6만. 아니면 대상의 주소 전부이되,
    /// 대상에 IPv4가 있고 자기 노드에 `magicdns-aaaa`가 없으면 IPv6를 뺀다(피어가 IPv6를 제대로 하는지 보장하지 않으므로).
    private static func answerAddresses(of node: Node, in netmap: Netmap) -> [IPAddress] {
        let selfAddresses = netmap.selfNode.addresses
        let selfIPv6Only = !selfAddresses.contains { $0.address.isIPv4 } && selfAddresses.contains { !$0.address.isIPv4 }
        let wantsAAAA = netmap.selfNode.capMap[peerAAAACapability] != nil
        let targetHasIPv4 = node.addresses.contains { $0.address.isIPv4 }
        return node.addresses.map(\.address).filter { address in
            selfIPv6Only ? !address.isIPv4 : address.isIPv4 || !targetHasIPv4 || wantsAAAA
        }
    }

    /// 노드 이름의 비교 키: 끝 점 하나를 떼고 ASCII 소문자로(Go `strings.ToLower(strings.TrimSuffix(name, "."))`).
    private static func canonicalKey(of name: String) -> some Collection<UInt8> {
        name.utf8.dropLast(name.utf8.last == UInt8(ascii: ".") ? 1 : 0).lazy.map(DNSMessage.Name.lowercased)
    }

    /// MagicDNS 접미사(소문자, 앞뒤 점 없음): 자기 노드 이름의 앞뒤 점을 떼고 첫 레이블을 뗀 나머지.
    /// 점이 없으면 이름 전체다(Go `MagicDNSSuffixOfNodeName`).
    private static func magicDNSSuffix(of selfName: String) -> [UInt8] {
        let dot = UInt8(ascii: ".")
        var bytes = Array(selfName.utf8.map(DNSMessage.Name.lowercased))
        while bytes.first == dot { bytes.removeFirst() }
        while bytes.last == dot { bytes.removeLast() }
        guard let firstDot = bytes.firstIndex(of: dot) else { return bytes }
        return Array(bytes[(firstDot + 1)...])
    }
}
