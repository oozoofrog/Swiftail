// 이름 해석 규칙은 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `net/tsdial/tsdial.go`(`resolveAddr`), `net/tsdial/dnsmap.go`(`canonMapKey`),
// `ipn/ipnlocal/node_backend.go`(`addNodeNameLocked`, `updateNodeByNameLocked`), `ipn/ipnlocal/resolve.go`
// (`resolveMagicDNS`, `nodeAddrForNetwork`), `types/netmap/netmap.go`(`MagicDNSSuffixOfNodeName`),
// `util/dnsname/dnsname.go`(`HasSuffix`, `TrimSuffix`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl

extension Netmap {
    /// `connect(to:port:)`의 `host`를 주소로 바꾼다(계약 `docs/contracts/SwiftailNetstack.md` 동작 A2 ②, TCP 노트 6.3 2).
    ///
    /// IP 주소면 그대로다. 아니면 소문자로 바꾸고 끝 점 하나를 뗀 이름을 자기 노드와 피어의 이름에서 찾는다: FQDN, 그리고
    /// MagicDNS 접미사(자기 이름의 첫 레이블 뒤)를 뗀 짧은 이름. 같은 이름이 여럿이면 Go의 표처럼 나중 것(자기 노드 다음에
    /// 피어를 node ID 순으로)이 이긴다. 찾은 노드의 주소 가운데 IPv4를 먼저, 없으면 IPv6을 고른다. `ExtraRecords`와
    /// tailnet 밖의 이름(시스템 DNS)은 찾지 않는다(계약 제외 표).
    ///
    /// - Returns: 찾지 못했거나 그 노드에 주소가 없으면 nil.
    func address(ofHost host: String) -> IPAddress? {
        if let address = IPAddress(host) { return address }
        let wanted = Self.canonicalName(host)
        guard !wanted.isEmpty else { return nil }
        let suffix = Self.magicDNSSuffix(ofNodeName: selfNode.name)

        var match: Node?
        for node in [selfNode] + peers.sorted(by: { $0.id < $1.id }) where !node.name.isEmpty {
            let name = Self.canonicalName(node.name)
            if name == wanted || Self.trimmingSuffix(suffix, from: name) == wanted {
                match = node
            }
        }
        guard let addresses = match?.addresses.map(\.address) else { return nil }
        return addresses.first(where: \.isIPv4) ?? addresses.first
    }

    /// Go `canonMapKey`: 끝 점 하나를 떼고 소문자로.
    private static func canonicalName(_ name: String) -> String {
        (name.hasSuffix(".") ? String(name.dropLast()) : name).lowercased()
    }

    /// Go `MagicDNSSuffixOfNodeName`: 양 끝의 점을 떼고 첫 레이블 뒤의 나머지. 점이 없으면 이름 그대로.
    static func magicDNSSuffix(ofNodeName name: String) -> String {
        let trimmed = name.trimmingDots
        guard let dot = trimmed.firstIndex(of: ".") else { return trimmed }
        return String(trimmed[trimmed.index(after: dot)...])
    }

    /// Go `dnsname.TrimSuffix`: `name`이 `.suffix`로 끝나면 그것을 뗀 짧은 이름. 아니면 nil(짧은 이름이 없다).
    private static func trimmingSuffix(_ suffix: String, from name: String) -> String? {
        let suffix = suffix.trimmingDots
        guard !suffix.isEmpty, name.hasSuffix("." + suffix) else { return nil }
        let short = name.dropLast(suffix.count + 1)
        return short.isEmpty ? nil : String(short)
    }
}

extension String {
    /// 양 끝의 점을 모두 뗀 것(Go `strings.Trim(s, ".")`).
    var trimmingDots: String {
        String(drop(while: { $0 == "." }).reversed().drop(while: { $0 == "." }).reversed())
    }
}
