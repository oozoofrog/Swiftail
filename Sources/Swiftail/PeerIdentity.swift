// `computedName`의 규칙은 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `tailcfg/tailcfg.go`(`Node.InitDisplayNames`), `util/dnsname/dnsname.go`(`HasSuffix`,
// `TrimSuffix`, `TrimCommonSuffixes`, `SanitizeHostname`, `SanitizeLabel`), `types/netmap/netmap.go`
// (`MagicDNSSuffixOfNodeName`), `ipn/ipnlocal/local.go`(`WhoIs`), `ipn/ipnlocal/node_backend.go`(`updateNodeByAddrLocked`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine

/// tailnet 노드 하나의 신원. 제어 서버가 netmap으로 알려 준 값이다.
public struct PeerIdentity: Sendable, Equatable {
    /// 노드의 바뀌지 않는 ID(`tailcfg.Node.StableID`). 비어 있지 않다. 허용 목록의 키로 쓴다.
    public var stableID: String
    /// MagicDNS 이름에서 끝의 점을 뗀 것(`rd-phone-1a2b3c4d.tail0001.ts.net`). 이름이 없으면 빈 문자열이다.
    public var name: String
    /// 표시용 이름. Go `Node.ComputedName`의 규칙이다(동작 W4): 자기 tailnet의 접미사가 레이블 경계에서 맞을 때만
    /// 그것을 떼고 끝의 점을 뗀다(`rd-phone-1a2b3c4d`). 다른 tailnet에서 공유받은 노드는 접미사가 달라 끝 점 없는
    /// FQDN이 남는다. 결과가 비면 정리한 호스트 이름, 그것도 비면 node 공개 키의 텍스트(`nodekey:` + hex).
    public var computedName: String
    /// 노드를 만든 사용자의 로그인 이름(`alice@example.com`). 표시용이다. 태그 노드에서는 사람을 가리키지 않는다.
    public var loginName: String

    /// 값을 직접 채운다. 노드는 netmap에서 만들므로 쓰지 않는다. 이 타입을 받는 쪽의 코드를 노드 없이 시험할 때 쓴다.
    public init(stableID: String, name: String, computedName: String, loginName: String) {
        self.stableID = stableID
        self.name = name
        self.computedName = computedName
        self.loginName = loginName
    }
}

// MARK: 주소로 찾기(동작 W1~W3)

extension PeerIdentity {
    /// `netmap`의 데이터면에서 `address`의 주인인 노드의 신원. 없으면 nil.
    ///
    /// 피어의 주소는 엔진이 그 주소를 AllowedIPs로 준 피어의 것이다(`EnginePeer.addressOwners(in:at:)`). 그 주소에서 온
    /// 패킷을 보낼 수 있는 노드가 그 피어뿐이므로, 연결의 원격 주소로 물은 답이 그 연결의 상대다. 그래서 데이터면에 오르지
    /// 않는 노드(키가 만료된 노드, 지원하지 않는 피어)의 주소는 nil이고, 같은 주소를 가진 노드가 여럿이면 엔진이 고른 쪽
    /// (node ID가 작은 쪽)이다. 서브넷 경로 안의 주소는 찾지 않는다. Go의 `WhoIs`는 netmap의 `Addresses` 표에서 나중 것을
    /// 고르지만, 그 표는 겹치는 netmap에서 데이터면과 다른 노드를 가리킨다.
    ///
    /// 자기 노드의 한 주소짜리 `Addresses`는 자기 노드다. 다만 그 주소를 데이터면 피어도 가졌으면 그 주소에서 온 연결이 누구의
    /// 것인지 가릴 수 없으므로 nil이다(닫힌 쪽). IPv4-mapped IPv6 주소는 IPv4로 바꿔 찾는다. 찾은 노드의 `StableID`가
    /// 비었거나 사용자 프로필이 netmap에 없으면 nil이다.
    ///
    /// shortcut: 주소 표를 따로 쥐지 않고 질의마다 netmap에서 만든다(MagicDNS 이름 찾기와 같다). 첫 사용처는 연결마다 한 번만
    /// 묻는다. 노드가 수천이고 질의가 초당 수천이 되면 netmap을 적용할 때 만든 표를 쥔다.
    ///
    /// - Parameter now: 피어의 키 만료를 판단할 지금 시각(로컬 벽시계).
    init?(address: IPAddress, in netmap: Netmap, at now: Date) {
        let address = address.unmappedIPv4
        let peer = EnginePeer.addressOwners(in: netmap, at: now)[address]
        let isLocal = netmap.selfNode.hasSingleAddress(address)
        guard let node = isLocal ? (peer == nil ? netmap.selfNode : nil) : peer,
            !node.stableID.isEmpty, let profile = netmap.userProfiles[node.user]
        else { return nil }
        stableID = node.stableID
        name = node.name.hasSuffix(".") ? String(node.name.dropLast()) : node.name
        computedName = Self.computedName(
            nodeName: node.name,
            hostname: node.hostinfo.hostname,
            key: node.key,
            magicDNSSuffix: Netmap.magicDNSSuffix(ofNodeName: netmap.selfNode.name)
        )
        loginName = profile.loginName
    }
}

private extension Node {
    /// `Addresses`에 `address` 한 주소짜리 접두(/32, /128)가 있는가. Go `IsSingleIP`.
    func hasSingleAddress(_ address: IPAddress) -> Bool {
        addresses.contains { $0.address == address && $0.length == address.bytes.count * 8 }
    }
}

private extension IPAddress {
    /// IPv4-mapped IPv6(`::ffff:a.b.c.d`)는 IPv4로 바꾼 주소, 그 밖에는 자기 자신. Go `Addr.Unmap`.
    var unmappedIPv4: IPAddress {
        let mappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        guard bytes.count == 16, bytes.starts(with: mappedPrefix) else { return self }
        return IPAddress(bytes: bytes.dropFirst(12)) ?? self
    }
}

// MARK: 표시 이름(동작 W4)

extension PeerIdentity {
    /// Go `Node.InitDisplayNames`의 `ComputedName`.
    ///
    /// 노드 이름에서 `magicDNSSuffix`를 뗀 것이다. 접미사가 레이블 경계에서 맞을 때만 떼므로 다른 tailnet의 이름은 FQDN
    /// 그대로 남는다(끝 점은 뗀다). 결과가 비면 `hostname`을 정리한 것, 그것도 비면 node 공개 키의 텍스트다.
    ///
    /// - Parameters:
    ///   - nodeName: netmap `Node.name`.
    ///   - hostname: 노드가 알린 `Hostinfo.hostname`.
    ///   - key: 노드의 공개 키.
    ///   - magicDNSSuffix: 자기 tailnet의 접미사(`Netmap.magicDNSSuffix(ofNodeName:)`).
    static func computedName(nodeName: String, hostname: String, key: NodePublicKey, magicDNSSuffix: String) -> String {
        let name = trimmingSuffix(magicDNSSuffix, from: nodeName)
        guard name.isEmpty else { return name }
        let host = sanitizedHostname(hostname)
        return host.isEmpty ? key.description : host
    }

    /// Go `dnsname.TrimSuffix`: `name`이 `.suffix`로 끝날 때만(레이블 경계) 접미사를 떼고, 끝 점 하나를 뗀다.
    private static func trimmingSuffix(_ suffix: String, from name: String) -> String {
        var name = name
        if hasSuffix(suffix, in: name) {
            name = name.removingSuffix(".")
            name = name.removingSuffix(suffix.trimmingDots)
        }
        return name.removingSuffix(".")
    }

    /// Go `dnsname.HasSuffix`: 끝의 점과 접미사 앞뒤의 점을 하나씩 무시하고, `name`이 `<레이블>.<suffix>`로 끝나는가.
    /// 접미사가 비어 있으면 false다. 접미사만 있는 이름도 false다.
    private static func hasSuffix(_ suffix: String, in name: String) -> Bool {
        let name = name.removingSuffix(".")
        let suffix = String(suffix.removingSuffix(".").removingPrefix("."))
        let base = name.removingSuffix(suffix)
        return base.count < name.count && base.hasSuffix(".")
    }

    /// Go `dnsname.SanitizeHostname`: `.local`·`.localdomain`·`.lan`을 이 차례로 한 번씩 떼고 DNS 레이블로 정리한다.
    private static func sanitizedHostname(_ hostname: String) -> String {
        let trimmed = hostname.removingSuffix(".local").removingSuffix(".localdomain").removingSuffix(".lan")
        return sanitizedLabel(trimmed)
    }

    /// Go `dnsname.SanitizeLabel`(RFC 1035). 바이트 단위로 본다.
    /// 63바이트로 자르고, 처음과 끝의 영숫자가 아닌 바이트를 버리고, 가운데의 구분자(공백·`.`·`@`·`_`)를 `-`로 바꾸고,
    /// 영숫자와 `-`가 아닌 바이트를 버리고, 대문자를 소문자로 바꾼다.
    private static func sanitizedLabel(_ label: String) -> String {
        let bytes = Array(label.utf8)
        var start = 0
        var end = min(bytes.count, 63)
        while start < end, !bytes[start].isASCIIAlphanumeric { start += 1 }
        while start < end, !bytes[end - 1].isASCIIAlphanumeric { end -= 1 }

        let separators = Set(" .@_".utf8)
        var result: [UInt8] = []
        for index in start..<end {
            let byte = bytes[index]
            let isBoundary = index == start || index == end - 1
            if !isBoundary, separators.contains(byte) {
                result.append(UInt8(ascii: "-"))
            } else if byte.isASCIIAlphanumeric || byte == UInt8(ascii: "-") {
                result.append(byte.isASCIIUppercase ? byte + 32 : byte)
            }
        }
        return String(decoding: result, as: UTF8.self)
    }
}

private extension String {
    /// `suffix`로 끝나면 그것을 뗀 문자열. Go `strings.TrimSuffix`.
    func removingSuffix(_ suffix: String) -> String {
        hasSuffix(suffix) ? String(dropLast(suffix.count)) : self
    }

    /// `prefix`로 시작하면 그것을 뗀 문자열. Go `strings.TrimPrefix`.
    func removingPrefix(_ prefix: String) -> Substring {
        hasPrefix(prefix) ? dropFirst(prefix.count) : self[...]
    }
}

private extension UInt8 {
    var isASCIIUppercase: Bool { (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(self) }

    var isASCIIAlphanumeric: Bool {
        isASCIIUppercase || (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(self)
            || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(self)
    }
}
