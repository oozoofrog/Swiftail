// 판정 순서와 응답 규칙은 Tailscale의 `net/dns/resolver/tsdns.go`(`respond`, `resolveLocal`, `marshalResponse`)와
// `forwarder.go`(`servfailResponse`, `nxDomainResponse`)(BSD-3-Clause, Copyright (c) Tailscale Inc & contributors)를
// 따른다. 규칙만 옮겼고 코드는 Swift로 새로 썼다.

import Foundation
import SwiftailBase
import SwiftailControl

/// MagicDNS 응답기. 서비스 IP(`100.100.100.100`, `fd7a:115c:a1e0::53`)의 UDP 53으로 온 질의 하나에 응답 하나를 만든다.
///
/// netmap의 노드 이름(self 포함)과 `ExtraRecords`로 A·AAAA·ANY·PTR에 답하고, 응답기의 영역(`localZones`) 안에서
/// 모르는 이름은 NXDOMAIN, 영역 밖의 이름은 SERVFAIL로 답한다. 질의를 상위 리졸버로 보내지 않는다(결정 D2).
/// 입출력과 시계가 없는 값이다: 엔진이 netmap을 적용할 때마다 새로 만들고, 시각은 질의마다 받는다.
/// 노드 이름은 미리 표로 만들지 않고 질의마다 netmap에서 찾는다(plan 5절).
///
/// 질의 이름을 기록하거나 오류에 담지 않는다(계약 K3).
///
/// `docs/protocol-notes/dns-state-node.md` 3.1·4.2, `docs/contracts/SwiftailTunnel.md` 동작 D.
struct MagicDNSResolver: Sendable {
    /// 노드 색인의 출처. nil이면 노드 이름을 하나도 모른다.
    let netmap: Netmap?
    /// 응답기가 권한을 갖는 영역. 소문자이고, 끝 점을 포함한 표기의 바이트 순이다.
    /// (Go의 `LocalDomains`는 만든 순서 그대로다: 접미사, ip6.arpa, in-addr.arpa. 영역이 서로 겹치지 않으면
    /// 순서는 답에 영향을 주지 않는다. Go 기준값 자료에는 겹치는 영역이 없다.)
    /// 이름을 포함하는 첫 영역이 부정 응답의 SOA가 된다.
    let zones: [DNSMessage.Name]
    /// `ExtraRecords`의 A·AAAA. 노드 색인보다 먼저 찾는다.
    let hosts: [HostRecord]

    /// 응답기를 만든다(동작 S7, 노트 4.1.4 6).
    ///
    /// - Parameters:
    ///   - netmap: 노드 이름·주소와 `DNSConfig`(`Proxied`, `ExtraRecords`)의 출처. netmap이 없거나 자기 노드 키가
    ///     만료됐으면 nil을 넘긴다. 그러면 노드 이름을 모르고, `localZones`도 비우면 모든 이름이 SERVFAIL이다(동작 D7).
    ///   - localZones: 응답기가 권한을 갖는 영역. 설정 산출(동작 S5)의 `localZones`이고 `dnsMatchDomains`를 그대로 넘겨도 된다.
    ///     끝 점은 있어도 없어도 되며, 이름이 될 수 없는 문자열은 버린다.
    init(netmap: Netmap?, localZones: [String]) {
        self.netmap = netmap
        zones = localZones.compactMap { DNSMessage.Name($0)?.lowercased() }
            .sorted { $0.presentation.lexicographicallyPrecedes($1.presentation) }
        hosts = Self.hostRecords(from: netmap?.dnsConfig?.extraRecords ?? [])
    }

    /// 질의 바이트에 대한 응답 바이트. 어떤 바이트열에도 트랩 없이 응답 하나를 낸다.
    ///
    /// 동작 D의 무응답에 해당하는 경우는 없다. 해석할 수 없는 질의에도 Go처럼 FORMERR로 답한다
    /// (머리 12바이트가 없으면 ID 0의 머리로).
    ///
    /// - Parameter now: SOA SERIAL에 쓸 지금 시각.
    func response(to message: [UInt8], at now: Date) -> [UInt8] {
        let limit = DNSMessage.udpPayloadLimit(ofQuery: message)
        let query: DNSMessage.Query
        do {
            query = try DNSMessage.Query(parsing: message)
        } catch {
            // 질문은 싣지 않는다. Go는 머리가 짧거나 QR=1이면 풀에서 다시 쓴 파서에 남은 앞 질의의 질문을 싣는데,
            // 다른 앱의 질의 이름이 새어 나가므로 따르지 않는다(동작 D2).
            let header = DNSMessage.Header(parsing: message) ?? DNSMessage.Header(id: 0, flags: [])
            return DNSMessage.Response(header: header.localResponse(.formatError))
                .encoded(udpPayloadLimit: limit)
        }

        let question = query.question
        let outcome: LocalOutcome?
        if !question.name.isPrintable {
            outcome = LocalOutcome(code: .formatError)
        } else if question.type == .ptr {
            outcome = pointerOutcome(for: question.name.lowercased())
        } else {
            outcome = addressOutcome(for: question.name.lowercased(), type: question.type)
        }
        guard let outcome else { return unansweredResponse(to: query) }

        // Go `marshalResponse`: 질문을 읽은 응답은 RCODE가 NOERROR이거나 QTYPE이 0이 아닐 때 질문을 싣는다.
        let includesQuestion = outcome.code == .noError || question.type.rawValue != 0
        return DNSMessage.Response(
            header: query.header.localResponse(outcome.code),
            question: includesQuestion ? question : nil,
            answer: outcome.answer,
            authority: outcome.negativeZone.map { .init(zone: $0, serial: Self.serial(at: now)) }
        ).encoded(udpPayloadLimit: limit)
    }
}

// MARK: - 판정

extension MagicDNSResolver {
    /// 로컬 판정의 결과. nil 대신 이것이 나오면 응답기가 직접 답한다.
    struct LocalOutcome: Sendable {
        var code: DNSMessage.ResponseCode
        var answer: DNSMessage.Response.Answer?
        /// 부정 응답에 SOA로 실을 영역.
        var negativeZone: DNSMessage.Name?
    }

    /// `magicdns.localhost-tailscale-daemon.`: 서비스 IP의 역방향 이름이고, 이 이름의 A·AAAA는 서비스 IP다(Go `dnsSymbolicFQDN`).
    static let symbolicName = DNSMessage.Name("magicdns.localhost-tailscale-daemon.")

    /// PTR 밖의 질의(노트 4.2.2 3, Go `resolveLocal`). nil이면 로컬 답이 없다.
    ///
    /// `shortcut:` 4via6 이름과 `dns-subdomain-resolve` 서브도메인 규칙은 없다(동작 D8). 그 이름은 모르는 이름으로 다룬다.
    /// 필요해지는 시점: 그 기능을 쓰는 tailnet을 만날 때.
    func addressOutcome(for name: DNSMessage.Name, type: DNSMessage.RecordType) -> LocalOutcome? {
        // RFC 7686: .onion은 늘 NXDOMAIN이다.
        if name.labels.count >= 2, name.labels.last == Array("onion".utf8) {
            return LocalOutcome(code: .nameError, negativeZone: zone(containing: name))
        }
        if name == Self.symbolicName {
            if type == .a, let address = ServiceIP.ipv4 { return LocalOutcome(code: .noError, answer: .address(address)) }
            if type == .aaaa, let address = ServiceIP.ipv6 { return LocalOutcome(code: .noError, answer: .address(address)) }
        }
        guard let addresses = addresses(for: name) else {
            guard let zone = zone(containing: name) else { return nil }
            return LocalOutcome(code: .nameError, negativeZone: zone)
        }

        // 이름이 있으면 그 타입의 레코드가 없어도 NXDOMAIN이 아니라 NOERROR다.
        let answer: IPAddress?
        switch type {
        case .a: answer = addresses.first(where: \.isIPv4)
        case .aaaa: answer = addresses.first { !$0.isIPv4 }
        case .any: answer = addresses.first
        case .ns, .soa, .axfr, .hinfo: return LocalOutcome(code: .notImplemented)
        default: return LocalOutcome(code: .noError)
        }
        guard let answer else {
            return LocalOutcome(code: .noError, negativeZone: zone(containing: name))
        }
        return LocalOutcome(code: .noError, answer: .address(answer))
    }

    /// PTR 질의(노트 4.2.2 5, Go `respondReverse`). nil이면 로컬 답이 없다.
    func pointerOutcome(for name: DNSMessage.Name) -> LocalOutcome? {
        guard !name.isBonjourBrowsingName, let address = Self.address(fromReverseName: name) else { return nil }
        // 4to6 주소는 대응하는 100.x.y.z로 먼저 찾는다.
        if let ipv4 = Self.ipv4(from4to6: address), let target = self.name(for: ipv4) {
            return LocalOutcome(code: .noError, answer: .pointer(target))
        }
        if let target = self.name(for: address) {
            return LocalOutcome(code: .noError, answer: .pointer(target))
        }
        guard let zone = zone(containing: name) else { return nil }
        return LocalOutcome(code: .nameError, negativeZone: zone)
    }

    /// 로컬 답이 없는 질의. Go는 여기서 전달기로 넘기고, 전달기는 Bonjour 탐색 이름을 NXDOMAIN으로, 맞는 상위가 없는 이름을
    /// SERVFAIL로 답한다(노트 4.2.3, Go `forwardWithDestChan`). 이 응답에는 크기 검사가 없다(Go와 같다).
    ///
    /// `shortcut:` 상위 전달(UDP·TCP·DoH)은 없다(결정 D1·D2, 제외 표). OS는 match 도메인 밖의 이름을 서비스 IP로
    /// 보내지 않으므로 여기 오는 것은 `dig @100.100.100.100`처럼 직접 물은 것뿐이다. 필요해지는 시점: 사용자 지정
    /// 분할 DNS를 터널로 풀어야 할 때.
    func unansweredResponse(to query: DNSMessage.Query) -> [UInt8] {
        var header = query.header
        header.flags.subtract(.reserved)
        header.flags.insert(.response)
        if query.question.name.lowercased().isBonjourBrowsingName {
            // Go `nxDomainResponse`: AA는 질의 값, RA = RD.
            if header.flags.contains(.recursionDesired) {
                header.flags.insert(.recursionAvailable)
            } else {
                header.flags.remove(.recursionAvailable)
            }
            header.setResponseCode(.nameError)
        } else {
            // Go `servfailResponse`: AA = 1, RA는 질의 값.
            header.flags.insert(.authoritative)
            header.setResponseCode(.serverFailure)
        }
        return DNSMessage.Response(header: header, question: query.question).encoded()
    }

    /// 이름을 포함하는 첫 영역.
    func zone(containing name: DNSMessage.Name) -> DNSMessage.Name? {
        zones.first { name.isWithin($0) }
    }

    /// SOA SERIAL: 유닉스 초의 아래 32비트(Go `uint32(time.Now().Unix())`). 표현할 수 없는 시각이면 0.
    static func serial(at now: Date) -> UInt32 {
        UInt32(truncatingIfNeeded: Int64(exactly: now.timeIntervalSince1970.rounded(.down)) ?? 0)
    }
}

// MARK: - 머리와 이름의 도우미

extension DNSMessage.Header {
    /// 로컬 응답의 머리(Go `marshalResponse`): 질의 머리를 복사하고 QR=1, AA=1, RD=1이면 RA=1, RCODE를 덮는다.
    /// Opcode·TC·AD·CD와 RD=0일 때의 RA는 질의 값이 남고, Z는 0이 된다(노트 3.1).
    func localResponse(_ code: DNSMessage.ResponseCode) -> DNSMessage.Header {
        var header = self
        header.flags.subtract(.reserved)
        header.flags.formUnion([.response, .authoritative])
        if header.flags.contains(.recursionDesired) {
            header.flags.insert(.recursionAvailable)
        }
        header.setResponseCode(code)
        return header
    }
}

extension DNSMessage.Name {
    /// 끝 점을 포함한 표기의 바이트. 영역을 Go와 같은 순서로 정렬할 때 쓴다.
    var presentation: [UInt8] {
        labels.isEmpty ? [UInt8(ascii: ".")] : labels.flatMap { $0 + [UInt8(ascii: ".")] }
    }

    /// Bonjour 서비스 탐색 이름(`b`·`db`·`r`·`dr`·`lb` + `._dns-sd._udp.`, RFC 6763 11). 소문자 이름에 쓴다.
    /// Go는 이것을 상위로 보내지 않고 NXDOMAIN으로 답한다(모바일 배터리, `forwarder.go`).
    var isBonjourBrowsingName: Bool {
        labels.count >= 3
            && ["b", "db", "r", "dr", "lb"].contains { labels[0].elementsEqual($0.utf8) }
            && labels[1].elementsEqual("_dns-sd".utf8)
            && labels[2].elementsEqual("_udp".utf8)
    }
}
