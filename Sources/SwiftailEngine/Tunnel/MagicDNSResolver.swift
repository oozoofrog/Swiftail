// Decision order and response rules follow Tailscale's `net/dns/resolver/tsdns.go` (`respond`, `resolveLocal`, `marshalResponse`) and
// `forwarder.go` (`servfailResponse`, `nxDomainResponse`) (BSD-3-Clause, Copyright (c) Tailscale Inc & contributors).
// Only the rules were ported. The code was written from scratch in Swift.

import Foundation
import SwiftailBase
import SwiftailControl

/// A MagicDNS responder that produces one response to a query on UDP port 53 at the service IP (`100.100.100.100`, `fd7a:115c:a1e0::53`).
///
/// Answers A, AAAA, ANY, and PTR using netmap node names (including self) and `ExtraRecords`. Returns NXDOMAIN for unknown names within the responder's
/// zones (`localZones`) and SERVFAIL for other unresolved names, subject to the built-in rules below. Does not forward queries upstream (decision D2).
/// A value with no I/O or clock. The engine creates it each time it applies a netmap, and each query supplies the time.
/// Looks up node names in the netmap for each query without building a table in advance (`docs/plan.md` §5).
///
/// Query names are kept out of logs and errors (contract K3).
///
/// `docs/protocol-notes/dns-state-node.md` 3.1 and 4.2, and `docs/contracts/SwiftailTunnel.md` behavior D.
struct MagicDNSResolver: Sendable {
    /// The origin of the node index. If nil, no node names are known.
    let netmap: Netmap?
    /// The zones for which the responder is authoritative. Lowercase, sorted by presentation bytes including the trailing dot.
    /// Go also sorts `LocalDomains` by string and uses them in that order (`slices.Sort` in `net/dns/manager.go`).
    /// The first zone that contains a name supplies the SOA for a negative response.
    let zones: [DNSMessage.Name]
    /// A and AAAA from `ExtraRecords`. Looked up before the node index.
    let hosts: [HostRecord]

    /// Creates the responder (behavior S7, notes 4.1.4 6).
    ///
    /// - Parameters:
    ///   - netmap: The origin of node names and addresses and `DNSConfig` (`Proxied`, `ExtraRecords`). Pass nil if the netmap is missing or the local node key
    ///     has expired. This leaves node names unknown. If `localZones` is also empty, unresolved names yield SERVFAIL unless a built-in rule handles them (behavior D7).
    ///   - localZones: The zones for which the responder is authoritative. These are `localZones` from settings derivation (behavior S5). You can pass `dnsMatchDomains` directly.
    ///     The trailing dot is optional. Strings that cannot be names are dropped.
    init(netmap: Netmap?, localZones: [String]) {
        self.netmap = netmap
        zones = localZones.compactMap { DNSMessage.Name($0)?.lowercased() }
            .sorted { $0.presentation.lexicographicallyPrecedes($1.presentation) }
        hosts = Self.hostRecords(from: netmap?.dnsConfig?.extraRecords ?? [])
    }

    /// Response bytes for query bytes. Produces one response for any byte sequence without trapping.
    ///
    /// No case corresponds to the no-response outcome in behavior D. As in Go, even an unparseable query gets FORMERR
    /// (using a header with ID 0 if the message has fewer than 12 header bytes).
    ///
    /// - Parameter now: The current time for the SOA SERIAL.
    func response(to message: [UInt8], at now: Date) -> [UInt8] {
        let limit = DNSMessage.udpPayloadLimit(ofQuery: message)
        let query: DNSMessage.Query
        do {
            query = try DNSMessage.Query(parsing: message)
        } catch {
            // Omits the question. If the header is too short or QR=1, Go includes a previous query's question left in a parser reused from a pool.
            // This responder avoids that behavior because it leaks another app's query name (behavior D2).
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

        // Go `marshalResponse` includes the parsed question if RCODE is NOERROR or QTYPE is not 0.
        let includesQuestion = outcome.code == .noError || question.type.rawValue != 0
        return DNSMessage.Response(
            header: query.header.localResponse(outcome.code),
            question: includesQuestion ? question : nil,
            answer: outcome.answer,
            authority: outcome.negativeZone.map { .init(zone: $0, serial: Self.serial(at: now)) }
        ).encoded(udpPayloadLimit: limit)
    }
}

// MARK: - Decisions

extension MagicDNSResolver {
    /// The result of a local decision. When present in place of nil, the responder answers directly.
    struct LocalOutcome: Sendable {
        var code: DNSMessage.ResponseCode
        var answer: DNSMessage.Response.Answer?
        /// The zone to include as the SOA in a negative response.
        var negativeZone: DNSMessage.Name?
    }

    /// `magicdns.localhost-tailscale-daemon.` is the PTR target for the service IPs. Its A and AAAA records contain the service IPs (Go `dnsSymbolicFQDN`).
    static let symbolicName = DNSMessage.Name("magicdns.localhost-tailscale-daemon.")

    /// Handles queries other than PTR (notes 4.2.2 3, Go `resolveLocal`). Nil means there is no local answer.
    ///
    /// `shortcut:` Omits 4via6 names and the `dns-subdomain-resolve` subdomain rule (behavior D8). Treats those names as unknown.
    /// This will be needed when a tailnet using those features is encountered.
    func addressOutcome(for name: DNSMessage.Name, type: DNSMessage.RecordType) -> LocalOutcome? {
        // RFC 7686 requires NXDOMAIN for .onion in every case.
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

        // If the name exists, returns NOERROR even without a record of that type.
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

    /// Handles PTR queries (notes 4.2.2 5, Go `respondReverse`). Nil means there is no local answer.
    func pointerOutcome(for name: DNSMessage.Name) -> LocalOutcome? {
        guard !name.isBonjourBrowsingName, let address = Self.address(fromReverseName: name) else { return nil }
        // Looks up a 4to6 address first as its corresponding 100.x.y.z address.
        if let ipv4 = Self.ipv4(from4to6: address), let target = self.name(for: ipv4) {
            return LocalOutcome(code: .noError, answer: .pointer(target))
        }
        if let target = self.name(for: address) {
            return LocalOutcome(code: .noError, answer: .pointer(target))
        }
        guard let zone = zone(containing: name) else { return nil }
        return LocalOutcome(code: .nameError, negativeZone: zone)
    }

    /// Handles a query without a local answer. Go passes it to the forwarder, which returns NXDOMAIN for Bonjour discovery names and SERVFAIL for names with
    /// no matching upstream (notes 4.2.3, Go `forwardWithDestChan`). This response is not size-checked (as in Go).
    ///
    /// `shortcut:` Omits upstream forwarding (UDP, TCP, and DoH) (decisions D1 and D2, exclusions table). The OS does not send names outside match domains
    /// to the service IP, so only direct queries such as `dig @100.100.100.100` reach this point. This will be needed when custom
    /// split DNS must resolve through the tunnel.
    func unansweredResponse(to query: DNSMessage.Query) -> [UInt8] {
        var header = query.header
        header.flags.subtract(.reserved)
        header.flags.insert(.response)
        if query.question.name.lowercased().isBonjourBrowsingName {
            // Go `nxDomainResponse` preserves the query's AA and sets RA = RD.
            if header.flags.contains(.recursionDesired) {
                header.flags.insert(.recursionAvailable)
            } else {
                header.flags.remove(.recursionAvailable)
            }
            header.setResponseCode(.nameError)
        } else {
            // Go `servfailResponse` sets AA = 1 and preserves the query's RA.
            header.flags.insert(.authoritative)
            header.setResponseCode(.serverFailure)
        }
        return DNSMessage.Response(header: header, question: query.question).encoded()
    }

    /// The first zone containing the name.
    func zone(containing name: DNSMessage.Name) -> DNSMessage.Name? {
        zones.first { name.isWithin($0) }
    }

    /// SOA SERIAL uses the lower 32 bits of Unix seconds (Go `uint32(time.Now().Unix())`). Returns 0 for an unrepresentable time.
    static func serial(at now: Date) -> UInt32 {
        UInt32(truncatingIfNeeded: Int64(exactly: now.timeIntervalSince1970.rounded(.down)) ?? 0)
    }
}

// MARK: - Header and name helpers

extension DNSMessage.Header {
    /// A local response header (Go `marshalResponse`). Copies the query header, sets QR=1 and AA=1, sets RA=1 if RD=1, and replaces RCODE.
    /// Opcode, TC, AD, CD, and RA when RD=0 retain their query values. Z becomes 0 (notes 3.1).
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
    /// Presentation bytes including the trailing dot. Used to sort zones in the same order as Go.
    var presentation: [UInt8] {
        labels.isEmpty ? [UInt8(ascii: ".")] : labels.flatMap { $0 + [UInt8(ascii: ".")] }
    }

    /// Bonjour service discovery names (`b`, `db`, `r`, `dr`, or `lb` + `._dns-sd._udp.`, RFC 6763 11). Uses lowercase names.
    /// Go returns NXDOMAIN for these without forwarding upstream to save battery on mobile devices (`forwarder.go`).
    var isBonjourBrowsingName: Bool {
        labels.count >= 3
            && ["b", "db", "r", "dr", "lb"].contains { labels[0].elementsEqual($0.utf8) }
            && labels[1].elementsEqual("_dns-sd".utf8)
            && labels[2].elementsEqual("_udp".utf8)
    }
}
