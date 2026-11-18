// STUN address selection follows the Go implementation. Origin: tailscale.com v1.104.6 `net/netcheck/netcheck.go`
// (`nodeAddrPort`). Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase
import SwiftailControl
import SwiftailDERP
import SwiftailMagicsock

/// Selects candidate home regions for `Magicsock` from a DERPMap (tailcfg). The node converts them because
/// `SwiftailMagicsock` has no knowledge of tailcfg.
///
/// A pure function without I/O. The node calls it whenever it receives a netmap and passes the result to
/// `Magicsock.setRegions`. `Magicsock` ignores an unchanged list. Contract `docs/contracts/SwiftailEngine.md`, “Changes
/// in M4” N3, and `docs/contracts/SwiftailMagicsock.md` behavior E3.
extension Magicsock.Region {
    /// The default STUN port for nodes with a port of 0 (RFC 5389).
    static let defaultSTUNPort = 3478

    /// Regions eligible to be home, in ascending region ID order.
    ///
    /// Includes only regions without `noMeasureNoHome` and with at least one connectable server (`DERPServer`), the M3
    /// home criteria. Collects STUN addresses by examining nodes in order within each region, including `stunOnly`
    /// nodes. The score is `homeParams.regionScore`.
    static func homeCandidates(in derpMap: DERPMap?) -> [Magicsock.Region] {
        let regions = derpMap?.regions ?? [:]
        let scores = derpMap?.homeParams?.regionScore ?? [:]
        return regions.keys.sorted().compactMap { id in
            guard let region = regions[id], !region.noMeasureNoHome,
                  region.nodes.contains(where: { DERPServer($0) != nil })
            else { return nil }
            return Magicsock.Region(id: id, stunServers: region.nodes.compactMap(stunServer), score: scores[id] ?? 0)
        }
    }

    /// The IPv4 address for a STUN request to one node. Returns nil if it cannot be queried.
    ///
    /// A negative or out-of-range `stunPort` disables STUN on that node. 0 means 3478. If `stunTestIP` is present, uses
    /// it and skips the node if it is not IPv4. Otherwise uses `ipv4` if it is an IPv4 literal.
    // shortcut: Skips DNS lookup for nodes with empty `ipv4` (contract E3). Revisit when encountering a DERPMap without literals.
    static func stunServer(of node: DERPNode) -> IPEndpoint? {
        let portNumber = node.stunPort == 0 ? defaultSTUNPort : node.stunPort
        guard let port = UInt16(exactly: portNumber) else { return nil }
        let text = node.stunTestIP.isEmpty ? node.ipv4 : node.stunTestIP
        guard let address = IPAddress(text), address.isIPv4 else { return nil }
        return IPEndpoint(address: address, port: port)
    }
}
