import SwiftailBase

/// Input and output values shared by parts of `Magicsock`, including peers, candidate home regions, and local endpoints.
///
/// The node extracts these values from the netmap and DERPMap and passes them in. This target is independent of the tailcfg models.
/// "Public API" in `docs/contracts/SwiftailMagicsock.md`.
extension Magicsock {
    /// The portion of a netmap peer needed for path discovery. The node creates it from `EnginePeer`.
    public struct Peer: Sendable, Equatable {
        /// The peer's node key. It is the WireGuard public key.
        public var key: NodePublicKey
        /// A value of 0 disables disco with this peer (DERP only).
        public var discoKey: DiscoPublicKey
        /// A value of 0 means unknown.
        public var homeDERP: Int64
        /// The netmap's `Endpoints`. Only IPv4 addresses are candidates.
        public var endpoints: [IPEndpoint]

        /// Copies a netmap peer. Use 0 for `discoKey` if the peer does not use disco, and for `homeDERP` if its home is unknown.
        public init(key: NodePublicKey, discoKey: DiscoPublicKey, homeDERP: Int64, endpoints: [IPEndpoint]) {
            self.key = key
            self.discoKey = discoKey
            self.homeDERP = homeDERP
            self.endpoints = endpoints
        }
    }

    /// A DERP region that can be selected as home. The node extracts it from DERPMap.
    public struct Region: Sendable, Equatable {
        /// The DERP region ID.
        public var id: Int64
        /// The address to query for STUN. If empty, the region is left unmeasured and can only be chosen as a fallback home when there are no measurements.
        public var stunServers: [IPEndpoint]
        /// DERPMap `HomeParams.RegionScore`. Used as a latency multiplier only when positive. Defaults to 0 if absent.
        public var score: Double

        /// Creates a candidate home region. The default `score` of 0 compares unweighted latencies.
        public init(id: Int64, stunServers: [IPEndpoint], score: Double = 0) {
            self.id = id
            self.stunServers = stunServers
            self.score = score
        }
    }

    /// A local endpoint to publish to the control server.
    public struct Endpoint: Sendable, Equatable {
        /// How this address was discovered. Converted to tailcfg `EndpointType`.
        public enum Source: Sendable, Equatable {
            /// An interface address + socket port. tailcfg `EndpointLocal` (1).
            case local
            /// The external address from a STUN response. tailcfg `EndpointSTUN` (2).
            case stun
        }

        /// The address and port a peer can use to reach this node.
        public var address: IPEndpoint
        /// The origin of the address.
        public var source: Source

        /// Creates an endpoint from an address and its origin.
        public init(address: IPEndpoint, source: Source) {
            self.address = address
            self.source = source
        }
    }
}
