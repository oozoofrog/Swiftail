import SwiftailBase

/// `Magicsock`에 넣고 받는 값 가운데 여러 부품이 함께 쓰는 것: 피어, 홈 후보 지역, 자기 엔드포인트.
///
/// 노드는 netmap과 DERPMap에서 이 값들을 뽑아 넘긴다. 이 타깃은 tailcfg 모델을 모른다.
/// `docs/contracts/SwiftailMagicsock.md` "공개 API".
extension Magicsock {
    /// netmap의 피어 하나 가운데 경로 찾기에 필요한 부분. 노드가 `EnginePeer`에서 만든다.
    public struct Peer: Sendable, Equatable {
        /// 피어의 node 키. WireGuard 공개 키와 같다.
        public var key: NodePublicKey
        /// 0이면 이 피어와 disco를 하지 않는다(DERP만).
        public var discoKey: DiscoPublicKey
        /// 0이면 모른다.
        public var homeDERP: Int64
        /// netmap의 `Endpoints`. IPv4만 후보로 쓴다.
        public var endpoints: [IPEndpoint]

        public init(key: NodePublicKey, discoKey: DiscoPublicKey, homeDERP: Int64, endpoints: [IPEndpoint]) {
            self.key = key
            self.discoKey = discoKey
            self.homeDERP = homeDERP
            self.endpoints = endpoints
        }
    }

    /// 홈으로 고를 수 있는 DERP 지역. 노드가 DERPMap에서 뽑는다.
    public struct Region: Sendable, Equatable {
        /// DERP 지역 ID.
        public var id: Int64
        /// STUN을 물을 주소. 비면 이 지역은 재지 않는다(측정이 없을 때의 대체 홈으로만 고른다).
        public var stunServers: [IPEndpoint]
        /// DERPMap `HomeParams.RegionScore`. 양수일 때만 지연에 곱한다. 없으면 0.
        public var score: Double

        public init(id: Int64, stunServers: [IPEndpoint], score: Double = 0) {
            self.id = id
            self.stunServers = stunServers
            self.score = score
        }
    }

    /// 제어 서버에 올릴 자기 엔드포인트 하나.
    public struct Endpoint: Sendable, Equatable {
        /// 이 주소를 어떻게 알았는가. tailcfg `EndpointType`으로 옮겨진다.
        public enum Source: Sendable, Equatable {
            /// 인터페이스 주소 + 소켓 포트. tailcfg `EndpointLocal`(1).
            case local
            /// STUN 응답의 바깥 주소. tailcfg `EndpointSTUN`(2).
            case stun
        }

        /// 피어가 이 노드에 닿을 수 있는 주소와 포트.
        public var address: IPEndpoint
        /// 주소의 출처.
        public var source: Source

        public init(address: IPEndpoint, source: Source) {
            self.address = address
            self.source = source
        }
    }
}
