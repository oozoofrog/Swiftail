import SwiftailBase

extension TailnetNode {
    /// 이 tailnet 주소를 가진 노드가 누구인지 지금의 netmap에서 찾는다. tsnet `LocalClient().WhoIs(addr)`.
    ///
    /// 자기 노드와 피어의 주소(netmap `Addresses`의 한 주소짜리)만 찾는다. 서브넷 경로 안의 주소는 찾지 않는다.
    /// netmap이 아직 없거나, 그 주소의 노드가 없거나, 노드를 만든 사용자의 프로필이 netmap에 없으면 nil이다.
    /// 기다리지 않는다.
    ///
    /// 연결의 상대를 확인할 때는 `TailnetConnection.remoteEndpoint.address`를 넘긴다. 그 주소는 WireGuard가 인증한
    /// 피어의 것이고, 주소의 주인이 바뀌면 노드가 그 연결을 끊는다(`ConnectionError.peerRemoved`).
    ///
    /// 노드 actor 안에서 `apply(_:)`가 쥔 `lastNetmap`을 읽는다. 엔진·필터·스택의 주인 확인도 같은 `apply(_:)` 안에서
    /// 같은 netmap으로 바뀌므로, 살아 있는 연결의 원격 주소에 대한 답은 그 연결을 맺은 피어의 것이다(동작 W6).
    public func whoIs(_ address: IPAddress) -> PeerIdentity? {
        lastNetmap.flatMap { PeerIdentity(address: address, in: $0) }
    }
}
