import Foundation
import SwiftailBase
import SwiftailControl

extension EnginePeer {
    /// 데이터면의 주소 → 그 주소의 주인 노드. 주인은 그 주소 한 주소짜리 접두(/32, /128)를 AllowedIPs로 가진 피어다.
    ///
    /// WireGuard는 피어가 보낸 패킷의 출발 주소를 그 피어의 AllowedIPs로 검사하므로, 이 표의 노드가 그 주소에서 온 연결의
    /// 상대다. 엔진이 피어를 올릴 때 쓰는 것과 같은 계산(`eligibleNodes(in:at:)`)에서 만든다: 데이터면에 오르지 않는 노드
    /// (만료, 지원하지 않는 피어)의 주소는 없고, 같은 주소를 여러 노드가 내세우면 엔진이 그 주소를 준 노드(node ID가 작은 쪽)
    /// 하나만 있다. 자기 노드의 주소는 넣지 않는다.
    ///
    /// 노드가 연결의 주인 확인(`SwiftailNetstack` 계약 동작 X10), 피어별 한도, `whoIs`에 함께 쓴다. 셋이 서로 다른 표를
    /// 보면 앱이 연결의 상대를 다른 노드의 신원으로 볼 수 있다.
    ///
    /// - Parameter now: 키 만료를 판단할 지금 시각(로컬 벽시계).
    package static func addressOwners(in netmap: Netmap, at now: Date) -> [IPAddress: Node] {
        var owners: [IPAddress: Node] = [:]
        for (node, peer) in eligibleNodes(in: netmap, at: now) {
            for prefix in peer.allowedIPs where isSingleAddress(prefix) {
                owners[prefix.address] = node
            }
        }
        return owners
    }
}
