import SwiftailControl
import SwiftailMagicsock

/// `Magicsock`이 정한 자기 엔드포인트를 제어 서버에 올릴 모양으로 옮긴다.
///
/// 계약 `docs/contracts/SwiftailEngine.md` "M4에서 바뀌는 것" N4. `ControlClient`는 상태를 올릴 때마다 disco 키와
/// 엔드포인트 전체를 함께 보내므로, testcontrol이 노드 값을 통째로 덮어도 빠지는 값이 없다(`disco-magicsock.md` 4.9 4).
extension ControlClient.LocalStatus {
    /// 엔드포인트 목록을 바꾼다. 주소와 종류는 같은 순서로 담는다(순서가 의미 있다. 노트 4.9 1).
    mutating func setEndpoints(_ endpoints: [Magicsock.Endpoint]) {
        self.endpoints = endpoints.map(\.address)
        endpointTypes = endpoints.map { endpoint in
            switch endpoint.source {
            case .local: .local
            case .stun: .stun
            }
        }
    }
}
