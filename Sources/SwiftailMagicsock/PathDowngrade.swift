/// 피어의 경로가 나빠진 까닭: `direct`에서 `relayed`로, 또는 알린 경로에서 nil로 갈 때(계약 동작 G4).
///
/// 노드의 진단 로그에만 쓴다. 실기기 기록에서 "전송 중의 `relayed`"가 Pong이 끊긴 것인지, 후보를 지운 것인지,
/// disco 키나 소켓이 바뀐 것인지를 가르려고 둔다. 상태 기계의 동작에는 쓰이지 않는다.
package enum PathDowngrade: Sendable, Equatable {
    /// 마지막 Pong 뒤 `trustDuration`(6.5초)이 지났다. 그 뒤 Ping 기한으로 `bestAddr`를 지운 것도 여기에 든다.
    case trustExpired
    /// `bestAddr`였던 후보를 지웠다(netmap에서 빠짐, Ping으로 배운 후보가 낡음, 다음 CallMeMaybe에서 빠짐).
    case candidateRemoved
    /// UDP 소켓을 다시 묶었다(`noteConnectivityChange`).
    case rebind
    /// 피어의 활성 disco 키가 바뀌었다(netmap, TSMP 광고, 비활성 키로 온 disco). 송신 기록이 지워져 경로가 nil이 된다.
    case discoKeyChanged
    /// 마지막 WireGuard 송신 뒤 `sessionActiveTimeout`(45초)이 지났다.
    case idle
    /// 피어가 netmap에서 빠졌다(node 키가 바뀐 것도 같다).
    case peerRemoved
}
