// 재결속의 처리는 Go 구현을 따랐다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/magicsock.go` (`Rebind`, `resetEndpointStates`, `ReSTUN`),
// `wgengine/magicsock/endpoint.go` (`noteConnectivityChange`). Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 망이 바뀐 뒤의 재결속과 STUN 다시 하기(계약 `SwiftailTunnel` 동작 N 2·3.3, 노트 4.11).
///
/// 노드가 UDP 소켓을 새로 열어 묶은 뒤 `rebind`를, 인터페이스와 주소가 같은 채 링크만 바뀌었을 때 `restartSTUN`을 부른다.
/// 이 타입은 소켓을 열지 않는다. 노드의 순서는 소켓을 연 다음 `rebind`, 그 출력을 처리하고 `nextDeadline`에 맞춰
/// `advance`를 부르는 것이다.
extension Magicsock {
    /// UDP 소켓이 새로 묶였음을 알린다. 모든 피어의 직접 경로를 버리고 STUN 회차를 곧바로 시작한다.
    ///
    /// - 자기 엔드포인트의 입력을 새 값으로 바꾼다. 엔드포인트 목록은 회차가 끝날 때 다시 정해지고, 집합으로 바뀌었을
    ///   때만 `.endpointsChanged`가 나온다.
    /// - 모든 피어의 `bestAddr`·신뢰·Ping 기록을 지운다(`PeerPathState.noteConnectivityChange`). 경로가 바뀐 피어는
    ///   `.pathChanged`가 나온다. 유휴 피어는 경로가 nil 그대로라 사건이 없다(동작 G3).
    /// - 진행 중인 회차는 버린다. 옛 회차의 응답이 뒤늦게 와도 `.dropped(.unexpectedSTUN)`이다.
    /// - 출력의 순서는 경로 사건(피어 순서), STUN 요청이다.
    ///
    /// - Parameters:
    ///   - localPort: 새 소켓이 묶인 포트.
    ///   - localAddresses: 인터페이스의 IPv4 주소(loopback 제외). `init`과 같다.
    ///   - loopbackAddresses: loopback IPv4 주소. `init`과 같다.
    ///   - now: 지금 시각. 이전 호출보다 줄어들지 않아야 한다.
    public mutating func rebind(
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        at now: ContinuousClock.Instant
    ) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return rebind(
            localPort: localPort, localAddresses: localAddresses, loopbackAddresses: loopbackAddresses,
            at: now, using: &random
        )
    }

    /// 소켓은 그대로이고 링크만 바뀌었을 때 STUN 회차를 다시 시작한다(Go `ReSTUN`, 동작 N 2의 "같음"). 경로 상태는 그대로다.
    ///
    /// 회차가 이미 진행 중이거나 지역이 없으면 아무것도 하지 않는다. 엔드포인트가 바뀌었으면 회차가 끝날 때
    /// `.endpointsChanged`가 나온다.
    ///
    /// shortcut: Go는 진행 중인 회차가 있으면 끝난 뒤에 한 번 더 돌도록 예약한다(`wantEndpointsUpdate`). 여기서는 진행
    /// 중인 회차(최대 3초)가 같은 인터페이스·주소에서 잰 것이라 그 결과를 쓴다. 필요해지는 시점: 링크가 바뀐 직후의
    /// 회차 결과가 낡아서 엔드포인트가 틀리는 것이 실기기에서 보일 때.
    public mutating func restartSTUN(at now: ContinuousClock.Instant) -> [Output] {
        var random = SystemRandomNumberGenerator()
        return restartSTUN(at: now, using: &random)
    }

    /// `rebind(localPort:localAddresses:loopbackAddresses:at:)`와 같다. 난수를 `generator`에서 뽑는다.
    mutating func rebind(
        localPort: UInt16,
        localAddresses: [IPAddress],
        loopbackAddresses: [IPAddress],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Output] {
        var outputs: [Output] = []
        for key in peerOrder {
            peers[key]?.path.noteConnectivityChange()
            reportPathChange(of: key, at: now, into: &outputs)
        }
        let actions = netcheck.rebind(
            localPort: localPort, localAddresses: localAddresses, loopbackAddresses: loopbackAddresses,
            at: now, using: &generator
        )
        return outputs + handle(actions, at: now, using: &generator)
    }

    /// `restartSTUN(at:)`와 같다. 난수를 `generator`에서 뽑는다.
    mutating func restartSTUN(at now: ContinuousClock.Instant, using generator: inout some RandomNumberGenerator) -> [Output] {
        handle(netcheck.reSTUN(at: now, using: &generator), at: now, using: &generator)
    }
}
