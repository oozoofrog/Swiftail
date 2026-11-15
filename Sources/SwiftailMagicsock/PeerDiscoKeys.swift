// netmap 키와 TSMP 키 가운데 활성 키를 고르는 규칙은 Go 구현을 옮겼다.
// 출처: tailscale.com v1.104.7 `wgengine/magicsock/endpoint.go` (`endpointDisco`, `updateDiscoKey`,
// `updateTSMPDiscoKey`, `checkAndUpdateDiscoKey`), `wgengine/magicsock/magicsock.go` (`HandleDiscoKeyAdvertisement`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 피어 하나의 disco 키 두 벌과 그 가운데 활성인 것(계약 "TSMP disco 키 광고" 동작 T4, 노트 4.10 2).
///
/// netmap으로 배운 키와 TSMP 광고로 배운 키를 따로 쥐고, 보내는 disco는 활성 키 하나로 봉한다. 규칙은 Go와 같다.
/// - TSMP 광고가 오면 그 키가 활성이 된다(netmap이 더 새 키를 줬더라도).
/// - netmap이 키를 바꿔도 TSMP 키가 활성이면 활성은 그대로다. netmap 키가 활성이 되는 길은 TSMP 키가 없을 때와,
///   비활성 키로 봉한 Ping·CallMeMaybe를 받았을 때(`noteSeen`)뿐이다.
///
/// 바꾸는 진입점은 Go의 같은 함수가 참을 돌려줄 때 참을 돌려준다. 활성 키 값이 그대로여도 참일 수 있다(처음 온 광고가
/// netmap 키와 같을 때, TSMP 키가 활성인데 netmap 키가 바뀔 때). 참이면 부르는 쪽이 경로를 다시 찾게 한다(Go
/// `changedActiveDiscoLocked`, `PeerPathState.resetForNewDiscoKey`).
///
/// 0 키는 넣지 않는다. 0이나 다른 피어가 이미 가진 키는 부르는 쪽이 nil로 넘긴다(동작 B1).
struct PeerDiscoKeys: Sendable, Equatable {
    /// netmap으로 배운 키. Go `controlKey`.
    private(set) var netmap: DiscoPublicKey?
    /// TSMP 광고로 배운 키. Go `tsmpKey`.
    private(set) var tsmp: DiscoPublicKey?
    /// TSMP 키가 활성인가. Go `tsmpActive`.
    private(set) var tsmpActive = false

    /// 보내는 disco를 봉할 키. 두 키가 모두 없으면 nil(disco 없이 DERP만).
    var active: DiscoPublicKey? {
        tsmpActive ? tsmp : netmap
    }

    /// netmap이 준 키(Go `updateFromNode` → `updateDiscoKey`). netmap 키가 그대로면 아무것도 하지 않는다.
    ///
    /// nil이면 netmap 키를 지우고 TSMP 키가 있으면 그것을 활성으로 둔다. 아니면 TSMP 키가 활성이던 때만 활성이 그대로다.
    mutating func updateNetmap(_ key: DiscoPublicKey?) -> Bool {
        guard key != netmap else { return false }
        tsmpActive = tsmpActive || key == nil
        netmap = key
        normalize()
        return true
    }

    /// TSMP 광고가 준 키(Go `updateTSMPDiscoKey`). 이전 TSMP 키와 같으면 활성이 netmap 키여도 바꾸지 않는다(Go
    /// `HandleDiscoKeyAdvertisement`가 그 경우를 "바뀌지 않음"으로 먼저 거른다).
    ///
    /// nil은 다른 피어가 그 키를 가져가 이 피어가 TSMP 키를 잃을 때만 쓴다(Go의 0 키 갱신과 같다).
    mutating func updateTSMP(_ key: DiscoPublicKey?) -> Bool {
        guard key != tsmp else { return false }
        tsmp = key
        tsmpActive = key != nil
        normalize()
        return true
    }

    /// 이 피어가 보낸 것으로 확인된 disco 메시지의 보낸 쪽 키(Go `checkAndUpdateDiscoKey`).
    ///
    /// - Returns: `known`은 그 키가 이 피어의 두 키 가운데 하나인가, `changed`는 비활성 키였어서 활성을 그쪽으로
    ///   바꿨는가.
    mutating func noteSeen(_ key: DiscoPublicKey) -> (known: Bool, changed: Bool) {
        if active == key { return (true, false) }
        let inactive = tsmpActive ? netmap : tsmp
        guard inactive == key else { return (false, false) }
        tsmpActive.toggle()
        return (true, true)
    }

    /// 두 키가 다 없으면 처음 상태로 돌린다(Go는 `endpointDisco`를 nil로 둔다).
    private mutating func normalize() {
        if netmap == nil, tsmp == nil {
            tsmpActive = false
        }
    }
}
