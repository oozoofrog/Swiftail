extension PairingHost {
    /// `PairingHost`가 알리는 변화. `PairingHost.events`로 받는다.
    ///
    /// 비밀(제안의 비밀과 링크), 증명, 확인 숫자, 인증 키는 싣지 않는다. 짝 목록 전체는 `pairedPeers`로 읽는다.
    public enum Event: Sendable, Equatable {
        /// 짝이 되어 목록에 저장했다. 이미 짝인 노드가 다시 짝이 되면 그 자리의 항목이 바뀌고(`pairedAt`이 새 시각이다) 이
        /// 사건이 다시 나온다.
        case pairedPeerAdded(PairedPeer)
        /// `removePairedPeer(withStableID:)`가 짝을 지우고 저장했다. 없는 짝을 지우면 나오지 않는다.
        case pairedPeerRemoved(stableID: String)
        /// 제안의 상태가 바뀌었다.
        ///
        /// 사건은 일어난 차례대로 온다. `.opened` 뒤에 오는 `.used`·`.expired`·`.closed`는 그 `.opened`가 알린 제안의 것이다
        /// (앞 제안의 사건은 반드시 다음 `.opened`보다 앞에 있다). 그래서 화면의 제안은 `openOffer`가 돌려준 때가 아니라 이
        /// 사건의 차례로 맞춘다: 받은 `.opened`의 수가 `openOffer`를 부른 수와 같아진 뒤의 상태 사건만 지금 제안의 것이다.
        case offerChanged(OfferState)
    }

    /// 열어 둔 제안에 일어난 일. 제안은 한 번에 하나다.
    public enum OfferState: Sendable, Equatable {
        /// `openOffer(lifetime:authKey:)`가 새 제안을 열었다. 앞의 제안은 그 자리에서 못 쓰게 되고, 그것은 따로 알리지 않는다.
        case opened
        /// 들어오는 쪽의 증명이 맞아 제안이 쓰였다. 이 연결의 승인(`decide`)을 묻기 직전에 나온다. 제안은 한 번만 쓰인다.
        case used
        /// 쓰이지 않은 채 만료 시각이 지났다. `run()`이 도는 동안 그 시각에 나온다. `run()` 밖에서 지난 만료는 `run()`이
        /// 시작할 때 나온다.
        case expired
        /// `closeOffer()`가 열린 제안을 닫았다. 열린 제안이 없을 때 닫으면 나오지 않는다.
        case closed
    }
}
