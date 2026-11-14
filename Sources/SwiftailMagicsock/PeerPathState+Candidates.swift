// 후보의 출처, 지우기 규칙, 받은 Ping·CallMeMaybe의 처리는 Go 구현을 따라 옮겼다.
// 출처: tailscale.com v1.104.6 `wgengine/magicsock/endpoint.go` (`endpointState.shouldDeleteLocked`,
// `deleteEndpointLocked`, `setEndpointsLocked`, `addCandidateEndpoint`, `handleCallMeMaybe`).
// Copyright (c) Tailscale Inc & AUTHORS. BSD-3-Clause.

import SwiftailBase

/// 후보 주소 표: 피어에게 직접 닿을지도 모르는 주소와 그 출처.
///
/// 후보는 세 곳에서 온다(노트 4.4 1). netmap의 `Endpoints`, UDP로 받은 Ping의 출처, DERP로 받은 CallMeMaybe의
/// 주소 목록이다. 자기 STUN 결과와 Pong의 Src는 후보가 아니다. 출처마다 지우는 규칙이 다르다(노트 4.4 2).
///
/// 받은 Ping과 CallMeMaybe는 상대가 정하는 입력이다. 표는 `maxCandidates`를 넘지 않고, 가득 차면 지울 것을
/// 먼저 지운 뒤에도 자리가 없으면 새 후보를 넣지 않는다. 있는 후보와 `bestAddr`를 밀어내지 않는다(계약 H).
extension PeerPathState {
    /// 후보 하나와 그 출처·측정 기록. Go `endpointState`.
    struct Candidate: Sendable, Equatable {
        let address: IPEndpoint
        /// 마지막 netmap에 있다.
        var inNetmap = false
        /// UDP Ping으로 배운 후보의 마지막 Ping 받은 시각. netmap·CallMeMaybe로 먼저 안 후보는 nil로 남는다(Go와 같다).
        var lastPingReceived: ContinuousClock.Instant?
        /// 이 주소에서 마지막으로 받은 Ping의 TxID. 같은 Ping의 재전송에 Pong을 두 번 보내지 않는다.
        var lastPingReceivedTxID: TransactionID?
        /// 마지막 CallMeMaybe에 들어 있었다. 이 후보는 다음 CallMeMaybe에서 빠질 때만 지운다.
        var fromCallMeMaybe = false
        /// 이 주소로 마지막 Ping을 보낸 시각. `pingInterval` 안이면 전체 Ping에서 건너뛴다.
        var lastPingSent: ContinuousClock.Instant?
    }

    /// 피어당 후보의 상한. Go의 정리 문턱(100) 위에 둔 계약 H의 한도다.
    static let maxCandidates = 128
    /// Ping으로 배운 후보를 넣어 후보가 이 수를 넘으면 지울 것을 지운다. Go `addCandidateEndpoint`(`endpoint.go:1835`).
    static let candidatePruneThreshold = 100

    /// UDP로 온 Ping(노트 4.2 4.2). 출처를 후보로 넣고, Pong을 보내야 하면 true를 돌려준다.
    ///
    /// 같은 후보에서 직전과 같은 TxID가 오면 재전송으로 보고 false다. 후보 표가 가득 차 넣지 못해도 Pong은
    /// 보낸다(Ping은 공유 키 없이는 만들 수 없고 Pong은 Ping과 크기가 비슷해 증폭 수단이 되지 않는다. 받은 Ping에 답하는 Go와 같다). 받을 수 없는 출처(IPv6, 포트 0)는
    /// 답할 수도 없으므로 false다.
    mutating func receivePing(_ txID: TransactionID, from source: IPEndpoint, at now: ContinuousClock.Instant) -> Bool {
        guard let address = Self.candidateAddress(source) else { return false }
        if let index = candidates.firstIndex(where: { $0.address == address }) {
            let isDuplicate = candidates[index].lastPingReceivedTxID == txID
            candidates[index].lastPingReceivedTxID = txID
            if candidates[index].lastPingReceived != nil {
                candidates[index].lastPingReceived = now
            }
            return !isDuplicate
        }
        var candidate = Candidate(address: address)
        candidate.lastPingReceived = now
        candidate.lastPingReceivedTxID = txID
        insertCandidate(candidate, at: now)
        if candidates.count > Self.candidatePruneThreshold {
            removeStaleCandidates(at: now)
        }
        return true
    }

    /// DERP로 온 CallMeMaybe(노트 4.8 5). 출처 확인은 `Magicsock`이 마쳤다.
    ///
    /// 목록의 주소를 CallMeMaybe 후보로 삼고 지난 CallMeMaybe에만 있던 주소는 출처를 따지지 않고 지운다. 그리고
    /// 후보별 Ping 간격을 풀어 모든 후보에 곧바로 Ping한다. 이 전체 Ping은 CallMeMaybe를 되보내지 않는다.
    mutating func receiveCallMeMaybe(
        _ endpoints: [IPEndpoint],
        at now: ContinuousClock.Instant,
        using generator: inout some RandomNumberGenerator
    ) -> [Action] {
        let wanted = Self.candidateAddresses(endpoints)
        let wantedSet = Set(wanted)
        // Go는 새 주소를 넣은 뒤 빠진 주소를 지운다. 결과는 같고, 먼저 지우면 가득 찬 표에 자리가 난다.
        candidates.removeAll { $0.fromCallMeMaybe && !wantedSet.contains($0.address) }
        dropBestAddrIfRemoved()
        for index in candidates.indices where wantedSet.contains(candidates[index].address) {
            candidates[index].fromCallMeMaybe = true
        }
        let known = Set(candidates.map(\.address))
        for address in wanted where !known.contains(address) {
            insertCandidate(Candidate(address: address, fromCallMeMaybe: true), at: now)
        }
        for index in candidates.indices {
            candidates[index].lastPingSent = nil
        }
        return pingAllCandidates(at: now, sendCallMeMaybe: false, using: &generator)
    }

    /// netmap의 엔드포인트로 netmap 후보를 다시 맞춘다(Go `setEndpointsLocked`).
    mutating func replaceNetmapCandidates(with endpoints: [IPEndpoint], at now: ContinuousClock.Instant) {
        let wanted = Self.candidateAddresses(endpoints)
        let wantedSet = Set(wanted)
        for index in candidates.indices {
            candidates[index].inNetmap = wantedSet.contains(candidates[index].address)
        }
        removeStaleCandidates(at: now)
        let known = Set(candidates.map(\.address))
        for address in wanted where !known.contains(address) {
            insertCandidate(Candidate(address: address, inNetmap: true), at: now)
        }
    }

    /// 지울 때가 된 후보를 지운다(노트 4.4 2, Go `shouldDeleteLocked`). 지운 주소가 `bestAddr`면 그것도 지운다.
    ///
    /// - CallMeMaybe 후보는 남긴다.
    /// - Ping을 받은 적 없는 후보(netmap 출처)는 netmap에서 빠졌으면 지운다.
    /// - Ping으로 배운 후보는 마지막 Ping 뒤 `sessionActiveTimeout`이 지났으면 지운다(netmap에 있어도. Go와 같다).
    mutating func removeStaleCandidates(at now: ContinuousClock.Instant) {
        candidates.removeAll { candidate in
            if candidate.fromCallMeMaybe { return false }
            guard let received = candidate.lastPingReceived else { return !candidate.inNetmap }
            return now - received > Self.sessionActiveTimeout
        }
        dropBestAddrIfRemoved()
    }

    /// 표에 없는 후보 하나를 넣는다. 가득 찼으면 지울 것을 먼저 지우고, 그래도 가득이면 넣지 않는다.
    private mutating func insertCandidate(_ candidate: Candidate, at now: ContinuousClock.Instant) {
        if candidates.count >= Self.maxCandidates {
            removeStaleCandidates(at: now)
        }
        guard candidates.count < Self.maxCandidates else { return }
        candidates.append(candidate)
    }

    /// `bestAddr`는 언제나 후보다. 후보에서 빠졌으면 `bestAddr`와 신뢰를 지운다(Go `deleteEndpointLocked`).
    private mutating func dropBestAddrIfRemoved() {
        if let bestAddr, !candidates.contains(where: { $0.address == bestAddr.address }) {
            clearBestAddr()
        }
    }

    /// 후보로 받을 수 있는 주소들. 순서를 지키고 중복은 처음 것만 남긴다.
    static func candidateAddresses(_ endpoints: [IPEndpoint]) -> [IPEndpoint] {
        var seen: Set<IPEndpoint> = []
        return endpoints.compactMap(candidateAddress).filter { seen.insert($0).inserted }
    }

    /// 후보로 받을 수 있으면 그 주소. IPv4-mapped IPv6는 IPv4로 푼다. 포트 0은 보낼 수 없으므로 받지 않는다.
    ///
    /// shortcut: 소켓이 IPv4 하나라 IPv6 후보는 받지 않는다(계약 D1, "결정" 표 "UDP 소켓"). 필요해지는 시점:
    /// IPv6만 되는 망(셀룰러 일부)을 M5 실기기에서 만날 때. 그때 Go처럼 IPv6 link-local만 거른다.
    static func candidateAddress(_ endpoint: IPEndpoint) -> IPEndpoint? {
        guard endpoint.port != 0 else { return nil }
        let bytes = endpoint.address.bytes
        if bytes.count == 4 {
            return endpoint
        }
        let mappedPrefix: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF]
        guard bytes.count == 16, bytes.starts(with: mappedPrefix),
              let unmapped = IPAddress(bytes: bytes.suffix(4))
        else { return nil }
        return IPEndpoint(address: unmapped, port: endpoint.port)
    }
}
