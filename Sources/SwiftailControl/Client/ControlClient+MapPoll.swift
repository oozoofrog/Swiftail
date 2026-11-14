import Foundation
import SwiftailHTTP2
import SwiftailIO

/// 등록 뒤의 `POST /machine/map` 두 가지와 맵 스트림 곁의 일.
///
/// - 상태 올리기: `Stream=false, OmitPeers=true`. Hostinfo·NetInfo·DiscoKey·Endpoints를 올리고 응답 본문은
///   끝까지 읽어 버린다. 스트림이 열린 뒤의 변경도 이 형태로만 보낸다. 다른 형태(`Stream=false,
///   OmitPeers=false` 등)는 서버가 기존 스트림을 끊는다. 응답이 `timeouts.request` 안에 끝나지 않으면 연결 오류다.
/// - 맵 스트림: `Stream=true, KeepAlive=true, Compress=""`. 본문을 `MapResponseFramer` → `MapSession`에 넣고
///   netmap이 바뀌면 사건으로 낸다. 스트림마다 새 `MapSession`으로 시작한다(세션 재개는 하지 않는다).
/// - 감시: 맵 스트림에서 120초 동안 아무것도 오지 않으면 끊는다. 서버는 1분 안쪽 간격으로 KeepAlive를 보낸다.
///   마지막 netmap의 self 노드 키 만료 시각에도 깨어나, 새 맵이 오지 않아도 만료를 알아챈다.
/// - 만료: self 노드의 키가 만료되면 새 키로 다시 등록한다. 그렇게 받은 새 키도 곧바로 만료라면 `nodeKeyExpired`로
///   끝낸다(다시 시도해도 같은 결과이고, 되풀이하면 서버를 몰아붙인다).
/// - 핑: `Types`가 빈 `PingRequest`에는 그 URL에 HEAD로 답한다. 다른 종류는 무시한다.
///
/// `docs/protocol-notes/control-map.md` 3.4, 3.5, 4.2, 4.5, 5장, 6.2
/// (출처: tailscale.com `control/controlclient/direct.go` `sendMapRequest`·`answerPing`, BSD-3-Clause).
extension ControlClient {
    static let watchdogTimeout = Duration.seconds(120)
    static let pingTimeout = Duration.seconds(15)

    // MARK: 상태 올리기

    func uploadStatus(over connection: ControlConnection) async throws {
        let status = localStatus
        guard status != uploadedStatus else { return }
        guard let nodeKey = nodePublicKey else { throw ControlError.connection("등록 전에는 상태를 올릴 수 없다") }
        let request = MapRequest(
            nodeKey: nodeKey,
            discoKey: status.discoKey,
            hostinfo: hostinfo,
            endpoints: status.endpoints,
            endpointTypes: status.endpointTypes,
            omitPeers: true
        )
        let httpRequest = connection.jsonRequest("POST", path: "/machine/map", nodeKey: nodeKey)
        let body = try Self.encode(request)
        try await withControlTimeout(timeouts.request) {
            var reader = try await connection.responseStream(to: httpRequest, body: body)
            try Self.check(status: reader.status, retryAfter: reader.header("retry-after"))
            while try await reader.nextChunk() != nil {}
        }
        uploadedStatus = status
    }

    // MARK: 맵 스트림

    func receiveMap(over connection: ControlConnection) async throws {
        guard let nodeKey = nodePublicKey else { throw ControlError.connection("등록 전에는 맵을 받을 수 없다") }
        let status = localStatus
        let request = MapRequest(
            compress: "",
            keepAlive: true,
            nodeKey: nodeKey,
            discoKey: status.discoKey,
            stream: true,
            hostinfo: hostinfo,
            endpoints: status.endpoints,
            endpointTypes: status.endpointTypes
        )
        var reader = try await connection.responseStream(
            to: connection.jsonRequest("POST", path: "/machine/map", nodeKey: nodeKey),
            body: Self.encode(request)
        )
        lastMapActivity = .now
        try Self.check(status: reader.status, retryAfter: reader.header("retry-after"))
        mapStreamOpen = true

        var framer = MapResponseFramer()
        var session = MapSession()
        while let chunk = try await reader.nextChunk() {
            lastMapActivity = .now
            let responses: [MapResponse]
            do {
                responses = try framer.receive(chunk)
            } catch {
                throw ControlError.connection("맵 프레임 오류: \(error)")
            }
            for response in responses {
                if let info = response.tkaInfo { lastTKAInfo = info }
                let update: MapSession.Update
                do {
                    update = try session.apply(response, receivedAt: Date())
                } catch {
                    throw ControlError.connection("맵 응답 적용 오류: \(error)")
                }
                if let ping = update.pingRequest, queuedPings < Self.queuedPingLimit, let signals {
                    queuedPings += 1
                    signals.yield(.ping(ping))
                }
                if let netmap = update.netmap {
                    try accept(netmap)
                }
            }
        }
        throw ControlError.connection("서버가 맵 스트림을 끝냈다")
    }

    private func accept(_ netmap: Netmap) throws {
        if netmap.tailnetLockEnabled {
            throw ControlError.tailnetLockEnabled
        }
        eventContinuation.yield(.netmap(netmap))
        if netmap.selfNode.keyExpiry != selfKeyExpiry {
            selfKeyExpiry = netmap.selfNode.keyExpiry
            selfKeyExpiryChanged?.yield()
        }
        if let expiry = selfKeyExpiry, expiry <= Date() {
            try selfKeyExpired()
        }
        // 만료된 self 노드는 성공이 아니다. 물러나기는 쓸 수 있는 netmap에서만 초기화한다.
        renewedExpiredKey = false
        consecutiveFailures = 0
    }

    /// self 노드의 키가 만료되었다. 새 키로 다시 등록하게 하고 연결을 끝낸다. 그렇게 등록한 새 키도 만료라면 끝낸다.
    private func selfKeyExpired() throws {
        if renewedExpiredKey { throw ControlError.nodeKeyExpired }
        renewedExpiredKey = true
        rotateNodeKey = true
        needsRegistration = true
        throw SessionInterruption.nodeKeyExpired
    }

    /// 맵 스트림이 120초 동안 조용하면 던진다. 기준 시각은 `receiveMap`이 받을 때마다 옮긴다.
    /// self 노드의 키 만료 시각이 더 이르면 그때도 깨어나 만료를 처리한다. 만료 시각이 바뀌면(첫 netmap 포함)
    /// 곧바로 깨어나 깨어날 시각을 다시 계산한다.
    func watchMapActivity() async throws {
        while true {
            var deadline = lastMapActivity + Self.watchdogTimeout
            if let expiry = selfKeyExpiry {
                // 감시 주기보다 먼 만료는 다음에 깨어날 때 다시 본다. 먼 날짜를 Duration으로 바꾸지 않는다.
                let untilExpiry = expiry.timeIntervalSinceNow
                if untilExpiry < Self.watchdogTimeout / .seconds(1) {
                    deadline = min(deadline, .now + .seconds(max(untilExpiry, 0)))
                }
            }
            // 바뀜 알림은 잠들 때마다 새 흐름으로 받는다. 경쟁에서 진 쪽을 취소하면 그 흐름은 끝나기 때문이다.
            let (expiryChanges, continuation) = AsyncStream.makeStream(of: Void.self, bufferingPolicy: .bufferingNewest(1))
            selfKeyExpiryChanged = continuation
            let wake = deadline
            await withTaskGroup(of: Void.self) { group in
                group.addTask { try? await Task.sleep(until: wake, clock: .continuous) }
                group.addTask { for await _ in expiryChanges { return } }
                await group.next()
                group.cancelAll()
            }
            try Task.checkCancellation()
            if let expiry = selfKeyExpiry, expiry <= Date() {
                try selfKeyExpired()
            }
            if lastMapActivity + Self.watchdogTimeout <= .now {
                throw ControlError.connection("맵 스트림에서 120초 동안 아무것도 오지 않았다")
            }
        }
    }

    // MARK: 신호

    /// 맵 스트림 밖의 일을 차례로 처리한다: 바뀐 상태 올리기, 대화형 로그인 요청, 핑 답하기.
    func handle(_ signals: AsyncStream<SessionSignal>, over connection: ControlConnection) async throws {
        for await signal in signals {
            switch signal {
            case .statusChanged:
                // 올리는 동안 또 바뀌면 신호가 다시 들어오게 먼저 푼다.
                isStatusChangeQueued = false
                try await uploadStatusRetrying(over: connection)
            case .loginRequested:
                throw SessionInterruption.loginRequested
            case .ping(let ping):
                queuedPings -= 1
                guard ping.types.isEmpty, !ping.url.isEmpty, ping.url != lastPingURL else { continue }
                lastPingURL = ping.url
                await answer(ping, over: connection)
            }
        }
    }

    /// 상태 올리기가 HTTP 오류로 실패하면 스트림은 그대로 두고 물러났다가 다시 올린다.
    /// 연결 오류는 던진다(스트림도 같은 연결이므로 함께 끝난다).
    private func uploadStatusRetrying(over connection: ControlConnection) async throws {
        var failures = 0
        while true {
            do {
                try await uploadStatus(over: connection)
                return
            } catch SessionInterruption.rateLimited(let wait) {
                try await Task.sleep(for: wait, clock: .continuous)
            } catch ControlError.http {
                failures += 1
                try await Task.sleep(for: Backoff.delay(failures: failures, maximum: RetryPolicy.maximumBackoff, jitter: .random(in: 0..<1)), clock: .continuous)
            }
        }
    }

    /// 핑 URL에 HEAD를 보낸다. `URLIsNoise`면 Noise 연결 위로, 아니면 평범한 HTTP(S)로. 실패는 무시한다
    /// (Go도 기록만 한다).
    ///
    /// shortcut: Noise가 아닌 핑의 HEAD는 URLSession이라 `setNetworkInterface`의 인터페이스에 묶이지 않는다(`ServerKey`의
    /// `/key`와 같은 사정이다). 필요해지는 시점: 실기기에서 이 요청이 터널로 들어가는 것이 보일 때.
    private func answer(_ ping: PingRequest, over connection: ControlConnection) async {
        guard let url = URL(string: ping.url), ["http", "https"].contains(url.scheme?.lowercased()) else { return }
        if ping.urlIsNoise {
            var path = url.path(percentEncoded: true)
            if path.isEmpty { path = "/" }
            if let query = url.query(percentEncoded: true) { path += "?" + query }
            let request = HTTP2ClientConnection.Request(method: "HEAD", path: path, authority: connection.authority)
            _ = try? await withControlTimeout(Self.pingTimeout) {
                try await connection.responseStream(to: request, body: nil).status
            }
        } else {
            var request = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: 15)
            request.httpMethod = "HEAD"
            _ = try? await URLSession.shared.data(for: request)
        }
    }
}
