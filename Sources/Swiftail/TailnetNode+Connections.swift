import SwiftailBase
import SwiftailNetstack

/// 듣기·걸기와 연결 핸들의 호출(`docs/contracts/SwiftailNetstack.md` "공개 API", 동작 A).
///
/// 앱의 호출은 앱의 Task가 노드 actor로 건너와 스택을 부른다. 기다려야 하면 그 Task가 노드에서 멈추고(`suspend(until:)`),
/// 스택의 사건이 깨운다. 분리된 Task는 없다. 기다림이 끝나는 길은 넷이고 어느 쪽이든 호출은 한 번 돌아온다:
/// - 사건(읽을 것이 생김, 자리가 남, 맺어짐, 대기열에 들어옴) → 다시 시도한다.
/// - 연결이 끝남 → 까닭의 오류. 앱이 `close`·`abort`했으면 `closed`.
/// - 호출한 Task의 취소 → `read`는 `cancelled`(연결과 데이터는 그대로), `write`는 RST로 끊고 `cancelled`, `connect`는
///   시도를 버리고 `cancelled`, 리스너의 흐름은 nil.
/// - `run()`의 끝 → `notRunning`, 리스너의 흐름은 nil.
extension TailnetNode {
    /// 리스너 수의 상한(계약 동작 S3, M). 스택과 같은 값이다. `run()` 전의 리스너도 이 안에 들게 노드가 먼저 센다.
    static let listenerLimit = 16

    // MARK: 듣기 (동작 A1)

    /// 이 노드의 tailnet 주소(IPv4·IPv6)에서 TCP 포트 하나를 듣는다. tsnet `Listen("tcp", ":<port>")`.
    ///
    /// `run()` 전에 불러도 된다(`run()`이 시작할 때 스택에 올린다). netmap 전이어도 된다. 리스너는 리스너를 닫거나,
    /// 버리거나, `run()`이 끝날 때까지 듣는다. 버려진 리스너는 이 호출이 먼저 닫으므로 포트와 상한(16)을 쥐지 않는다.
    ///
    /// - Throws: 장치가 `.inProcess`가 아니거나 포트가 0이면 `invalidConfiguration`, 그 포트에 아직 쓰는 리스너가 있으면
    ///   `addressInUse`, 쓰는 리스너가 16개면 `limitReached`, `run()`이 끝났거나 시작 검사(`stateDirectoryInUse` 등)에서
    ///   끝났으면 `notRunning`.
    public func listen(port: UInt16) throws(ConnectionError) -> TailnetListener {
        try checkInProcessDevice(port: port)
        if hasRun, !isRunning { throw .notRunning }
        closeDroppedListeners()
        guard !listenerRecords.values.contains(where: { $0.port == port }) else { throw .addressInUse }
        guard listenerRecords.count < Self.listenerLimit else { throw .limitReached }
        var stackID: TCPStack.ListenerID?
        do throws(TCPStack.ListenError) {
            stackID = try netstack?.stack.listen(on: port)
        } catch {
            throw error == .addressInUse ? .addressInUse : .limitReached
        }
        let token = nextListenerToken
        nextListenerToken += 1
        let listener = TailnetListener(node: self, token: token, port: port)
        listenerRecords[token] = ListenerRecord(port: port, handle: listener, stackID: stackID)
        Self.log.info("듣기 시작: 포트 \(port, privacy: .public)")
        return listener
    }

    /// 리스너의 다음 연결. 대기열에 있으면 곧바로, 없으면 들어올 때까지 기다린다.
    ///
    /// 꺼낸 연결은 대기열에 있는 동안 받은 데이터와 FIN을 그대로 쥐고 있다(`read`가 스택에서 읽는다).
    func nextConnection(from token: UInt64) async -> TailnetConnection? {
        while let record = listenerRecords[token], record.waiter == nil {
            if let stackID = record.stackID, let id = netstack?.stack.accept(from: stackID),
                let connection = adoptConnection(id)
            {
                Self.log.info("연결을 받음: 포트 \(record.port, privacy: .public)")
                return connection
            }
            await suspend { listenerRecords[token]?.waiter = $0 }
            listenerRecords[token]?.waiter = nil
            if Task.isCancelled { return nil }
        }
        return nil
    }

    /// 듣기를 그만둔다. 대기열의 연결은 RST로 끊고 기다리던 흐름을 끝낸다. 없는 리스너면 아무 일도 하지 않는다.
    func closeListener(_ token: UInt64, at now: ContinuousClock.Instant = .now) {
        guard let record = listenerRecords.removeValue(forKey: token) else { return }
        record.waiter?.finish()
        if let stackID = record.stackID {
            process(netstack?.stack.stopListening(stackID) ?? [], at: now)
        }
        Self.log.info("듣기 끝: 포트 \(record.port, privacy: .public)")
    }

    // MARK: 걸기 (동작 A2)

    /// tailnet의 피어에게 TCP 연결을 건다. tsnet `Dial(ctx, "tcp", "<host>:<port>")`. 연결이 맺어질 때까지 기다린다.
    ///
    /// `host`는 IP 주소이거나 netmap에 있는 이름이다: MagicDNS FQDN(`rd-phone-1a2b3c4d.tail0001.ts.net`), MagicDNS 접미사를
    /// 뗀 짧은 이름(`rd-phone-1a2b3c4d`). 대소문자와 끝의 점은 가리지 않는다. 이름이면 그 노드의 IPv4 주소를 먼저 고른다.
    /// 주소는 데이터면에 오른 피어의 것이거나 이 노드의 것이어야 한다. tailnet 밖의 이름을 시스템 DNS로 찾거나 OS 소켓으로
    /// 걸지 않는다(tsnet과 다르다). 자기 주소로 건 연결은 자기 리스너에 닿는다.
    ///
    /// - Throws: 장치가 `.inProcess`가 아니거나 포트가 0이거나 호스트가 비면 `invalidConfiguration`, 상태가 `.running`이
    ///   아니면 `notRunning`(맺는 사이 `run()`이 끝나도), 이름·주소를 찾지 못하면 `unknownHost`, 연결이 256개이거나 그
    ///   주소의 연결이 64개면 `limitReached`, 상대가 거절하면 `refused`, 247초 안에 답이 없으면 `timedOut`, 그 사이
    ///   주소의 주인이 바뀌면 `peerRemoved`, 맺어진 직후 이 호출이 돌아오기 전에 상대의 RST가 오면 `reset`, 호출한 Task가
    ///   취소되면 `cancelled`(시도를 버린다).
    public func connect(to host: String, port: UInt16) async throws(ConnectionError) -> TailnetConnection {
        try checkInProcessDevice(port: port)
        guard !host.isEmpty else { throw .invalidConfiguration("호스트가 비었다") }
        guard netstack != nil, stateMachine.state == .running else { throw .notRunning }
        guard let address = lastNetmap?.address(ofHost: host),
            netstack?.addressOwners[address] != nil || netstack?.stack.localAddresses.contains(address) == true
        else { throw .unknownHost }

        let now = ContinuousClock.now
        let opened: (connection: TCPStack.ConnectionID, outputs: [TCPStack.Output])?
        do throws(TCPStack.ConnectError) {
            opened = try netstack?.stack.connect(to: IPEndpoint(address: address, port: port), at: now)
        } catch {
            throw error == .limitReached ? .limitReached : .unknownHost
        }
        guard let id = opened?.connection else { throw .notRunning }
        netstack?.connections[id] = ConnectionRecord()
        process(opened?.outputs ?? [], at: now)

        while let record = netstack?.connections[id] {
            if let reason = record.closeReason {
                netstack?.connections[id] = nil
                throw ConnectionError(closedBy: reason) ?? .closed
            }
            if record.isEstablished, let connection = adoptConnection(id) {
                Self.log.info("연결을 맺음: 포트 \(port, privacy: .public)")
                return connection
            }
            await suspend { netstack?.connections[id]?.writeWaiter = $0 }
            netstack?.connections[id]?.writeWaiter = nil
            if Task.isCancelled {
                if netstack?.connections.removeValue(forKey: id) != nil {
                    let now = ContinuousClock.now
                    process(netstack?.stack.abort(id, at: now) ?? [], at: now)
                }
                throw .cancelled
            }
        }
        throw .notRunning
    }

    // MARK: 연결 핸들의 호출 (동작 A3~A7)

    /// `TailnetConnection.read(upTo:)`.
    func readConnection(_ id: TCPStack.ConnectionID, upTo maximumLength: Int) async throws(ConnectionError) -> [UInt8]? {
        guard maximumLength > 0 else { throw .invalidConfiguration("읽을 길이는 1 이상이어야 한다") }
        guard try usableRecord(id).readWaiter == nil else { throw .concurrentUse }
        while true {
            netstack?.connections[id]?.hasReadEvent = false
            let now = ContinuousClock.now
            let result = netstack?.stack.read(upTo: maximumLength, from: id, at: now) ?? (bytes: [], outputs: [])
            process(result.outputs, at: now)
            if !result.bytes.isEmpty { return result.bytes }

            let record = try usableRecord(id)
            if record.closeReason == .finished || netstack?.stack.connection(id)?.hasReceivedEndOfStream == true {
                return nil
            }
            guard !record.hasReadEvent else { continue }
            await suspend { netstack?.connections[id]?.readWaiter = $0 }
            netstack?.connections[id]?.readWaiter = nil
            if Task.isCancelled { throw .cancelled }
        }
    }

    /// `TailnetConnection.write(_:)`. 자리가 있는 만큼 넣고, 남으면 자리가 날 때까지 기다렸다 이어 넣는다(동작 A4·A5).
    func writeConnection(_ id: TCPStack.ConnectionID, _ bytes: [UInt8]) async throws(ConnectionError) {
        guard try usableRecord(id).writeWaiter == nil else { throw .concurrentUse }
        var written = 0
        while true {
            guard !(try usableRecord(id).hasFinishedWriting) else { throw .closed }
            guard written < bytes.count else { return }
            netstack?.connections[id]?.hasWriteEvent = false
            let now = ContinuousClock.now
            let result = netstack?.stack.write(bytes[written...], to: id, at: now) ?? (accepted: 0, outputs: [])
            written += result.accepted
            process(result.outputs, at: now)
            guard written < bytes.count else { return }

            guard !(try usableRecord(id).hasWriteEvent) else { continue }
            await suspend { netstack?.connections[id]?.writeWaiter = $0 }
            netstack?.connections[id]?.writeWaiter = nil
            if Task.isCancelled {
                // 얼마나 들어갔는지 앱이 알 수 없으므로 연결을 끊는다(첫 사용처 검토 결과 3).
                let now = ContinuousClock.now
                process(netstack?.stack.abort(id, at: now) ?? [], at: now)
                throw .cancelled
            }
        }
    }

    /// `TailnetConnection.finishWriting()`. 기다리던 `write`는 `closed`로 깨어난다.
    func finishWritingConnection(_ id: TCPStack.ConnectionID) throws(ConnectionError) {
        guard !(try usableRecord(id).hasFinishedWriting) else { return }
        netstack?.connections[id]?.hasFinishedWriting = true
        let now = ContinuousClock.now
        process(netstack?.stack.finishWriting(id, at: now) ?? [], at: now)
        wakeWriter(id)
    }

    /// `TailnetConnection.close()`. 기록을 지우고 기다리던 호출을 깨운다(`closed`). 마무리는 스택이 한다.
    func closeConnection(_ id: TCPStack.ConnectionID) {
        guard let record = netstack?.connections.removeValue(forKey: id) else { return }
        record.finishWaiters()
        let now = ContinuousClock.now
        process(netstack?.stack.close(id, at: now) ?? [], at: now)
    }

    /// `TailnetConnection.abort()`와 버려진 연결(`deinit`). RST로 끊는다.
    func abortConnection(_ id: TCPStack.ConnectionID) {
        guard let record = netstack?.connections.removeValue(forKey: id) else { return }
        record.finishWaiters()
        let now = ContinuousClock.now
        process(netstack?.stack.abort(id, at: now) ?? [], at: now)
    }

    // MARK: 도우미

    /// 장치가 `.inProcess`인가. `listen`·`connect`가 되는 노드인지를 `SwiftailPairing`이 `PairingHost`를 만들 때 본다.
    package nonisolated var hasInProcessDevice: Bool {
        if case .inProcess = device { return true }
        return false
    }

    private func checkInProcessDevice(port: UInt16) throws(ConnectionError) {
        guard case .inProcess = device else { throw .invalidConfiguration("listen·connect는 .inProcess 장치에서만 쓴다") }
        guard port != 0 else { throw .invalidConfiguration("포트는 0이 아니어야 한다") }
    }

    /// 앱이 연결 `id`를 아직 쓸 수 있으면 그 기록. `run()`이 끝났으면 `notRunning`, 앱이 닫았으면 `closed`, 상대 쪽 일로
    /// 끝났으면 그 까닭의 오류(동작 A7). `finished`로 끝난 연결은 남은 데이터를 읽도록 기록을 돌려준다.
    private func usableRecord(_ id: TCPStack.ConnectionID) throws(ConnectionError) -> ConnectionRecord {
        guard netstack != nil else { throw .notRunning }
        guard let record = netstack?.connections[id] else { throw .closed }
        if let reason = record.closeReason, let error = ConnectionError(closedBy: reason) { throw error }
        return record
    }

    /// 맺어진 연결의 핸들을 만든다. 받은 연결이면 기록도 만든다.
    private func adoptConnection(_ id: TCPStack.ConnectionID) -> TailnetConnection? {
        guard let connection = netstack?.stack.connection(id) else { return nil }
        if netstack?.connections[id] == nil {
            netstack?.connections[id] = ConnectionRecord(isEstablished: true)
        }
        return TailnetConnection(
            node: self, id: id, localEndpoint: connection.localEndpoint, remoteEndpoint: connection.remoteEndpoint)
    }
}
