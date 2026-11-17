import SwiftailBase

/// 응용과 노드의 호출: 듣기, 걸기, 연결 ID로 부르는 읽기·쓰기·닫기, 주소 바뀜(계약 동작 S3·S5·S8·S9, X10).
///
/// 연결 ID로 부르는 호출은 응용이 쥔 연결(`connect`로 건 것, `accept`로 꺼낸 것)에만 듣는다. 없는 ID, 응용이 `close`·`abort`로
/// 놓은 ID, 대기열에 있는 ID는 아무 일도 하지 않는다(쓰기는 0바이트, 읽기는 빈 배열).
extension TCPStack {
    // MARK: 리스너

    /// 자기 노드의 모든 tailnet 주소(IPv4·IPv6)에서 `port`를 듣는다(계약 동작 S3). 포트 하나에 하나, 16개까지다.
    /// 포트 0을 거르는 일은 노드가 한다.
    package mutating func listen(on port: UInt16) throws(ListenError) -> ListenerID {
        guard listenersByPort[port] == nil else { throw .addressInUse }
        guard listeners.count < Self.maximumListeners else { throw .limitReached }
        let id = makeListenerID()
        listeners[id] = Listener(port: port)
        listenersByPort[port] = id
        return id
    }

    /// 듣기를 그만둔다. 대기열의 연결은 RST로 끊고 맺는 중인 연결은 아무것도 보내지 않고 버린다(계약 동작 S5).
    /// 응용이 이미 꺼낸 연결은 그대로다. 없는 ID면 아무 일도 하지 않는다.
    package mutating func stopListening(_ id: ListenerID) -> [Output] {
        guard let listener = listeners.removeValue(forKey: id) else { return [] }
        listenersByPort[listener.port] = nil
        var outputs: [Output] = []
        for connectionID in listener.queue {
            let connectionOutputs = modifyConnection(connectionID) { $0.abort() } ?? []
            for case .segment(let segment) in connectionOutputs {
                append(segment, to: &outputs)
            }
            removeConnection(connectionID)
        }
        let halfOpen = connections.compactMap { connectionID, entry in
            entry.role == .halfOpen(id) ? connectionID : nil
        }
        for connectionID in halfOpen.sorted(by: { $0.rawValue < $1.rawValue }) {
            removeConnection(connectionID)
        }
        return outputs
    }

    /// 리스너의 accept 대기열에서 맺어진 연결 하나를 꺼낸다. 비었거나 없는 리스너면 `nil`.
    ///
    /// 꺼낸 연결은 응용이 쥔 것이 되어 그 뒤의 사건이 나온다. 대기열에 있는 동안 받은 데이터와 FIN은 사건으로 알리지 않았으므로,
    /// 노드는 꺼낸 뒤 `connection(_:)`으로 읽을 것과 FIN 여부를 본다. 대기열에 있는 동안 작게 묶어 둔 받는 창을 여기서 열고,
    /// 출력에 그 창 갱신 ACK가 든다(`TCPConnection.openReceiveWindow(at:)`).
    package mutating func accept(
        from listenerID: ListenerID, at now: ContinuousClock.Instant
    ) -> (connection: ConnectionID, outputs: [Output])? {
        guard let index = listeners.index(forKey: listenerID), !listeners.values[index].queue.isEmpty else { return nil }
        let id = listeners.values[index].queue.removeFirst()
        connections[id]?.role = .application
        let connectionOutputs = modifyConnection(id) { $0.openReceiveWindow(at: now) } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        return (id, outputs)
    }

    // MARK: 걸기

    /// `remote`로 연결을 건다(능동 열기). SYN이 출력에 들어 있고, 맺어지면 `.established(id)`, 거절되면 `.closed(id, .refused)`가
    /// 나온다.
    ///
    /// 출발 주소는 목적지와 같은 계열의 첫 자기 주소이고, 포트는 49152…65535에서 차례로 고르되 연결이나 TIME-WAIT 기록이 쓰는
    /// 4-튜플은 건너뛴다(계약 동작 S8).
    ///
    /// 연결이 256개이거나, 그 상대 피어의 연결이 64개이거나, TIME-WAIT 기록이 1,024개면 `limitReached`다(계약 동작 S6과 그 아래).
    package mutating func connect(
        to remote: IPEndpoint, at now: ContinuousClock.Instant
    ) throws(ConnectError) -> (connection: ConnectionID, outputs: [Output]) {
        guard let localAddress = localAddresses.first(where: { $0.isIPv4 == remote.address.isIPv4 }) else {
            throw .noLocalAddress
        }
        guard connections.count < Self.maximumConnections, !isConnectionLimitReached(for: remote.address),
            timeWaitRecords.count < Self.maximumTimeWaitRecords,
            let local = freeLocalEndpoint(address: localAddress, remote: remote)
        else { throw .limitReached }

        let initialSequenceNumber = initialSequenceNumbers.initialSequenceNumber(local: local, remote: remote, at: now)
        let opened = TCPConnection.connect(
            from: local, to: remote, initialSequenceNumber: initialSequenceNumber, at: now)
        let id = insertConnection(ConnectionEntry(connection: opened.connection, role: .application))
        var outputs: [Output] = []
        process(opened.outputs, of: id, at: now, into: &outputs)
        return (id, outputs)
    }

    /// 나가는 연결의 자기 쪽 주소와 포트. `nextEphemeralPort`부터 한 바퀴 돌며 쓰이지 않는 4-튜플을 찾는다.
    private mutating func freeLocalEndpoint(address: IPAddress, remote: IPEndpoint) -> IPEndpoint? {
        let range = Self.ephemeralPorts
        for _ in range {
            let port = nextEphemeralPort
            nextEphemeralPort = port == range.upperBound ? range.lowerBound : port + 1
            let tuple = FourTuple(local: IPEndpoint(address: address, port: port), remote: remote)
            if connectionsByTuple[tuple] == nil, timeWaitRecords[tuple] == nil {
                return tuple.local
            }
        }
        return nil
    }

    // MARK: 연결 ID로 부르는 호출

    /// 보내는 버퍼에 자리가 있는 만큼 넣는다(`TCPConnection.write`). 다 받지 못했으면 자리가 날 때 `.writable(id)`가 나온다.
    package mutating func write(
        _ bytes: ArraySlice<UInt8>, to id: ConnectionID, at now: ContinuousClock.Instant
    ) -> (accepted: Int, outputs: [Output]) {
        guard isLive(id) else { return (0, []) }
        let result = modifyConnection(id) { $0.write(bytes, at: now) } ?? (accepted: 0, outputs: [])
        var outputs: [Output] = []
        process(result.outputs, of: id, at: now, into: &outputs)
        return (result.accepted, outputs)
    }

    /// 읽을 수 있는 바이트를 `maximumLength`까지 꺼낸다(`TCPConnection.read`). 끝난 연결에 남은 데이터도 읽는다.
    package mutating func read(
        upTo maximumLength: Int, from id: ConnectionID, at now: ContinuousClock.Instant
    ) -> (bytes: [UInt8], outputs: [Output]) {
        guard let index = connections.index(forKey: id), connections.values[index].role == .application else {
            return ([], [])
        }
        if connections.values[index].isDetached {
            return (connections.values[index].connection.receiveBuffer.read(upTo: maximumLength), [])
        }
        let result = modifyConnection(id) { $0.read(upTo: maximumLength, at: now) } ?? (bytes: [], outputs: [])
        var outputs: [Output] = []
        process(result.outputs, of: id, at: now, into: &outputs)
        return (result.bytes, outputs)
    }

    /// 보내기를 끝낸다(`TCPConnection.finishWriting`). 읽기는 계속할 수 있다.
    package mutating func finishWriting(_ id: ConnectionID, at now: ContinuousClock.Instant) -> [Output] {
        guard isLive(id) else { return [] }
        let connectionOutputs = modifyConnection(id) { $0.finishWriting(at: now) } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        return outputs
    }

    /// 연결을 닫고 놓는다(`TCPConnection.close`). 마무리(FIN 주고받기, TIME-WAIT)는 스택이 하고 그 사건은 알리지 않는다.
    /// 마무리가 끝나면(CLOSED, TIME-WAIT) 로그용 `.releasedConnectionClosed`가 한 번 나온다. 이 호출에서 곧바로
    /// 끝나면(읽지 않은 데이터가 있어 RST) 대신 `.closed(id, .aborted)`가 나온다.
    package mutating func close(_ id: ConnectionID, at now: ContinuousClock.Instant) -> [Output] {
        guard let index = connections.index(forKey: id), connections.values[index].role == .application else {
            return []
        }
        if connections.values[index].isDetached {
            removeConnection(id)
            return []
        }
        let connectionOutputs = modifyConnection(id) { $0.close(at: now) } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        connections[id]?.role = .released
        return outputs
    }

    /// 연결을 곧바로 끊고 놓는다(`TCPConnection.abort`). `.closed(id, .aborted)`가 나온다.
    package mutating func abort(_ id: ConnectionID, at now: ContinuousClock.Instant) -> [Output] {
        guard let index = connections.index(forKey: id), connections.values[index].role == .application else {
            return []
        }
        if connections.values[index].isDetached {
            removeConnection(id)
            return []
        }
        let connectionOutputs = modifyConnection(id) { $0.abort() } ?? []
        var outputs: [Output] = []
        process(connectionOutputs, of: id, at: now, into: &outputs)
        return outputs
    }

    /// 남은 연결을 모두 끊고 버린다. 노드가 멈출 때 부른다(계약 동작 N8).
    ///
    /// 응용이 쥔 것뿐 아니라 맺는 중인 것, 대기열에 있는 것, 응용이 `close`로 놓았지만 아직 FIN을 주고받는 것까지 RST를 한 번씩
    /// 낸다(`TCPConnection.abort`가 RST를 내지 않는 상태는 그대로 버린다). 사건은 내지 않는다. 리스너와 TIME-WAIT 기록은
    /// 건드리지 않는다.
    package mutating func abortAll() -> [Output] {
        var outputs: [Output] = []
        for id in connections.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            let connectionOutputs = modifyConnection(id) { $0.abort() } ?? []
            for case .segment(let segment) in connectionOutputs {
                append(segment, to: &outputs)
            }
            removeConnection(id)
        }
        return outputs
    }

    /// 응용이 쥐었고 TCP가 아직 도는 연결.
    private func isLive(_ id: ConnectionID) -> Bool {
        guard let entry = connections[id] else { return false }
        return entry.role == .application && !entry.isDetached
    }

    // MARK: 주소 바뀜

    /// 자기 tailnet 주소를 바꾼다. 노드가 netmap을 적용할 때마다 부른다(계약 동작 S9, N7).
    ///
    /// 자기 주소가 아니게 된 주소를 쓰는 연결은 아무것도 보내지 않고 끝난다. 응용이 쥔 연결에는 `.closed(id, .peerRemoved)`가
    /// 나오고, 맺는 중이거나 대기열에 있는 연결은 알리지 않고 지운다. TIME-WAIT 기록은 기한까지 둔다.
    package mutating func setLocalAddresses(_ addresses: [IPAddress]) -> [Output] {
        localAddresses = addresses
        return discardConnections { !addresses.contains($0.local.address) }
    }

    /// 상대 주소가 `remoteAddress`인 연결을 모두 아무것도 보내지 않고 끝낸다(계약 동작 X10의 스택 쪽).
    ///
    /// 노드는 netmap을 적용할 때 연결을 맺을 때의 주소 주인(node 키)과 견주어, 주인이 없어지거나 바뀐 주소마다 이것을 부른다.
    /// 응용이 쥔 연결에는 `.closed(id, .peerRemoved)`가 나오고, 맺는 중이거나 대기열에 있는 연결은 알리지 않고 지운다.
    /// TIME-WAIT 기록은 기한까지 둔다(새 주인이 같은 4-튜플로 거는 SYN은 기록이 challenge ACK로 받는다).
    package mutating func removeConnections(toRemoteAddress remoteAddress: IPAddress) -> [Output] {
        discardConnections { $0.remote.address == remoteAddress }
    }

    /// TCP가 아직 도는 연결 가운데 4-튜플이 `matches`인 것을 ID 순으로 끝낸다.
    private mutating func discardConnections(where matches: (FourTuple) -> Bool) -> [Output] {
        let doomed = connections.compactMap { id, entry in
            !entry.isDetached && matches(entry.tuple) ? id : nil
        }
        var outputs: [Output] = []
        for id in doomed.sorted(by: { $0.rawValue < $1.rawValue }) {
            discard(id, reason: .peerRemoved, into: &outputs)
        }
        return outputs
    }
}
