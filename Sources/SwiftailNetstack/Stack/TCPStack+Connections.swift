import SwiftailBase

/// 연결 표 다루기: 연결의 출력을 스택의 출력으로 바꾸고, 연결이 움직인 뒤 상태에 맞춰 표를 고친다.
///
/// 연결을 움직이는 모든 길(받기, 시각, 응용 호출)은 끝에서 `process(_:of:at:into:)`를 부른다. 그래서 맺는 중 → 대기열,
/// TIME-WAIT → 기록, 닫힘 → 지움이 한 곳에서 일어나고, 상한을 세는 값(맺는 중인 수, 대기열)이 표와 어긋나지 않는다.
extension TCPStack {
    /// 연결 하나를 제자리에서 고친다. 없는 ID면 `nil`.
    ///
    /// 항목을 꺼냈다가 다시 넣으면 그 사이 버퍼의 저장소가 둘에게 쥐여 고칠 때 통째로 복사되므로, 표 안에서 바로 고친다.
    mutating func modifyConnection<Result>(
        _ id: ConnectionID, _ body: (inout TCPConnection) -> Result
    ) -> Result? {
        guard let index = connections.index(forKey: id) else { return nil }
        return body(&connections.values[index].connection)
    }

    /// 연결 `id`가 낸 출력을 스택의 출력으로 옮기고 표를 고친다.
    ///
    /// 세그먼트는 IP 패킷으로, 사건은 응용이 쥔 연결의 것만 ID를 붙여 옮긴다(타입 문서). 순서는 연결이 낸 그대로다.
    mutating func process(
        _ connectionOutputs: [TCPConnection.Output], of id: ConnectionID, at now: ContinuousClock.Instant,
        into outputs: inout [Output]
    ) {
        for output in connectionOutputs {
            switch output {
            case .segment(let segment):
                append(segment, to: &outputs)
            case .event(let event):
                report(event, of: id, into: &outputs)
            }
        }
        settle(id, at: now, into: &outputs)
    }

    /// 세그먼트를 IP 패킷으로 만들어 낸다. 연결의 두 주소는 늘 같은 계열이고 세그먼트는 MTU 안이라 만들기가 실패하지 않는다.
    func append(_ segment: TCPSegment, to outputs: inout [Output]) {
        if let packet = segment.ipPacket() {
            outputs.append(.ipPacket(packet))
        }
    }

    /// 응용이 쥔 연결의 사건이면 ID를 붙여 낸다. 끝남은 `reportClose(_:of:into:)`가 한 번만 알린다.
    private mutating func report(_ event: TCPConnection.Event, of id: ConnectionID, into outputs: inout [Output]) {
        if case .closed(let reason) = event {
            reportClose(CloseReason(reason), of: id, into: &outputs)
            return
        }
        guard let index = connections.index(forKey: id),
            connections.values[index].role == .application, !connections.values[index].hasReportedClose
        else { return }
        switch event {
        case .established: outputs.append(.event(.established(id)))
        case .readable: outputs.append(.event(.readable(id)))
        case .writable: outputs.append(.event(.writable(id)))
        case .endOfStream: outputs.append(.event(.endOfStream(id)))
        case .closed: break
        }
    }

    /// TCP의 일이 끝난 연결(CLOSED가 됐거나 TIME-WAIT에 들었다)을 연결마다 한 번 알린다. 응용이 쥔 연결이면 `.closed` 사건,
    /// 응용이 놓은 연결이면 로그에만 쓰는 `.releasedConnectionClosed`다(계약 "연결 종료 통계 로그"). 맺는 중이거나 대기열의
    /// 연결은 알리지 않는다.
    private mutating func reportClose(_ reason: CloseReason, of id: ConnectionID, into outputs: inout [Output]) {
        guard let index = connections.index(forKey: id), !connections.values[index].hasReportedClose else { return }
        let statistics = connections.values[index].connection.statistics
        switch connections.values[index].role {
        case .application: outputs.append(.event(.closed(id, reason, statistics)))
        case .released: outputs.append(.releasedConnectionClosed(reason, statistics))
        case .halfOpen, .queued: return
        }
        connections.values[index].hasReportedClose = true
    }

    /// 연결이 움직인 뒤의 상태에 맞춰 표를 고친다.
    ///
    /// - 맺는 중이던 수동 열기가 맺어지면 대기열로 옮기고 `.acceptable`을 낸다(계약 동작 S5).
    /// - 닫혔으면 지운다. 맺는 중이던 연결이 `.reset`으로 닫힌 것(RFC 9293 3.10.7.4 둘째의 "LISTEN으로 돌아감")도 알리지 않고
    ///   지운다. 응용이 쥔 연결에 읽지 않은 데이터가 남았으면 응용이 놓을 때까지 그것만 둔다.
    /// - TIME-WAIT에 들었으면 `.closed(.finished)`(놓은 연결이면 `.releasedConnectionClosed(.finished)`)를 알리고, 상대 FIN에 대한 ACK가 나간 뒤 기록으로 옮긴다(계약 동작
    ///   S6). 기록이 1,024개면 옮기지 않고 연결 그대로 두어 TIME-WAIT를 마치게 한다(기록도 연결도 상한을 넘지 않는다).
    ///   기록의 수명은 연결이 TIME-WAIT에 든 때부터 240초까지다(`TimeWaitRecord.lifetimeEnd`).
    /// - 그 밖에는 연결의 기한을 다시 적는다.
    private mutating func settle(_ id: ConnectionID, at now: ContinuousClock.Instant, into outputs: inout [Output]) {
        guard let index = connections.index(forKey: id), !connections.values[index].isDetached else { return }
        let state = connections.values[index].connection.state
        let role = connections.values[index].role

        if case .halfOpen(let listenerID) = role, state != .synReceived, state != .closed {
            leaveHalfOpen(connections.values[index].connection.remoteEndpoint.address, listener: listenerID)
            connections.values[index].role = .queued(listenerID)
            listeners[listenerID]?.queue.append(id)
            outputs.append(.event(.acceptable(listenerID)))
        }

        switch state {
        case .closed:
            finish(id)
        case .timeWait:
            reportClose(.finished, of: id, into: &outputs)
            let connection = connections.values[index].connection
            if connection.timers[.acknowledgment] == nil, timeWaitRecords.count < Self.maximumTimeWaitRecords {
                addTimeWaitRecord(
                    TimeWaitRecord(
                        sendNext: connection.sendNext, receiveNext: connection.receiveNext,
                        deadline: connection.timers[.timeWait] ?? now + TCPConnection.timeWaitDuration,
                        lifetimeEnd: (connection.timeWaitEnteredAt ?? now) + TCPConnection.maximumTimeWaitLifetime),
                    for: connections.values[index].tuple)
                finish(id)
            } else {
                connectionDeadlines[id] = connection.nextDeadline
            }
        default:
            connectionDeadlines[id] = connections.values[index].connection.nextDeadline
        }
    }

    /// TCP의 일이 끝난 연결을 표에서 뺀다. 응용이 쥔 연결에 읽지 않은 데이터가 남았으면 그것만 남긴다.
    private mutating func finish(_ id: ConnectionID) {
        guard let index = connections.index(forKey: id) else { return }
        if connections.values[index].role == .application, connections.values[index].connection.readableByteCount > 0 {
            connections.values[index].isDetached = true
            connectionsByTuple[connections.values[index].tuple] = nil
            connectionDeadlines[id] = nil
        } else {
            removeConnection(id)
        }
    }

    /// 아무것도 보내지 않고 연결을 끝낸다. 응용이 쥔 연결이면 `.closed(reason)`, 놓은 연결이면
    /// `.releasedConnectionClosed(reason)`을 알린다(계약 동작 S9, X10).
    mutating func discard(_ id: ConnectionID, reason: CloseReason, into outputs: inout [Output]) {
        reportClose(reason, of: id, into: &outputs)
        removeConnection(id)
    }

    /// 맺는 중인 연결 하나가 빠진다(맺어졌거나 지워졌다).
    mutating func leaveHalfOpen(_ remoteAddress: IPAddress, listener listenerID: ListenerID) {
        halfOpenCount -= 1
        let remaining = halfOpenCountByAddress[remoteAddress, default: 1] - 1
        halfOpenCountByAddress[remoteAddress] = remaining > 0 ? remaining : nil
        listeners[listenerID]?.halfOpenCount -= 1
    }

    /// 새 연결 ID. 스택 안에서 다시 쓰지 않는다(2⁶⁴개를 다 쓸 일은 없다). 표에 넣는 일은 `insertConnection(_:)`이 한다.
    mutating func makeConnectionID() -> ConnectionID {
        defer { nextIdentifier &+= 1 }
        return ConnectionID(rawValue: nextIdentifier)
    }

    /// 새 리스너 ID. 연결 ID와 같은 번호 줄을 쓴다.
    mutating func makeListenerID() -> ListenerID {
        defer { nextIdentifier &+= 1 }
        return ListenerID(rawValue: nextIdentifier)
    }
}
