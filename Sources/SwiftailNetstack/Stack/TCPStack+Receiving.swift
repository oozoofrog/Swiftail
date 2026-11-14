import SwiftailBase

/// 패킷 받기: 해석, 찾기, LISTEN, 연결 없는 곳의 RST(계약 동작 S1~S6, X7·X8).
extension TCPStack {
    /// IP 패킷 하나를 받는다. 어떤 바이트열을 넣어도 죽지 않는다(계약 동작 X1).
    ///
    /// 찾는 순서(계약 동작 S1): 목적지가 자기 주소가 아니면 버린다 → 4-튜플의 연결 → 같은 4-튜플의 TIME-WAIT 기록 →
    /// 목적지 포트의 리스너 → 어디에도 없으면 RST로 답한다(S2). TIME-WAIT 기록이 리스너보다 앞이라, 기록이 있는 동안 같은
    /// 4-튜플의 SYN은 새 연결이 되지 않는다.
    ///
    /// 연결이 내는 순수 ACK는 여기서 나오지 않는다. 묶음을 다 넣은 뒤 같은 시각으로 `advance(to:)`를 부른다.
    package mutating func receive(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output] {
        let segment: TCPSegment
        do {
            segment = try TCPSegment(parsingIPPacket: ipPacket)
        } catch {
            switch error {
            case .notTCP: return [.dropped(.notTCP)]
            case .malformed: return [.dropped(.malformed)]
            case .badChecksum: return [.dropped(.badChecksum)]
            }
        }
        // 필터가 이미 걸렀지만 스택도 본다(계약 동작 S1).
        guard localAddresses.contains(segment.destination.address) else { return [.dropped(.notForUs)] }

        var outputs: [Output] = []
        let tuple = FourTuple(local: segment.destination, remote: segment.source)
        if let id = connectionsByTuple[tuple] {
            let connectionOutputs = modifyConnection(id) { $0.receive(segment, at: now) } ?? []
            process(connectionOutputs, of: id, at: now, into: &outputs)
        } else if timeWaitRecords[tuple] != nil {
            if let reply = replyInTimeWait(to: segment, for: tuple, at: now) {
                append(reply, to: &outputs)
            }
        } else if let listenerID = listenersByPort[segment.destination.port] {
            receiveInListen(segment, listener: listenerID, at: now, into: &outputs)
        } else if let reset = Self.reset(answering: segment) {
            append(reset, to: &outputs)
        }
        return outputs
    }

    // MARK: LISTEN (RFC 9293 3.10.7.2)

    /// 리스너에 온 세그먼트. 차례로: RST는 무시, ACK가 있으면 `<SEQ=SEG.ACK><CTL=RST>`, SYN이면 상한을 본 뒤 연결을 만든다,
    /// 그 밖은 버린다. SYN의 보안·구획 검사(같은 절 셋째)는 쓰지 않는다.
    ///
    /// 상한(계약 동작 S4~S6, X7)에 닿은 SYN은 응답 없이 버린다. 상대는 SYN을 다시 보낸다.
    private mutating func receiveInListen(
        _ segment: TCPSegment, listener listenerID: ListenerID, at now: ContinuousClock.Instant,
        into outputs: inout [Output]
    ) {
        let flags = segment.flags
        if flags.contains(.rst) { return }
        if flags.contains(.ack) {
            append(
                TCPSegment(
                    source: segment.destination, destination: segment.source,
                    sequenceNumber: segment.acknowledgmentNumber, flags: [.rst]),
                to: &outputs)
            return
        }
        guard flags.contains(.syn), let listener = listeners[listenerID] else { return }

        let remoteAddress = segment.source.address
        let exceeded: Limit? =
            if connections.count >= Self.maximumConnections {
                .connections
            } else if timeWaitRecords.count >= Self.maximumTimeWaitRecords {
                .timeWaitRecords
            } else if halfOpenCount >= Self.maximumHalfOpenConnections {
                .halfOpenConnections
            } else if halfOpenCountByAddress[remoteAddress, default: 0] >= Self.maximumHalfOpenConnectionsPerAddress {
                .halfOpenConnectionsPerAddress
            } else if listener.queue.count + listener.halfOpenCount >= Self.maximumAcceptQueueLength {
                .acceptQueue
            } else {
                nil
            }
        if let exceeded {
            outputs.append(.dropped(.limitReached(exceeded)))
            return
        }

        let initialSequenceNumber = initialSequenceNumbers.initialSequenceNumber(
            local: segment.destination, remote: segment.source, at: now)
        let opened: (connection: TCPConnection, outputs: [TCPConnection.Output])
        do {
            opened = try TCPConnection.accept(segment, initialSequenceNumber: initialSequenceNumber, at: now)
        } catch {
            // 상대 MSS가 64보다 작으면 그 SYN에 RST로 답한다(계약 동작 X9). notInitialSYN은 위에서 걸렀다.
            if case .unacceptableMaximumSegmentSize(let reset) = error {
                append(reset, to: &outputs)
            }
            return
        }

        let id = makeConnectionID()
        connections[id] = ConnectionEntry(connection: opened.connection, role: .halfOpen(listenerID))
        connectionsByTuple[FourTuple(local: segment.destination, remote: segment.source)] = id
        halfOpenCount += 1
        halfOpenCountByAddress[remoteAddress, default: 0] += 1
        listeners[listenerID]?.halfOpenCount += 1
        process(opened.outputs, of: id, at: now, into: &outputs)
    }

    // MARK: 연결 없는 곳 (RFC 9293 3.10.7.1)

    /// 연결도 기록도 리스너도 없는 곳으로 온 세그먼트에 답할 RST. RST에는 답하지 않는다(`nil`).
    ///
    /// ACK가 꺼져 있으면 `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>`, 켜져 있으면 `<SEQ=SEG.ACK><CTL=RST>`. 답은 데이터가 없어
    /// 받은 것보다 크지 않으므로 증폭이 없다. 따로 속도를 제한하지 않는다(계약 동작 X8).
    static func reset(answering segment: TCPSegment) -> TCPSegment? {
        guard !segment.flags.contains(.rst) else { return nil }
        if segment.flags.contains(.ack) {
            return TCPSegment(
                source: segment.destination, destination: segment.source,
                sequenceNumber: segment.acknowledgmentNumber, flags: [.rst])
        }
        return TCPSegment(
            source: segment.destination, destination: segment.source, sequenceNumber: SequenceNumber(0),
            acknowledgmentNumber: segment.sequenceNumber.advanced(by: segment.sequenceLength), flags: [.rst, .ack])
    }
}
