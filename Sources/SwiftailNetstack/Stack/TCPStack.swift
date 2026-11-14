import SwiftailBase

/// 여러 TCP 연결과 리스너를 묶는 스택(계약 동작 S, X7·X8·X10).
///
/// 소켓·시계·난수가 없는 값 타입이다. 입력은 IP 패킷 바이트(`receive(_:at:)`), 시각(`advance(to:)`), 응용의 호출
/// (리스너 열기·닫기, accept 대기열에서 꺼내기, `connect`, 연결 ID로 부르는 `write`·`read`·`finishWriting`·`close`·`abort`),
/// 자기 주소 목록의 갱신이다. 출력은 내보낼 IP 패킷, 사건, 버린 것(`Output`)이고 낸 순서대로 처리해야 한다(계약 동작 S10).
///
/// 노드가 부르는 순서:
/// 1. 만든 뒤 `setLocalAddresses(_:)`로 자기 tailnet 주소를 넘긴다(netmap을 적용할 때마다 다시).
/// 2. 받은 패킷 묶음을 하나씩 `receive(_:at:)`에 넣고, 묶음이 끝나면 **같은 시각으로 `advance(to:)`를 불러** 미뤄 둔 ACK를
///    받는다. 연결은 `receive`에서 순수 ACK를 내지 않는다(계약 동작 F5, M6-4에서 정해진 것).
/// 3. `nextDeadline`에 타이머를 맞추고, 깨면 `advance(to:)`를 부른다.
///
/// 연결은 `ConnectionID`로, 리스너는 `ListenerID`로 가리킨다. 둘 다 스택 하나 안에서 다시 쓰지 않는 번호라, 끝난 연결의
/// 옛 ID로 부른 호출은 새 연결에 닿지 않고 아무 일도 하지 않는다. 사건은 응용이 쥔 연결(`connect`로 건 것, `accept`로 꺼낸 것)
/// 에 대해서만 나온다. 맺는 중이거나 대기열에 있는 연결의 일, 응용이 `close`·`abort`한 뒤의 일은 알리지 않는다.
///
/// 이 파일은 타입의 선언과 상태, 시각을 담는다. 받기·응용 호출·연결 정리·ISN·TIME-WAIT 기록은 같은 폴더의 파일에 있다.
/// 계약: `docs/contracts/SwiftailNetstack.md` 동작 S·X·M. 노트: `docs/protocol-notes/tcp-netstack.md` 4.2·4.3절.
package struct TCPStack: Sendable {
    /// 연결 하나의 이름. 스택 안에서 다시 쓰지 않는다.
    package struct ConnectionID: Hashable, Sendable {
        /// 스택이 차례로 매기는 번호. 리스너 ID와 같은 번호 줄을 쓴다. 차례(결정적인 출력 순서)를 정하는 데 쓴다.
        package let rawValue: UInt64
    }

    /// 리스너 하나의 이름. 스택 안에서 다시 쓰지 않는다(같은 포트를 다시 열어도 새 이름이다).
    package struct ListenerID: Hashable, Sendable {
        /// 스택이 차례로 매기는 번호. 연결 ID와 같은 번호 줄을 쓴다.
        package let rawValue: UInt64
    }

    /// 스택이 내놓는 일. 낸 순서대로 처리한다. 한 연결의 패킷은 시퀀스 순서로 나온다(계약 동작 S10).
    package enum Output: Sendable, Equatable {
        /// 내보낼 IP 패킷. 노드가 엔진에 넣는다.
        case ipPacket([UInt8])
        /// 응용에 알릴 일.
        case event(Event)
        /// 받은 패킷을 버렸다. 노드가 로그의 횟수를 센다(계약 동작 K2).
        case dropped(Drop)
    }

    /// 응용에 알릴 일. 응용이 쥔 연결과 리스너의 것만 나온다.
    package enum Event: Sendable, Equatable {
        /// `connect`로 건 연결이 맺어졌다.
        case established(ConnectionID)
        /// 리스너의 accept 대기열에 연결이 하나 들어왔다. `accept(from:)`로 꺼낸다.
        case acceptable(ListenerID)
        /// 읽을 바이트가 없다가 생겼다.
        case readable(ConnectionID)
        /// 보내는 버퍼가 찼다가 자리가 났다.
        case writable(ConnectionID)
        /// 상대가 쓰기를 닫았다(FIN). 그 전에 받은 데이터는 모두 읽을 수 있다.
        case endOfStream(ConnectionID)
        /// 연결이 끝났다. 이 뒤로는 그 연결의 사건이 없다. `.finished`면 읽지 않은 데이터를 아직 읽을 수 있다.
        case closed(ConnectionID, CloseReason)
    }

    /// 연결이 끝난 까닭. `TCPConnection.CloseReason`에 스택이 내는 `peerRemoved`를 더했다.
    package enum CloseReason: Sendable, Equatable {
        /// 양쪽 FIN이 오갔다. TIME-WAIT에 들어간 때에 알린다(남은 60초는 스택이 기록으로 지킨다).
        case finished
        /// 상대가 RST로 끊었다.
        case reset
        /// 건 연결을 상대가 거절했다(SYN에 RST, 또는 상대 MSS가 64보다 작음).
        case refused
        /// 상대가 답하지 않는다(재전송 한도, 0 창 탐침, keep-alive, FIN-WAIT-2의 기한).
        case timedOut
        /// 이 쪽이 끊었다(`abort`, 읽지 않은 데이터가 있을 때의 `close`, `close` 뒤에 온 데이터).
        case aborted
        /// 이 쪽 주소가 바뀌었거나(계약 동작 S9) 상대 주소의 주인이 바뀌었다(계약 동작 X10). 아무것도 보내지 않았다.
        case peerRemoved

        init(_ reason: TCPConnection.CloseReason) {
            switch reason {
            case .finished: self = .finished
            case .reset: self = .reset
            case .refused: self = .refused
            case .timedOut: self = .timedOut
            case .aborted: self = .aborted
            }
        }
    }

    /// 받은 패킷을 버린 까닭. 프로토콜이 조용히 버리라는 세그먼트(연결 없는 곳의 RST 등)는 여기 넣지 않는다.
    package enum Drop: Sendable, Equatable {
        /// TCP가 아니다(계약 동작 N2. ICMP·UDP는 다루지 않는다).
        case notTCP
        /// 길이·머리·옵션이 맞지 않거나 조각이다.
        case malformed
        /// 체크섬이 틀리다.
        case badChecksum
        /// 목적지가 자기 tailnet 주소가 아니다(계약 동작 S1).
        case notForUs
        /// 상한에 닿아 SYN에 답하지 않았다(계약 동작 S4~S6).
        case limitReached(Limit)
    }

    /// SYN을 버리게 한 상한(계약 동작 M의 표).
    package enum Limit: Sendable, Equatable {
        /// 맺는 중인 연결 64개(스택 전체).
        case halfOpenConnections
        /// 맺는 중인 연결 16개(상대 주소 하나).
        case halfOpenConnectionsPerAddress
        /// 리스너 하나의 accept 대기열 32개(맺는 중인 것을 함께 센다).
        case acceptQueue
        /// 연결 256개(스택 전체).
        case connections
        /// 연결 64개(상대 주소 하나). 한 피어가 256개를 채워 다른 피어를 막지 못하게 한다(M6 검토 A).
        case connectionsPerAddress
        /// TIME-WAIT 기록 1,024개(스택 전체).
        case timeWaitRecords
    }

    /// `listen(on:)`의 실패.
    package enum ListenError: Error, Sendable, Equatable {
        /// 그 포트에 이미 리스너가 있다.
        case addressInUse
        /// 리스너가 16개다.
        case limitReached
    }

    /// `connect(to:at:)`의 실패.
    package enum ConnectError: Error, Sendable, Equatable {
        /// 목적지와 같은 계열의 자기 주소가 없다(계약 동작 S8. 노드는 `unknownHost`로 알린다).
        case noLocalAddress
        /// 연결이 256개이거나, 그 상대 주소의 연결이 64개이거나, TIME-WAIT 기록이 1,024개이거나, 그 목적지로 쓸 나가는
        /// 포트가 없다.
        case limitReached
    }

    // MARK: 상한 (계약 동작 M)

    static let maximumListeners = 16
    static let maximumHalfOpenConnections = 64
    static let maximumHalfOpenConnectionsPerAddress = 16
    static let maximumAcceptQueueLength = 32
    static let maximumConnections = 256
    static let maximumConnectionsPerAddress = 64
    static let maximumTimeWaitRecords = 1_024
    static let maximumTimeWaitRecordsPerAddress = 64
    /// 나가는 연결의 포트(계약 동작 S8).
    static let ephemeralPorts: ClosedRange<UInt16> = 49_152...65_535

    // MARK: 상태

    /// 자기 tailnet 주소. 이 주소로 온 패킷만 받고, 나가는 연결의 출발 주소를 여기서 고른다.
    package internal(set) var localAddresses: [IPAddress] = []
    /// 모든 연결. 맺는 중·대기열·응용이 쥔 것·응용이 놓았지만 아직 닫는 중인 것·남은 데이터만 있는 것. 256개까지다.
    /// `insertConnection(_:)`과 `removeConnection(_:)`으로만 넣고 뺀다(상대 주소별 수가 어긋나지 않게). 항목의 값은 제자리에서
    /// 고친다.
    var connections: [ConnectionID: ConnectionEntry] = [:]
    /// 상대 주소별 연결 수(`connections`의 항목 수). 주소 하나에 64개까지다.
    private(set) var connectionCountByAddress: [IPAddress: Int] = [:]
    /// 4-튜플 → 연결. TCP가 끝난(TIME-WAIT 기록으로 옮겼거나 닫힌) 연결은 여기서 빠진다.
    var connectionsByTuple: [FourTuple: ConnectionID] = [:]
    /// 연결마다의 `nextDeadline`. 연결을 움직일 때마다 고친다(기한 찾기가 연결의 타이머를 다시 훑지 않게).
    var connectionDeadlines: [ConnectionID: ContinuousClock.Instant] = [:]
    /// TIME-WAIT 기록. 1,024개까지이고 기한 전에 버리지 않는다(계약 동작 S6). 다만 상대 주소 하나의 기록이 64개를 넘으면
    /// 그 주소의 가장 오래된 기록을 지운다(M6 검토 A). 아래 "TIME-WAIT 기록"의 함수로만 고친다.
    private(set) var timeWaitRecords: [FourTuple: TimeWaitRecord] = [:]
    /// 상대 주소별 TIME-WAIT 기록의 4-튜플. 만든 순서이고 `timeWaitRecords`와 같은 기록을 가리킨다.
    private(set) var timeWaitTuplesByAddress: [IPAddress: [FourTuple]] = [:]
    /// TIME-WAIT 기록 가운데 가장 이른 기한. 기한이 된 것이 없는 `advance`가 기록을 훑지 않게 한다.
    private(set) var earliestTimeWaitDeadline: ContinuousClock.Instant?
    var listeners: [ListenerID: Listener] = [:]
    var listenersByPort: [UInt16: ListenerID] = [:]
    /// SYN-RECEIVED인 연결 수(스택 전체, 상대 주소별).
    var halfOpenCount = 0
    var halfOpenCountByAddress: [IPAddress: Int] = [:]
    /// 다음에 줄 ID. 연결과 리스너가 함께 쓴다.
    var nextIdentifier: UInt64 = 1
    /// 다음에 시도할 나가는 포트.
    var nextEphemeralPort = TCPStack.ephemeralPorts.lowerBound
    let initialSequenceNumbers: InitialSequenceNumberGenerator

    /// 스택을 만든다.
    ///
    /// - Parameters:
    ///   - isnSecret: ISN의 비밀(RFC 6528 3). 노드가 `run()`마다 시스템 난수로 32바이트를 뽑아 넘긴다. 사건·오류·
    ///     `description`·`dump`에 나오지 않는다(계약 동작 K1).
    ///   - now: ISN의 시계 성분이 0인 시각.
    package init(isnSecret: [UInt8], now: ContinuousClock.Instant) {
        initialSequenceNumbers = InitialSequenceNumberGenerator(secret: isnSecret, origin: now)
    }

    // MARK: 읽을 수 있는 값

    /// 연결의 지금 값(상태, 주소, 읽을 수 있는 바이트 수, 쓸 자리, FIN 수신 여부). 없는 ID면 `nil`.
    ///
    /// 값의 복사본이다. 읽고 곧바로 버린다(쥐고 있으면 스택이 버퍼를 고칠 때 버퍼 전체가 복사된다).
    package func connection(_ id: ConnectionID) -> TCPConnection? {
        connections[id]?.connection
    }

    /// 모든 연결과 TIME-WAIT 기록 가운데 가장 이른 기한. 없으면 `nil`.
    ///
    /// 연결마다 적어 둔 기한(256개까지)을 훑고 TIME-WAIT 기록의 가장 이른 기한과 견준다.
    // shortcut: 연결의 기한은 힙 없이 훑는다(계약 제외 표 "스택의 기한 찾기"). 연결 상한을 크게 올리면 바꾼다.
    package var nextDeadline: ContinuousClock.Instant? {
        var earliest = earliestTimeWaitDeadline
        for deadline in connectionDeadlines.values where earliest.map({ deadline < $0 }) ?? true {
            earliest = deadline
        }
        return earliest
    }

    // MARK: 시각

    /// `now`까지 기한이 지난 일을 모두 한다: 기한이 된 TIME-WAIT 기록을 지우고, 기한이 된 연결을 `advance(to:)`한다.
    /// 미뤄 둔 ACK도 여기서 나간다. 연결은 기한, 같은 기한이면 ID 순으로 움직인다(출력이 결정적이게).
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output] {
        expireTimeWaitRecords(at: now)

        var due: [(deadline: ContinuousClock.Instant, id: ConnectionID)] = []
        for (id, deadline) in connectionDeadlines where deadline <= now {
            due.append((deadline, id))
        }
        due.sort { ($0.deadline, $0.id.rawValue) < ($1.deadline, $1.id.rawValue) }

        var outputs: [Output] = []
        for (_, id) in due {
            let connectionOutputs = modifyConnection(id) { $0.advance(to: now) } ?? []
            process(connectionOutputs, of: id, at: now, into: &outputs)
        }
        return outputs
    }
}

// MARK: - 연결 표

extension TCPStack {
    /// 새 연결을 표에 넣고 ID를 준다. 상대 주소별 연결 수는 여기서만 늘린다(줄이는 곳은 `removeConnection(_:)`).
    mutating func insertConnection(_ entry: ConnectionEntry) -> ConnectionID {
        let id = makeConnectionID()
        connections[id] = entry
        connectionsByTuple[entry.tuple] = id
        connectionCountByAddress[entry.connection.remoteEndpoint.address, default: 0] += 1
        return id
    }

    /// 연결을 표에서 지운다. 아무것도 보내지 않는다. 맺는 중인 수와 대기열, 상대 주소별 연결 수를 함께 고친다.
    mutating func removeConnection(_ id: ConnectionID) {
        guard let entry = connections.removeValue(forKey: id) else { return }
        connectionDeadlines[id] = nil
        let tuple = entry.tuple
        if connectionsByTuple[tuple] == id {
            connectionsByTuple[tuple] = nil
        }
        let address = entry.connection.remoteEndpoint.address
        let remaining = connectionCountByAddress[address, default: 1] - 1
        connectionCountByAddress[address] = remaining > 0 ? remaining : nil
        switch entry.role {
        case .halfOpen(let listenerID):
            leaveHalfOpen(address, listener: listenerID)
        case .queued(let listenerID):
            listeners[listenerID]?.queue.removeAll { $0 == id }
        case .application, .released:
            break
        }
    }

    /// 상대 주소 `address`의 연결이 64개다. 새 SYN과 `connect`를 받지 않는다.
    func isConnectionLimitReached(for address: IPAddress) -> Bool {
        connectionCountByAddress[address, default: 0] >= Self.maximumConnectionsPerAddress
    }
}

// MARK: - TIME-WAIT 기록

extension TCPStack {
    /// 기록을 더한다. 4-튜플의 연결은 이미 표에서 빠졌어야 하고, 그 4-튜플의 기록은 없어야 한다.
    ///
    /// 상대 주소의 기록이 이미 64개면 그 주소의 가장 오래된 기록을 먼저 지운다. 기한 전에 버리지 않는다는 동작 S6의 예외이고,
    /// 영향은 그 피어 자신의 옛 연결에만 간다(그 4-튜플의 늦은 세그먼트에는 RST로 답하게 된다). 한 피어가 기록 1,024개를 채워
    /// 다른 피어의 SYN과 `connect`를 막지 못하게 한다(M6 검토 A).
    mutating func addTimeWaitRecord(_ record: TimeWaitRecord, for tuple: FourTuple) {
        let address = tuple.remote.address
        if let sameAddress = timeWaitTuplesByAddress[address],
            sameAddress.count >= Self.maximumTimeWaitRecordsPerAddress
        {
            let evicted = forgetTimeWaitRecord(sameAddress[0])
            if evicted?.deadline == earliestTimeWaitDeadline {
                earliestTimeWaitDeadline = timeWaitRecords.values.lazy.map(\.deadline).min()
            }
        }
        timeWaitRecords[tuple] = record
        timeWaitTuplesByAddress[address, default: []].append(tuple)
        earliestTimeWaitDeadline = min(earliestTimeWaitDeadline ?? record.deadline, record.deadline)
    }

    /// `tuple`의 기록에 온 세그먼트에 답한다(`TimeWaitRecord.reply`). 기록이 없으면 `nil`.
    mutating func replyInTimeWait(
        to segment: TCPSegment, for tuple: FourTuple, at now: ContinuousClock.Instant
    ) -> TCPSegment? {
        guard let index = timeWaitRecords.index(forKey: tuple) else { return nil }
        let previousDeadline = timeWaitRecords.values[index].deadline
        let reply = timeWaitRecords.values[index].reply(to: segment, at: now)
        // 기한은 뒤로만 간다. 가장 이른 것이 늦춰졌을 때만 다시 찾는다.
        if timeWaitRecords.values[index].deadline != previousDeadline, previousDeadline == earliestTimeWaitDeadline {
            earliestTimeWaitDeadline = timeWaitRecords.values.lazy.map(\.deadline).min()
        }
        return reply
    }

    /// 기한이 된 기록을 지운다. 가장 이른 기한이 아직이면 훑지 않는다.
    mutating func expireTimeWaitRecords(at now: ContinuousClock.Instant) {
        guard let earliest = earliestTimeWaitDeadline, earliest <= now else { return }
        var expired: [FourTuple] = []
        for (tuple, record) in timeWaitRecords where record.deadline <= now {
            expired.append(tuple)
        }
        for tuple in expired {
            forgetTimeWaitRecord(tuple)
        }
        earliestTimeWaitDeadline = timeWaitRecords.values.lazy.map(\.deadline).min()
    }

    /// 기록 하나를 표와 주소별 목록에서 뺀다. 가장 이른 기한은 부른 쪽이 다시 찾는다.
    @discardableResult
    private mutating func forgetTimeWaitRecord(_ tuple: FourTuple) -> TimeWaitRecord? {
        guard let record = timeWaitRecords.removeValue(forKey: tuple) else { return nil }
        let address = tuple.remote.address
        timeWaitTuplesByAddress[address]?.removeAll { $0 == tuple }
        if timeWaitTuplesByAddress[address]?.isEmpty == true {
            timeWaitTuplesByAddress[address] = nil
        }
        return record
    }
}

// MARK: - 표의 항목

/// 연결을 찾는 열쇠: (자기 주소, 자기 포트, 상대 주소, 상대 포트).
struct FourTuple: Hashable, Sendable {
    var local: IPEndpoint
    var remote: IPEndpoint
}

/// 듣는 포트 하나.
struct Listener: Sendable {
    let port: UInt16
    /// 맺어졌지만 응용이 아직 꺼내지 않은 연결. 들어온 순서다.
    var queue: [TCPStack.ConnectionID] = []
    /// 이 리스너에 온 SYN으로 만든, 아직 맺는 중인 연결 수. 대기열과 합쳐 32개까지다.
    var halfOpenCount = 0
}

/// 연결 표의 항목.
struct ConnectionEntry: Sendable {
    /// 연결을 누가 쥐는가.
    enum Role: Sendable, Equatable {
        /// SYN-RECEIVED. 리스너에 온 SYN으로 만들었다.
        case halfOpen(TCPStack.ListenerID)
        /// 맺어져 리스너의 대기열에 있다.
        case queued(TCPStack.ListenerID)
        /// 응용이 쥐고 있다(`connect`, `accept`). 사건을 알린다.
        case application
        /// 응용이 `close`로 놓았다. TCP가 닫기를 마치면 지운다.
        case released
    }

    var connection: TCPConnection
    var role: Role
    /// 응용에 `.closed`를 알렸다. 그 뒤의 사건은 내지 않는다.
    var hasReportedClose = false
    /// TCP의 일이 끝났다(닫혔거나 TIME-WAIT 기록으로 옮겼다). 응용이 읽지 않은 데이터만 남아, 응용이 `close`·`abort`할 때까지 둔다.
    var isDetached = false

    var tuple: FourTuple {
        FourTuple(local: connection.localEndpoint, remote: connection.remoteEndpoint)
    }
}
