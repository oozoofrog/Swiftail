import Foundation
import SwiftailBase
import SwiftailControl
import SwiftailEngine
import SwiftailNetstack

/// 노드와 프로세스 안의 TCP 스택 잇기(`docs/contracts/SwiftailNetstack.md` 동작 N, X10, K).
///
/// ```
/// engine.receive ─ .ipPacket ─► deliverToDevice ─► inbox ─► stack.receive ─┬ .ipPacket ─► engine.send ─► Magicsock …
///                                                                       │                  └ .ipPacket(자기 주소) ─► inbox
///                                                                       └ .event ─► 기다리던 read·write·accept·connect를 깨움
/// 앱의 호출(read·write·connect·close…) ─► stack.<호출> ─► 위와 같이 출력 처리
/// 타이머 ─► stack.advance(to:)
/// ```
///
/// 스택은 노드 actor의 저장 프로퍼티인 값이고, 스택·엔진·`Magicsock` 사이의 주고받기는 한 번의 actor 실행 안에서 `await`
/// 없이 끝난다. 그래서 노드와 스택 사이에 버퍼·버림·둘째 타이머가 없다(구조 3).
///
/// 사건 하나에서 비롯된 일은 재귀가 아니라 대기열(`Netstack.inbox`)로 돈다(동작 N4): 스택의 출력을 처리하다 엔진이 되돌린
/// 패킷(자기 주소로 건 연결)은 대기열에 쌓이고, 가장 바깥의 처리가 출력을 낸 순서대로 다 처리한 뒤 차례로 스택에 넣는다.
/// 대기열이 비면 같은 시각으로 `advance(to:)`를 불러 미뤄 둔 ACK를 낸다.
///
/// 기다리는 호출은 `suspend(until:)`로 멈추고 스택의 사건이 깨운다. 깨우는 통로는 값을 나르지 않는다: 깨어난 호출이 상태를
/// 다시 보고 무엇을 할지 정한다. 그래서 취소와 깨우기가 겹쳐도 데이터나 연결을 잃지 않는다.
extension TailnetNode {
    // MARK: 수명 (동작 N8)

    /// `run()`이 시작할 때 스택을 만든다. `.inProcess`가 아니면 아무것도 하지 않는다(다른 장치에는 스택의 상태가 없다).
    ///
    /// ISN의 비밀 32바이트는 `run()`마다 시스템 난수로 뽑는다(계약 동작 S7). `run()` 전에 연 리스너를 스택에 올린다(동작 A1).
    func startNetstack() {
        guard case .inProcess = device else { return }
        var generator = SystemRandomNumberGenerator()
        let isnSecret = (0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
        netstack = Netstack(stack: TCPStack(isnSecret: isnSecret, now: .now))
        for token in listenerRecords.keys.sorted() {
            guard let port = listenerRecords[token]?.port else { continue }
            do throws(TCPStack.ListenError) {
                listenerRecords[token]?.stackID = try netstack?.stack.listen(on: port)
            } catch {
                // `listen(port:)`이 스택과 같은 중복·상한을 먼저 보므로 일어나지 않는다. 일어나면 그 리스너의 흐름을 끝낸다.
                listenerRecords.removeValue(forKey: token)?.waiter?.finish()
            }
        }
    }

    /// `run()`이 끝날 때 부른다. 두 번 불러도 된다.
    ///
    /// 리스너를 모두 닫고(받아 가지 않은 연결은 RST), 응용이 쥔 연결마다 RST를 한 번 낸다. 소켓과 엔진이 아직 있을 때 불러야
    /// 직접 경로로 나간다(DERP 통로에 있던 것은 사라질 수 있다). 기다리던 호출을 모두 깨운다: 깨어난 호출은 스택이 없는 것을
    /// 보고 `notRunning`을 던지고, 리스너의 흐름은 끝난다. 그 뒤에 버려진 핸들은 무시한다.
    func stopNetstack() {
        let now = ContinuousClock.now
        for token in listenerRecords.keys.sorted() {
            closeListener(token, at: now)
        }
        if let ids = netstack?.connections.keys.sorted(by: { $0.rawValue < $1.rawValue }) {
            for id in ids {
                process(netstack?.stack.abort(id, at: now) ?? [], at: now)
            }
            // 응용이 `close`로 놓았지만 아직 닫는 중인 연결, 맺는 중인 연결도 RST로 끊는다. 상대가 재전송 한도까지 기다리지
            // 않게 한다.
            process(netstack?.stack.abortAll() ?? [], at: now)
            netstack?.connections.values.forEach { $0.finishWaiters() }
            netstack = nil
        }
        handleReleases.finish()
    }

    /// 버려진 핸들을 처리한다. 취소될 때까지 돈다(동작 N9).
    func releaseHandles() async {
        for await release in handleReleaseStream {
            switch release {
            case let .connection(id):
                abortConnection(id)
            case let .listener(token):
                closeListener(token)
            }
        }
    }

    // MARK: 출력 처리 (동작 N2~N5)

    /// 엔진이 장치로 쓰라고 낸 패킷 하나를 스택에 넣는다(동작 N2). TCP가 아닌 것은 스택이 버린다.
    func deliverToNetstack(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) {
        guard netstack != nil, inProcessLoss?.dropsNext() != true else { return }
        netstack?.inbox.append(ipPacket)
        process([TCPStack.Output](), at: now)
    }

    /// 스택의 출력을 낸 순서대로 처리한다. 스택을 바꾼 모든 호출 뒤에 부른다.
    ///
    /// 가장 바깥의 호출이면 그동안 쌓인 대기열을 스택에 넣고, 대기열이 빈 뒤 같은 시각으로 `advance(to:)`를 불러 미뤄 둔
    /// ACK를 낸다. 그 ACK가 되돌아와 대기열이 다시 차면 되풀이한다(버퍼가 묶으므로 끝난다). 안쪽 호출이면 출력만 처리한다.
    func process(_ outputs: [TCPStack.Output], at now: ContinuousClock.Instant) {
        guard let isProcessing = netstack?.isProcessing else { return }
        netstack?.isProcessing = true
        handle(outputs, at: now)
        guard !isProcessing else { return }
        repeat {
            while let batch = netstack?.inbox, !batch.isEmpty {
                netstack?.inbox = []
                for packet in batch {
                    handle(netstack?.stack.receive(packet, at: now) ?? [], at: now)
                }
            }
            handle(netstack?.stack.advance(to: now) ?? [], at: now)
        } while netstack?.inbox.isEmpty == false
        netstack?.isProcessing = false
        rearmTimer()
    }

    private func handle(_ outputs: [TCPStack.Output], at now: ContinuousClock.Instant) {
        for output in outputs {
            switch output {
            case let .ipPacket(bytes):
                // 엔진은 M5의 로컬 처리를 그대로 한다: 자기 주소로 간 것은 되돌리고(→ 대기열), 서비스 IP는 RST로 거절한다(N3).
                guard inProcessLoss?.dropsNext() != true else { continue }
                process(engine?.send(bytes, at: now) ?? [], at: now)
            case let .event(event):
                dispatch(event)
            case let .dropped(.limitReached(limit)):
                countLimitDrop(limit)
            case .dropped:
                break
            }
        }
    }

    /// 스택의 사건으로 기다리던 호출을 깨운다(동작 N5).
    private func dispatch(_ event: TCPStack.Event) {
        switch event {
        case let .established(id):
            netstack?.connections[id]?.isEstablished = true
            wakeWriter(id)
        case let .acceptable(listenerID):
            for (token, record) in listenerRecords where record.stackID == listenerID {
                listenerRecords[token]?.waiter?.finish()
            }
        case let .readable(id), let .endOfStream(id):
            wakeReader(id)
        case let .writable(id):
            wakeWriter(id)
        case let .closed(id, reason):
            guard netstack?.connections[id] != nil else { return }
            netstack?.connections[id]?.closeReason = reason
            wakeReader(id)
            wakeWriter(id)
            Self.log.info("연결이 끝남: \(reason.logName, privacy: .public)")
        }
    }

    /// 읽기 쪽 사건을 적고 기다리던 `read`를 깨운다. 적어 두는 것은, 사건이 호출 자신의 출력 처리 안에서 나와 깨울 대상이
    /// 아직 없을 때(자기 주소로 건 연결) 호출이 기다리기 전에 보고 다시 시도하게 하기 위해서다.
    func wakeReader(_ id: TCPStack.ConnectionID) {
        netstack?.connections[id]?.hasReadEvent = true
        netstack?.connections[id]?.readWaiter?.finish()
    }

    /// 쓰기 쪽 사건(자리가 남, 맺어짐, 끝남)을 적고 기다리던 `write`·`connect`를 깨운다.
    func wakeWriter(_ id: TCPStack.ConnectionID) {
        netstack?.connections[id]?.hasWriteEvent = true
        netstack?.connections[id]?.writeWaiter?.finish()
    }

    /// 상한에 닿아 버린 SYN을 센다. 홍수에 로그가 넘치지 않게 1·2·4·8…번째에만 남긴다(동작 K2).
    private func countLimitDrop(_ limit: TCPStack.Limit) {
        netstack?.limitDropCount += 1
        let count = netstack?.limitDropCount ?? 0
        guard count & (count - 1) == 0 else { return }
        Self.log.notice("상한에 닿아 SYN을 버림: \(limit.logName, privacy: .public), 누적 \(count, privacy: .public)개")
    }

    // MARK: 기다리기

    /// 깨우는 통로를 `register`로 상태에 걸고, 깨우기나 호출한 Task의 취소까지 기다린다.
    ///
    /// 통로는 기다릴 때마다 새로 만들어 한 번만 쓰고, 깨우는 쪽은 `finish()`만 부른다(정확히 한 번 깨어난다: 이미 끝난 통로의
    /// `finish()`는 아무 일도 하지 않는다). 통로를 상태에서 지우는 것은 깨어난 호출이다. 거는 일과 기다리기 사이에 `await`가
    /// 없으므로 그 사이의 깨우기를 놓치지 않는다. 지켜야 할 것 둘:
    /// - 걸 자리(기록)가 있는지 먼저 확인하고 부른다. 없는 자리에 건 통로는 아무도 깨우지 않는다.
    /// - 기록을 상태에서 통째로 지우는 쪽은 그 기록의 통로를 `finish()`한다.
    func suspend(until register: (Wakeup) -> Void) async {
        let (wakeups, wakeup) = AsyncStream.makeStream(of: Void.self)
        register(wakeup)
        for await _ in wakeups {}
    }

    // MARK: netmap (동작 N7, S9, X10)

    /// netmap을 적용할 때마다 부른다. 자기 주소를 스택에 넘기고, 데이터면 피어의 주소마다 주인(node 키)을 견주어 주인이
    /// 없어지거나 바뀐 주소의 연결을 끊는다(`peerRemoved`, 아무것도 보내지 않는다). 주소를 물려받은 다른 노드가 앞 노드의
    /// 연결을 이어 쓰는 것을 막는다(계약 총괄 확정 N8).
    ///
    /// 피어의 패킷은 그 피어의 AllowedIPs로 출발지를 검사받으므로(엔진 계약 M3 동작 2·5), 한 주소의 연결은 모두 그때의 주인과
    /// 맺은 것이다. 그래서 연결마다 키를 적지 않고 주소마다의 주인을 견준다. 맺는 중이거나 대기열에 있는 연결도 함께 끊긴다.
    func updateNetstack(for netmap: Netmap) {
        guard netstack != nil else { return }
        var owners: [IPAddress: NodePublicKey] = [:]
        for peer in EnginePeer.peers(in: netmap, at: Date()) {
            for prefix in peer.allowedIPs where prefix.isSingleAddress {
                owners[prefix.address] = peer.key
            }
        }
        let previous = netstack?.addressOwners ?? [:]
        netstack?.addressOwners = owners

        let localAddresses = netmap.selfNode.addresses.filter(\.isSingleAddress).map(\.address)
        var outputs = netstack?.stack.setLocalAddresses(localAddresses) ?? []
        let lost = previous.filter { owners[$0.key] != $0.value }.keys
        for address in lost.sorted(by: { $0.bytes.lexicographicallyPrecedes($1.bytes) }) {
            outputs += netstack?.stack.removeConnections(toRemoteAddress: address) ?? []
        }
        process(outputs, at: .now)
    }

    // MARK: 시험용 손실 (동작 N11)

    /// 시험 전용(공개 API 아님). 스택과 엔진 사이의 패킷을 양방향으로 `rate`의 확률로 버린다. 난수는 `seed`에서 만들어
    /// 같은 씨앗이면 같은 패킷 차례에서 버린다. 0이면(기본) 버리지 않는다. 자기 주소로 건 연결의 패킷은 나갈 때와 돌아올
    /// 때 두 번 걸린다. `rate`는 0…1로 자른다.
    ///
    /// 관문(`SwiftailInteropTests`)이 손실 1%·5%의 처리량을 잴 때 쓴다(계약 관문 (가) 8·9). Go 피어 쪽에는 주입이 없다.
    package func setInProcessLoss(rate: Double, seed: UInt64) {
        let clamped = rate.isNaN ? 0 : min(max(rate, 0), 1)
        inProcessLoss = clamped > 0 ? PacketLoss(rate: clamped, generator: SplitMix64(seed: seed)) : nil
    }
}

// MARK: - 노드가 쥐는 값

/// 버려진 핸들(`deinit`). `run()`의 자식이 받아 끊는다.
enum HandleRelease: Sendable {
    case connection(TCPStack.ConnectionID)
    case listener(UInt64)
}

/// 기다리는 호출 하나를 깨우는 통로(`TailnetNode.suspend(until:)`).
typealias Wakeup = AsyncStream<Void>.Continuation

/// `.inProcess` 장치에서 `run()` 동안 노드가 쥐는 TCP 상태.
struct Netstack: Sendable {
    var stack: TCPStack
    /// 데이터면 피어의 tailnet 주소 → 그 주소의 주인. netmap마다 견준다(동작 X10).
    var addressOwners: [IPAddress: NodePublicKey] = [:]
    /// 응용이 쥔 연결과 거는 중인 연결. 응용이 `close`·`abort`하거나 핸들이 버려지면 지운다.
    var connections: [TCPStack.ConnectionID: ConnectionRecord] = [:]
    /// 엔진이 장치로 낸 뒤 아직 스택에 넣지 않은 패킷(동작 N4).
    var inbox: [[UInt8]] = []
    /// 스택의 출력을 처리하는 중이다. 그동안 온 패킷은 `inbox`에 쌓고 가장 바깥의 처리가 넣는다.
    var isProcessing = false
    /// 상한에 닿아 버린 SYN 수(로그용).
    var limitDropCount = 0
}

/// 응용이 쥔(또는 거는 중인) 연결 하나의 가장자리 상태. 데이터는 스택에만 있다(가장자리에 따로 쌓는 버퍼가 없다, 동작 A5).
struct ConnectionRecord: Sendable {
    /// 기다리는 `read`.
    var readWaiter: Wakeup?
    /// 기다리는 `write`, 또는 맺어지기를 기다리는 `connect`.
    var writeWaiter: Wakeup?
    /// 마지막 시도 뒤 읽기·쓰기 쪽 사건이 왔다(`TailnetNode.wakeReader(_:)`).
    var hasReadEvent = false
    var hasWriteEvent = false
    /// 세 방향 핸드셰이크가 끝났다. 받은 연결은 처음부터 참이다.
    var isEstablished = false
    /// 응용이 `finishWriting`을 불렀다. 그 뒤의 `write`는 `closed`다.
    var hasFinishedWriting = false
    /// 스택이 알린 끝난 까닭. `finished`면 남은 데이터를 읽은 뒤 nil을 돌려준다.
    var closeReason: TCPStack.CloseReason?

    func finishWaiters() {
        readWaiter?.finish()
        writeWaiter?.finish()
    }
}

/// 열린 리스너 하나.
struct ListenerRecord: Sendable {
    let port: UInt16
    /// 스택의 리스너. `run()` 전에 열었으면 `run()`이 시작할 때까지 nil이다.
    var stackID: TCPStack.ListenerID?
    /// 다음 연결을 기다리는 흐름.
    var waiter: Wakeup?
}

/// 시험용 손실 주입(`TailnetNode.setInProcessLoss(rate:seed:)`).
struct PacketLoss: Sendable {
    let rate: Double
    var generator: SplitMix64

    /// 다음 패킷을 버릴지 정한다.
    mutating func dropsNext() -> Bool {
        Double.random(in: 0..<1, using: &generator) < rate
    }
}

/// 씨앗이 있는 난수(SplitMix64, Steele·Lea·Flood 2014). 시험의 손실 주입에만 쓴다. 암호용이 아니다.
struct SplitMix64: RandomNumberGenerator, Sendable {
    private var state: UInt64

    init(seed: UInt64) {
        state = seed
    }

    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

extension IPPrefix {
    /// 주소 하나짜리 접두(/32, /128). 노드의 tailnet 주소다.
    var isSingleAddress: Bool {
        length == address.bytes.count * 8
    }
}

extension ConnectionError {
    /// 스택이 알린 끝난 까닭을 그 뒤의 호출이 던질 오류로 옮긴다. `finished`는 오류가 아니다(남은 데이터를 읽고 nil).
    /// `aborted`는 이 쪽이 끊은 것이라 `closed`다.
    init?(closedBy reason: TCPStack.CloseReason) {
        switch reason {
        case .finished: return nil
        case .reset: self = .reset
        case .refused: self = .refused
        case .timedOut: self = .timedOut
        case .aborted: self = .closed
        case .peerRemoved: self = .peerRemoved
        }
    }
}

extension TCPStack.CloseReason {
    /// 로그에 남길 이름.
    var logName: String {
        switch self {
        case .finished: "finished"
        case .reset: "reset"
        case .refused: "refused"
        case .timedOut: "timedOut"
        case .aborted: "aborted"
        case .peerRemoved: "peerRemoved"
        }
    }
}

extension TCPStack.Limit {
    /// 로그에 남길 이름.
    var logName: String {
        switch self {
        case .halfOpenConnections: "halfOpenConnections"
        case .halfOpenConnectionsPerAddress: "halfOpenConnectionsPerAddress"
        case .acceptQueue: "acceptQueue"
        case .connections: "connections"
        case .timeWaitRecords: "timeWaitRecords"
        }
    }
}
