import Network
import SwiftailCrypto
import Synchronization

/// 다리가 연 루프백 연결만 리스너를 지나가게 하는 표와 framer(계약 `docs/contracts/SwiftailHost.md` 동작 B6, M7-9b).
///
/// 다리는 루프백 연결을 맺으면 TLS 바이트보다 먼저 32바이트 토큰을 보낸다. 리스너의 스택에서 TLS 아래(TCP 바로 위)에
/// 놓인 `LoopbackAdmissionFramer`가 그 토큰을 이 표에서 찾아 소비한 연결만 위로 올린다. 그 연결의
/// `(출발 포트, 리스너 포트)`에 상대를 적어 두고, 서버가 그 연결이 `.ready`가 된 뒤 한 번 가져간다.
///
/// 출발 포트만으로는 연결을 가릴 수 없다(검토에서 재현된 것: 다른 리스너로 같은 출발 포트를 쓰는 연결, RST로 풀린 포트를
/// 다시 쓰는 연결). 토큰은 그 연결 안에서만 오가므로 같은 기기의 다른 프로세스는 그것을 내밀 수 없다.
final class LoopbackAdmissionTable: Sendable {
    /// 루프백 연결 하나를 가리키는 열쇠. 두 끝이 모두 `127.0.0.1`이므로 4-튜플은 두 포트로 정해진다.
    struct Key: Hashable, Sendable {
        var sourcePort: UInt16
        var listenerPort: UInt16
    }

    /// 시험이 보는 표의 모양. 토큰과 신원은 담지 않는다.
    struct Snapshot: Sendable {
        var expected: Set<Key>
        var admitted: Set<Key>
    }

    /// 토큰의 길이(바이트).
    static let tokenLength = 32
    /// 기다리는 토큰의 상한. 다리가 잇는 연결의 상한(256)과 같다.
    static let expectedLimit = 256
    /// 서버가 아직 가져가지 않은 허가의 상한. 넘으면 가장 오래된 것을 버린다(그 연결의 조회는 nil이 된다).
    static let admittedLimit = 256

    private struct Expected {
        var token: [UInt8]
        var key: Key
        var origin: LoopbackBridge.Origin
    }

    private struct State {
        var expected: [Expected] = []
        var admitted: [Key: LoopbackBridge.Origin] = [:]
        /// `admitted`의 열쇠를 적은 차례(오래된 것부터). 상한을 넘을 때 버릴 것을 고른다.
        var admittedOrder: [Key] = []
    }

    private let state = Mutex(State())

    /// 연결마다 새로 만드는 일회용 토큰.
    static func makeToken() -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<tokenLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }

    /// 다리: `key`의 연결에서 올 `token`을 기다린다.
    ///
    /// 그 열쇠가 이미 기다리는 중이거나, 허가된 채 서버가 아직 가져가지 않았으면 적지 않고 false다. 그 허가는 앞서 같은
    /// 4-튜플을 썼던 연결의 것이고, 서버가 그 연결에 대해 아직 물을 수 있기 때문이다. 상한에 닿아도 false다.
    func expect(_ token: [UInt8], for key: Key, origin: LoopbackBridge.Origin) -> Bool {
        state.withLock { state in
            guard state.expected.count < Self.expectedLimit,
                  state.admitted[key] == nil,
                  !state.expected.contains(where: { $0.key == key })
            else { return false }
            state.expected.append(Expected(token: token, key: key, origin: origin))
            return true
        }
    }

    /// 다리: 끝난 연결의 토큰을 거둔다. framer가 이미 소비했으면 아무것도 하지 않는다.
    func withdraw(_ key: Key) {
        state.withLock { $0.expected.removeAll { $0.key == key } }
    }

    /// framer: `token`을 찾아 소비하고, 그것이 `key`의 연결을 위한 것이면 허가를 적고 true다.
    ///
    /// 기다리는 토큰을 모두 상수 시간으로 견준다(맞은 것이 있어도 멈추지 않는다). 맞은 토큰은 열쇠가 달라도 소비한다:
    /// 다른 리스너나 다른 출발 포트에서 내민 토큰은 가로챈 것이다.
    func admit(_ token: [UInt8], for key: Key) -> Bool {
        state.withLock { state in
            var match: Int?
            for (index, expected) in state.expected.enumerated() where constantTimeEqual(expected.token, token) {
                match = index
            }
            guard let match else { return false }
            let expected = state.expected.remove(at: match)
            guard expected.key == key, state.admitted[key] == nil else { return false }
            if state.admittedOrder.count >= Self.admittedLimit {
                state.admitted[state.admittedOrder.removeFirst()] = nil
            }
            state.admitted[key] = expected.origin
            state.admittedOrder.append(key)
            return true
        }
    }

    /// 서버: 허가된 연결의 상대를 한 번 내준다. 내준 뒤에는 지운다.
    func take(_ key: Key) -> LoopbackBridge.Origin? {
        state.withLock { state in
            guard let origin = state.admitted.removeValue(forKey: key) else { return nil }
            state.admittedOrder.removeAll { $0 == key }
            return origin
        }
    }

    var snapshot: Snapshot {
        state.withLock { Snapshot(expected: Set($0.expected.map(\.key)), admitted: Set($0.admitted.keys)) }
    }
}

/// 리스너 쪽 framer. 연결의 첫 32바이트를 토큰으로 읽고, 표에서 소비한 연결만 그 뒤의 바이트를 위로 올린다.
///
/// 스택의 TLS 아래(TCP 바로 위)에 둔다(`applicationProtocols`의 끝에 더한다). 토큰을 기다리는 동안 위로 한 바이트도
/// 올리지 않고 연결을 준비 상태로 두지 않으므로(`willMarkReady`), 토큰이 없거나 틀리거나 짧은 연결은 서버에게
/// `.ready`가 되지 않고 실패한다. 맞으면 이미 받아 둔 바이트를 올린 뒤 지나가게 한다(`passThroughInput`은 그 전에
/// 받아 둔 바이트를 올리지 않는다).
///
/// Network.framework가 연결마다 만들고 그 연결의 문맥에서만 부른다. 상태는 그 문맥 안에서만 바뀐다.
final class LoopbackAdmissionFramer: NWProtocolFramerImplementation {
    static let label = "SwiftailLoopbackAdmission"
    static let definition = NWProtocolFramer.Definition(implementation: LoopbackAdmissionFramer.self)
    /// `NWProtocolFramer.Options`에 표를 싣는 열쇠.
    static let tableOption = "table"
    /// 토큰을 기다리는 시간(밀리초). 다리가 루프백 연결을 맺는 기한과 같다.
    static let tokenTimeout: UInt64 = 5_000

    private let table: LoopbackAdmissionTable?
    private var admitted = false

    init(framer: NWProtocolFramer.Instance) {
        table = framer.options[Self.tableOption] as? LoopbackAdmissionTable
    }

    func start(framer: NWProtocolFramer.Instance) -> NWProtocolFramer.StartResult {
        framer.scheduleWakeup(wakeupTime: .milliseconds(Self.tokenTimeout))
        return .willMarkReady
    }

    func handleInput(framer: NWProtocolFramer.Instance) -> Int {
        guard !admitted else { return 0 }
        let length = LoopbackAdmissionTable.tokenLength
        var token: [UInt8]?
        var ended = false
        _ = framer.parseInput(minimumIncompleteLength: length, maximumLength: length) { buffer, isComplete in
            ended = isComplete
            guard let buffer, buffer.count >= length else { return 0 }
            token = Array(buffer.prefix(length))
            return length
        }
        guard let token else {
            if ended { framer.markFailed(error: .posix(.ECONNRESET)) }
            return length
        }
        guard let table, let key = Self.key(of: framer), table.admit(token, for: key) else {
            framer.markFailed(error: .posix(.EACCES))
            return 0
        }
        admitted = true
        Self.deliverBuffered(framer)
        framer.passThroughOutput()
        framer.passThroughInput()
        framer.markReady()
        return 0
    }

    /// 허가 전에는 위에서 내려오는 것이 없어야 한다(준비 상태가 아니다). 오면 내보내지 않고 연결을 끝낸다.
    func handleOutput(framer: NWProtocolFramer.Instance, message: NWProtocolFramer.Message, messageLength: Int, isComplete: Bool) {
        framer.markFailed(error: .posix(.EACCES))
    }

    func wakeup(framer: NWProtocolFramer.Instance) {
        if !admitted { framer.markFailed(error: .posix(.ETIMEDOUT)) }
    }

    func stop(framer: NWProtocolFramer.Instance) -> Bool { true }

    func cleanup(framer: NWProtocolFramer.Instance) {}

    /// 연결의 두 끝이 `127.0.0.1`일 때 그 열쇠.
    private static func key(of framer: NWProtocolFramer.Instance) -> LoopbackAdmissionTable.Key? {
        guard case .hostPort(.ipv4(let remoteHost), let remotePort)? = framer.remote, remoteHost == .loopback,
              case .hostPort(.ipv4(let localHost), let localPort)? = framer.local, localHost == .loopback
        else { return nil }
        return LoopbackAdmissionTable.Key(sourcePort: remotePort.rawValue, listenerPort: localPort.rawValue)
    }

    /// 토큰과 함께 받아 둔 바이트를 위로 올린다.
    private static func deliverBuffered(_ framer: NWProtocolFramer.Instance) {
        while true {
            var available = 0
            _ = framer.parseInput(minimumIncompleteLength: 0, maximumLength: 65_536) { buffer, _ in
                available = buffer?.count ?? 0
                return 0
            }
            guard available > 0,
                  framer.deliverInputNoCopy(length: available, message: NWProtocolFramer.Message(instance: framer), isComplete: false)
            else { return }
        }
    }
}
