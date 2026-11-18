import Network
import SwiftailCrypto
import Synchronization

/// A table and framer that admit only loopback connections opened by the bridge (contract
/// `docs/contracts/SwiftailHost.md` behavior B6, M7-9b).
///
/// When the bridge establishes a loopback connection, it sends a 32-byte token before any TLS bytes.
/// `LoopbackAdmissionFramer`, below TLS and directly above TCP in the listener's stack, passes up only connections
/// whose token it finds and consumes in this table. The table records the peer under the connection's
/// `(source port, listener port)`. The server retrieves it once after the connection becomes `.ready`.
///
/// The source port alone cannot distinguish connections. The review reproduced connections using the same source port
/// with different listeners and connections reusing a port released by RST. The token travels only within that
/// connection, so other processes on the same device cannot present it.
final class LoopbackAdmissionTable: Sendable {
    /// A key for one loopback connection. Both ends are `127.0.0.1`, so the two ports determine the 4-tuple.
    struct Key: Hashable, Sendable {
        var sourcePort: UInt16
        var listenerPort: UInt16
    }

    /// The table snapshot used by tests. Contains no tokens or identities.
    struct Snapshot: Sendable {
        var expected: Set<Key>
        var admitted: Set<Key>
    }

    /// The token length in bytes.
    static let tokenLength = 32
    /// The pending token limit, equal to the bridge's connection limit (256).
    static let expectedLimit = 256
    /// The limit on admissions the server has yet to claim. On overflow, drops the oldest admission among connections
    /// that have ended on the bridge side, causing lookups for that connection to return nil. The bridge forwards at
    /// most 256 connections, so admissions for live connections are retained.
    static let admittedLimit = 256

    private struct Expected {
        var token: [UInt8]
        var key: Key
        var origin: LoopbackBridge.Origin
    }

    private struct Admitted {
        var origin: LoopbackBridge.Origin
        /// The bridge ended the loopback connection. The admission stays if the server did not claim it, as with a
        /// connection that ends before the TLS handshake.
        var hasBridgeEnded = false
    }

    private struct State {
        var expected: [Expected] = []
        var admitted: [Key: Admitted] = [:]
        /// The insertion order of `admitted` keys, oldest first. Used to choose what to drop when the limit is exceeded.
        var admittedOrder: [Key] = []
    }

    private let state = Mutex(State())

    /// A one-time token generated for each connection.
    static func makeToken() -> [UInt8] {
        var generator = SystemRandomNumberGenerator()
        return (0..<tokenLength).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
    }

    /// Records that the bridge expects `token` from the connection identified by `key`.
    ///
    /// Returns false without recording if the key is already pending or has an admission the server has not claimed.
    /// That admission belongs to an earlier connection with the same 4-tuple, which the server may still query. The
    /// bridge retries with a different source port. Returns false at the limit as well.
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

    /// Withdraws the bridge's token for an ended connection. If the framer already consumed it, marks the admission as
    /// ended on the bridge side.
    ///
    /// Keeps the admission because the server may still query that connection. Removing it could let a new admission
    /// with the same key answer the query.
    func withdraw(_ key: Key) {
        state.withLock { state in
            state.expected.removeAll { $0.key == key }
            state.admitted[key]?.hasBridgeEnded = true
        }
    }

    /// Lets the framer find and consume `token`. Records an admission and returns true if the token belongs to the
    /// connection identified by `key`.
    ///
    /// Compares all pending tokens in constant time, continuing even after a match. Consumes a matching token even if
    /// the key differs. Treats a token presented from a different listener or source port as intercepted.
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
                let ended = state.admittedOrder.firstIndex { state.admitted[$0]?.hasBridgeEnded == true }
                state.admitted[state.admittedOrder.remove(at: ended ?? 0)] = nil
            }
            state.admitted[key] = Admitted(origin: expected.origin)
            state.admittedOrder.append(key)
            return true
        }
    }

    /// Gives the server the admitted connection's peer once and removes it after returning it.
    func take(_ key: Key) -> LoopbackBridge.Origin? {
        state.withLock { state in
            guard let admitted = state.admitted.removeValue(forKey: key) else { return nil }
            state.admittedOrder.removeAll { $0 == key }
            return admitted.origin
        }
    }

    var snapshot: Snapshot {
        state.withLock { Snapshot(expected: Set($0.expected.map(\.key)), admitted: Set($0.admitted.keys)) }
    }
}

/// The listener-side framer. Reads the connection's first 32 bytes as a token and passes subsequent bytes up only for
/// connections whose token it consumes in the table.
///
/// Place it below TLS and directly above TCP by appending it to `applicationProtocols`. While waiting for the token, it
/// passes up no bytes and leaves the connection unready (`willMarkReady`). Connections with missing, incorrect, or
/// short tokens fail before the server sees them as `.ready`. On a match, it passes up already received bytes and then
/// enables passthrough, because `passThroughInput` does not deliver bytes received before it was enabled.
///
/// Network.framework creates a framer per connection and calls it only in that connection's context. State changes only within that context.
final class LoopbackAdmissionFramer: NWProtocolFramerImplementation {
    static let label = "SwiftailLoopbackAdmission"
    static let definition = NWProtocolFramer.Definition(implementation: LoopbackAdmissionFramer.self)
    /// The key for storing the table in `NWProtocolFramer.Options`.
    static let tableOption = "table"
    /// The wait for a token in milliseconds, equal to the bridge's deadline for establishing a loopback connection.
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
        _ = framer.parseInput(minimumIncompleteLength: length, maximumLength: length) { buffer, _ in
            guard let buffer, buffer.count >= length else { return 0 }
            token = Array(buffer.prefix(length))
            return length
        }
        // Before the complete token arrives, the framer cannot tell if the peer closed with FIN. A framer that is not
        // ready receives no end notification (verified experimentally). Those connections end at the `wakeup` deadline.
        guard let token else { return length }
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

    /// Nothing should come down from above before admission because the connection is not ready. If anything does, end
    /// the connection without sending it.
    func handleOutput(framer: NWProtocolFramer.Instance, message: NWProtocolFramer.Message, messageLength: Int, isComplete: Bool) {
        framer.markFailed(error: .posix(.EACCES))
    }

    func wakeup(framer: NWProtocolFramer.Instance) {
        if !admitted { framer.markFailed(error: .posix(.ETIMEDOUT)) }
    }

    func stop(framer: NWProtocolFramer.Instance) -> Bool { true }

    func cleanup(framer: NWProtocolFramer.Instance) {}

    /// The connection key when both ends are `127.0.0.1`.
    private static func key(of framer: NWProtocolFramer.Instance) -> LoopbackAdmissionTable.Key? {
        guard case .hostPort(.ipv4(let remoteHost), let remotePort)? = framer.remote, remoteHost == .loopback,
              case .hostPort(.ipv4(let localHost), let localPort)? = framer.local, localHost == .loopback
        else { return nil }
        return LoopbackAdmissionTable.Key(sourcePort: remotePort.rawValue, listenerPort: localPort.rawValue)
    }

    /// Passes up bytes already received along with the token.
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
