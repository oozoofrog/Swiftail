# Swiftail netstack contract (M6, draft)

M6's goal is to **listen for and initiate TCP connections at tailnet addresses in process, without using the OS TCP stack** (M6 in `docs/plan.md` §7). Through M5, the node exchanged IP packets. M6 layers TCP written in Swift on top and exposes a public API corresponding to tsnet's `Listen("tcp", ":443")` and `Dial`. The first adopter is the Mac host (an HTTPS server on the tailnet). Removing the Go core from that host (`tsnet.Server.Listen` + `tls.NewListener` + `http.Server`) in M7 depends on this contract. The library is written entirely in Swift and uses neither C nor external packages (plan §4(a)).

This document is a **draft**. Finalize it after resolving "Lead session confirmation needed" and receiving the answers in "First adopter confirmation needed."

Protocol details follow [tcp-netstack.md](../protocol-notes/tcp-netstack.md) ("TCP notes" below). The notes were **unverified in the initial draft**. The lead session decisions below record the later source review and what remains unverified. This document defines only scope, architecture, public API, limits, tests, and gates.

This document supplements the existing, unchanged contracts in [SwiftailTunnel.md](SwiftailTunnel.md) (M5) and [SwiftailEngine.md](SwiftailEngine.md) with the M6 changes. This contract takes precedence in a conflict.

## Targets

| Target | Additions in M6 | Rationale |
| --- | --- | --- |
| `SwiftailNetstack` (new target, not exposed as a product) | TCP segment codec, a state machine for one connection (`TCPConnection`), and a `TCPStack` that groups multiple connections and listeners. All are `package` value types without sockets, clocks, or random number generation | Code standards in plan §5. Used only within the package, like `SwiftailIO` |
| `SwiftailBase` | Move the Internet checksum (RFC 1071) here with `package` visibility | The engine's service IP replies and the netstack share the calculation (decision D10) |
| `SwiftailEngine` | `ServiceIPReply+Checksum.swift` calls the relocated checksum. Behavior stays the same | Same rationale |
| `Swiftail` | `TunnelDevice.inProcess`, public API (`listen` and `connect`, `TailnetListener`, `TailnetConnection`, and `ConnectionError`), node and stack integration, and resumption of waiting reads and writes | The public API stays in `Swiftail` alone (existing architecture) |

The dependency direction is `SwiftailBase ◄─ SwiftailNetstack ◄─ Swiftail`. It reverses the diagram in plan §5 (`Swiftail ◄─ SwiftailNetstack`) (lead session confirmation needed N1). `SwiftailNetstack` uses only `SwiftailBase` and CryptoKit (to generate ISNs by hashing). It has no knowledge of the engine, control, or WireGuard.

## Scope supported in M6

The scope follows the first adopter's actual use (TCP notes §8): one listener (port 443 or a test port) serving HTTPS, dialing by the diagnostic proxy, dozens of concurrent connections opened by a few paired devices, transfers of several hundred MB to 4GiB from server to client, and up to 4MB from client to server. The peer TCP stacks are the iPhone kernel and gVisor.

| Included | Rationale |
| --- | --- |
| IPv4 and IPv6 tailnet addresses | The node has addresses in both families. Only the IP header and pseudo-header differ |
| Passive open (listen), active open (connect), half-close, and RST | TCP notes §8 items 1 and 5 |
| Checksum generation and validation, and the MSS option | Connections cannot be established without them (TCP notes §4.8) |
| Window scaling | Without scaling the window is capped at 64KiB, limiting throughput to about 10Mbit/s at 50ms RTT |
| RFC 6298 retransmission timer (Karn), SYN and data retransmission limits | Required (MUST-18, MUST-20) |
| slow start, congestion avoidance, fast retransmit, fast recovery, NewReno | Required (MUST-19) and plan §4(a) |
| 0-window probes, sender and receiver SWS avoidance | Required (MUST-36, MUST-38, MUST-39) |
| Delayed ACK | Plan §4(a). Every ACK requires WireGuard encryption and a UDP send |
| keep-alive (fixed settings, always on) | The Go host uses this to reclaim connections to dead peers (lead session confirmation needed N5) |
| RFC 5961 RST, SYN, and ACK validation and challenge ACK rate limiting | Behavior X |
| Storage for out-of-order segments (within the receive window, with a range count limit) | Avoids receiving the entire window again after loss |
| Receiver-side SACK with SACK-Permitted negotiation and SACK blocks for ranges in the receive buffer (M6-10a) | The peer (gVisor or kernel) retransmits multiple losses in one window without RTO. Gate loss measurements triggered this work (N3). Sender-side retransmission based on received blocks (RFC 6675) is in the exclusions table |
| TIME-WAIT | MUST-13 |

The "Exclusions" table below gives the rationale and when each feature would become necessary. Omitted features fail closed. Options the stack does not negotiate are omitted on send and ignored on receipt.

## Architecture

```
App Task ── await connection.read/write ──┐
                                         ▼
TailnetNode (actor, edge)   Holds and resumes waiting reads, writes, accepts, and connects. Supplies the time
   │   stack: TCPStack (value)  ◄── .ipPacket ── engine.receive ◄── Magicsock ◄── sockets and DERP
   │        └ outgoing IP packets ──► engine.send ──► Magicsock ──► sockets and DERP
   ▼
TCPStack (value)        Listener table, 4-tuple → connection, connections being established and accept queue, ISNs and ports, limits, and RST for missing connections
   └ TCPConnection (value)   One connection with state, send and receive buffers, retransmission timers, and congestion control
        └ TCPSegment (value)  A validated segment. Converts to and from IP packet bytes
```

1. **Each connection is a value-type state machine.** Inputs are segments, application calls (write, read, close, and abort), and time. Outputs are outgoing segments and events (established, readable, writable, peer finished writing, and closed with a reason). It owns no socket, clock, or random number generator. The ISN is an argument. It follows the WireGuard and engine design (`advance(to:)`, `nextDeadline`).
2. **The stack is also a value type.** The 32-byte secret used to generate ISNs is a construction argument. The node draws randomness from the system.
3. **The only edge is the `TailnetNode` actor.** The stack is a stored property on the node and exchanges data with the engine and `Magicsock` in the same actor without `await`. There is no buffering, dropping, or independent timer between the node and the stack. The node's one timer wakes at the earliest deadline across the engine, `Magicsock`, and stack.
4. **There is no separate Task.** All stack progress happens in `run()`. An app's Task crosses into the node actor for reads and writes and suspends if it has to wait.

```swift
// SwiftailNetstack (package). Outline only. The implementation units finalize names and arguments.
package struct TCPSegment: Sendable, Equatable {
    package init(parsingIPPacket bytes: [UInt8]) throws(ParseError)   // Behavior W
    package func ipPacket(hopLimit: UInt8 = 64) -> [UInt8]?   // nil if address families differ or the segment does not fit in one IP packet
}

package struct TCPConnection: Sendable {
    package enum Output: Sendable, Equatable { case segment(TCPSegment), event(Event) }
    package enum Event: Sendable, Equatable { case established, readable, writable, endOfStream, closed(CloseReason) }
    package mutating func receive(_ segment: TCPSegment, at now: ContinuousClock.Instant) -> [Output]
    package mutating func write(_ bytes: ArraySlice<UInt8>, at now: ContinuousClock.Instant) -> (accepted: Int, outputs: [Output])
    package mutating func read(upTo maximumLength: Int, at now: ContinuousClock.Instant) -> (bytes: [UInt8], outputs: [Output])
    package mutating func finishWriting(at now: ContinuousClock.Instant) -> [Output]
    package mutating func abort() -> [Output]
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    package var nextDeadline: ContinuousClock.Instant? { get }
}

package struct TCPStack: Sendable {
    package enum Output: Sendable, Equatable { case ipPacket([UInt8]), event(Event), dropped(Drop) }
    package init(isnSecret: [UInt8], now: ContinuousClock.Instant)
    package mutating func receive(_ ipPacket: [UInt8], at now: ContinuousClock.Instant) -> [Output]
    package mutating func advance(to now: ContinuousClock.Instant) -> [Output]
    package var nextDeadline: ContinuousClock.Instant? { get }
    // listen, stopListening, accept, and connect, plus write, read, finishWriting, close, and abort by connection ID
}
```

## Public API (`Swiftail`, additions in M6)

```swift
import SwiftailBase

public enum TunnelDevice: Sendable {
    case utun(fileDescriptor: Int32, mtu: Int = 1280)   // Same as M5
    case memory(mtu: Int = 1280)                         // Same as M5
    /// An in-process TCP stack. It receives packets peers send to this node's addresses and sends its own packets to the tailnet.
    /// `listen(port:)` and `connect(to:port:)` are available only with this device. The MTU is fixed at 1280.
    case inProcess
}

extension TailnetNode {
    /// Listens on one TCP port at this node's tailnet addresses (IPv4 and IPv6). Corresponds to tsnet `Listen("tcp", ":<port>")`.
    /// You can call this before `run()`. The listener ends when `run()` ends.
    public func listen(port: UInt16) throws(ConnectionError) -> TailnetListener

    /// Opens a TCP connection to a tailnet peer. Corresponds to tsnet `Dial(ctx, "tcp", "<host>:<port>")`.
    /// `host` is an IP address or a name in the netmap (a MagicDNS FQDN or short name). This call waits for the connection to establish.
    /// Canceling the calling Task abandons the attempt and throws `.cancelled`.
    public func connect(to host: String, port: UInt16) async throws(ConnectionError) -> TailnetConnection
}

/// A single listening port that yields established connections in order. The stream ends when you close the listener or `run()` ends.
/// Only one Task can iterate at a time. The listener closes when deinitialized (`deinit`).
///
///     let listener = try await node.listen(port: 443)
///     for await connection in listener { … }
public final class TailnetListener: AsyncSequence, Sendable {
    public typealias Element = TailnetConnection
    public typealias Failure = Never
    public let port: UInt16
    /// Stops listening. Resets unaccepted connections with RST. Accepted connections continue.
    public func close() async
}

/// An established TCP connection. One read and one write can run concurrently in separate Tasks.
/// Deinitialization (`deinit`) resets the connection with RST if it has yet to close.
public final class TailnetConnection: Sendable {
    /// The local node's address and port.
    public let localEndpoint: IPEndpoint
    /// The peer's tailnet address and port. The address belongs to the peer authenticated by WireGuard (AllowedIPs source check in M3 engine contract behaviors 2 and 5).
    public let remoteEndpoint: IPEndpoint

    /// Returns received bytes in order. Returns buffered bytes immediately (at least 1 byte and at most `maximumLength`) or waits for bytes to arrive.
    /// Returns nil when the peer has finished writing and the buffer is empty. Reading opens the receive window by the number of bytes read.
    public func read(upTo maximumLength: Int = 65_536) async throws(ConnectionError) -> [UInt8]?

    /// Waits until all bytes enter the send buffer. The peer may not have received them yet. A full buffer suspends the call until space becomes available.
    /// Cancellation resets the connection with RST and throws `.cancelled` because the caller cannot tell how many bytes the call already added to the buffer.
    public func write(_ bytes: [UInt8]) async throws(ConnectionError)

    /// Finishes sending (FIN) after all buffered bytes have been sent. Reads can continue. Corresponds to tsnet `CloseWrite`.
    public func finishWriting() async throws(ConnectionError)

    /// Closes the connection. Sends remaining buffered data and finishes with FIN. Returns immediately, and the node finishes the work in `run()`.
    /// Resets the connection with RST if data remains unread or arrives after closing. Corresponds to tsnet `Close`.
    public func close() async

    /// Resets the connection immediately (RST) and discards buffered data.
    public func abort() async
}

/// Failures while listening, connecting, or using a connection.
public enum ConnectionError: Error, Sendable, Equatable {
    /// The device is other than `.inProcess`, the port is 0, or the host is empty. The message states only what is invalid.
    case invalidConfiguration(String)
    /// The node is no longer running (`run()` ended). `connect` also throws this error when the state is other than `.running`.
    case notRunning
    /// The netmap has no such name, or no peer owns that address.
    case unknownHost
    /// A listener already uses the port.
    case addressInUse
    /// The connection or listener count reached its limit.
    case limitReached
    /// The peer refused the connection attempt (RST in response to SYN).
    case refused
    /// The peer did not respond (retransmission limit, no keep-alive response, or closing deadline).
    case timedOut
    /// The peer reset the connection (RST).
    case reset
    /// The peer left the netmap, the owner of its address changed, or this node's address changed.
    case peerRemoved
    /// The connection or listener has already been closed or aborted.
    case closed
    /// The calling Task was canceled.
    case cancelled
    /// A call in the same direction is already waiting (two reads or two writes).
    case concurrentUse
}
```

API correspondence with tsnet

| tsnet (Go) | Swiftail | Differences |
| --- | --- | --- |
| `Server.Listen("tcp", ":443")` | `node.listen(port: 443)` | Address selection, `tcp4` and `tcp6`, and port 0 are unsupported (exclusions table) |
| `Listener.Accept()` | `for await connection in listener` | Unaccepted connections have no 1-second close deadline. The queue limit bounds them (behavior S5) |
| `Listener.Close()` | `listener.close()` or dropping the listener | |
| `Server.Dial(ctx, "tcp", "host:443")` | `node.connect(to: "host", port: 443)` | Does not wait for `Running` or connect to addresses outside the tailnet (behavior A2) |
| `net.Conn.Read` and `Write` | `read(upTo:)` and `write(_:)` | Calls have no deadline. Cancel the Task to terminate them |
| `CloseWrite()` | `finishWriting()` | |
| `Close()` | `close()` | |
| `SetLinger(0)` + `Close()` | `abort()` | |
| `RemoteAddr()` and `LocalAddr()` | `remoteEndpoint` and `localEndpoint` | These return `IPEndpoint` values in place of strings |

Differences from the draft in `docs/plan.md` §6 are `dial(host:port:)` → `connect(to:port:)` (lead session confirmation needed N2), `listen` is synchronous rather than `async` (an actor method that requires `await` from outside but does not wait internally), and `TunnelDevice.inProcess` takes no arguments.

## Behaviors

Tests and reviews refer to behaviors by number. Unless stated otherwise, values are proposed by this contract and will be adjusted based on gate measurements.

### W. Segment codec (`TCPSegment`)

1. **Parsing**. Input is IP packet bytes. Read addresses and lengths from the IPv4 header (including options) or IPv6 header (no extension headers). Return `notTCP` if the protocol is other than 6, `malformed` if the TCP header is shorter than 20 bytes, the data offset is below 5, or it points outside the segment, and `badChecksum` for a bad checksum. Although the engine has already validated the IP header (`IPPacket`), the stack checks it again at its own boundary. This supports independent stack tests and direct input from packet captures.
2. **Options** (TCP notes §3.2). Stop at EOL and skip NOP. Read only MSS (kind 2, length 4), Window Scale (kind 3, length 3), SACK-Permitted (kind 4, length 2), and SACK (kind 5, length `2 + 8n`, n ≥ 1). Store the first three only in SYN segments and SACK only in non-SYN segments. Ignore them in other cases (RFC 2018 §2 sends SACK-Permitted only in SYN). Skip unknown options using their length. If the length is below 2 or goes past the header, drop the segment as `malformed` (the precaution for MUST-7. The connection stays open). Read MSS 0 as 536 (IPv4) or 1220 (IPv6) and clamp shifts above 14 to 14 (RFC 7323 §2.3). Return SACK blocks as pairs of 32-bit left and right edges in option order, without judging what the numbers mean (whether the left edge precedes the right or is within the sent range). A SACK whose blocks exceed the 40-byte option space (n ≥ 5, length at least 42) extends beyond the header and is `malformed`. **The connection does not use received SACK blocks yet** (sender recovery is M6-10b).
3. **Encoding**. Encode a 20-byte header + options + data. In a SYN, include MSS, two NOPs and SACK-Permitted (when present), and NOP and Window Scale (if negotiating), in that order (the Linux order followed by gVisor `makeSynOptions`). In non-SYN segments, include two NOPs and SACK only when there are SACK blocks (as in gVisor `makeOptions`). Every combination aligns to 4 bytes. Over 4 SACK blocks do not fit in the header, so return `nil` without encoding. Fill in the checksum. For the IP header, IPv4 uses IHL 5, DF set, identifier 0, TTL 64. IPv6 uses hop limit 64 and flow label 0. 64 is the Go and gVisor default (tunnel contract behavior L2).
4. Set urgent pointer, CWR, and ECE to 0 on send and ignore them on receive.
Implementation decisions (M6-1, 2026-11-15)

- Validation order is IP header structure → protocol (`notTCP`) → fragmentation → IPv4 header checksum → TCP header → TCP checksum → options. Check the IPv4 header checksum too (`badChecksum` on failure). IPv4 fragments (MF or offset) are `malformed`. IPv6 extension and fragmentation headers (next header other than 6) produce `notTCP`.
- Skip MSS with a nonstandard length (other than 4) and Window Scale with a nonstandard length (other than 3) using the declared length without reading the value. If an option occurs more than once, the last one wins (as in gVisor). Validate option lengths for non-SYN segments too.
- Implementation decisions (M6-10a, 2026-11-15). Skip SACK-Permitted with a length other than 2 and SACK with a length other than `2 + 8n` (n ≥ 1, including length 2 with no blocks) by length without reading the value, under the same rule. gVisor stops parsing on a SACK whose length is other than `2 + 8n` (the result is the same if no more options follow) and reads a SACK of length 2 as 0 blocks, **clearing earlier blocks**, then moves to the next option (`header/tcp.go`). Thus, for "valid SACK followed by a SACK of length 2," Swift retains the earlier blocks and gVisor clears them. This combination is absent from the reference fixtures because the comparison tool cannot show the difference in blocks. Revisit it in M6-10b, when received blocks become used. The fields are `sackPermitted` (SYN only) and `sackBlocks` (`leftEdge` and `rightEdge` of `TCPSegment.SACKBlock`, non-SYN only). 13 SACK cases were added to the Go reference comparison (5 gVisor-encoded SYNs and ACKs also match Swift's encoded bytes. The 2 SACKs extending past the header are documented differences where gVisor stops parsing and the contract drops them as `malformed`).
- Declaration. `TCPSegment` fields are `source` and `destination` (`IPEndpoint`), `sequenceNumber` and `acknowledgmentNumber` (`SequenceNumber`), `flags` (`fin`, `syn`, `rst`, `psh`, `ack`), `window` (the 16-bit header value as given), `maximumSegmentSize` and `windowScale` (SYN only), `payload`, and `sequenceLength` (SEG.LEN). The checksum uses `InternetChecksum` (`add`, `addPseudoHeader`, `value`) from `SwiftailBase`.

5. Handle sequence numbers only as a wrapping modulo-2^32 type (`SequenceNumber`). Use the signed 32-bit difference for comparisons and differences. There must be no code directly comparing `UInt32` values.

### T. Connection state machine (`TCPConnection`)

1. States are SYN-SENT, SYN-RECEIVED, ESTABLISHED, FIN-WAIT-1, FIN-WAIT-2, CLOSE-WAIT, CLOSING, LAST-ACK, TIME-WAIT, and CLOSED (RFC 9293 §3.3.2). The stack handles LISTEN (behavior S).
2. **Segment processing order** follows RFC 9293 §3.10.7.4 (TCP notes §4.2) exactly: sequence check → RST → SYN → ACK → data → FIN. Keep this order. SYN-SENT follows the separate RFC 9293 §3.10.7.3 procedure (ACK check → RST → SYN). gVisor's processing order differs from the RFC (received data first, ACK later), so it is not the basis for this order. Consume FIN only after all preceding data has arrived without gaps.
3. **Active open**. Send SYN (MSS, SACK-Permitted, and Window Scale) and enter SYN-SENT. Retransmitted SYNs use the same options. On SYN-ACK, send ACK, enter ESTABLISHED, and emit `.established`. On RST with a valid ACK, emit `.closed(.refused)`. Drop SYN without ACK (simultaneous open, exclusions table).
4. **Passive open**. The stack passes in a SYN to create the connection. Send SYN-ACK and enter SYN-RECEIVED. Include SACK-Permitted in the SYN-ACK only if the peer's SYN included it (RFC 2018 does not specify a condition for the passive side. This matches the SYN-ACK in gVisor `connect.go`). Retransmitted SYN-ACKs follow the same rule. **Send SACK blocks in each direction only if the peer's SYN (SYN-ACK) carried SACK-Permitted** (RFC 2018 §4 MUST NOT). The SYN option space used is MSS 4 + two NOPs and SACK-Permitted 4 + NOP and Window Scale 4 = 12 bytes, within 40 bytes. On valid ACK, enter ESTABLISHED and emit `.established`. Reply to an invalid ACK with `<SEQ=SEG.ACK><CTL=RST>`. Handle RST under behavior X3. Only `SEG.SEQ = RCV.NXT` silently removes the connection. Other values in the window elicit a challenge ACK. For a silent removal, emit `.closed` without notifying the app because it has yet to accept the connection.
5. **MSS**. Advertise 1280 − IP header − 20 (IPv4 1240, IPv6 1220, TCP notes §7). Outgoing data length is at most `min(peer's advertised MSS, same formula as the advertised value)` minus the TCP option length of that segment (RFC 9293 §3.7.1). SACK is the only data segment option and has length `4 + 8n` (n blocks, 36 bytes for 4 blocks). The advertised MSS fills the 1280 MTU, leaving no spare space. Carrying SACK reduces the data by that amount (1204 bytes for IPv4 with 4 blocks, M6-10a). With no MSS option in the peer SYN, assume 536 for IPv4 or 1220 for IPv6 (same section). Honoring MSS does not rule out fragmentation along the path. WireGuard guarantees 1280 for the tailnet path.
6. **Closing** (TCP notes §4.4)
   - `finishWriting` sends FIN when the send buffer empties. ESTABLISHED → FIN-WAIT-1, CLOSE-WAIT → LAST-ACK.
   - `close` ends reading in addition to `finishWriting`. If unread data is in the receive buffer, send RST immediately and end. If data arrives after closing, send RST and end (SHLD-3).
   - A connection on which `close` was called goes away in FIN-WAIT-2 if the peer's FIN has not arrived within 60 seconds (gVisor's default linger). A connection that only called `finishWriting` (read side stays open) has no deadline and is protected by keep-alive.
   - TIME-WAIT lasts 60 seconds (gVisor's value. 2MSL in RFC 9293 §3.6.1 is 4 minutes). If a FIN-bearing segment arrives in this state, send ACK and restart the 60-second timer even if the sequence check would reject it (retransmission of a consumed FIN, RFC 9293 §3.10.7.4 TIME-WAIT exception). Check this separately because dropping it in the normal sequence check would prevent this path from running.
   - `abort` sends nothing in SYN-SENT. Otherwise, send `<SEQ=SND.NXT><CTL=RST>` and enter CLOSED.
   - Even when the receive window is 0, **consume a data-free FIN arriving at RCV.NXT**. FIN uses no buffer space. gVisor sends data-free FIN regardless of the window and backs off retransmissions by RTO. Rejecting it could delay EOF by up to 120 seconds and hit the peer's retransmission limit (M6 review A).
7. **Peer closes**. On FIN, emit `.endOfStream`. All data received before it remains readable. On RST, empty the buffers and emit `.closed(.reset)`. These are separate events (MUST-12).
8. **keep-alive**. After 2 hours without receiving or sending in ESTABLISHED, CLOSE-WAIT, or FIN-WAIT-2, send `<SEQ=SND.NXT-1><CTL=ACK>` (no data) every 75 seconds. If nothing arrives after sending 9 probes, emit `.closed(.timedOut)`. Receiving anything restarts the 2-hour interval. These are gVisor defaults (TCP notes §5). Keep-alive cannot be disabled (lead session confirmation needed N5).
9. The sequence check's "ACK an unacceptable segment" rule answers an incoming keep-alive probe (`SEG.SEQ = RCV.NXT-1`, length 0 or 1). No separate handling is required.

Implementation decisions (M6-4, 2026-11-15, `Sources/SwiftailNetstack/Connection/`)

- **Creation** uses `TCPConnection.connect(from:to:initialSequenceNumber:at:)` and `accept(_:initialSequenceNumber:at:) throws(AcceptError)`, to which the stack passes a SYN with no ACK or RST. If the peer's MSS is below 64, throw an error containing an RST for that SYN. Do not accept data or FIN in SYN or SYN-ACK. The peer retransmits it.
- **Emit immediate ACKs from `receive` for the corresponding segment.** For out-of-order data, gap-filling data, in-order data accumulating to 2×MSS, FIN, segments outside the window, and challenge ACKs, set a timer due "now" and emit the ACK at the end of that `receive` call (piggyback it if outgoing data is available). Only ACKs deferred with a 40ms deadline come from `advance(to:)`. The stack and node call `advance(to:)` with the same time after passing in a group of packets (behavior N4). Application calls (`write`, `read`, `close`, and so on) emit at the end of the call. Originally `receive` emitted no pure ACKs and `advance` at the end of the group emitted them together. Once the node began receiving UDP in groups, the ACKs for out-of-order segments in one group coalesced into one and delayed the peer's fast retransmit, so this changed (2026-11-15).
- **Close reasons** are `finished`, `reset`, `refused`, `timedOut`, and `aborted`. Only `finished` keeps the receive buffer. `close(at:)` was added to the declaration. The stack emits `peerRemoved` and discards the connection without sending anything.
- **Timers** number seven (TIME-WAIT, FIN-WAIT-2 linger, retransmission, 0-window probe, SWS override, keep-alive, and ACK), and `nextDeadline` is the earliest. The value is nil for a closed connection. If due at the same time, timers that produce data run before ACK.
- **go-back-N** uses a separate "next sequence to send" rather than rewinding SND.NXT (as in gVisor). ACK range validation uses the highest sequence sent so far.
- A **0-window probe** is an ACK at `<SEQ=SND.UNA−1>` carrying one byte of value 0 (gVisor's format, distinct from "one byte of new data" in RFC 9293 §3.8.6.1. Probes do not count as retransmissions). With a 0 window, a data segment starting at RCV.NXT has only its data dropped, then ACK and RST processing occurs, followed by an immediate ACK (RFC 9293 §3.10.7.4).
- Check invalid ACKs in SYN-RECEIVED before the RFC 5961 §5.2 range check and always reply with RST (T4, as in Linux and gVisor). The challenge ACK rate limit (10 in 5 seconds) also applies to ACKs in behaviors X2 and X3.
- The TIME-WAIT FIN exception applies only to FIN at RCV.NXT−1 (retransmission of a consumed FIN, as in gVisor). `abort` sends no RST in CLOSING, LAST-ACK, or TIME-WAIT (RFC 9293 §3.10.5). `close` in SYN-SENT sends nothing and ends with `aborted`.
- The 2×MSS for delayed ACK is based on this side's advertised MSS. If SYN was not retransmitted, the handshake round trip is the first RTT sample. Set PSH on the segment carrying the buffer's last byte.
- Record the sequence number of a FIN that arrives beyond a gap and consume it after all preceding data arrives (RFC 9293 §3.10.7.4 SHLD-31. This was originally a `shortcut:`, and independent test M6-6 identified the need for it).
- On paths with high loss, closing can end with `timedOut` in place of `finished`. If the peer's FIN retransmission (RTO can grow to 120 seconds) arrives after the 60-second TIME-WAIT ends, the connection is already gone. All data was delivered before that point (observed in M6-6 combinations with 20% loss).

### R. Retransmission and congestion control

1. **RTO** (TCP notes §4.5). Start at 1 second. Once measurements are available, use the formulas in RFC 6298 §2.2 and §2.3. The minimum is 200ms and the maximum is 120 seconds (as in gVisor. The 1-second minimum in RFC 6298 §2.4 is a SHOULD. Lead session confirmation needed N4). Treat G as 0 because the clock uses nanoseconds.
2. **RTT measurement**. Measure the round trip for one segment at a time. Discard the sample if that segment is retransmitted (Karn). Do not use the timestamp option.
3. **Timer management** follows RFC 6298 §5.1~5.6 exactly. If the SYN retransmission timer expired and the RTO after establishment is below 3 seconds, raise it to 3 seconds (§5.7. Do not lower an already higher value).
4. **Limits**. For data, emit `.closed(.timedOut)` if the same segment is retransmitted 15 times without an acknowledgment (as in gVisor). Retransmit SYN and SYN-ACK 7 times (1, 3, 7, 15, 31, 63, and 127 seconds after sending). Discard at 247 seconds, when the timer for the seventh retransmission expires (128 seconds capped at 120 seconds). The connection counts the retransmissions, and intervals follow `RTOEstimator`'s doubling rule and cap exactly. RFC 9293 §3.8.3 (MUST-23) requires SYN R2 to be at least 3 minutes. gVisor stops at 127 seconds (6 retransmissions), which this implementation does not follow. Discarding a SYN-ACK too early drops a connection the peer believes is established if its final ACK was lost.
5. **Send allowance** is `min(cwnd, SND.WND) − (SND.NXT − SND.UNA)`.
6. **Congestion control** (TCP notes §4.7). Use initial window `min(10*MSS, max(2*MSS, 14600))` (RFC 6928, gVisor also uses 10 segments). Use RFC 5681 equations 2 and 3 for slow start and congestion avoidance (increase by 1 byte if the integer division in equation 3 yields 0), and equation 4 for ssthresh on loss. **Repeated retransmission timer expirations for the same segment do not reduce ssthresh again** (RFC 5681 §3.1. Apply equation 4 only on the first expiration). On RTO expiration, set cwnd to 1 segment and enter slow start. On 3 duplicate ACKs, apply RFC 5681 §3.2 steps 2~6 with `recover` and partial ACK handling from RFC 6582 §3.2. Duplicate ACKs follow the definition in RFC 5681 §2.
   - Implementation decisions (M6-3, 2026-11-15, `RTOEstimator`, `NewRenoCongestionControl`). The connection that holds the send buffer enforces Karn (discard samples from retransmitted segments), and the estimator accepts samples only from segments that were never retransmitted. `recover` stores the position one beyond RFC 6582's "highest sequence sent" (SND.NXT at the time) and compares with `ACK > recover`. The formula is equivalent, but loss in the first window still triggers fast retransmit with the initial value ISS. Literal `ACK − 1 > recover` would be false with only SYN acknowledged. When a new ACK exceeds `recover`, raise the value to ACK − 1. This keeps the comparison from reversing and blocking fast retransmit after sending more than 2³¹ bytes without loss, an addition absent from the RFC. For a full ACK, cwnd is `min(ssthresh, max(FlightSize, SMSS) + SMSS)`. Treat `cwnd == ssthresh` as congestion avoidance. Cap cwnd at 2³⁰. Use `SND.UNA` to identify repeated RTO expiration for the same segment. `shortcut:` Inflation in fast recovery is not bounded by the number of in-flight segments (the MAY in RFC 5681 §3.2 step 4).
7. Retransmit one segment starting from SND.UNA every time (received SACK blocks are unused. Sender-side SACK recovery is M6-10b). After RTO expiration, slow start reopens the window and retransmits in order (go-back-N).
8. If idle for longer than RTO, reduce cwnd to `min(initial window, cwnd)` before sending (RFC 5681 §4.1).

### F. Flow control and buffers

1. The **receive buffer** is 256KiB per connection. Advertise the remaining buffer space (up to 16KiB while in a listener queue, behavior M). Never move the right edge of the window left (SHLD-14). Even when rounding down for window scaling produces an advertisement smaller than the last one, accept up to the previously allowed right edge (RFC 7323 §2.4).
2. **Window scaling** (RFC 7323 §2.2~2.4). Always include the option in an active open SYN. In a passive open SYN-ACK, include it only if the peer's SYN included it. Enable scaling **only if both SYNs carry it**, with a separate shift per direction (the peer's shift for the send window and our shift for the advertised window). Do not scale the window field in SYN or SYN-ACK segments. Treat a peer shift above 14 as 14. Our shift is 3 (the smallest value satisfying `65535 << 3 >= 262144`, as in gVisor `FindWndScale`). With scaling disabled, the window is at most 65,535.
3. **Receiver SWS avoidance**. Advance the right edge only when it can increase by at least `min(buffer/2, MSS)` (RFC 9293 §3.8.6.2.2). After the app reads enough to open the window by that amount, send a pure window-update ACK immediately **only if the remaining advertised window (advertised right edge − RCV.NXT) is at most half the receive buffer**. A larger remaining window leaves the peer ample room to send, so ACKs for data (behavior 5, 2×MSS or 40ms) and outgoing data carry the new window. This avoids a pure ACK every time the app reads a little (2026-11-15). A 0 or small window has at most half the buffer remaining, so announce as soon as the window opens by the threshold. Advance under the same rule even while a gap exists. A rule freezing the right edge while a gap existed to keep duplicate ACK windows equal was added and then removed. If a gap appeared after the remaining window rounded down to 0 by the window scale shift, draining the buffer did not reopen it, so the peer's 0-window probes never ended. At 1% loss, throughput was in the same range with and without the freeze (2026-11-15).
4. Store **out-of-order data** only within the receive window, in its place in the receive buffer. Keep up to 32 ranges (contiguous blocks separated by gaps). Drop the segment if it would exceed this limit. The peer retransmits it. For overlapping bytes, keep the first arrival. For segments straddling the left or right edge, accept only the portion inside the window.
   - Implementation decisions (M6-2, `ReceiveBuffer`). Store ranges as distances from `RCV.NXT`. The 32-range limit applies only to segments requiring a new range. Even at 32 ranges, accept segments that extend or join existing ranges or reach `RCV.NXT`. Reject even the in-window portion of a segment requiring a 33rd range. Use one ring per connection and grow only as needed (doubling from 4KiB). `shortcut:` Storage does not shrink after growing. `ReceiveBuffer.windowEnd` advances only when the app reads. The connection separately remembers the right edge after SWS avoidance and rounding down for the shift. The buffer only trims at the physical limit, so **the connection trims bytes beyond the advertised right edge before `insert`**.
5. **Sending ACKs**. ACK out-of-order segments, segments that fill a gap, FIN, and segments outside the window immediately. ACK in-order data immediately for at least 2×MSS unacknowledged, otherwise within 40ms (the RFC limit is less than 500ms). Piggyback on an outgoing data segment if available. Even in a group of packets that the node processes together, emit one immediate ACK **per segment** (RFC 5681 §4.2 immediate ACK. Combining the out-of-order segments in the group into one duplicate ACK delays the peer's fast retransmit). Only ACKs for in-order data coalesce within a group, and even then emit one for each 2×MSS (MUST-58 and MUST-59, behavior N4).
   - **SACK blocks** (M6-10a, RFC 2018 §4 and §7, only when the peer sent SACK-Permitted, behavior T4). While a range beyond a gap is present in the receive buffer, include a SACK option in **every outgoing ACK** (pure ACK, data-bearing ACK, 0-window probe, keep-alive, and challenge ACK). Build up to 4 blocks as option space allows from the receive buffer's out-of-order ranges (behavior F4, up to 32 ranges). Timestamps are unused. **The first block is the range containing the segment that triggered the ACK.** This rule does not apply if that segment advanced RCV.NXT. Order the rest by when they were most recently reported. Because out-of-order segments always get immediate ACKs, record for each range the order in which it last gained a segment. Selecting in reverse order yields the order "most recently reported as the first block." Ranges do not overlap, so no block is a subset of an earlier block. Even if bytes arrive again within a previously received range, that range becomes the first block. Omit SACK when all gaps fill. Received data is never discarded (no reneging), so blocks always refer to bytes in the receive buffer. Omit SACK on RST and on ACKs from the stack's TIME-WAIT records, which have no receive buffer. `shortcut:` Omit D-SACK (RFC 2883). Reduce outgoing data segment payloads by the size of the SACK option (behavior T5).
   - Send new data even when the receive buffer has a gap. Without SACK, gVisor resets its duplicate ACK count to 0 on a data-bearing segment and does not retransmit the next gap on a data-bearing partial ACK (`checkDuplicateAck` and `isDupAck` in `snd.go`, `DoRecovery` in `reno_recovery.go`). Thus, simultaneous bidirectional transfers wait for the peer's RTO after each loss. Holding new data while a gap exists was tried and removed. If the app reads only after finishing its write and the advertised window is 0, the peer cannot retransmit the gap and only probes, so both sides stall waiting for each other. At 1% loss, throughput was somewhat higher with holding (5.2~7.3MB/s versus 3.6~5.0MB/s without it, measured two or three times each and highly variable between runs). That difference does not justify the stall. SACK (M6-10) addresses this loss recovery weakness (2026-11-15).
6. The **send buffer** is 256KiB per connection (unacknowledged bytes plus unsent bytes). `write` accepts only what fits.
   - Implementation decisions (M6-2, `SendBuffer`). SYN and FIN use sequence numbers outside the buffer, so the connection counts them. `startSequence` is the data-side `SND.UNA`. Out-of-range ACKs do not change the buffer. `shortcut:` Copy into a new array on every extraction (`Span` is unavailable at the supported minimums of macOS 15 and iOS 18).
7. **Sender SWS avoidance**. Given data D to send and usable window U, send when `min(D, U) >= MSS`, `D <= U`, or `min(D, U) >= largest SND.WND seen so far / 2`. Otherwise wait for the window to open. A small window above 0 could keep the sender waiting forever, so if there is data to send and these conditions are unmet for **200ms**, send as much as the window allows (override time in RFC 9293 §3.8.6.2.1, recommended 0.1~1 second). For a 0 window, use the probes below. Nagle is excluded (exclusions table).
8. **0-window probes**. With data to send and SND.WND of 0, send 1 byte after RTO, then continue doubling the interval (up to 60 seconds). Keep the connection open as long as the peer ACKs (MUST-37). With no ACK after 15 probes, emit `.closed(.timedOut)` (gVisor `snd.go:597`). For **a connection the application released with `close`**, terminate with RST after 15 probes even if the peer responds (`.closed(.timedOut)`). Otherwise a peer that keeps the window at 0 and only ACKs probes can hold a connection slot and its send buffer indefinitely (resource-management exception allowed by RFC 9293 §3.8.6.1, RFC 6429, M6 review A). Keep connections held by the app open (the app terminates them by canceling the Task).
   - If the peer reduces the window to 0 (moves the right edge left) while data is in flight, keep a live peer connected despite the retransmission limit. If the window is 0 when the retransmission timer expires and an ACK arrived since the last retransmission, that expiration does not count toward the limit of 15 (RFC 9293 §3.8.6 SHLD-17 and MUST-35, M6 review A).
   - Implementation decisions (6af902c). Reset a released connection's probe count only when new data is acknowledged or the window grows above 0 (to avoid dropping a long response to a slowly reading peer). "ACK after the last retransmission" means any acceptable ACK. Released connections count to 15 without the shrunk-window exception and send RST at the limit.
9. Accept window updates only from segments with `SND.UNA =< SEG.ACK =< SND.NXT`, following RFC 9293 §3.10.7.4 SND.WL1 and WL2. Old ACKs (before `SND.UNA`) accepted under behavior X3 do not change the window.

### S. Stack (`TCPStack`)

1. **Lookup**. For an incoming segment, look up a connection by (local address, local port, remote address, remote port). If none exists, look up a listener by local port. A destination other than a local tailnet address produces `.dropped(.notForUs)` (the filter has already checked this, and the stack checks again).
2. **If there is no connection or listener**, reply with RST under RFC 9293 §3.10.7.1. Do not reply to RST. This also applies to SYN received on a port without a listener. tsnet also sends RST (TCP notes §6.2 item 4).
3. **Listeners**. Allow one per port and up to 16 in total. Listen on all local tailnet addresses (IPv4 and IPv6). Apply the LISTEN rules from TCP notes §4.2 to segments reaching a listener. Ignore RST, reply with RST if ACK is present, and create a connection on SYN. For segments without SYN, ACK, or RST (such as FIN alone), reply with the same `<SEQ=0><ACK=SEG.SEQ+SEG.LEN><CTL=RST,ACK>` as a port without a listener (behavior S2, 2026-11-17). The fourth step of RFC 9293 §3.10.7.2 says to drop them, but the receive filter checks only SYN against its rules. Silently dropping would let an ACL-blocked peer infer which ports listen from the presence or absence of a reply. All listener responses to non-SYN segments now match the responses of ports without listeners.
4. **Limit on connections being established (SYN-RECEIVED)**. Allow 64 across the stack and 16 per remote peer (see "Per-peer share" below). Drop excess SYN without responding (like the gVisor forwarder, TCP notes §5). The peer retransmits SYN. Connections in this state have no buffers.
5. **Accept queue**. Each listener allows up to 32 established connections that the app has yet to accept. When full, drop new SYN without response. Up to 16 may belong to one remote peer (see "Per-peer share" below). While waiting, a connection receives data up to its receive window (16KiB before acceptance, behavior M). Closing the listener resets queued connections with RST and discards connections still being established.
6. **Connection count limit**. Allow 256 connections across establishment, established, and closing states. At the limit, drop new SYN without response and return `limitReached` from `connect`. Keep up to 1,024 separate TIME-WAIT records and **retain them until their deadline**, subject to the per-peer eviction rule below. Discarding them would cause RST replies to the peer's FIN retransmissions and could let late segments from a previous connection enter a new connection with the same 4-tuple. At 1,024 records, drop new SYN without response and return `limitReached` from `connect` until a record expires (fail closed). Each record contains only the 4-tuple, two sequence numbers, and a deadline.
7. **ISN** (RFC 6528 §3). `ISN = M + F`. M increments by 1 every 4 microseconds from stack creation. F is the first 32 bits of `HMAC-SHA256(secret, local address ‖ local port ‖ remote address ‖ remote port)`. The node draws and supplies a 32-byte secret from the system RNG each `run()`.
8. **Ports for outgoing connections**. Pick sequentially from 49152…65535, skipping an already-used 4-tuple (including TIME-WAIT). Use a local source address in the destination's family (as in tsnet). If there is no local address in that family, return `unknownHost`.
9. **Address changes**. The node passes its local address list whenever it applies a netmap. Connections using addresses that are no longer local end with `.closed(.peerRemoved)` and send nothing.
10. **Output order**. Process outputs from `receive`, `advance`, and application calls in emission order. A connection's segments are emitted in sequence order.

Implementation decisions (M6-5, 2026-11-15, `Sources/SwiftailNetstack/Stack/`)

- **IDs**. `TCPStack.ConnectionID` and `ListenerID` are `UInt64` values that are never reused within the stack. Calls on old IDs cannot reach new connections. Calls on IDs the application does not hold (nonexistent IDs, IDs released by `close` or `abort`, or queued IDs) do nothing.
- **Declaration**. `init(isnSecret:now:)`, inputs `receive(_:at:)`, `advance(to:)`, `setLocalAddresses(_:)`, `setRemoteAddressGroups(_:)`, and `removeConnections(toRemoteAddress:)`, application calls `listen(on:) throws(ListenError)`, `stopListening(_:)`, `accept(from:at:)` (connection ID and outputs), `connect(to:at:) throws(ConnectError)`, and `write`, `read`, `finishWriting`, `close`, and `abort` by ID, and read access through `connection(_:)` (a copy), `nextDeadline`, and `localAddresses`. Outputs are `.ipPacket`, `.event`, and `.dropped`. Events are `.established(id)`, `.acceptable(listener)`, `.readable(id)`, `.writable(id)`, `.endOfStream(id)`, and `.closed(id, reason)`. The reasons include the added `peerRemoved`.
- **Emit events only for connections the application holds.** Do not notify for connections being established, queued, or after `close`. Inspect data and FIN received while queued through `connection(_:)` after `accept`. Emit `.closed(.finished)` on entering TIME-WAIT, and keep remaining data readable until the application calls `close`.
- **Node call order**. Create the stack and call `setLocalAddresses` → pass a group of packets one by one to `receive`, then call `advance(to:)` at the same time (emits deferred ACKs) → arm the timer for `nextDeadline` → process outputs in emission order. Every time the node applies a netmap or the engine handles key expiration and changes the peers, call `setLocalAddresses` and `setRemoteAddressGroups` again. Call `removeConnections(toRemoteAddress:)` for each remote address whose owner changed or disappeared (the stack's part of behavior X10).
- **Limits**. Connections being established count toward the accept queue's 32 slots so the queue cannot exceed 32. The 256 connection cap includes connections being established, queued connections, connections held by the application, and released connections still closing. Signal overflow with `.dropped(.limitReached(kind))`. Once there are 1,024 TIME-WAIT records, connections newly entering TIME-WAIT finish as connections without being converted to records.
- **TIME-WAIT records**. Ignore RST (RFC 9293 §3.10.7.4 calls for CLOSED, but this follows S6's decision to retain records until the deadline and gVisor). ACK SYN and data and do not reopen a new connection with the same 4-tuple. ACK FIN retransmissions and restart the deadline. Do not reply to data-free ACKs. Keep records until their deadline even if an address changes.
- Choose outgoing ports sequentially (this does not use RFC 6056 random selection. The remote side is an authenticated tailnet peer). The node filters out port 0. `stopListening` discards connections being established without sending anything.
- Cost (256 connections and 1,024 records, debug build). About 7µs per `receive`, about 5µs for `nextDeadline`, and about 27µs for `advance` with no deadline. `shortcut:` Scan for deadlines without a heap.

Review fixes (M6 review A, 2026-11-15). Prevent one peer from exhausting another peer's share.

- **One remote address can have up to 64 connections** (total of connections being established, queued, held by the application, and released but still closing. As of 2026-11-17, "one remote address" in these items means one peer, see "Per-peer share" below). Drop excess SYN without response (`.dropped(.limitReached(.connectionsPerAddress))`) and return `limitReached` for `connect` to that address. With only the 256 total limit, a single peer can fill all 256 slots and block other peers' SYNs. The first adopter uses about 10 connections per device (review result 2).
- **Allow up to 64 TIME-WAIT records per remote address.** On overflow, remove the oldest record **for that address**, affecting only that peer's old connections. The behavior at the 1,024 total limit still drops new SYNs.
- **TIME-WAIT records live for at most 240 seconds from creation** (2MSL = 4 minutes in RFC 9293 §3.6.1). Restart the 60-second timer on each FIN retransmission without extending beyond that cap. Without the cap, a peer could retain the record forever by retransmitting FIN every 59 seconds.
- Implementation decisions (6af902c). The per-address connection count includes connections still held by the application with only unread data remaining. For SYN, check 256 total connections → 64 per peer → 1,024 records → connections being established (total and per peer) → queue (total and per-peer share). Determine the oldest record by creation order. Measure 240 seconds from entry into TIME-WAIT, and apply the same cap to TIME-WAIT connections that remain as connections because the records are full. Reply with RST to a late FIN on the 4-tuple of a record removed by the per-address cap (an accepted cost).

Per-peer share (fixed during data plane security verification, 2026-11-17)

- **All limits above for "one remote address" apply per remote peer**. The limits are 64 connections, 16 connections being established, and 64 TIME-WAIT records. A peer has both IPv4 and IPv6 addresses, so counting by address alone gives one peer twice its share. With 16 × 2 = 32 connections being established, equal to the listener queue of 32, one peer blocked all other peers from one listener.
- **Groups**. Every time the node updates the owner table (netmap application or key expiration handling), it passes a "remote address → group" table along with local addresses (`setRemoteAddressGroups(_:)`). It comes from the same table used to check address ownership (behavior X10, `EnginePeer.addressOwners` maps each address to the peer that has it in AllowedIPs). The group name is that peer's node ID, whose meaning is opaque to the stack. An address absent from the table (such as a local address) is a group of its own. The stack stores counts by address and sums the counts for the addresses in each group when it checks, so an updated table takes effect immediately for counting.
- **One peer gets 16 slots in a listener's queue** (established and being established combined. Excess SYN produces `.dropped(.limitReached(.acceptQueueShare))`). Established connections leave the count of connections being established, so without this share a peer could fill the queue with 32 completed handshakes. 16 is half the queue and matches the per-peer limit on connections being established. It exceeds the first adopter's roughly 10 connections per device (review result 2) even if opened together. Two ACL-allowed peers can still fill one listener's queue and block a third peer. Reducing the share further would force legitimate peers' concurrent connections to wait for SYN retransmission.
- For TIME-WAIT records, "the peer's oldest record" is the one that entered TIME-WAIT earliest among the first records (in creation order) for each of the peer's addresses.
- `shortcut:` Count each listener's connections per peer by scanning the connection table (up to 256) for every SYN. Revisit when the connection limit increases substantially.

### X. Untrusted input

WireGuard authenticates tailnet peers, and the source address is checked against that peer's AllowedIPs (M3 engine contract behaviors 2 and 5, M-E2). A peer therefore cannot inject segments into **another peer's connection**. Remaining threats are invalid segments from the peer itself and resource exhaustion. The receive filter checks only TCP SYN against its rules (`PacketFilter`), so **non-SYN segments reach the stack even from peers blocked by ACLs.**

1. No input byte sequence may cause a crash. Avoid out-of-bounds indices, integer overflow (length sums, window calculations, `SEG.SEQ + SEG.LEN`), and unbounded option traversal.
2. **Sequence outside the window**. Reject it and reply only with ACK (TCP notes §4.2 item 1). ACKs for data-free, out-of-window segments are rate limited under item 4 to prevent ACK loops.
3. **RST** (RFC 5961 §3.2). Silently drop outside the window, reset only for `SEG.SEQ = RCV.NXT`, and send a challenge ACK for other sequences inside the window. **SYN** (§4.2). In synchronized states, always send a challenge ACK and drop the segment. **ACK** (§5.2). Drop and send ACK if outside `SND.UNA − MAX.SND.WND =< SEG.ACK =< SND.NXT`.
4. Allow up to 10 challenge ACKs per connection per 5 seconds (example in RFC 5961 §7). Suppress excess ACKs.
5. **0 window**. Probes keep the connection alive even if the peer leaves its window at 0 (behavior F8). The send buffer stops at 256KiB and `write` waits. The connection remains within its memory limit.
6. **Small segments**. Even if a peer sends scattered 1-byte segments, there are at most 32 out-of-order ranges (behavior F4). Data is stored within one receive buffer, with no separate memory retained per segment. The buffer grows to cover the written position, so 1 byte at the window's end grows that connection's buffer to the window size. Before the application accepts the connection, that window is 16KiB (behavior M).
7. **SYN flood**. Apply the limits in behaviors S4, S5, and S6. Connections being established have no buffers and expire within 247 seconds (behavior R4). One remote peer can hold 16 across all its addresses and 16 in one listener's queue (behavior S, "Per-peer share").
8. **Segments with no connection**. Reply with at most one RST per segment and ignore incoming RSTs, as in behavior S2. The reply is at most the size received, so there is no amplification. There is no separate rate limit.
9. **Peer-advertised values**. Cap MSS again by the local MTU (behavior T5). If the peer advertises an MSS below 64, **do not establish the connection**. On passive open, reply to SYN with RST. On active open, send RST and emit `.closed(.refused)`. Raising a small value would exceed the peer's receive limit (RFC 9293 §3.7.1 MUST-16), while following it could generate 1-byte segments indefinitely. 64 is this contract's value (gVisor clamps a nonzero advertised MSS to a minimum of 48, `gvisor/header/tcp.go:463-470`. The RFC does not provide a basis for this). Tolerate shrinking windows (MUST-34). Do not send new data when the usable window is negative.
10. **Address ownership changes**. When the engine recomputes peers (netmap application or key expiration handling), the node compares the current data plane table of address owners (`addressOwners`) with the previous table. If a remote address loses its owner or the node key changes, end connections for the address with `.closed(.peerRemoved)`. This prevents a different node that inherits the address from continuing the previous node's connection (N8). Go's netstack has no such handling. It leaves connections open when a peer disappears or address ownership changes and relies on retransmission, keep-alive, or application closure (near `wgengine/netstack/netstack.go:729`, TCP notes). Swiftail is stricter. Review decisions (M6 review B, 2026-11-15) follow.
    - Compare owners by **node key**. Even a key change on the same node (reauthentication) drops connections to that node with `peerRemoved`. This covers more than the intended case (a different node inheriting an address), but when the key changes the WireGuard session is established again and the receiver recovers by resuming. Comparing by node ID would require carrying the ID in `EnginePeer`. Revisit if interrupted long transfers during key rotation are reported as a problem.

### N. Node integration (`Swiftail`)

1. **Device**. With `.inProcess`, the node uses neither utun nor the memory stream. `inboundPackets` emits nothing and `send(_:)` discards packets. `networkSettings` emits as in M5 (the app may leave it unread). On `.utun` or `.memory`, `listen` and `connect` produce `invalidConfiguration`.
2. **Inbound path**. Feed `.ipPacket` outputs emitted by the engine for device writes (peer packets that passed the filter and packets looped back to local addresses) into `stack.receive(_:at:)`. The stack drops non-TCP packets as `.dropped(.notTCP)` (ICMP and UDP in the exclusions table).
3. **Outbound path**. Feed stack `.ipPacket` outputs into `engine.send(_:at:)`. They follow M5 local handling (behavior L). The engine loops packets from connections to local addresses back to the stack and rejects connections to service IPs with RST.
4. **Complete each event**. Exchanges between the stack and engine stemming from one packet (or one app call or timer) run to completion without `await`. Use a queue to avoid recursion and growing call depth on large transfers to the node's own addresses. Emit deferred ACKs after the queue drains (behavior F5).
5. **Events**. Stack events resume waiting calls. `readable` → the connection's `read`, `writable` → `write`, `established` → `connect` or the listener queue, `closed(reason)` → all waiting or subsequent calls for the connection receive the corresponding error.
6. **Timer**. The node timer wakes at the earliest `nextDeadline` of the engine, `Magicsock`, and stack and calls `advance` on all three.
7. **netmap**. Whenever a netmap is applied or the engine handles key expiration and changes the peers, pass local addresses (behavior S9) and per-peer remote address groups (behavior S, "Per-peer share") to the stack. Compare each address's owner key with the previous table (behavior X10).
8. **Node shutdown**. When `run()` ends, emit one RST for each open connection (direct paths send it. Packets in the DERP channel may be lost). Resume waiting calls with `notRunning` and end the listener stream. Subsequent `listen` and `connect` calls produce `notRunning`.
9. **Dropped handles**. `deinit` of `TailnetConnection` or `TailnetListener` inserts an "abort" request into a nonwaiting channel, which one child of `run()` handles (same approach as M5 `startInteractiveLogin`). Do not create a separate Task.
10. **Backpressure from loss**. TCP treats stack packets lost due to UDP send failure or DERP channel overflow (256 items and 1MiB, tunnel contract behavior M) as ordinary loss. Congestion control reduces sending. The channel sends no separate signal to the stack.
11. Test-only (outside the public API) `package func setInProcessLoss(rate: Double, seed: UInt64)` drops packets between the stack and engine in both directions with probability `rate`. Generate randomness from `seed`. Defaults to 0.

Implementation decisions (M6-8, 2026-11-15, `TailnetNode+Netstack*.swift`, `TailnetListener.swift`, and `TailnetConnection.swift` in `Sources/Swiftail/`)

- **Processing loop**. With `.inProcess`, engine `.ipPacket` outputs enter the stack queue. One outermost call drains the queue: feed queued packets to `stack.receive` in order → when empty, call `advance(to:)` with the same time (deferred ACKs) → repeat if its outputs refill the queue → rearm the timer at the end. Packets the engine loops back for connections to the node's own addresses only accumulate in the queue. The call depth stays constant. There is no separate timer. The node timer wakes at the earliest deadline of the engine, `Magicsock`, and stack.
- **Stack lifetime**. The stack exists only during `run()` on `.inProcess`. At the start of `run()`, draw a 32-byte ISN secret from system randomness, create the stack, and register listeners opened before `run()`. On exit, close listeners, abort connections held by the application, and terminate the rest (being established, queued, or released by `close` but still closing) with `TCPStack.abortAll()`. Do this before closing sockets and the engine (RST goes out on direct paths. Packets left in the DERP channel may be lost).
- **Waiting calls**. Install a new channel without a payload each time a call waits. The resumer only finishes it. A resumed call rechecks state before deciding what to do, which avoids double resumption. Code removing a record (`close`, `abort`, listener closure, or end of `run()`) must finish any installed channel. On local-address connections, an event may occur while the call processes its own outputs. Record missed events and check them before waiting.
- **Cancellation**. `read` throws `cancelled` and preserves the connection and data. `write` aborts the connection (RST) and then throws `cancelled`. `connect` abandons the attempt and throws `cancelled`. The listener stream ends and the listener stays open. When `run()` ends, waiting calls receive `notRunning`. One child Task of `run()` reclaims dropped handles with RST (connections) or closure (listeners).
- **Owner changes (X10)**. The node keeps no key per connection. When the engine recomputes peers (netmap application or key expiration handling), it compares the owner key of each data plane peer address with the previous one and calls `removeConnections(toRemoteAddress:)` for each address whose owner key disappeared or changed. The owner comes from the same table read by `whoIs` (`addressOwners` retained by the node from the engine, host contract behavior W6). AllowedIPs source checks mean all connections for an address were established with its owner at the time.
- **Name resolution**. On a name collision, the later node wins, as in Go (local node → peers in ID order). This differs from `path(toPeerNamed:)`, where the lower ID wins. Compare the suffix of a short name without changing case (as in Go).
- **Public API details**. A `read(upTo:)` length of 0 or less produces `invalidConfiguration`. If two Tasks iterate a listener concurrently, the later Task's stream ends immediately (it cannot throw because `Failure = Never`). Two calls to `finishWriting()` are allowed. `connect` requires state `.running` (the app waits via `events`).
- **Dropped listeners** (M6 review B). Listener records hold a weak handle reference. `listen(port:)` and the start of `run()` first close listeners whose handles were dropped. Thus, dropped listeners hold neither their port nor a slot in the limit (16) before or during `run()`. During `run()`, the child that reclaims dropped handles or the next `listen` closes the stack listener and resets queued connections (RST). A SYN arriving in the interim establishes a connection that is then reset with RST.
- `connect` may throw `reset` if a peer RST arrives right after establishment and before return.
- **Loss hook**. `package func setInProcessLoss(rate:seed:)` drops packets in both directions between stack and engine (SplitMix64). 0 disables it. Packets for local-address connections pass through it twice.
- Unmeasured are the iOS tunnel extension binary size increase (N1) and throughput (gate).

### A. Edge: listen, connect, read, and write

1. **`listen`**. Validate the device and port, then register the listener with the stack. Before `run()`, record it and register it when `run()` starts. This avoids a failure when called immediately after launching `run()`. Listening before a netmap is allowed (SYN arrives only after the netmap and filter are ready).
2. **`connect`**. ① If the state is other than `.running`, throw `notRunning`. ② If `host` is an IP address, use it as given. Otherwise lowercase it, remove the trailing dot, and look up the name in the netmap among peer and local node FQDNs and short names with the MagicDNS suffix removed. Prefer IPv4, with IPv6 as fallback (Go `resolve.go:54-75`, `:115-140`). ③ Throw `unknownHost` unless the address belongs to a data plane peer or the local node. ④ Send SYN and wait for establishment. The result is a connection, `refused`, `timedOut` (247 seconds), or `cancelled`. Names outside the tailnet are never resolved through system DNS or connected via OS sockets (unlike tsnet).
3. **`read`**. Return immediately if the receive buffer contains data, otherwise wait for `readable`. Return nil once the buffer is empty after the peer's FIN. Cancellation throws `.cancelled` and preserves the connection and buffered data.
4. **`write`**. Buffer as much as fits. With bytes left, wait for `writable` and continue adding bytes. Suspend the call between chunks so other work can run on the actor so a large write does not monopolize the node. `write` after `finishWriting` or `close` produces `closed`.
5. **Backpressure**. On receive, the window opens only as the app reads (if it does not read, the peer stops at 256KiB). On send, `write` suspends at the 256KiB buffer limit. The edge has no separate backlog buffer.
6. **Concurrent use**. One `read` and one `write` may wait concurrently on a connection. A second call in the same direction produces `concurrentUse`. One Task iterates the listener.
7. **Ended connection**. After `closed(reason)`, `read`, `write`, and `finishWriting` throw the corresponding error (`reset`, `timedOut`, `peerRemoved`). After app `close` or `abort`, they produce `closed`.
8. **Deadlines**. The API has none. The app uses Task cancellation for deadlines (first adopter confirmation needed F6).

### M. Memory

| Buffer | Limit | On overflow |
| --- | --- | --- |
| Connection receive buffer (including out-of-order data) | 256KiB. 16KiB before application acceptance (listener queue) | Reject bytes outside the window |
| Connection send buffer | 256KiB | `write` waits |
| Out-of-order ranges | 32 per connection | Drop the segment |
| Connections (being established, established, or closing) | 256, up to 64 per remote peer | Drop SYN and return `limitReached` from `connect` |
| Connections being established | 64, up to 16 per remote peer | Drop SYN |
| Accept queue | 32 per listener (including those being established), up to 16 per remote peer | Drop SYN |
| Listeners | 16 | `limitReached` |
| TIME-WAIT records | 1,024, up to 64 per remote peer (no buffers). Lifetime up to 240 seconds | At the total limit, drop new SYN and return `limitReached` from `connect`. At the per-peer limit, remove that peer's oldest record (behavior S6 and below) |

- "One remote peer" groups its addresses (IPv4 and IPv6). Addresses the node did not identify as belonging to a peer each have their own share (behavior S, "Per-peer share").
- Buffers allocate as needed and grow to the limit. Idle connections hold no buffers.
- **The receive window before acceptance is 16KiB** (2026-11-17). The receive buffer grows as one block up to the written position. With a 256KiB window, 1 in-order byte and 1 byte just before the window's end can allocate 256KiB for one connection, and one listener's queue (32 connections) can hold 8MiB before the app accepts. The stack caps the receive window for a connection created by a SYN to a listener at 16KiB and carries that value in the SYN-ACK window field. `accept(from:at:)` opens the window to the full buffer (256KiB) and sends an immediate window update ACK for an established connection. One queue can hold up to 32 × 16KiB = 512KiB of receive buffers. 16KiB was chosen because ① it is the smallest power of 2 that fits the peer's initial window (10 × MSS from RFC 6928, 12,400 bytes at MSS 1240), so the first request can arrive before acceptance without hitting the window limit. ② The SYN-ACK window field is unscaled (behavior F2), so the value must be at most 65,535 to fit as given. ③ It is a multiple of the local scale implied by shift 3, so rounding down does not distort the window field after establishment. A peer that fills 16KiB before acceptance waits at a 0 window and resumes sending after the window update ACK. Direct users of `TCPConnection` (the default in `accept(_:initialSequenceNumber:receiveWindowLimit:at:)`) and active opens retain the full buffer.
- Worst case is 256 × 512KiB = 128MiB, based on the first adopter's Mac host. Using `.inProcess` inside an iOS extension with these limits could not guarantee staying within the 50MiB budget (first adopter confirmation needed F6).
- Go comparison. gVisor defaults to 1MiB of buffer per direction and a limit of 2,048 connections being established on macOS (TCP notes §5).

### K. Secrets and logs

1. The ISN secret never appears in events, errors, `description`, or `dump`.
2. The node records logs with `os.Logger(subsystem: "Swiftail")` (same rules as M5). Log listener opening and closure (port), connection establishment and closure reason, and the count of drops at the limit. Omit full addresses and payload data.

## Decisions

| # | Decision | Defined | Rationale |
| --- | --- | --- | --- |
| D1 | Congestion control | NewReno (RFC 5681 + 6582) | Plan §4(a). The specification is short and easy to cover with deterministic tests. Omit gVisor's CUBIC |
| D2 | Initial window | RFC 6928 (10 segments) | Matches gVisor and Linux. Small HTTP replies finish in one round trip |
| D3 | Timestamps | Unused | Optional. Karn alone is sufficient for RTO measurement. Saves 12 bytes per segment |
| D4 | Delayed ACK | 2×MSS or 40ms | RFC SHOULD. gVisor appears to send without delay (TCP notes §11 item 1) |
| D5 | Nagle | None | Bytes from `write` go out as the window permits. The app groups small writes |
| D6 | Unaccepted connections | Keep up to the queue limit (32) | tsnet's "close after 1 second" rule exists because its channel has no buffer (TODO in `tsnet.go:2406-2418`) |
| D7 | Segments with no connection | RST | Matches the RFC and gVisor |
| D8 | Checksum validation | Validate on receive | Tailscale also validates before the netstack. The gate catches errors in this implementation |
| D9 | MTU | 1280 fixed | Default value for Tailscale TUN. The MTU takes no argument |
| D10 | Checksum code location | `SwiftailBase` (`package`) | Keep one copy of the RFC 1071 calculation. The engine changes only its call |
| D11 | Access level of `SwiftailNetstack` | `package`, not a product | The app uses only types exposed by `Swiftail`. The stack target adds no public API surface. |

## Lead session confirmation needed

| # | What | Options | Recommendation |
| --- | --- | --- | --- |
| N1 | Target dependency direction | (a) `Swiftail` depends on `SwiftailNetstack`. The stack is a value inside the node actor / (b) Per plan §5, `SwiftailNetstack` depends on `Swiftail`. The stack is a separate actor above `inboundPackets` and `send` on the `.memory` device | (a). Option (b) adds streams that drop at 256 items between the node and stack and two actor hops per packet. It doubles the timers and forces the API into a different type because `extension TailnetNode` cannot store state. The trade-off is that the stack code is in binaries that do not use TCP (iOS tunnel extension). State is created only for `.inProcess`. Measure code size after implementation |
| N2 | Public API shape | (a) Handles (`TailnetListener` and `TailnetConnection` are `final class` and disconnect when dropped), named `listen(port:)` and `connect(to:port:)` / (b) Only scoped functions (`withConnection(to:port:) { … }`, `acceptConnections(port:) { connection in … }`) / (c) The plan §6 name `dial(host:port:)` | (a). Maps one-to-one to tsnet and lets the first adopter's HTTP server easily add connections to its own Task group. Disconnect in `deinit` is a fallback. Option (b) guarantees lifetime structurally but prevents passing connections elsewhere. "Dial" is Go terminology. `connect` is familiar in Swift (Network framework, POSIX) |
| N3 | SACK | (a) Leave it out of the minimum M6 scope, decide from gate records at 1% and 5% loss / (b) Receiver only (emit SACK blocks) / (c) Both sides (RFC 6675 recovery) | (a). Plan §4(a) says "decide after measuring." Swift sends the first adopter's large transfers, so (b) helps little, and (c) is the largest part of the state machine. Set the criterion in advance: open implementation unit M6-10 if throughput at 1% loss falls below 1/10 of the throughput at 0% loss. Only record the 5% loss result |
| N4 | RTO minimum | (a) 200ms (gVisor, Linux) / (b) 1 second (RFC 6298 §2.4 SHOULD) | (a). A 1-second minimum would stall for 1 second on each loss at the end of a window. Both peer stacks use about 200ms (unverified for the kernel) |
| N5 | keep-alive | (a) Always on (2 hours, 75 seconds, 9 probes), no settings / (b) Off / (c) API to toggle per connection | (a). The RFC requires off by default and application choice (MUST-24 and MUST-25), but tsnet always enables it on incoming connections. The Mac host runs for days, and iPhones disappear without notice. With (b), connections that stop while reading the body consume slots from the limit of 256. (c) has not been requested |
| N6 | Value of memory limit | Table of behavior M (connection 256, buffer 256KiB each) / larger (like gVisor at 1MiB) / smaller | Start with values from the table and adjust based on gate throughput records. A window of 256KiB achieves approximately 100Mbit/s over a RTT of 20ms |
| N7 | Gate against the macOS kernel stack | (a) Administrator privileges once: Go tool creates utun and starts tsnet on top (`addKernelPeer`). Repeatable / (b) Real device: iPhone with the M5 tunnel extension enabled receives from the Mac Swift listener (first adopter session) / (c) Mac with the official Tailscale app on a real tailnet | (a) as the default gate, (b) for final verification. No path was found for exchanging IP packets with kernel TCP without utun (gate (b) below). For (a), the owner must authorize sudo once |
| N8 | Connections whose address owner changed | (a) Close them (behavior X10) / (b) Leave them open | (a). The first adopter runs WhoIs for the remote address on every request, so even with (b) the next request would catch it, but transfers already in progress would continue. Go's handling is unverified. The cost is retaining the previous address owner table and comparing it with the new table whenever the node recomputes peers |
| N9 | TLS over the connection (M7 work that affects the M6 API) | (a) Loopback bridge: connect the Swiftail connection to a TLS `NWListener` on `127.0.0.1`. Pass the remote address separately / (b) TLS 1.3 server written in Swift / (c) SecureTransport (`SSLSetIOFuncs`, deprecated since macOS 10.15 and iOS 13, verified in SDK headers) | Defer the decision. The M6 API exposes only a byte stream (`read` and `write`), and any option can run above it. No public API was found for layering Network framework TLS over a user-provided byte stream (unverified). Investigate separately before the M7 contract |
| N10 | Move the checksum to `SwiftailBase` | (a) Move it (changes the call in one engine file) / (b) Keep an additional copy in the netstack | (a) (decision D10). Existing engine tests continue to cover it |
| N11 | Respond to ICMP echo in `.inProcess` | (a) No reply / (b) Reply (tsnet replies) | Start with (a). Disco ping works without the stack. Move to (b) based on the first adopter's answer (F12) |

### Lead session decisions (2026-11-15, draft stage)

These decisions precede the first adopter's review (F1–F13 below). The table marks decisions that may change based on the answers.

| # | Decision | Follow-up |
| --- | --- | --- |
| N1 | (a) `Swiftail` depends on `SwiftailNetstack` | Measure and record the iOS tunnel extension binary size increase after implementation. Update the plan §5 diagram and module table together after review |
| N2 | (a) Handles and `listen(port:)` and `connect(to:port:)` | The plan §6 draft name `dial` is unused |
| N3 | (a) Start without SACK and decide from gate records | Criterion. Open M6-10 if throughput at 1% loss is below 1/10 of throughput at 0% loss |
| N4 | (a) RTO lower bound set to 200ms | — |
| N5 | (a) Always enable keep-alive | Document in the doc comments that this differs from the RFC's "off by default." Revisit based on the F5 answer |
| N6 | Start with values in the table (256 connections, 256KiB buffers each) | Based on Mac host. If iOS extension uses `.inProcess` (F6), separately define lower values. |
| N7 | (b) Use a real device for final verification by default. Use (a) `addKernelPeer` **only if the owner authorizes sudo** | Only the owner can grant administrator privileges. Until then, use the Go peer (gVisor) gate (a) and real device |
| N8 | (a) Terminate connections where the address owner has changed | — |
| N9 | Deferred. The M6 API exposes only a byte stream | **The greatest risk for M7**. Apple platforms lack an apparent public API for layering TLS over a user-provided byte stream. Investigate separately before the M7 contract and get the answer to F1 first |
| N10 | (a) Move checksum to `SwiftailBase` | — |
| N11 | (a) Start with `.inProcess` sending no ICMP echo reply | Revisit based on the F12 answer |

A separate session revised the TCP notes (`docs/protocol-notes/tcp-netstack.md`) against 12 RFCs and pinned Go sources (2026-11-15). The contract incorporates the resulting corrections in behaviors T2, T4, T5, T6, R3, R4, R6, F1, F2, F7, F9, S6, X7, X9, and X10. The RFC is the basis for processing order (gVisor differs). RST follows the single rule in X3. The override interval prevents stalls on small windows. SYN and SYN-ACK retransmit up to 247 seconds (the RFC requires at least 3 minutes). TIME-WAIT records survive until their deadline, small MSS values are rejected, and window scaling follows the negotiation rules. Unverified against references are the kernel TCP (XNU) default values and runtime gVisor behavior.

## First adopter confirmation needed

This section presents assumptions and questions formed from reviewing the committed code of the first adopter (`core/internal/node/node.go`·`tls.go`, `core/internal/proxy/proxy.go`, `core/internal/host/`, `docs/protocol.md`, `docs/protocol-addenda.md`, `docs/tunnel.md`). The clauses that change based on the answers are listed together.

Mapping for the Mac host

```swift
let node = try TailnetNode(configuration: configuration, device: .inProcess)
let listener = try await node.listen(port: 443)
try await withThrowingDiscardingTaskGroup { group in
    group.addTask { try await node.run() }
    for await connection in listener {
        group.addTask {
            // connection.remoteEndpoint.address → (M7) node.whoIs(…)
            // TLS and HTTP run on top of this connection (F1)
            await serve(connection)
        }
    }
}
```

| # | Question | Assumed | Changes based on answer |
| --- | --- | --- | --- |
| F1 | Who owns the TLS and HTTP servers when replacing the Mac host? Does the first adopter implement the equivalent of Go's `tls.NewListener` + `http.Server` in Swift, or does Swiftail need to provide something? | Swiftail exposes only a byte stream | N9. M7 scope expands if Swiftail owns this |
| F2 | Is there only one listener (port 443 or test port)? Can a node listen on multiple ports simultaneously? | One | Behavior S3 upper bound of 16 |
| F3 | How many connections can be open simultaneously (at most, up to number of paired devices × connections per device)? | Dozens | Behavior M upper bound of 256, upper bound of S4·S5 |
| F4 | Are the largest transfers 4GiB server → client (maximum for one file) and 4MB client → server? Do any exceed 4GiB? | Yes | At 4GiB the sequence number wraps (test 6). If larger transfers are common, revisit timestamps and PAWS (exclusions table) |
| F5 | Does the Swift HTTP server also set `ReadHeaderTimeout` to 10 seconds and `IdleTimeout` to 60 seconds? Go has no timeout for reading a request body, so tsnet's keep-alive (2 hours) reclaims connections to vanished clients | keep-alive is needed | N5. If the server times out every read, keep-alive can be removed |
| F6 | Is the proxy mode (diagnostic use) being migrated to Swiftail? Moving it would require using `.inProcess` in the iOS extension. | No. `connect` is used in testing and `rdtestenv` | If migrated, lower the behavior M limits on iOS (50MiB), determine whether `connect` needs a timeout parameter (15 seconds in Go), and check whether `finishWriting` can serve in place of `CloseWrite` |
| F7 | Is `IPEndpoint` (address and port) sufficient for the connection's remote address? Is the `r.RemoteAddr` string used outside WhoIs anywhere? | Sufficient | Public API `remoteEndpoint` |
| F8 | Today, listening starts after `Running`, and 3 listen failures produce `Error`. Swiftail's `listen` fails only for duplicate ports or limits, and can be called before `run()`. Can the retry logic be removed? | Yes | Behavior A1 |
| F9 | When a node stops (app termination, restart), open connections are terminated with a single RST (it may not reach if the direct path is not available). Should ongoing transmissions be completed and then the node be halted? | A single RST is sufficient | Behavior N8 |
| F10 | Is there a throughput target for lossy paths (cellular, DERP)? Use any recorded IPA transfer rates measured with the Go host as a baseline. | No | N3(SACK), Gate (a) 8·9 records |
| F11 | Should the fake tailnet e2e test (`listenTLS=false`) use the Swift node's listener as-is? | Covered in M7 | Scope of gate (a) |
| F12 | Is there a procedure to send an ICMP ping to the tailnet address on a Mac host for diagnostics? | No | N11 |
| F13 | Does allowing up to 32 connections that the listener does not accept (Go closes them after 1 second) align with current behavior expectations? | It does not conflict | Decision D6 |

## First adopter review results (2026-11-15)

The RemoteDebug session answered F1 through F13 with findings from its Go code at `2814b2c` and proposals. All assumptions were confirmed, and the following contract provisions are settled.

1. **TLS and HTTP (F1)**. The first adopter writes the HTTP server in Swift. The current Go host uses `tls.NewListener` + `http.Server.Serve`, so it uses **HTTP/1.1 only**. TLS uses a **loopback bridge** that connects the Swiftail connection to an `NWListener` on `127.0.0.1` (TLS, ALPN `http/1.1`, minimum TLS 1.2). The first adopter already has an OS TCP listener independent of the tailnet (same-Wi-Fi direct connection), so one HTTP server will accept both entry points the same way. There will be no TLS server written in Swift. **M6's API remains a byte stream** (N9 is decided in M7). The M7 contract will decide the following.
   - Whether Swiftail provides the bridge as an optional product (accurately relaying backpressure and half-close) or the first adopter writes it. In either case, the HTTP server must be able to look up the loopback connection's source port → tailnet `IPEndpoint` mapping for every request (WhoIs).
   - Shape of the ts.net certificate API: a certificate chain (DER or PEM), private key (in a form usable to create a `SecKey`, X9.63 raw representation for P-256), and a renewal event. The first adopter adds them to the keychain and creates a `SecIdentity`.
2. **Scope (F2, F3, F4, F6, F12)**. There is one listener (default 443), about 10 concurrent connections per device (the 256 cap is sufficient), and a maximum transfer of 4GiB server → client and 4MiB in the reverse direction. Proxy mode goes away with Go (no callers). So **the iOS extension has no use for `.inProcess`**, and behavior M limits remain based on the Mac host. Tests and diagnostics use `connect`. Do not respond to ICMP echo (N11 confirmed).
3. **Timeouts and keep-alive (F5)**. The first adopter's Swift server sets 10 seconds for the header, 30 seconds without progress reading the body, 60 seconds idle, and 60 seconds without write progress. Keep-alive stays on (N5 as written. Other adopters may have no timeouts). Enforce the write timeout by canceling the Task that called `write`. A canceled `write` resets the connection with RST and throws `.cancelled` (behavior A4 and the `write` comment in the public API).
4. **Other items (F7, F8, F9, F13)**. `IPEndpoint` suffices for the remote address. Remove listen retry logic (`listen` can run before `run()`). One RST is sufficient on node shutdown (the receiver resumes with Range). Keeping up to 32 unaccepted connections does not conflict with current use.
5. **Throughput baseline (F10)**. There are no records. The first adopter provides a measurement of the time to receive 100MB using the Go tunnel + Go host in gate (b) (direct Wi-Fi, and cellular and DERP if possible). This is the comparison baseline for N3 (SACK) and the gate results. **Measured value received (2026-11-15, iPhone 14 Pro, direct UDP path on the same Wi-Fi): 100MiB in 23.0 seconds (4.56MB/s).** Cellular and DERP-only measurements are still unavailable. The Swift stack's loopback result at 0% loss (about 80MB/s) exceeds this baseline by more than tenfold. Real device testing will measure how far throughput under actual network loss falls below this baseline, rather than no-loss speed.
6. **Integration test setup (F11)**. Fake-tailnet e2e is M7 work. First, document in `Tools/interop/README.md` how to run two in-process Swiftail nodes (one `listen`, one `connect`) against the `Tools/interop` test control server without an account (added to M6-9b). The first adopter builds the host migration integration test on this setup.
7. **Copies in large transfers (proposal)**. Measure the effect of copying in `write(_: [UInt8])` on Mac CPU during a 4GiB transfer using the 100MB transfer in gate (a). If a problem appears, add a write API with fewer copies (`Span` family or `some Collection<UInt8>`). Keep unsafe pointers out of the public API (code standards in plan §5). Leave this as a `shortcut:`.
8. **Kernel stack gate**. The first adopter session checks that an iPhone with the M5 tunnel enabled can receive a large file from the Mac's Swift listener. It builds a minimal HTTPS server on the Swift listener that serves one file with Range in time for that check.

## Exclusions (recorded as `shortcut:` comments)

| Excluded | Rationale | Time of need |
| --- | --- | --- |
| Sender-side SACK (selecting lost ranges from received blocks, RFC 6675), D-SACK (RFC 2883) | Receiver-side SACK (negotiation and emitting blocks, under behavior F5) shipped in M6-10a. The codec exposes received blocks as values, and the connection does not use them | Sender: M6-10b (start based on measurements after 10a and real device records). D-SACK: when the peer's reordering detection becomes a problem |
| Timestamps, PAWS | D3 | When RTO is inaccurate on a path with frequent retransmissions, or one connection passes 4GiB repeatedly and could confuse old segments with new ones |
| CUBIC, RACK, limited transmit (RFC 3042) | D1 | When NewReno throughput is a problem on high-bandwidth, high-delay paths |
| Nagle | D5 | When applications frequently perform small writes |
| Simultaneous open (SYN without ACK in SYN-SENT) | The use cases have fixed accepting and connecting sides. Drop that SYN | When using a protocol where both sides connect simultaneously |
| Urgent data | Ignore URG and read as normal data (differs from MUST-30) | When encountering a peer that uses urgent data |
| ECN | Optional | |
| IP fragment reassembly, path MTU discovery, ICMP error handling | The engine does not accept fragments. MSS fits within the 1280 MTU | When a path has a smaller MTU than the tunnel (this occurs outside WireGuard and is invisible to inner TCP) |
| Receive buffer autotuning | Fixed at 256KiB | When throughput measurements show that the window is the bottleneck |
| address-specific listening, `tcp4`·`tcp6`, port 0 | the first adopter specifies only the port | When a use case requires them |
| establishing connections outside the tailnet (system DNS, OS socket) | a convenience specific to tsnet | |
| `connect` waiting for `Running` | The app waits through `events` | When there is a caller that cannot observe state |
| timeout parameters for read, write, and connect | handled via task cancellation | depending on the response from F6 |
| UDP socket (`ListenPacket`), ICMP echo response | the first adopter does not use it. N11 | depending on the response from F12 |
| TCP 53 at the service IP (DNS over TCP) | There is no OS resolver querying the service IP with `.inProcess`, and the utun device has no stack attached. Keep M5's RST | When MagicDNS responses over 512 bytes actually occur in tunnel mode (requires attaching the stack to the utun device) |
| TLS, HTTP | N9, F1 | M7 |
| Byte `AsyncSequence` (`for try await chunk in connection`) | A one-line loop around `read` | |
| Finding the stack's next deadline by scanning all connections | Up to 256 connections | When the limit increases substantially |
| Per-packet `[UInt8]` allocation and copying | Same structure as through M5 | When gate throughput records show a bottleneck |

## Tests

### Unit tests (no sockets, deterministic with supplied times)

`Tests/SwiftailNetstackTests/` (new test target):

1. **Codec**. Round-trip parsing and encoding of IPv4 and IPv6 segments. Checksum (odd length, multiple carries, IPv6 pseudo-header). Options: MSS and Window Scale, alignment skewed by NOP, bytes after EOL, unknown options, length 0 or 1 or extending past the header, shift 15, MSS in a non-SYN segment. Data offset 4 and 16 (outside the header). Packet with IPv4 options. No crash on arbitrary bytes (10,000 inputs per fuzz case, with a fixed seed for each case).
2. **Sequence number**: Comparison, difference, and window inclusion judgment when exceeding the 2^32 boundary.
3. **State machine paths** (two connections linked in memory). Passive and active open, bidirectional data, all close orders (one side first, simultaneous, reverse-direction data after half-close), RST on `close` with unread data, RST for data received after close, `abort`, refusal (RST on SYN), retransmission limits and elapsed times for SYN, SYN-ACK, and data, FIN-WAIT-2 deadline, FIN retransmission in TIME-WAIT, keep-alive (probe after 2 hours, restart on response, close after 9 unanswered probes).
4. **Segment processing order** (one test per line in TCP notes §4.2). All four cases in the segment acceptability table, ACK for out-of-window segments, trimming segments that straddle the window, RST for invalid ACK in SYN-SENT, RST for invalid ACK in SYN-RECEIVED, WL1 and WL2 window update rules, and `SEG.ACK > SND.NXT`.
5. **RFC 5961**. RST outside the window (drop), exactly at RCV.NXT (reset), and elsewhere in the window (challenge ACK). SYN in a synchronized state (challenge ACK), ACK outside its range, and suppression of the 11th challenge ACK within 5 seconds.
6. **Sequence wraparound**: Send 1MiB over a connection with ISS `0xFFFF_F000`. For a transfer beyond 4GiB, use simulated data (length only) to verify a full sequence-number wrap.
7. **Retransmission timer**. Compare to a table calculated by hand from the RFC 6298 §2.2 and §2.3 formulas. Minimum and maximum, backoff, Karn (discard samples for retransmitted segments), and §5.7.
8. **Congestion control**. Initial window, transition from slow start to congestion avoidance, fast retransmit and cwnd on 3 duplicate ACKs, partial and full ACK, cwnd and ssthresh after RTO, and reduction after idle. Values come from a table calculated using RFC formulas.
9. **Flow control**. The sender stops at the window if the receiver does not read. Test the 0-window probe interval and resume when the window opens, receiver and sender SWS avoidance, shrinking windows, and delayed ACK (immediately on the second segment, after 40ms for a single segment, and immediately for out-of-order data).
10. **Out-of-order data**. Reverse order, overlaps (front, back, middle, completely covering), dropping the 33rd range, and memory staying within the limit for 10,000 1-byte segments.
11. **Stack**. Connection and listener lookup, both RST forms with no connection, no response to RST, RST for ACK to a listener, limits (64 being established, 16 per peer, queue 32 and 16 per peer share, 256 connections, 16 listeners) and no response to excess SYN, two-address peer's share (combined across both addresses), identical non-SYN responses on listening and non-listening ports, 16KiB receive window before acceptance and window update after it, ISN increases with time for the same 4-tuple and differs for another 4-tuple, port selection skips TIME-WAIT 4-tuples, and address change yields `peerRemoved`.
12. **Loss injection (property test)**. Put a fake link between two stacks (`LinkSimulator`, with seeded randomness for loss, reordering, duplication, and delay) and run on a fake clock. Send 1MiB in each direction with loss {0, 1, 5, 20}% × reordering {absent, present} × duplication {absent, present} × delay {1ms, 50ms, 500ms} × multiple seeds. Check ① matching hashes of received bytes, ② completion within the specified fake time, ③ buffers within limits at every step, and ④ both connections disappear into CLOSED afterward. Print the seed on failure.

`Tests/SwiftailTests` (node, no sockets):

13. **Name resolution** (behavior A2). IP address, FQDN, short name, letter case and trailing dot, IPv4 first, unknown name, non-peer address, and the node's own name.
14. **Waiting and cancellation**. A `read` with no data waits and resumes, data remains after a canceled `read`, a canceled `write` ends the connection, a canceled `connect`, a second call in the same direction gets `concurrentUse`, waiting calls get `notRunning` when `run()` ends, and a dropped connection is reset with RST.
15. **Address ownership changes** (behavior X10). Peer removal from the netmap, same address assigned to a different key, and a local address change.
16. **Device**. `listen` and `connect` produce `invalidConfiguration` on `.utun` and `.memory`. `inboundPackets` is empty on `.inProcess`. A connection to a local address reaches the local listener and transfers 1MiB (queue from behaviors N3 and N4).

### Go reference comparison

`Tools/interop/cmd/tcpfixtures` (new tool) creates segments using gVisor's `header` package (`gvisor/pkg/tcpip/header`) and emits bytes and expected parse results (ports, numbers, flags, window, options, checksum) as JSON. Cases come from unit test 1. Fixture: `Tests/SwiftailNetstackTests/Fixtures/tcp-segments.json`. A different session from the one that wrote the codec writes the comparison tests. The state machine reference is the real gVisor peer in gate (a) rather than the fixture.

## M6 gate

### (a) Go peer (gVisor)

Start a Swift node with `.inProcess` against `tailnet` from `Tools/interop` (testcontrol + DERP + STUN + Go tsnet peer). The tests live in `Tests/SwiftailInteropTests/NetstackTests.swift` and skip when `SWIFTAIL_TAILNET` is absent.

Commands to add to the `tailnet` tool. Each responds immediately and the transfer runs in the background because the tool handles commands sequentially.

- `peerServe`: `{"cmd":"peerServe","name":"go-peer-a","port":9100}`. Open that peer's tsnet listener. Run the transfer described below for each accepted connection.
- `peerDial`: `{"cmd":"peerDial","name":"go-peer-a","to":"100.64.0.2","port":9100,"send":104857600,"seed":1,"timeoutSec":15}`. The peer connects to the Swift node.
- Implementation decisions (M6-9a, 2026-11-15. See `Tools/interop/README.md` for the exact protocol). `peerDial` returns a `transferID` immediately and the transfer runs in the background. The dialing side first sends a 16-byte header containing **the length the receiving side will send (UInt64 BE) + seed (UInt64 BE)**. The header does not count toward the byte total or SHA-256. Data concatenates successive updated LCG64 states (`x₀ = seed`, `xₙ₊₁ = 6364136223846793005 × xₙ + 1442695040888963407 mod 2⁶⁴`) as 8-byte little-endian values and truncates the final word at the length. Both directions run concurrently. On finishing a send, use `CloseWrite`, and read through EOF on the receiving side. `peerClose` only closes the listener. There is no loss or delay injection on the Go side (use the Swift node's loss hook). `addKernelPeer` was not implemented (N7). A bidirectional 100MB transfer between two Go peers took about 1.8 seconds (loopback).
- `transfers`: List of completed or ongoing transfers. Each entry is `{"name","remote","sent","sentSHA256","received","receivedSHA256","elapsedMs","error","state"}`.
- `peerClose`: Closes the listener.
- "Transfer" means a Task writes `send` bytes of a seeded pseudorandom stream (Swift and Go use the same generator) and calls `CloseWrite`. The other side reads through EOF while computing SHA-256 and counting bytes. The first 16 bytes of the connection (byte count to send and seed) determine how much `peerServe` sends.

| # | Items to verify | Pass criteria |
| --- | --- | --- |
| 1 | Swift listens, Go connects | After 3-way handshake, each side sends 100MB to the other concurrently. Both sides compute SHA-256 hashes and byte counts, which must match. Record the elapsed time and throughput. |
| 2 | Swift connects, Go listens | Same as item 1. Connect using each of the FQDN, short name, and IP address. |
| 3 | IPv6 | As in #1 and #2, but using the peer's IPv6 tailnet address, sending 10MB each. |
| 4 | DERP-only | Block the direct path using the M4 gate method and run item 1 with 100MB. Overflow in the DERP channel causes real loss. Hashes match and the transfer does not stall |
| 5 | Refusal | When Go connects to a Swift port with no listener, the connection ends with "connection refused" before the timeout. When Swift connects to a Go port with no listener, the result is `refused`. |
| 6 | Close and abort | Half-close (one direction completes even after the other finishes first). Go sees a reset error when Swift calls `abort`. Swift receives `reset` when Go aborts. A normal close yields EOF on both sides |
| 7 | Concurrent connections | Open 32 connections simultaneously, sending 4MB in each direction. All hashes match. Record the peak `phys_footprint` of the process during this time. |
| 8 | 1% loss | Run item 1 with 20MB and `setInProcessLoss(rate: 0.01, seed:)`. Hashes match and the received byte count never stops increasing for 30 seconds or longer before the transfer completes. Record throughput for N3 |
| 9 | 5% loss | Same as item 8 with `rate: 0.05` and the same criteria. Record throughput |
| 10 | Limits | No reply to SYN for one peer's 65th connection (64 per remote peer) and 17th unaccepted connection (16 per-peer queue share, or 33rd before 2026-11-17). Connections establish once space becomes available. The node stays up. Unit tests check the total cap of 256 and queue cap of 32 because reaching them requires multiple peers |
| 11 | Regression | M3, M4, and M5 gate (a) all continue to pass on the `.memory` device |

"Does not stall" means that the transfer completes and the longest interval without receive progress is under 30 seconds.

Gate (a) results (2026-11-15, run by the lead session on a single development Mac's loopback tailnet, Go peer with gVisor netstack)

- All 14 verification tests passed (code with reviews A and B incorporated, 3 runs by the delegated session and a full rerun by the lead session). Bidirectional 100MiB transfers matched byte counts and SHA-256 over IPv4, IPv6, FQDN, short name, and DERP-only paths.
- **Throughput** (bidirectional total, 100MiB simultaneously in each direction)

  | Build | Direct path 100MiB × 2 | CPU time | DERP-only |
  | --- | --- | --- | --- |
  | Debug | Approximately 19 seconds (approximately 11 MB/s) | 40–55 seconds | Approximately 20 seconds |
  | Release | 8.85 seconds (23.7 MB/s, approximately 11.8 MB/s per direction) | Approximately 11.5 seconds | 9.0 seconds, CPU 23.6 seconds |

  Measured with the same tool, a 100MB bidirectional transfer between two Go peers (gVisor ↔ gVisor) took about 1.8 seconds. **Swift is about 5 times slower even in release.** CPU time exceeds transfer time (1.3 cores), so per-packet processing cost (about 33µs) appears to be the bottleneck. This covers the whole UDP receive → `Magicsock` → WireGuard → engine → stack → application path, plus test data generation and hashing. The time spent in each part was unmeasured. The gate criteria were met (matching hashes, no stall, and throughput recorded). Reducing the cost is a separate unit that starts with measurements.
- **Loss** (20MiB per direction, seed 19766): debug 0% 11.1MB/s, 1% 7.8MB/s (70%), 5% 0.23MB/s. Release 0% 23.6MB/s, 1% 6.0MB/s (26%), 5% 0.22MB/s. Throughput at 1% loss is above 1/10 of that at 0%, so **N3: Do not start SACK work (M6-10)** (it was opened on reevaluation after fixing the transfer path, see "Results after the three improvement units" below). At 5% loss, 20MiB takes about 3 minutes (no stall, longest receive interval about 3~4 seconds).
- **Memory** (peak `phys_footprint` sample, entire test process): about 14MB for direct 100MiB transfer and about 50~57MB for 32 concurrent connections (debug). **A DERP-only 100MiB transfer used 81MB in release.** Why it is so much higher than direct remains unverified (check for accumulation on the DERP send side).

Measurements (2026-11-15, taken by another session with `sample` in a release build before fixes)

- The **node actor** is the bottleneck rather than the TCP stack. The actor accounts for 93% of time during transfer, which makes transfer times consistent across runs. Between 2 stacks connected in memory, 100MiB bidirectional takes about 0.44 seconds (about 2.4µs per packet). Through the node, one datagram takes about 33µs.
- Breakdown: timer deadline calculation 24.6% (`rearmTimer` is called 3 times per datagram, each with a copy of the entire value and an array allocation), UDP `sendto` 21.2% (called in the actor), WireGuard 20% (about 30% of that is cryptographic computation, the rest copying and allocation), `recvfrom` 5.9%, concurrency runtime 4.9%, TCP state machine 3.2%, TCP buffers 0.2%. Allocation, deallocation, copying, and reference counting make up 30.8% of the total.
- Batch size was 1 (one actor entry per datagram, with `advance` each time). Delayed ACKs did not coalesce, so one pure ACK was sent per segment. The UDP receive queue (256 items) filled and dropped 913 packets. As a result, "simultaneous bidirectional" transfer effectively ran one direction at a time.
- **The 81MB on the DERP path came from Tasks for 5-second write deadlines, not the queue** (`withTimeout` in `DERPClient.writeLoop`). Tasks and timers stayed alive for 5 seconds even after writes finished, accumulating in proportion to write rate × 5 seconds (about 70,000 Tasks at peak). All contract queue limits were enforced. This is a defect that also affects iOS extension memory.
- Effects of temporary fixes measured cumulatively: rearm the timer only at the outermost level and calculate deadlines without allocations → 6.9 seconds, window update condition → 6.6 seconds, group UDP receives and call `advance` once at the end → 3.6 seconds, move `sendto` outside the actor → **2.29 seconds, CPU 4.1 seconds** (before fixes, 8.87 seconds and 11.4 seconds).
- This opened three improvement units: node transfer path (grouped receive, timer, `sendto`, window updates), DERP write deadline, and WireGuard copies.

Results after the three improvement units (2026-11-15, lead session run, same Mac, release, Go peer with gVisor, code incorporating another session's review)

| | Before fix | After fix |
| --- | --- | --- |
| Direct path 100MiB × 2 | 8.85 seconds (23.7 MB/s) | 2.03 seconds (103 MB/s) |
| CPU time | Approximately 11.5 seconds | Approximately 4.0 seconds |
| DERP-only 100MiB × 2 | 9.0 seconds, CPU 23.6 seconds | 4.1 seconds, CPU 10.1 seconds |
| Peak sample of `phys_footprint` for DERP-only | 81 MB | 17 MB |
| Peak sample of `phys_footprint` for direct path | Approximately 14 MB | Approximately 15 MB |
| Loss 0% (20MiB × 2) | 23.6 MB/s | 81 MB/s |
| Loss 1% | 6.0 MB/s (delegated session baseline measurement: 10.1 MB/s) | 3.6–5.0 MB/s (over three runs) |
| 5% loss | 0.22MB/s | 0.20~0.27MB/s |

- The full test suite, including the 14 verification items, passed. All 16 suites ran on the merged code before review fixes. After those fixes, the gate suite and the affected targets' unit tests passed.
- Transfer time approached the roughly 1.8 seconds measured between two Go peers.
- **Throughput at 1% loss decreased.** It was 0.04~0.06 times that at 0%. The cause is gVisor's duplicate ACK counting in behavior F5. Without SACK, data-bearing segments reset the duplicate ACK count to 0. This simultaneously bidirectional test waits for the peer's RTO (200ms) instead of fast retransmit. As Swift became faster, data-bearing segments went out closer together, magnifying the effect. One-way loss throughput had yet to be measured.
- **One-way transfer** (20MiB, gate test `oneWayLoss`, closer to actual use with large transfers in one direction). Swift→Go at 0% loss 82MB/s and 1% loss 6.3MB/s. Go→Swift at 0% 80MB/s and 1% 2.0MB/s. At 0%, 20MiB finishes in about 0.25 seconds, so connection setup and teardown bound those measurements and the actual ratio is lower. At 1% loss, the longest receive interval is about 0.5 seconds, suggesting some losses wait for RTO (at least 200ms) instead of recovering through fast retransmit. Account for loopback's RTT of nearly 0, which makes one RTO look much costlier than on a real network.
- **N3 reevaluation: Open SACK (M6-10) because throughput at 1% loss is below 1/10 of 0% in bidirectional and one-way transfers.** Split into two units.
  - M6-10a receiver side. Negotiate SACK-Permitted and emit receive-buffer ranges as SACK blocks (RFC 2018). This lets the peer (gVisor or kernel) retransmit multiple losses from one window at once. Targets Go→Swift, the slowest direction. This is a small change.
  - M6-10b sender side. Use received SACK blocks to select lost ranges and retransmit them (RFC 6675). This is the largest part of the state machine, so open implementation based on measurements after 10a and real device records (first adopter review result 5). First, check the TCP notes against RFC 6675.
  - SACK does not fully address the weakness of simultaneous bidirectional transfer. Even when it negotiates SACK, gVisor does not count data-bearing ACKs as duplicate ACKs (`isDupAck` in `snd.go` requires `seg.logicalLen() == 0`. The lead session verified this in the source).
- The values prior to the fix were measured during a separate test process that consumed one CPU core for over three hours (the process was later terminated). The post-fix measurements were free of interference from that process.

After receiver-side SACK (M6-10a) (2026-11-15, same conditions. Throughput at 1% loss in MB/s, with ranges due to substantial run-to-run variation)

| | Before | After |
| --- | --- | --- |
| Go→Swift unidirectional | 1.8~2.2 | 4.0~6.8 |
| Bidirectional concurrent | 3.6~5.0 | 7.7~11.6 |
| Swift→Go unidirectional | 5.4~6.3 | 3.4~5.8 |
| 5% loss, bidirectional | 0.20~0.27 | 0.27~0.31 |

- Ranges combine 3 runs by the delegated session and 2 by the lead session (code after review). Throughput at 0% loss stayed the same (about 80MB/s). The gate group of 34 tests and 328 stack unit tests passed.
- Go→Swift and bidirectional throughput more than doubled. Whether gVisor uses SACK recovery was not directly verified from packets. The evidence is indirect. Swift's SYN matches the reference SACK-Permitted SYN byte for byte, gVisor source selects `newSACKRecovery` in that case (`snd.go:356-361`), and only the ACKs sent by Swift changed, yet the direction sent by gVisor sped up.
- **Swift→Go did not improve and measured slightly lower.** Swift does not use received SACK blocks, so there is no reason for an improvement. Whether the decrease was variability (the ranges overlap) or a change in the ACKs sent by gVisor as a receiver after SACK negotiation remains unverified. Review with RTO counters when opening sender-side SACK (M6-10b).
- The bidirectional 1%/0% ratio is 0.096~0.14, near the N3 threshold of 0.1. The one-way ratio is still below 0.1 in both directions. The actual ratio is lower because connection setup and teardown bound the 0% value.

### (b) macOS and iOS kernel stacks

**No path without utun was found.** Kernel TCP needs a tunnel interface (utun), raw socket, or BPF to exchange IP packets with a user process. As far as this repository has established, all require administrator privileges or a Network Extension entitlement (tunnel contract test 9, unverified against XNU source). There are 3 paths (lead session confirmation needed N7).

1. **Go peer launched with administrator privileges** (recommended default gate). Add `addKernelPeer` to `tailnet`. Create utun with wireguard-go's `tun.CreateTUN("utun", 1280)` and pass it to `tsnet.Server.Tun` at startup. When given a TUN, tsnet sends packets for its own address to the TUN instead of the netstack (`tsnet.go:332-335`, `:921-931`). The tool assigns the peer's tailnet address to utun and adds a route to the Swift node's address (`ifconfig`, `route`), then performs "Transfer" from gate (a) with **OS sockets** (`net.Listen`, `net.Dial`). The Swift stack's peer is then macOS kernel TCP. Only this command runs in a separate process launched with `sudo`. It is unverified whether tsnet works with testcontrol in TUN mode and whether utun address or route setup requires anything else. Unit M6-9 runs it manually once first.
2. **Real device** (final verification). Connect from an iPhone with the M5 tunnel extension enabled (Swiftail build variant) to the Mac's Swift listener. iPhone kernel TCP ↔ utun ↔ Swiftail tunnel ↔ tailnet ↔ Mac Swift TCP. This matches the first adopter's actual path. The first adopter session owns this test.
3. **Official Tailscale app**. Connect to the Swift node with an OS socket from a Mac running the official app. Requires a real tailnet and account (same procedure as the final gate in plan §4(b)).

| # | Items to verify | Pass criteria |
| --- | --- | --- |
| 1 | Kernel connects and Swift listens | Hashes match for 100MB in each direction. Record throughput |
| 2 | Swift connects, kernel listens | Same as #1 |
| 3 | 1%·5% loss | (a) Same criteria as 8·9 |
| 4 | Close and abort | Same as gate (a) item 6 |
| 5 | Options selected by the kernel | Capture SYN and SYN-ACK and record MSS, Window Scale, SACK-Permitted, and Timestamps (fill in TCP notes §11 item 4). The kernel uses only options Swift negotiates |
| 6 | (Real device) iPhone receives 100MB from Mac's Swift listener | Hash matches. Record throughput for Wi-Fi and cellular separately. |

#### (b) First measurements for item 6: real device, Wi-Fi (2026-11-15, first adopter session)

An iPhone 14 Pro (iOS 27.2, Swiftail tunnel variant, kernel TCP) requested `GET /file` from a Swiftail host on a Mac mini (`.inProcess`, minimal HTTPS server, TLS via the bridge) on the same Wi-Fi. Production tailnet and staging certificate. Both sides recorded the same 100MiB (104,857,600-byte) length, with no disconnection.

| Execution | Path | Time | Speed | Longest pause |
| --- | --- | --- | --- | --- |
| Range 0~1MiB | relayed | 2.90s | 0.3MiB/s | 0.13s |
| Full 1 | starts relayed, transitions to direct at 22s mark | 48.92s | 2.0MiB/s | 1.15s |
| Range 0~8MiB | relayed | 5.98s | 1.3MiB/s | 0.13s |
| full 2 | direct (at startup, fluctuating between direct·relayed·direct) | 32.20s | 3.1MiB/s | 0.57s |

- Baseline (Go tunnel + Go host over direct UDP in review result 5) was 23.0 seconds. This takes **about 1.4 times as long**.
- Extension memory was 8.8MiB immediately before transfer and 9.0MiB immediately after. No samples during transfer.
- There is no measurement starting on a clean direct path (both started on DERP or fluctuated). The 25~44 seconds to establish a direct path is investigated separately ([Direct Path Delay Investigation](SwiftailMagicsock.md#direct-path-delay-investigation-2026-11-16)).
- The 0.57~1.15-second stalls look like RTO expirations. Add connection close statistics logging to observe RTO and retransmission counts and whether the iPhone kernel includes SACK (M6-10b S1 below). Measure again after inspecting that line.

#### (b) Second measurements for item 6: starting on a direct path (2026-11-16, first adopter session)

Same configuration, same Wi-Fi, both sides on `b27b482` (after TSMP disco key advertising was added). The first contact after enabling the tunnel established direct in about 2 seconds ([Real-Device Remeasurement](SwiftailMagicsock.md#real-device-remeasurement-2026-11-16-first-adopter-session)). Both full transfers started after direct was established. Neither fell back to `relayed` during transfer.

| Run | Path | iPhone measured time | Speed | Longest stall | Server measured time |
| --- | --- | --- | --- | --- | --- |
| Range 0~8MiB | relayed (20) at start, direct after ~2s | 5.55s | 1.4MiB/s | 0.12s | 4.368s |
| full 1 | direct | 24.53s | 4.1MiB/s | 0.83s | 24.377s |
| full 2 | direct | 20.30s | 4.9MiB/s | 0.13s | 20.211s |

- These take **1.07 and 0.88 times** the baseline (Go tunnel + Go host, 23.0 seconds on a different day). There is no same-day Go-to-Go result because the owner chose not to measure the Go baseline. The improvement over the first result (32.2 seconds) is attributed to starting direct (the TCP code did not change).
- Extension memory rose to 7.3MiB just after startup, with no new peak during either transfer (samples every 5 seconds). At most 7.3MiB during transfer.
- With Swiftail only on the receiving side (Go host → iPhone Swiftail tunnel, same day), both 100MiB transfers took about 26 seconds (1-second app log resolution). Extension memory peaked at 9.1MiB.
- **The connection close statistics line was unavailable again.** It is at info level in the unified log and does not persist to disk, so it could not be read afterward. The first adopter started `log stream --level info`, so the next transfer will be captured. M6-10b S1's conditions (RTO count and iPhone kernel SACK) remain open until that line arrives. The 0.83-second stall in Full 1 looks like one RTO.

#### First statistics line: cellular, 8MiB (2026-11-16, first adopter session)

Immediately after the iPhone left Wi-Fi for cellular (`pdp_ip0`), it received Range 0~8MiB once from the same server. The Mac was behind a home router. Both sides ran `b27b482`.

```
Connection ended: finished, lifetime 5898ms, sent 8404074B, retransmitted 0B, RTO 0, fast retransmits 0, partial ACK retransmits 0, duplicate ACKs 0, ACKs with SACK 0, SACK negotiated true, peak cwnd 4059334B, ssthresh reductions 0
```

- **The iPhone kernel negotiates SACK** (`SACK negotiated true`). This satisfies one of S1's two conditions.
- No loss in this transfer (0 retransmissions and 0 duplicate ACKs). The 100MiB transfer log is needed to learn whether the iPhone includes SACK blocks on loss and to count RTOs.
- Server measured 5.447 seconds (1.47MiB/s), and iPhone measured 6.78 seconds (including 1.10 seconds of connection setup). Transfer started `relayed` and became direct at about 3 seconds. A direct path is established on cellular too.
- Direct connectivity returned 8 seconds after switching Wi-Fi → cellular, and the tunnel stayed up. Extension memory peaked at 9.1MiB (before transition).

## M6-10b draft: sender-side SACK recovery

This section is a **draft**. After resolving "M6-10b lead session confirmation needed" below, merge it into behaviors R and F and remove this section. Protocol details are in TCP notes §12 (RFC 6675, RFC 2018 §5, §5.1, and §8 and Errata 1610, RFC 2883, and gVisor comparison). Existing behavior numbers (R6, F5, and so on) refer to "Behaviors" above.

Dependencies on 10a (receiver side). Align names when 10a is finalized.

- `TCPSegment` parses and exposes received SACK option blocks (pairs of left and right `SequenceNumber` edges, up to 4 per segment, RFC 2018 §3). Parsing checks only length (`8*n+2`). The connection validates block semantics in §4 below.
- The connection knows it "negotiated SACK" (both SYNs carried SACK-Permitted). The peer can send SACK blocks only if **this side's SYN carried SACK-Permitted** (RFC 2018 §4). A "SACK connection" in this section meets this condition.

### 1. Scope

| Added | Rationale |
| --- | --- |
| Scoreboard and Update, IsLost, and SetPipe (TCP notes §12.3) | RFC 6675 §4. Basis for recovery |
| RFC 6675 definition of duplicate ACK (new SACK information) | RFC 6675 §2. Use data-bearing and window-changing ACKs as loss signals too (this addresses the Swift-to-peer direction of the weakness described in behavior F5) |
| Entry into recovery (1)(2)(4), recovery in progress (A)(B)(C) | RFC 6675 §5 |
| NextSeg rules 1·2·3 | RFC 6675 §4. Rule 3 is SHOULD (originally MAY from RFC 3517) |
| Clearing the scoreboard on RTO, retransmitting the leftmost segment, and skipping ranges SACKed after RTO | RFC 2018 §5 (SHOULD/MUST), RFC 6675 §5.1 (SHOULD) |
| Condition for new recovery after RTO: `HighACK >= RecoveryPoint` | RFC 6675 §5.1 (MUST NOT) |
| Verification of received blocks and scoreboard upper bound, reneging check | Behavior X. For portions not specified in RFC, this contract's choice applies (below §4) |

| Excluded | Rationale | When to revisit |
| --- | --- | --- |
| NextSeg rule 4 (rescue retransmission) | SHOULD. Applies only when there is a loss at the window end and no new data to send. For large transfers, it occurs once at the end of the response and costs one RTO (200ms) | When gate or real device records show RTO at the end of a response, or small HTTP response latency is reported as a problem (lead session confirmation S2) |
| limited transmit (RFC 6675 §5 (3), RFC 3042) | MAY. Already omitted (exclusions table). Helps only with loss in small windows where 3 duplicate ACKs do not accumulate | When counters show RTOs with cwnd below 4 segments account for much of the total |
| RACK and TLP (RFC 8985) | Time-based loss detection also catches retransmission loss, but the implementation is large. The text was not checked (TCP notes §12.11) | When most remaining RTOs come from retransmission loss |
| Response to D-SACK | RFC 2883 specifies no response. Ignoring it is compliant (TCP notes §12.6) | When records show spurious retransmission from reordering reduces throughput |
| F-RTO (RFC 5682) and Eifel | Undo spurious RTO. The specifications were not read | When spurious RTO is recorded on cellular |
| Conservative timer in RFC 6675 §6 (restart on each retransmission in recovery) | MAY. Follow RFC 6298 as written (behavior R3) | When records show early RTO during recovery |
| Retaining SACK information after RTO (allowed by Errata 1610) | Requires robust reneging detection. The method is unspecified | When records show retransmission after RTO of data already received reduces throughput |
| Send volume control during recovery such as PRR (RFC 6937) | The specification was not read. Use only RFC 6675 pipe | When records show a burst immediately after recovery causes loss |

### 2. State

**`SACKScoreboard`** (new value type, `Sources/SwiftailNetstack/Recovery/SACKScoreboard.swift`). Has no sockets or clock and only numbers as input and output (same shape as `NewRenoCongestionControl`).

- Representation is an array of half-open ranges `[start, end)` expressed as **distances from the send buffer's `startSequence` (data-side `SND.UNA`)**. Ordered by `start`, disjoint and nonadjacent, with `start >= 1`. The byte at `SND.UNA` cannot be SACKed because the cumulative ACK would already have passed it. This is the same approach as `ReceiveBuffer` expressing ranges as distances from `RCV.NXT`.
- Upper bound is data-side `SND.NXT` (distance to `min(SND.NXT, FIN sequence number)`). The FIN sequence number is excluded from the scoreboard (gVisor also covers only data, TCP notes §12.8).
- Also store `retransmittedEnd` (RFC HighRxt + 1, same distance representation). It becomes meaningful only when recovery begins.
- On cumulative ACK, shift the distances by that amount and remove ranges ending at `0` or below. Check for reneging at this point (behavior SR10).
- **Limit: 32 ranges** (the same count and rules as behavior F4's receive buffer). An ACK can carry up to 4 blocks (RFC 2018 §3). Dividing a 256KiB send buffer by MSS 1240 gives about 212 segments, so the worst case of alternating ranges needs about 106 ranges. Loss detection needs only the top three ranges and a byte count (RFC 6675 §4). A Swift peer (32 receive-buffer ranges) cannot report more than 32. gVisor uses 100 (TCP notes §12.8). At 32 ranges, **discard blocks that need a new range** and accept blocks that extend or join existing ranges (gVisor discards even merging blocks at 100, which this does not follow). Discarded information only marks those bytes as not SACKed. Correctness is preserved, at the cost of possible unnecessary retransmission or conservative overestimation of pipe. Memory is at most 512 bytes per connection and at most 128KiB across 256 connections.
- CPU. Merging is bounded by 4 blocks × 32 ranges per ACK. SetPipe and loss boundary calculation scale with the number of ranges (SR6 and SR7 below), as does one NextSeg per segment sent. No calculation iterates byte by byte.

**Changes to existing types** (the implementation unit finalizes names and arguments)

| Type | What's changing |
| --- | --- |
| `SendBuffer` | No changes. Keeping data until cumulative ACK already satisfies the MUST NOT in RFC 2018 §8 and RFC 6675 §4. For retransmission, call existing `bytes(from:upTo:)` with a distance |
| `NewRenoCongestionControl` | Add SACK recovery entry and exit. At entry, set `ssthresh = cwnd = max(FlightSize/2, 2·SMSS)` (RFC 6675 (4.2), with the 2·SMSS floor from RFC 5681 equation 4) and `recover = SND.NXT`. Do not inflate cwnd (`+3·SMSS`, then `+SMSS` per duplicate ACK). ACKs during recovery leave cwnd unchanged. Exit on `SEG.ACK >= recover` (the RFC's "cumulative ACK greater than RecoveryPoint"), keeping cwnd unchanged. Entry requires `SEG.ACK >= recover` (RFC 6675 §5.1. One byte looser than NewReno's `>`). Use the current NewReno path for non-SACK connections and the SR1 exception below |
| `TCPConnection` | One `SACKScoreboard`. Send loop in recovery (SR5 (C)), recording received blocks (SR2), duplicate ACK classification (SR3), RTO handling (SR9), skipping during go-back-N (SR9), and clearing the scoreboard in `terminate` and TIME-WAIT |
| Error | No new error type. Invalid blocks are discarded and the connection is not terminated (same as behavior X1). Not counted in `TCPStack.Output.dropped` (only one option, not a packet) |

Test and gate counters (lead session confirmation S9) are per-connection counts of RTO expirations, recovery entries (NewReno and SACK separately), and retransmitted bytes. Readable only at `package` access. The property test uses them to verify "0 RTOs under burst loss."

### 3. Behaviors (SR)

1. **Branch**. For a non-SACK connection, keep existing behaviors R6 and R7 (NewReno). Even for an SACK connection, **if the scoreboard is empty when entering recovery** (the peer permits SACK but emits no blocks, which RFC 2018 §4 allows), use NewReno for that recovery. RFC 6675 recovery with an empty scoreboard cannot choose what to send on a partial ACK and waits for RTO (NextSeg rules 1 and 3 require SACK). Lead session confirmation S5.
2. **Recording blocks** (RFC 6675 §4 Update, §5 (B.1)). For a segment that passed behavior X3 ACK validation, process the cumulative ACK and move `SND.UNA` first. **Then** validate the blocks under §4 below and merge them. Return whether there was "new SACK information" (whether at least one previously un-SACKed byte was marked).
3. **Duplicate ACKs** (RFC 6675 §2 and §5). On receiving a cumulative ACK, reset DupAcks to 0 (MUST), then increment it by 1 if this ACK is a duplicate (the source states the two sentences in this order). An SACK connection's duplicate ACK is one for which **SR2 produced new SACK information or the current RFC 5681 §2 definition is met** (lead session confirmation S4). Count the former regardless of data, window change, or cumulative ACK progress. Count the latter too so performance does not worsen with a peer that emits no blocks (SR1). The protection RFC 6675 §8 attributes to the SACK criterion (duplicate ACKs caused by forged out-of-window segments) is already provided by WireGuard in the tailnet (introduction to behavior X).
4. **Entry** (RFC 6675 §5 (1), (2), and (4)). When outside recovery with a duplicate ACK and `SEG.ACK >= recover`, enter if `DupAcks >= 3` or `IsLost(SND.UNA)`. (4.1) Set `recover = SND.NXT`. (4.2) Set ssthresh and cwnd from the table above. (4.3) Retransmit `min(SMSS, start of first SACK range)` from `SND.UNA` and set `retransmittedEnd` to its end. (4.4) and (4.5) Run SetPipe, then (C). If neither condition matches, send nothing extra (limited transmit is absent. As now, only new data that cwnd permits goes out at the end of handling an incoming ACK).
5. **ACKs in recovery** (RFC 6675 §5 (A)~(C)). (A) If `SEG.ACK >= recover`, finish recovery. Keep the scoreboard above `SND.UNA` (SHOULD NOT clear). With cwnd unchanged, up to `cwnd − FlightSize` bytes can go out in succession (the burst noted in RFC 6675 §5 and accepted here). (B) Apply SR2 and SetPipe. (C) While `cwnd − pipe >= SMSS`, send what NextSeg selects and add its bytes to pipe. During recovery, `transmitNext` equals `SND.NXT` (no go-back-N).
6. **Loss detection** (RFC 6675 §4 IsLost). Sequence S is lost if there are 3 or more SACK ranges above it, or if the number of SACKed bytes above S is **greater than** `2·SMSS` (gVisor uses greater than or equal, which this does not follow. Lead session confirmation S8). SMSS is `sendMaximumSegmentSize` (Eff.snd.MSS). Count merged ranges in the scoreboard (TCP notes §12.8, difference 2). The test is monotonic, becoming true as S decreases (the SACKed portion above it only grows), so lost bytes are the un-SACKed bytes from `SND.UNA` to a boundary L. L is the start of the first range to cross the threshold while scanning down from the highest range. Compute it in one pass proportional to the range count (derived in this contract and compared against a slow byte-level implementation in tests).
7. **pipe** (RFC 6675 §4 SetPipe). For each un-SACKed byte in `[SND.UNA, data-side SND.NXT)`, add 1 if it is at or above L and 1 if it is before `retransmittedEnd`. The sum is in bytes (gVisor uses segments). Compute it in proportion to range count.
8. **Selecting what to send** (RFC 6675 §4 NextSeg). ① If the smallest un-SACKed sequence S2 at or above `max(SND.UNA, retransmittedEnd)` is below the end of the highest SACK range and below L, select `[S2, min(S2 + SMSS, start of next SACK range))`. ② Otherwise, select one new data segment (at most SMSS. Apply window and sender SWS avoidance under current `transmit` rules). ③ Otherwise, select S3 as in ① without the L condition. ④ Otherwise, send nothing. Trimming at the next SACK range is this contract's choice, unspecified by the RFC, and avoids retransmitting bytes already received. Sending through ① or ③ moves `retransmittedEnd` to the end of what was sent ((C.2)). As today, retransmissions ignore the peer's window (RFC 7323 §2.4), discard RTT samples per Karn (behavior R2), and do not count toward the retransmission limit (behavior R4. Only RTO expiration counts). If a selected range ends at the FIN sequence number and FIN has already been sent, include FIN (as in current `retransmitFirstUnacknowledgedSegment`).
9. **RTO** (in addition to behaviors R3, R4, and R6, RFC 2018 §5 and RFC 6675 §5.1). Clear the entire scoreboard (SHOULD, as in gVisor), exit recovery if in it, and set `recover = SND.NXT`. Do not start new SACK recovery until `SEG.ACK >= recover` (MUST NOT). Keep go-back-N retransmission from `SND.UNA` (always retransmit the leftmost segment, MUST), but skip ranges SACKed by **blocks received after RTO** (SHOULD, as in gVisor `snd.go:1118-1123`). Follow RFC 6298 timer behavior unchanged (default in RFC 6675 §6).
10. **reneging** (RFC 2018 §8, this contract's check). When a cumulative ACK moves `SND.UNA` to v, if v is at the start of or inside an SACK range (`start <= v < end`), the receiver no longer holds the SACKed data. If it still held that range, the cumulative ACK would be at or beyond its end. Late ACKs do not move `SND.UNA` and are outside this check. Clear the entire scoreboard. If in recovery, continue it (an empty scoreboard has nothing to select) and let RTO handle what remains. Data is retained until cumulative ACK, so it is not lost. Lead session confirmation S6.
11. **0 window·persist·FIN·closing**:
    - 0-window probes (behavior F8) are enabled only when nothing is in flight, so they do not overlap recovery. If the peer's window becomes 0 in recovery, retransmissions under ① and ③ still go out (they were in-window when first sent), while new data under ② stops. The shrunk-window exception (under behavior F8) is unchanged because it concerns RTO counting.
    - FIN is outside the scoreboard. If the right edge of a block exceeds the FIN number, trim the block to the end of the data (see §4 below).
    - Recovery runs only in states where `transmit` currently runs (ESTABLISHED, CLOSE-WAIT, FIN-WAIT-1, CLOSING, LAST-ACK). Clear the scoreboard on entering TIME-WAIT or termination. The `readClosed` rule (released connections in behavior F8) stays the same.
12. **Wording to update when finalizing this draft**
    - NewReno row of "Scope supported in M6": Add "SACK connections use RFC 6675 recovery (M6-10b)."
    - At the end of behavior R6, prepend "If this is not an SACK connection or the SR1 exception applies" to "On 3 duplicate ACKs, apply RFC 5681 §3.2 steps 2~6 with …". The `recover` comparison (`ACK > recover`) under "Implementation decisions" uses `>=` in SACK recovery.
    - Behavior R7, "Retransmit one segment starting from SND.UNA every time (no SACK)". Use SR8 for SACK connections and SR9 skipping for go-back-N after RTO.
    - At the end of the second item under behavior F5, "SACK (M6-10) addresses this loss recovery weakness". SR3 resolves it when Swift is the sender (counting data-bearing ACKs too), and it remains when Go is the sender because of gVisor's `isDupAck` (TCP notes §12.8, difference 1).
    - The 10b item under "Results after the three improvement units" points to this draft.
    - Behavior M table: "SACK scoreboard ranges | 32 per connection | Drop that block" row.
    - Behavior X: new item (summary of below 4).
    - Replace the "SACK (sender and receiver)" exclusions row with the exclusions table in §1 above.
    - Add §5 below to tests 8 and 12. Use the table in §6 below for the files owned by implementation unit M6-10.
    - Code doc comments: "No SACK (contract lead session decision N3)" in `NewRenoCongestionControl.swift`, "Retransmissions always start at `SND.UNA` (contract behavior R7, no SACK)" in the `TCPConnection+Sending.swift` header, and the `isDuplicateAcknowledgment` doc comment in `TCPConnection+Receiving.swift`.
    - In TCP notes §4.7 item 7 (definition of duplicate ACKs), add a sentence pointing to the definition for SACK connections. TCP notes §12.7 lists these changes.

### 4. Validation of received blocks

For each block, from SR2, after processing the cumulative ACK, examine `SND.UNA` (denoted U) and data-side `SND.NXT` (denoted E). The distance is a signed 32-bit difference as per behavior W5.

1. If not a SACK connection, ignore the SACK option. The peer must not send it (RFC 2018 §4).
2. At most 4 blocks per segment (the codec validates option length `8*n+2`, 10a). Do not assume sorting (RFC 2018 §4).
3. `s = left edge − U`, `e = right edge − U`. Discard the block if the following condition holds:
   - `s <= 0` means the block starts at or below U. This includes D-SACK (below the cumulative ACK of the same packet), late ACKs, and inconsistent blocks. D-SACK is not identified separately or used, so the RFC 2883 §5 comparison rules are unnecessary.
   - `e <= s`: Empty or reversed. A block of nearly 2³² size, cycling through 2³², is here (gVisor does not perform this check. TCP note 12.9).
   - A right edge beyond `SND.NXT` SACKs unsent data.
   Then truncate `e` to E (this removes any part covering the FIN sequence number). If after truncation `e <= s`, discard it.
4. Merge remaining blocks. Discard blocks requiring a 33rd range (see §2 above).
5. If D-SACK reiterates an already SACKed range above the cumulative ACK, no change occurs upon combining (no new information, so it is not counted as a duplicate ACK).
6. Discarding a block produces no response and leaves the connection open. Process the other blocks and the ACK in the same segment as usual.
7. Check for reneging on the cumulative ACK (SR10).

This bounds memory used by false blocks (32 ranges) and CPU per ACK (4 blocks × 32 ranges), prevents permanently skipping unsent data due to SACK, and rejects reversed blocks under wrapping arithmetic. A peer can still delay **its own connection** until RTO through false SACKs or reneging (correctness holds, and if cumulative ACK does not advance, behavior R4's limit ends the connection). Even if false SACKs reduce pipe, in-flight bytes stay within cwnd (halved on entering recovery), the peer's window, and the 256KiB send buffer.

### 5. Test plan

Unit (`Tests/SwiftailNetstackTests/Recovery/SACKScoreboardTests.swift`, no socket):

1. Merging: overlaps (front, back, middle, completely covering), touching ranges, 4 unordered blocks, and no new information from a repeated block.
2. Discarding: start at U (`s = 0`), below U, empty block, reversed block, beyond `SND.NXT`, and trimming a block that covers the FIN sequence number. Accept a valid block crossing the 2³² boundary (ISS `0xFFFF_F000`).
3. Limit: drop a 33rd range at 32 and still accept extensions and joins of existing ranges at 32.
4. Cumulative ACK: remove range prefixes and shift distances, clear on reneging (ACK at the start of or within a range), and do not treat ACK at the range end as reneging.
5. IsLost: true with three ranges above and false with two, false for exactly `2·SMSS` SACKed bytes and true for one more, and multiple segments smaller than SMSS.
6. Pipe and loss boundary: compare a slow byte-level reference implementation (in the test, following the wording of RFC 6675 §4 exactly) against 10,000 fixed-seed random scoreboard and `retransmittedEnd` inputs.
7. NextSeg: rule ① order, (1.a) only after `retransmittedEnd`, (1.b) only below the highest SACK, ② before ③, ③, failure, trimming at the next range, and an ending that includes FIN.

Connection (`Tests/SwiftailNetstackTests/Connection/ConnectionSACKRecoveryTests.swift`, `ScriptedTCPPeer` used to manually write the peer's blocks following RFC 6675 steps):

8. Send 10 segments and lose the third → enter on the third ACK carrying blocks (DupAcks). Another case: three large segments are SACKed in one ACK → enter on the first ACK (`IsLost(SND.UNA)`). Compare cwnd, ssthresh, pipe, and `retransmittedEnd` at each step to a hand-calculated table.
9. Lose three segments in one window (#2, #5, #7) → retransmit three ranges in one recovery without RTO, and the retransmitted bytes match the lost bytes.
10. Lose new data sent during recovery → use ① in the same recovery. Lose the segment immediately following recover → after recovery ends, reenter with `SEG.ACK >= recover` (a case where NewReno would hit RTO).
11. Lose retransmission → RTO → scoreboard empty, retransmit `SND.UNA` → skip ranges covered by blocks received after the RTO. During recovery, RTO → do not re-enter before `SEG.ACK >= recover`.
12. An ACK carrying data, or an ACK with a changed window, counts as a duplicate ACK if it carries a new block. If SACK is not enabled, the current test (data-bearing ACKs and ACKs with window changes do not count as duplicates) still passes unchanged.
13. Peer allows SACK but does not send a block → NewReno recovery (the current recovery test is also run with SACK-enabled connection).
14. Reneging: After the peer sends a SACK block, the cumulative ACK reaches a sequence number within that SACKed range → scoreboard is cleared and transmission continues to completion.
15. Invalid blocks: 1,000 ACKs with 4 blocks each (fixed seed, mix below U, above `SND.NXT`, reversed, and valid) → no crash, at most 32 ranges, and received byte hashes match.
16. Peer window becomes 0 during recovery (retransmissions go out and new data stops), a gap that includes FIN, recovery in CLOSE-WAIT and FIN-WAIT-1, and empty scoreboard after termination.

`LinkSimulator` property tests (add to test 12)

17. Add one more dimension: SACK on/off (enable and disable the negotiation on both sides of 10a). Add to current four properties (hash, time, buffer limit, CLOSED) the scoreboard range count ≤ 32.
18. Burst loss: Use `DropRule` to drop k consecutive packets once in one direction (k ∈ {3, 10, 30}). With SACK enabled, there are 0 RTO expirations (seeds without retransmission loss), and the virtual completion time is shorter than with SACK disabled.

Gate measurements. Add records only to gates (a) and (b), with no new pass criteria.

19. (a) One-way Swift→Go at 1% loss (`oneWayLoss`): throughput (currently 6.3MB/s) and longest receive interval (currently about 0.5 seconds). Swift→Go throughput at 1% bidirectional loss. Loss at 5%. Measure before and after 10b using the same seed.
20. Gate (b) item 5: XNU SACK-Permitted. Gate (b) item 6: iPhone receiving 100MB over Wi-Fi and cellular before and after 10b (comparison requires a test switch to disable SACK. Check whether 10a provides it).

### 6. Size and assessment

**Change Scale (Estimated)**:

| File | Lines added (including documentation comments) |
| --- | --- |
| `Sources/SwiftailNetstack/Recovery/SACKScoreboard.swift`(new) | about 200 |
| `Sources/SwiftailNetstack/Recovery/NewRenoCongestionControl.swift` | about 40 |
| `Sources/SwiftailNetstack/Connection/TCPConnection.swift`, `+Receiving`, `+Sending`, `+Timers` | about 170 |
| `Tests/SwiftailNetstackTests/Recovery/SACKScoreboardTests.swift`(new) | about 300 |
| `Tests/SwiftailNetstackTests/Connection/ConnectionSACKRecoveryTests.swift`(new) | about 350 |
| `Tests/SwiftailNetstackTests/Support/LinkSimulator.swift`, `Scenarios/LinkPropertyTests.swift` | about 60 |

About 400 lines of product code (about 12% of the current 3,348 lines of `SwiftailNetstack`) and about 700 lines of tests. It builds on `Wire/` and `TCPConnection+Opening.swift` changes from 10a, so open it once 10a is complete.

**Risk**:

- Overestimating pipe can keep `cwnd − pipe < SMSS` and stall until RTO. Underestimating it can cause a burst. Comparison with the byte-level reference implementation (test 6) is the main defense.
- Off-by-one difference between the RFC's inclusive endpoints (HighRxt and RecoveryPoint) and this code's half-open endpoints.
- State machine that combines recovery path and go-back-N (`transmitNext`). During recovery, the invariant `transmitNext = SND.NXT` is checked in tests.
- Relies on the peer's SACK generation. If XNU does not generate a SACK block, the first adopter gains nothing from it (TCP notes §12.11 item 4).
- cwnd stays unchanged when recovery ends, so a large cumulative ACK causes a burst (acknowledged in RFC 6675 §5).

**Is it worth adding? Calculations and rationale.** The values below are all estimates. Use MSS 1240 (IPv4 tailnet, behavior T5) and a 200ms RTO minimum (behavior R1).

1. **Loopback exaggerates the cost of one RTO.** Loopback RTT is nearly 0, so a 200ms RTO minimum is thousands of round trips. In a 20MiB Swift→Go transfer (about 16,900 segments), 1% loss is about 170 losses. The 0% run takes about 0.25 seconds and 1% takes about 3.3 seconds (6.3MB/s). Attributing the full extra 3.1 seconds to RTO waits gives about 15 expirations, or about 9% of losses recovered by RTO (unverified by counters). If the same happens on a network with 20~50ms RTT, one RTO costs "200ms + 2~3 round trips for slow start back to ssthresh − 1 round trip that fast recovery would have taken," or about 5 round trips (50ms, if RTO is at the 200ms minimum) to 12 round trips (20ms). The drop to 1/10 throughput seen on loopback does not occur on a real network.
2. **Upper bound on a real network at 1% random loss.** The Mathis approximation `throughput ≈ (MSS/RTT) · √(3/2) / √p` gives about 0.76MB/s at 20ms RTT and 0.30MB/s at 50ms, with an average window of `√(1.5/p)` ≈ 12 segments. It assumes periodic loss, no timeouts, no window limit, and long transfers, so read it as an upper bound when "all losses recover without RTO." With timeouts, the Padhye et al. approximation (`T0 = 200ms`) gives 0.82× Mathis (20ms) and 0.92× (50ms) with an ACK per segment, or 0.58× and 0.65× with an ACK every two segments. **Even eliminating all timeouts gives at most 1.1~1.7× within this model.** Most model timeouts come from losses in small windows where three duplicate ACKs do not accumulate and from retransmission losses. RFC 6675 (without rescue or limited transmit) does not solve those.
3. **Multiple losses in one window are rare at 1% random loss.** Among 12-segment windows with any loss, the fraction with at least two losses is about 5.4% (3.5% in an 8-segment window and 7.4% in a 16-segment window, calculated from the independent-loss binomial distribution). Current NewReno also recovers these without RTO, one segment per partial ACK (partial ACK restarts the timer, behavior R3 and RFC 6298 §5.3). Even applying the 9% in item 1 to a real network and eliminating all those RTOs saves about 6% of time (50ms) to 13% (20ms). **Estimated SACK recovery throughput gain at 1% random loss and 20~50ms RTT is about 5~15%** (exceeding 20% is difficult).
4. **Loss patterns with increasing disparity**:
   - **Burst loss** (k consecutive segments). NewReno retransmits one per round trip, taking k round trips and sending little during that time. RFC 6675 retransmits gaps up to cwnd − pipe within the first round trip with SACK blocks. For k = 30 and 30ms RTT, NewReno takes about 0.9 seconds and SACK about 1~2 round trips (0.03~0.06 seconds). Bursts arise when slow start overflows the bottleneck queue (the window doubles and much of it is lost together), the DERP channel overflows (256 items and 1MiB, behavior N10), or a wireless segment suffers consecutive failures.
   - **Large-window paths**. At 1% loss and a 200-segment window, there are 2 losses per window on average and at least two in 60% of windows (as on loopback).
   - **Data-bearing ACKs and window-changing ACKs**. The current RFC 5681 definition does not count these, so those losses go to RTO. This occurs in bidirectional transfers and with peers that autotune the receive window so each ACK changes it (gVisor enables autotuning, TCP notes §5). This benefit comes from SR3's duplicate ACK definition rather than retransmission selection. **The hypothesis that some one-way loopback RTOs result from gVisor's window changes** is unverified (counters would distinguish it immediately).
   - **Loss of the segment immediately after recover**. The NewReno rule (`ACK − 1 > recover`) blocks entry and causes RTO. This is the first new data sent in recovery, so with 1% loss it occurs in about 1% of recoveries.
5. **First adopter**: Large transfers use the path Mac(Swift) → iPhone kernel, mostly via direct Wi-Fi. It is still unknown whether XNU generates SACK blocks (gate (b) 5). If not, 10b has no effect.

**Assessment**. There is a benefit. Compared with "throughput at 1% random loss" (estimated 5~15% on a real network), the main benefits are **faster recovery from burst loss, fewer RTO stalls over 200ms, and the use of data-bearing and window-changing ACKs as loss signals**. The first adopter's benefit depends on XNU emitting SACK. After 10a, ① check XNU's SACK-Permitted and SACK blocks in gate (b) item 5 and ② use the counters above to measure RTO expirations in current code and their causes (uncounted window-changing or data-bearing ACKs, loss of a retransmission, or insufficient duplicate ACKs). If XNU emits SACK, the recommendation is to implement the scope in §1. If ② attributes most RTOs to the duplicate ACK definition, S2 option (b) also captures that benefit (SACK for entry only, about 100 lines).

### M6-10b lead session confirmation needed

| # | What | Options | Recommendation | Reason |
| --- | --- | --- | --- | --- |
| S1 | When to open | (a) Immediately after 10a / (b) After 10a, after checking XNU SACK and RTO counters / (c) Defer until after M7 | (b) | Assessment in §6. The benefit for the first adopter depends on XNU, and the cause of RTOs changes the answer to S2 |
| S2 | Scope | (a) Table in §1 (NextSeg 1~3, pipe, skipping after RTO) / (b) SACK for entry only (enter using SR3's definition and `IsLost(SND.UNA)`, retransmit with NewReno) / (c) Add rescue (rule 4) to (a) | (a). Use (b) if counters point to the duplicate ACK definition | (b) addresses data-bearing and window-changing ACKs in about 100 lines but does not address burst loss. Rescue is SHOULD, but omitting it costs one RTO at the end of the response. Use measurements to decide whether to add it |
| S3 | Scoreboard limit | (a) 32 ranges, drop only blocks requiring a new range / (b) 100 ranges (gVisor) / (c) Half the segment count of the send buffer (about 106) | (a) | Easy to read because the count and rule match the receive buffer. The top three ranges suffice for loss detection. Dropped information has only a conservative effect |
| S4 | Duplicate ACK for SACK connection | (a) As defined in RFC 6675 or RFC 5681 / (b) Only as defined in RFC 6675 / (c) Both must be filled, as in gVisor | (a) | (b) Becomes worse than current when the peer does not send blocks. (c) Re-discards an ACK carrying data. Protection in RFC 6675 Section 8 is provided by WireGuard. |
| S5 | SACK connection with scoreboard empty upon entry | (a) Recovery follows NewReno / (b) As per RFC 6675 verbatim | (a) | (b) Has no data to send for partial ACKs and thus waits for RTO. |
| S6 | Reneging detection | (a) Clear if cumulative ACK reaches the start of or anywhere inside an SACK range (SR10) / (b) Clear only on RTO (gVisor) | (a) | One comparison proportional to the range count. Errata 1610 requires robust detection. Without it, correctness holds but recovery waits for RTO |
| S7 | Scoreboard on RTO | (a) Clear (RFC 2018 §5 SHOULD, gVisor) / (b) Keep (allowed by Errata 1610, Linux) | (a) | (b) assumes robust reneging detection, and the erratum does not specify the method |
| S8 | Byte threshold for IsLost | (a) greater than `2·SMSS` (RFC) / (b) at least `2·SMSS` (gVisor) | (a) | RFC 6675 §9 states that it maintains the requirement for "three segments" |
| S9 | Test and gate counters | (a) Connection `package` counters (RTO expirations, recovery entries, retransmitted bytes) / (b) No counters, count from output segments | (a) | Property test 18 and S1's ② can read the RTO count directly. The counters are not logged, so they do not conflict with behavior K |

Lead session decision (2026-11-15). **S1 is (b).** Open it after merging 10a and remeasuring, checking XNU SACK in gate (b) item 5, and reviewing RTO counters. Do not implement before then. Start S2~S9 as recommended when opening the work, and revisit S2 based on the counters. A different session verifies TCP notes §12 against the original RFCs before implementation.

## Implementation units

Divide ownership so files do not overlap. "Architecture" and each behavior define the interfaces between units (type shapes), and M6-0 finalizes them.

| Unit | Content | Owned files | Sequence |
| --- | --- | --- | --- |
| M6-0 | Lead session: finalize this contract (N1~N11, F answers), verify the TCP notes (another session), add `SwiftailNetstack` and `SwiftailNetstackTests` targets to `Package.swift`, and update the plan | `docs/contracts/SwiftailNetstack.md`, `docs/plan.md`, `Package.swift`, `docs/protocol-notes/` | First |
| M6-1 | Move the checksum and implement the `TCPSegment` codec (behavior W). The lead session created `SequenceNumber` in M6-0 (`Sources/SwiftailNetstack/Wire/SequenceNumber.swift`, shared by parallel units) | `Sources/SwiftailBase/InternetChecksum.swift`, `Sources/SwiftailEngine/Tunnel/ServiceIPReply+Checksum.swift` (call only), `Sources/SwiftailNetstack/Wire/*`, `Tests/SwiftailNetstackTests/Wire/*`, `Tests/SwiftailBaseTests/InternetChecksumTests.swift` | After M6-0. **In parallel with 2, 3, 7, and 9a** |
| M6-2 | Send and receive buffers (including out-of-order ranges, behaviors F1, F4, and F6) | `Sources/SwiftailNetstack/Buffers/*`, `Tests/SwiftailNetstackTests/Buffers/*` | **Parallel** (coordinate only the `SequenceNumber` shape with M6-1) |
| M6-3 | RTO estimator and NewReno (behaviors R1~R3, R6, and R8). Value types with only numeric inputs and outputs | `Sources/SwiftailNetstack/Recovery/*`, `Tests/SwiftailNetstackTests/Recovery/*` | **Parallel** |
| M6-4 | Connection state machine (behaviors T, R4·R5·R7, F2·F3·F5·F7~F9, X2~X5·X9) | `Sources/SwiftailNetstack/Connection/*`, `Tests/SwiftailNetstackTests/Connection/*` (basic path for tests 3·4·5·9) | After M6-1·2·3. Largest in size |
| M6-5 | Stack (behaviors S, X7·X8) | `Sources/SwiftailNetstack/Stack/*`, `Tests/SwiftailNetstackTests/Stack/*` | After M6-4 |
| M6-6 | Independent tests: `LinkSimulator` and property tests (test 12), and cases from tests 4, 5, 6, and 10. Write using only the contract and TCP notes | `Tests/SwiftailNetstackTests/Support/*`, `Tests/SwiftailNetstackTests/Scenarios/*` | A **different session** from M6-4's author. Write the harness in parallel with M6-4 and run tests after M6-5 |
| M6-7 | Go reference tool and fixtures, and comparison test | `Tools/interop/cmd/tcpfixtures/`, `Tests/SwiftailNetstackTests/Fixtures/tcp-segments.json`, `Tests/SwiftailNetstackTests/Wire/GoSegmentComparisonTests.swift`, new section in `Tools/interop/README.md` | Tool in **parallel**. A different session writes the comparison test after M6-1 |
| M6-8 | Node integration (behavior N·A·K, X10): `TunnelDevice.inProcess`, stack linking and queue, public API, name resolution, pending calls, dropped handles, loss hook | `Sources/Swiftail/**`, `Tests/SwiftailTests/Netstack*` (tests 13–16) | After M6-5 |
| M6-9 | Gate: (9a) `tailnet` tool's `peerServe`·`peerDial`·`transfers`·`peerClose`·`addKernelPeer` and README, (9b) `NetstackTests.swift` and documentation on how to attach two Swiftail nodes to a test control server to run `listen`·`connect` (first adopter review result 6) | `Tools/interop/cmd/tailnet/*`, the `tailnet` section in `Tools/interop/README.md`, `Tests/SwiftailInteropTests/NetstackTests.swift` | 9a can proceed **in parallel** because it edits a different README section from M6-7. 9b follows M6-8 |
| M6-10 | SACK. 10a receiver side (negotiation, emitting SACK blocks), 10b sender side (RFC 6675 recovery, start based on measurements after 10a) | `Sources/SwiftailNetstack/Recovery/SACK*` and files from M6-1, M6-2, and M6-4 | Opened because gate (a) item 8 was below the N3 threshold (2026-11-15) |

Order: M6-0 → (M6-1, 2, 3, 6 harness, 7 tool, 9a) in parallel → M6-4 → M6-5 → M6-6 tests → M6-8 → M6-9b → review by another session → lead session reruns gate (a) → gate (b) → M6-10 (if needed).

## Connection close statistics log (2026-11-16)

One log line at connection closure records the values needed for M6-10b S1 (① how many RTOs and fast retransmits occurred, ② whether the peer kernel includes SACK blocks) without expanding the public diagnostic API.

**Where counters are collected**. The connection state machine stores them in the `TCPConnection.Statistics` value (`package`). Each value is counted in one line at the point where the event occurs (`TCPConnection+Sending`, `+Receiving`, `+Timers`, and `+Opening`). The stack includes the value in `.closed(id, reason, statistics)` (for connections reported on entering TIME-WAIT, the counts stop at entry), and the node appends it to the `Connection ended` log entry (`privacy: .public`). The statistics contain only numbers and Booleans. The node omits addresses, ports, and peer names (behavior K2). Every connection the application has held gets one entry. Connections that end during establishment or while queued produce no event and therefore no log entry.

**Connections released by the application (updated 2026-11-16)**. A connection the application releases with `close` or `abort` also emits the same line **once** when TCP finishes and appends `, closed after release`. "When TCP finishes" means when the connection enters CLOSED (final ACK, RST, retransmission or keep-alive limit, or FIN-WAIT-2 deadline) or enters TIME-WAIT. The reason names and meanings are the same as for connections held by the application, and the values are counted up to that point (including retransmissions after release). Application events and `TailnetConnection` behavior stay the same. Closure of a released connection only produces a log entry and does not wake application calls. A connection that already logged closure while held and was then released does not log again. Connections dropped together when the node stops may omit the log entry.

When a peer sent FIN first, the application called `close` immediately (common in HTTP servers), so even normal closure produced no log line. This is exactly the case for statistics from connections where the server sent a large response.

The node uses the stack output `.releasedConnectionClosed(reason, statistics)` only for logging. It sits outside the application's `Event` type. An `abort` or a `close` that finishes immediately produces a single log line from the `.closed` emitted by that call. Tests are `StackReleasedCloseTests` and `NetstackCloseLogTests`. Gate (2026-11-16): 0 warnings, unit tests 79·231·226·142·340·37·243·256, interop tests 62·8·5.

Line from a real transfer (2026-11-16, real tailnet, this node sent 100MiB as the HTTP server, relayed for the first 3 seconds and then direct)

```
Connection ended: reset, lifetime 53189ms, sent 105002661B, retransmitted 439044B, RTO 7, fast retransmits 2, partial ACK retransmits 1, duplicate ACKs 428, ACKs with SACK 435, SACK negotiated true, peak cwnd 4729196B, ssthresh reductions 8, closed after release
```

The retransmitted amount was 0.42% of the sent amount. Of 10 loss recoveries, 7 were RTOs and only 2 were fast retransmits. The sender received 435 ACKs with SACK. Lifetime includes idle time after the transfer and cannot be used to infer transfer speed. One transfer does not determine the benefit of sender-side SACK.

**Format**

```
Connection ended: aborted, lifetime 240ms, sent 262144B, retransmitted 0B, RTO 0, fast retransmits 0, partial ACK retransmits 0, duplicate ACKs 0, ACKs with SACK 0, SACK negotiated true, peak cwnd 143840B, ssthresh reductions 0
```

| Name | Meaning |
| --- | --- |
| lifetime | From the first send of a SYN (active open) or SYN-ACK (passive open) until the node processed `.closed`, in milliseconds |
| sent | Data bytes sent for the first time, excluding SYN and FIN |
| retransmitted | Data bytes retransmitted by go-back-N after RTO, fast retransmit, or partial ACK. Excludes the 1-byte 0-window probe |
| RTO | The number of retransmission timer expirations for data or FIN, excluding SYN or SYN-ACK expirations |
| fast retransmits | The number of fast recovery entries after three duplicate ACKs (RFC 5681 §3.2) |
| partial ACK retransmits | The number of times a partial ACK caused a segment retransmission during fast recovery (RFC 6582 §3.2 item 3) |
| duplicate ACKs | The number of ACKs that met the RFC 5681 §2 definition (no data, same window as the previous ACK, and so on) |
| ACKs with SACK | The number of received segments with a SACK option that passed ACK validation (RFC 5961 §5.2). Counts arrivals regardless of negotiation. Blocks are still unused |
| SACK negotiated | The peer SYN (SYN-ACK) contained SACK-Permitted. This side always includes the option on an active open and includes it on a passive open only if the peer sent it, so both sides negotiated it |
| peak cwnd | The maximum cwnd in bytes immediately after acknowledgment of new data outside fast recovery. Excludes the inflated value during recovery. If no data was sent, this is the initial window (IPv4 12400). If the connection ended before establishment, this is 0 |
| ssthresh reductions | The number of times a loss (three duplicate ACKs or the first RTO expiration for the same segment) reduced ssthresh from its previous value |

Receiver-side values (maximum out-of-order range count and number of dropped segments) are omitted because they are not counted.

**How to read the statistics**

- `retransmitted / sent` is the retransmission ratio. At 1% loss during one large transfer, it is about 0.01. A much larger value means go-back-N after RTO retransmitted ranges the receiver already had.
- The ratio of `RTO` to `fast retransmits + partial ACK retransmits` shows how losses were recovered. A stall (a gap of more than 200ms) usually corresponds to one RTO.
- If `duplicate ACKs` is noticeably lower than `ACKs with SACK`, the RFC 5681 definition excluded some ACKs that carried loss signals because the window changed or the ACK carried data (M6-10b §6 item 4, "Data-bearing ACKs and window-changing ACKs"). The first duplicate ACK immediately after establishment is excluded because the preceding ACK was a SYN-ACK with a different window (the window field before scaling). A difference of about one per loss may therefore always occur.
- `ssthresh reductions` counts loss events (recovery entries). Repeated expirations for the same segment are excluded.

**How to use the statistics for M6-10b S1**. Run one 100MiB Mac (Swiftail) → iPhone transfer and inspect the log line for the sending connection.

1. If `SACK negotiated true` and `ACKs with SACK` is greater than 0, XNU emits SACK blocks (the answer to gate (b) item 5). If `SACK negotiated false`, or loss occurred (`ssthresh reductions` > 0) and `ACKs with SACK` is 0, it emits none and 10b will have no effect for the first adopter (assessment in §6 item 5).
2. If `RTO` is comparable to `fast retransmits`, RTO is the main cause of stalls. If the gap between `duplicate ACKs` and `ACKs with SACK` is large, changing the duplicate ACK definition captures that part of the benefit (S2 option (b), SACK only for recovery entry). If the gap is small and there are many `partial ACK retransmits`, multiple losses in one window (burst loss) point to S2 option (a).
3. If there are almost no `RTO` events and only `fast retransmits`, something other than loss recovery accounts for the difference between 32 seconds and 23 seconds (check `peak cwnd` to see whether the window failed to grow). In that case, 10b offers little benefit.
